const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

/**
 * Converted from PHP:
 * - Takes profile_id and date from body
 * - Fetches latest test for selected date
 * - Fetches previous test before selected date
 * - Extracts final_macro_summary from test_json
 * - Calculates macro percentage
 * - Calculates change from previous test
 *
 * Authentication is handled in apiRoutes.js using authMiddleware.
 */

/* ===============================
   Helpers
================================ */

function toNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

/**
 * Validates a calendar date in strict YYYY-MM-DD form (no SQL injection risk
 * since queries are parameterized, but rejects malformed input early).
 * Returns the normalized "YYYY-MM-DD" string, or null if invalid.
 */
function normalizeDate(value) {
  if (typeof value !== "string") return null;

  const trimmed = value.trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return null;

  const [year, month, day] = trimmed.split("-").map(Number);

  const parsed = new Date(Date.UTC(year, month - 1, day));

  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    return null;
  }

  return trimmed;
}

function roundOne(value) {
  return Math.round(value * 10) / 10;
}

function calculateMacroPercentage(macroSummary) {
  const carbsKcal = toNumber(macroSummary?.carbs_g) * 4;
  const proteinKcal = toNumber(macroSummary?.protein_g) * 4;
  const fatKcal = toNumber(macroSummary?.fat_g) * 9;
  const fiberKcal = toNumber(macroSummary?.fiber_g) * 2;

  const totalKcal = carbsKcal + proteinKcal + fatKcal + fiberKcal;

  if (totalKcal <= 0) {
    return {
      carbs_percent: 0,
      fat_percent: 0,
      protein_percent: 0,
      fiber_percent: 0,
    };
  }

  return {
    carbs_percent: roundOne((carbsKcal / totalKcal) * 100),
    fat_percent: roundOne((fatKcal / totalKcal) * 100),
    protein_percent: roundOne((proteinKcal / totalKcal) * 100),
    fiber_percent: roundOne((fiberKcal / totalKcal) * 100),
  };
}

function calculateChangePercentage(currentValue, previousValue) {
  const current = toNumber(currentValue);
  const previous = toNumber(previousValue);

  if (previous === 0) {
    return {
      change_percent: current > 0 ? 100 : 0,
      change_type: current > 0 ? "increase" : "no_change",
    };
  }

  const change = ((current - previous) / previous) * 100;

  return {
    change_percent: roundOne(Math.abs(change)),
    change_type:
      change > 0 ? "increase" : change < 0 ? "decrease" : "no_change",
  };
}

function parseTestJson(testJsonRaw) {
  try {
    if (!testJsonRaw) return null;

    if (Buffer.isBuffer(testJsonRaw)) {
      testJsonRaw = testJsonRaw.toString("utf8");
    }

    if (typeof testJsonRaw === "object") {
      return testJsonRaw;
    }

    if (typeof testJsonRaw !== "string") {
      return null;
    }

    return JSON.parse(testJsonRaw);
  } catch (error) {
    return null;
  }
}

function extractMacroSummary(row) {
  if (!row) return null;

  const decodedJson = parseTestJson(row.test_json);

  if (!decodedJson) return null;

  let macroSummary = null;

  if (decodedJson?.respyr_response?.final_macro_summary) {
    macroSummary = decodedJson.respyr_response.final_macro_summary;
  } else if (decodedJson?.final_macro_summary) {
    macroSummary = decodedJson.final_macro_summary;
  }

  if (!macroSummary) return null;

  const finalMacroSummary = {
    calories: toNumber(macroSummary.calories),
    carbs_g: toNumber(macroSummary.carbs_g),
    fat_g: toNumber(macroSummary.fat_g),
    fiber_g: toNumber(macroSummary.fiber_g),
    protein_g: toNumber(macroSummary.protein_g),
  };

  return {
    test_id: Number(row.test_id),
    profile_id: row.profile_id,
    date_time: row.date_time,
    final_macro_summary: finalMacroSummary,
    macro_percentage: calculateMacroPercentage(finalMacroSummary),
  };
}

/* ===============================
   Controller
================================ */

const get_macro_summary_by_date = async (req, res) => {
  try {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");

    const body = req.body || {};

    if (typeof body !== "object" || Array.isArray(body)) {
      return res.status(400).json({
        success: false,
        message: "Invalid request body",
      });
    }

    const profile_id = normalizeId(body.profile_id);
    const requestedDietitianId = normalizeDieticianId(body.dietitian_id);
    const date = normalizeDate(body.date);

    if (!body.profile_id || !body.dietitian_id || !body.date) {
      return res.status(400).json({
        success: false,
        message: "profile_id, dietitian_id and date are required",
      });
    }

    if (!profile_id) {
      return res.status(400).json({ success: false, message: "Invalid profile_id" });
    }

    if (!requestedDietitianId) {
      return res.status(400).json({ success: false, message: "Invalid dietitian_id" });
    }

    if (!date) {
      return res.status(400).json({ success: false, message: "Invalid date (expected YYYY-MM-DD)" });
    }

    /**
     * VAPT / object-level authorization:
     * 1. JWT dietician id must match requested dietitian_id
     * 2. profile_id must belong to this dietitian in table_clients
     * Blocks IDOR — a dietitian cannot read another dietitian's client PHI.
     */
    const access = await requireProfileAccess(
      req,
      requestedDietitianId,
      profile_id
    );

    if (!access.allowed) {
      return res.status(access.statusCode || 403).json({
        success: false,
        message: access.message || "Access denied",
      });
    }

    const dietitianId = access.dieticianId;

    /**
     * Same logic as PHP (WHERE profile_id = ? AND DATE(date_time) = ?),
     * additionally scoped to the authorized dietitian as defense-in-depth.
     */
    const currentSql = `
      SELECT
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        AND DATE(date_time) = ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [currentRows] = await pool.execute(currentSql, [
      profile_id,
      dietitianId,
      date,
    ]);

    const currentData = extractMacroSummary(currentRows[0]);

    const selectedDateStart = `${date} 00:00:00`;

    const previousSql = `
      SELECT
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        AND date_time < ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [previousRows] = await pool.execute(previousSql, [
      profile_id,
      dietitianId,
      selectedDateStart,
    ]);

    const previousData = extractMacroSummary(previousRows[0]);

    let macroChange = null;

    if (currentData && previousData) {
      const current = currentData.final_macro_summary;
      const previous = previousData.final_macro_summary;

      macroChange = {
        calories: calculateChangePercentage(
          current.calories,
          previous.calories
        ),
        carbs_g: calculateChangePercentage(current.carbs_g, previous.carbs_g),
        fat_g: calculateChangePercentage(current.fat_g, previous.fat_g),
        fiber_g: calculateChangePercentage(current.fiber_g, previous.fiber_g),
        protein_g: calculateChangePercentage(
          current.protein_g,
          previous.protein_g
        ),
      };
    }

    if (!currentData) {
      return res.status(200).json({
        success: false,
        message: "No macro summary found for selected date",
        profile_id,
        selected_date: date,
        previous_data: previousData,
      });
    }

    return res.status(200).json({
      success: true,
      message: "Macro summary fetched successfully",
      profile_id,
      selected_date: date,
      current_data: currentData,
      previous_data: previousData,
      macro_change_from_previous: macroChange,
    });
  } catch (error) {
    console.error("get_macro_summary_by_date error:", {
      message: error.message,
      code: error.code,
    });

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  get_macro_summary_by_date,
};