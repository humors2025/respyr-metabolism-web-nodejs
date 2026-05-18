const pool = require("../../../../config/db");

/**
 * GET AUTHENTICATED DIETITIAN ID
 * Supports common authMiddleware payload shapes.
 */
function getAuthenticatedDietitianId(req) {
  return (
    req.user?.dietician_id ||
    req.user?.dietitian_id ||
    req.user?.sub ||
    req.user?.dietician?.dietician_id ||
    req.auth?.dietician_id ||
    req.auth?.dietitian_id ||
    req.auth?.sub ||
    null
  );
}

/**
 * Strict YYYY-MM-DD validation.
 */
function isValidDateOnly(date) {
  if (typeof date !== "string") return false;

  const regex = /^\d{4}-\d{2}-\d{2}$/;
  if (!regex.test(date)) return false;

  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime())) return false;

  return parsed.toISOString().slice(0, 10) === date;
}

/**
 * Prevent unexpected profile_id payloads.
 * Adjust length only if your existing profile IDs are longer.
 */
function isValidProfileId(profileId) {
  if (typeof profileId !== "string") return false;
  return /^[A-Za-z0-9_-]{3,64}$/.test(profileId);
}

function toNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
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

function safeParseTestJson(rawValue) {
  try {
    if (!rawValue) return null;

    let jsonString = rawValue;

    if (Buffer.isBuffer(rawValue)) {
      jsonString = rawValue.toString("utf8");
    }

    if (typeof jsonString === "object") {
      return jsonString;
    }

    if (typeof jsonString !== "string") {
      return null;
    }

    return JSON.parse(jsonString);
  } catch {
    return null;
  }
}

function extractMacroSummary(row) {
  if (!row) return null;

  const decodedJson = safeParseTestJson(row.test_json);
  if (!decodedJson) return null;

  const macroSummary =
    decodedJson?.respyr_response?.final_macro_summary ||
    decodedJson?.final_macro_summary ||
    null;

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

/**
 * Important VAPT protection:
 * Prevent BOLA / horizontal access.
 * A logged-in dietitian can access only their own client's profile_id.
 */
async function verifyDietitianOwnsProfile(dietitianId, profileId) {
  const [rows] = await pool.query(
    `
      SELECT 1
      FROM table_clients
      WHERE profile_id = ?
        AND UPPER(dietician_id) = UPPER(?)
      LIMIT 1
    `,
    [profileId, dietitianId]
  );

  return rows.length > 0;
}

exports.get_macro_summary_by_date = async (req, res) => {
  try {
    const body = req.body || {};
    const profileId = typeof body.profile_id === "string" ? body.profile_id.trim() : "";
    const selectedDate = typeof body.date === "string" ? body.date.trim() : "";

    if (!profileId || !selectedDate) {
      return res.status(400).json({
        success: false,
        message: "profile_id and date are required",
      });
    }

    if (!isValidProfileId(profileId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid profile_id format",
      });
    }

    if (!isValidDateOnly(selectedDate)) {
      return res.status(400).json({
        success: false,
        message: "Invalid date format. Expected YYYY-MM-DD",
      });
    }

    const dietitianId = getAuthenticatedDietitianId(req);

    if (!dietitianId) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized",
      });
    }

    const hasAccess = await verifyDietitianOwnsProfile(dietitianId, profileId);

    if (!hasAccess) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      });
    }

    const selectedDateStart = `${selectedDate} 00:00:00`;

    /**
     * Avoid DATE(date_time) because it can prevent index usage.
     * This is better for performance and VAPT/DoS resilience.
     */
    const currentSql = `
      SELECT 
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND date_time >= ?
        AND date_time < DATE_ADD(?, INTERVAL 1 DAY)
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const previousSql = `
      SELECT 
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND date_time < ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [[currentRows], [previousRows]] = await Promise.all([
      pool.query(currentSql, [profileId, selectedDate, selectedDate]),
      pool.query(previousSql, [profileId, selectedDateStart]),
    ]);

    const currentData = extractMacroSummary(currentRows[0]);
    const previousData = extractMacroSummary(previousRows[0]);

    let macroChange = null;

    if (currentData && previousData) {
      const current = currentData.final_macro_summary;
      const previous = previousData.final_macro_summary;

      macroChange = {
        calories: calculateChangePercentage(current.calories, previous.calories),
        carbs_g: calculateChangePercentage(current.carbs_g, previous.carbs_g),
        fat_g: calculateChangePercentage(current.fat_g, previous.fat_g),
        fiber_g: calculateChangePercentage(current.fiber_g, previous.fiber_g),
        protein_g: calculateChangePercentage(current.protein_g, previous.protein_g),
      };
    }

    if (!currentData) {
      return res.status(404).json({
        success: false,
        message: "No macro summary found for selected date",
        profile_id: profileId,
        selected_date: selectedDate,
        previous_data: previousData,
      });
    }

    return res.status(200).json({
      success: true,
      message: "Macro summary fetched successfully",
      profile_id: profileId,
      selected_date: selectedDate,
      current_data: currentData,
      previous_data: previousData,
      macro_change_from_previous: macroChange,
    });
  } catch (error) {
    /**
     * Do not return DB errors, SQL errors, stack traces, or PHI.
     */
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