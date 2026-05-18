const pool = require("../../../../config/db");

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

    const profile_id =
      typeof body.profile_id === "string" ? body.profile_id.trim() : "";

    const date = typeof body.date === "string" ? body.date.trim() : "";

    if (!profile_id || !date) {
      return res.status(200).json({
        success: false,
        message: "profile_id and date are required",
      });
    }

    /**
     * Same logic as PHP:
     * WHERE profile_id = ?
     * AND DATE(date_time) = ?
     */
    const currentSql = `
      SELECT 
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND DATE(date_time) = ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [currentRows] = await pool.execute(currentSql, [profile_id, date]);

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
        AND date_time < ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [previousRows] = await pool.execute(previousSql, [
      profile_id,
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