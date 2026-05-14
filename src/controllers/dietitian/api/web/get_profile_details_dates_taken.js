const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

/**
 * Same response format as old PHP API:
 * {
 *   status: boolean,
 *   message: string,
 *   data?: object
 * }
 */
const sendResponse = (res, httpCode, status, message, data = null) => {
  const response = {
    status,
    message,
  };

  if (data !== null) {
    response.data = data;
  }

  return res.status(httpCode).json(response);
};

const toNumberOrNull = (value) => {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const numberValue = Number(value);

  return Number.isFinite(numberValue) ? numberValue : null;
};

const getZone = (score) => {
  const numericScore = toNumberOrNull(score);

  if (numericScore === null) {
    return "NA";
  }

  if (numericScore < 70) {
    return "Focus";
  }

  if (numericScore >= 70 && numericScore < 80) {
    return "Moderate";
  }

  return "Optimal";
};

const getEmptyMacroSummary = () => ({
  calories: null,
  protein_g: null,
  carbs_g: null,
  fat_g: null,
  fiber_g: null,
});

const safeJsonDecode = (testJson) => {
  if (testJson === null || testJson === undefined || testJson === "") {
    return null;
  }

  try {
    if (Buffer.isBuffer(testJson)) {
      return JSON.parse(testJson.toString("utf8"));
    }

    if (typeof testJson === "object") {
      return testJson;
    }

    if (typeof testJson === "string") {
      return JSON.parse(testJson);
    }

    return null;
  } catch (error) {
    return null;
  }
};

const getFinalMacroSummary = (testJson) => {
  const emptyMacro = getEmptyMacroSummary();

  const decoded = safeJsonDecode(testJson);

  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    return emptyMacro;
  }

  const macro =
    decoded?.respyr_response?.final_macro_summary ||
    decoded?.final_macro_summary ||
    null;

  if (!macro || typeof macro !== "object" || Array.isArray(macro)) {
    return emptyMacro;
  }

  return {
    calories: toNumberOrNull(macro.calories),
    protein_g: toNumberOrNull(macro.protein_g),
    carbs_g: toNumberOrNull(macro.carbs_g),
    fat_g: toNumberOrNull(macro.fat_g),
    fiber_g: toNumberOrNull(macro.fiber_g),
  };
};

const formatDisplayDate = (dateValue) => {
  if (!dateValue) {
    return "";
  }

  const dateString = String(dateValue).slice(0, 10);
  const [year, month, day] = dateString.split("-");

  if (!year || !month || !day) {
    return "";
  }

  const months = {
    "01": "Jan",
    "02": "Feb",
    "03": "Mar",
    "04": "Apr",
    "05": "May",
    "06": "Jun",
    "07": "Jul",
    "08": "Aug",
    "09": "Sep",
    "10": "Oct",
    "11": "Nov",
    "12": "Dec",
  };

  return `${day} ${months[month] || month}, ${year}`;
};

const get_profile_details_dates_taken = async (req, res) => {
  try {
    const body = req.body;

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return sendResponse(res, 400, false, "Invalid raw JSON body");
    }

    const rawProfileId = body.profile_id;
    const rawDietitianId = body.dietitian_id;

    if (rawProfileId === undefined || rawProfileId === null || String(rawProfileId).trim() === "") {
      return sendResponse(res, 400, false, "profile_id is required");
    }

    if (rawDietitianId === undefined || rawDietitianId === null || String(rawDietitianId).trim() === "") {
      return sendResponse(res, 400, false, "dietitian_id is required");
    }

    const profileId = normalizeId(rawProfileId);
    const requestedDietitianId = normalizeDieticianId(rawDietitianId);

    if (!profileId) {
      return sendResponse(res, 400, false, "Invalid profile_id");
    }

    if (!requestedDietitianId) {
      return sendResponse(res, 400, false, "Invalid dietitian_id");
    }

    /**
     * VAPT important:
     * This checks:
     * 1. JWT dietitian id matches requested dietitian_id
     * 2. profile_id belongs to this dietitian in table_clients
     */
    const access = await requireProfileAccess(
      req,
      requestedDietitianId,
      profileId
    );

    if (!access.allowed) {
      return sendResponse(
        res,
        access.statusCode || 403,
        false,
        access.message || "Access denied"
      );
    }

    const dietitianId = access.dieticianId;

    const [countRows] = await pool.execute(
      `
        SELECT COUNT(*) AS total_test_taken
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(TRIM(dietitian_id)) = ?
      `,
      [profileId, dietitianId]
    );

    const totalTestTaken = Number(countRows?.[0]?.total_test_taken || 0);

    const [rows] = await pool.execute(
      `
        SELECT 
          t1.test_id,
          DATE_FORMAT(t1.date_time, '%Y-%m-%d') AS test_date,
          DATE_FORMAT(t1.date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
          t1.fat_loss_metabolism_score,
          t1.test_json
        FROM table_test_data t1
        INNER JOIN (
          SELECT 
            DATE(date_time) AS only_date,
            MAX(date_time) AS max_date_time
          FROM table_test_data
          WHERE profile_id = ?
            AND UPPER(TRIM(dietitian_id)) = ?
          GROUP BY DATE(date_time)
          ORDER BY only_date DESC
          LIMIT 90
        ) t2 
          ON DATE(t1.date_time) = t2.only_date
         AND t1.date_time = t2.max_date_time
        WHERE t1.profile_id = ?
          AND UPPER(TRIM(t1.dietitian_id)) = ?
        ORDER BY test_date DESC
      `,
      [profileId, dietitianId, profileId, dietitianId]
    );

    const dates = rows.map((row) => {
      const score = toNumberOrNull(row.fat_loss_metabolism_score);

      return {
        test_id: row.test_id,
        date: row.test_date,
        display_date: formatDisplayDate(row.test_date),
        latest_test_datetime: row.date_time,

        fat_loss_metabolism_score: score,
        fat_loss_metabolism_score_text:
          score !== null ? `${Math.round(score)}%` : "NA",
        zone: getZone(score),

        final_macro_summary: getFinalMacroSummary(row.test_json),
      };
    });

    if (!dates.length) {
      return sendResponse(
        res,
        404,
        false,
        "No test dates found for this profile and dietitian",
        {
          profile_id: profileId,
          dietitian_id: dietitianId,
          total_test_taken: totalTestTaken,
          total_dates: 0,
          dates: [],
        }
      );
    }

    return sendResponse(
      res,
      200,
      true,
      "Test dates with fat loss score and macro summary fetched successfully",
      {
        profile_id: profileId,
        dietitian_id: dietitianId,
        total_test_taken: totalTestTaken,
        total_dates: dates.length,
        dates,
      }
    );
  } catch (error) {
    console.error("get_profile_details_dates_taken error:", {
      message: error.message,
      stack: process.env.NODE_ENV === "production" ? undefined : error.stack,
    });

    return sendResponse(res, 500, false, "Internal server error");
  }
};

module.exports = {
  get_profile_details_dates_taken,
};