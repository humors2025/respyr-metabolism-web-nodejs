"use strict";

/**
 * get-profile-details-dates-taken.js
 *
 * Converted from: get-profile-details-dates-taken.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get-profile-details-dates-taken
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 *
 * Behaviour parity with the PHP:
 *  - Returns the latest test per calendar day (last 90 days) for a profile, each
 *    with fat-loss metabolism score, zone, and the final macro summary parsed
 *    from test_json (BLOB/stream-safe), plus a total_test_taken count.
 *  - Same response shape: { status, message, data{ profile_id, dietitian_id,
 *    total_test_taken, total_dates, dates[] } }; 404 (with empty data) when no
 *    dates, 200 otherwise.
 *
 * VAPT / HIPAA hardening (beyond the PHP — the point of the sprint):
 *  - Object-level authorization. The PHP trusted body.dietitian_id + profile_id
 *    directly (a textbook IDOR: any authenticated caller could read ANY client's
 *    PHI). Here requireProfileAccess() enforces that the JWT dietitian matches the
 *    requested dietitian_id AND owns the profile_id in table_clients before any
 *    PHI is read. The dietitian_id used in queries comes from the verified token,
 *    never the body.
 *  - Every query is fully parameterized (no string interpolation).
 *  - DB/internal error details are suppressed from the client (the PHP echoed the
 *    raw PDO/exception message — an info-disclosure finding closed here).
 *  - Cache-Control: no-store, Pragma: no-cache (PHI must never be cached).
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_test_data
 * (+ table_clients via the access-control check).
 */

const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

// ─── Response helper (same shape as the PHP sendResponse) ─────────────────────

const sendResponse = (res, httpCode, status, message, data = null) => {
  const response = { status, message };
  if (data !== null) {
    response.data = data;
  }
  return res.status(httpCode).json(response);
};

// ─── Generic helpers ──────────────────────────────────────────────────────────

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

/** Decode test_json whether it arrives as a Buffer (BLOB), object, or string. */
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

/** Format a "YYYY-MM-DD" string as "DD Mon, YYYY" (parity with PHP date("d M, Y")). */
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
    "01": "Jan", "02": "Feb", "03": "Mar", "04": "Apr",
    "05": "May", "06": "Jun", "07": "Jul", "08": "Aug",
    "09": "Sep", "10": "Oct", "11": "Nov", "12": "Dec",
  };
  return `${day} ${months[month] || month}, ${year}`;
};

// ─── Controller ───────────────────────────────────────────────────────────────

const getProfileDetailsDatesTaken = async (req, res) => {
  // HIPAA: PHI responses must never be cached by intermediaries.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP REQUEST_METHOD check).
  if (req.method !== "POST") {
    return sendResponse(res, 405, false, "Only POST method is allowed");
  }

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
     * VAPT (object-level authorization):
     *  1. JWT dietitian id must match the requested dietitian_id
     *  2. profile_id must belong to this dietitian in table_clients
     * Closes the PHP IDOR where any caller could read any profile's PHI.
     */
    const access = await requireProfileAccess(req, requestedDietitianId, profileId);

    if (!access.allowed) {
      return sendResponse(
        res,
        access.statusCode || 403,
        false,
        access.message || "Access denied"
      );
    }

    // Trusted dietitian id (from the verified token), used for all PHI queries.
    const dietitianId = access.dieticianId;

    // ── Total tests taken (all-time) for this profile + dietitian ─────────────
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

    // ── Latest test per day, last 90 days, newest first ───────────────────────
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
    // VAPT: never echo the raw DB/exception message to the client.
    console.error("GET_PROFILE_DETAILS_DATES_TAKEN_ERROR:", {
      code: error?.code,
      errno: error?.errno,
      sqlState: error?.sqlState,
      message: error?.message,
    });

    return sendResponse(res, 500, false, "Internal server error");
  }
};

module.exports = {
  getProfileDetailsDatesTaken,
};
