'use strict';

const pool = require('../../../../config/db');
const {
  normalizeId,
  requireProfileAccess,
} = require('../../../../utils/accessControl');

/* ===============================
   Constants
================================ */
const MAX_DAYS_LIMIT = 90;
const ZONE_THRESHOLDS = {
  FOCUS_MAX: 70,
  MODERATE_MAX: 80,
};

/* ===============================
   Helpers
================================ */

/**
 * Sends a standardized JSON response.
 * Avoids leaking internal details to the client.
 */
function sendResponse(res, httpCode, status, message, data = null) {
  const payload = { status, message };
  if (data !== null) payload.data = data;
  return res.status(httpCode).json(payload);
}

/**
 * Classifies fat-loss / metabolism score into a zone.
 * Returns "NA" when the score is missing or not numeric.
 */
function getZone(score) {
  if (score === null || score === undefined || score === '') return 'NA';

  const numericScore = Number(score);
  if (!Number.isFinite(numericScore)) return 'NA';

  if (numericScore < ZONE_THRESHOLDS.FOCUS_MAX) return 'Focus';
  if (numericScore < ZONE_THRESHOLDS.MODERATE_MAX) return 'Moderate';
  return 'Optimal';
}

/**
 * Safely converts a value to a finite float, or null.
 */
function toFloatOrNull(value) {
  if (value === null || value === undefined || value === '') return null;
  const num = Number(value);
  return Number.isFinite(num) ? num : null;
}

/**
 * Extracts the `final_macro_summary` block from the stored test_json blob.
 * Defensive against:
 *  - NULL / empty values
 *  - Buffer (BLOB) inputs
 *  - Malformed JSON
 *  - Unexpected shapes (final_macro_summary may live at root or under respyr_response)
 */
function getFinalMacroSummary(testJson) {
  const emptyMacro = {
    calories: null,
    protein_g: null,
    carbs_g: null,
    fat_g: null,
    fiber_g: null,
  };

  if (testJson === null || testJson === undefined || testJson === '') {
    return emptyMacro;
  }

  // Handle BLOB / Buffer from MySQL
  let rawString;
  if (Buffer.isBuffer(testJson)) {
    rawString = testJson.toString('utf8');
  } else if (typeof testJson === 'object') {
    // Already parsed by driver
    return pickMacro(testJson, emptyMacro);
  } else {
    rawString = String(testJson);
  }

  let decoded;
  try {
    decoded = JSON.parse(rawString);
  } catch (err) {
    return emptyMacro;
  }

  if (!decoded || typeof decoded !== 'object') return emptyMacro;

  return pickMacro(decoded, emptyMacro);
}

function pickMacro(decoded, emptyMacro) {
  const macro =
    (decoded.respyr_response && decoded.respyr_response.final_macro_summary) ||
    decoded.final_macro_summary;

  if (!macro || typeof macro !== 'object') return emptyMacro;

  return {
    calories: toFloatOrNull(macro.calories),
    protein_g: toFloatOrNull(macro.protein_g),
    carbs_g: toFloatOrNull(macro.carbs_g),
    fat_g: toFloatOrNull(macro.fat_g),
    fiber_g: toFloatOrNull(macro.fiber_g),
  };
}

/**
 * Formats a Date or date-like value as "DD MMM, YYYY" (e.g. "14 May, 2026").
 */
function formatDisplayDate(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;

  const months = [
    'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec',
  ];

  const day = String(d.getDate()).padStart(2, '0');
  const month = months[d.getMonth()];
  const year = d.getFullYear();

  return `${day} ${month}, ${year}`;
}

/**
 * Returns YYYY-MM-DD (date-only) string from a date value.
 */
function toIsoDate(value) {
  if (!value) return null;
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return null;

  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');

  return `${yyyy}-${mm}-${dd}`;
}

/* ===============================
   Controller
================================ */

/**
 * POST /dietitian/api/web/get_profile_details_dates_taken
 *
 * Body: { profile_id: string, dietitian_id: string }
 *
 * Returns: list of distinct test dates (latest test per date) for the given
 * profile_id under the authenticated dietitian, plus total test count.
 *
 * Security:
 *  - Requires valid auth (via authMiddleware on the route).
 *  - Enforces dietitian self-access (token sub === dietitian_id).
 *  - Enforces ownership of profile_id under the authenticated dietitian.
 *  - Uses parameterized queries only (no string concatenation).
 *  - Generic error messages to the client; full errors logged server-side.
 */
async function get_profile_details_dates_taken(req, res) {
  try {
    const body = req.body && typeof req.body === 'object' ? req.body : {};

    const profileIdRaw = body.profile_id;
    const dietitianIdRaw = body.dietitian_id;

    if (
      profileIdRaw === undefined ||
      profileIdRaw === null ||
      String(profileIdRaw).trim() === ''
    ) {
      return sendResponse(res, 400, false, 'profile_id is required');
    }

    if (
      dietitianIdRaw === undefined ||
      dietitianIdRaw === null ||
      String(dietitianIdRaw).trim() === ''
    ) {
      return sendResponse(res, 400, false, 'dietitian_id is required');
    }

    // Validate IDs against strict whitelist regex (done inside accessControl).
    if (!normalizeId(profileIdRaw)) {
      return sendResponse(res, 400, false, 'Invalid profile_id');
    }

    // Auth + ownership check
    const access = await requireProfileAccess(req, dietitianIdRaw, profileIdRaw);

    if (!access.allowed) {
      return sendResponse(res, access.statusCode, false, access.message);
    }

    const { dieticianId, profileId } = access;

    // -- 1) Total tests taken --------------------------------------------------
    const [countRows] = await pool.execute(
      `
        SELECT COUNT(*) AS total_test_taken
        FROM table_test_data
        WHERE profile_id = ?
          AND dietitian_id = ?
      `,
      [profileId, dieticianId]
    );

    const totalTestTaken =
      countRows && countRows[0]
        ? parseInt(countRows[0].total_test_taken, 10) || 0
        : 0;

    // -- 2) Latest test per date (last MAX_DAYS_LIMIT distinct dates) ----------
    // NOTE: LIMIT is bound as a number to avoid integer-vs-string issues in
    // some mysql2 versions; value is a hard-coded constant so it is safe.
    const limitValue = MAX_DAYS_LIMIT;

    const [rows] = await pool.query(
      `
        SELECT
          t1.test_id,
          DATE(t1.date_time) AS test_date,
          t1.date_time,
          t1.fat_loss_metabolism_score,
          t1.test_json
        FROM table_test_data t1
        INNER JOIN (
          SELECT
            DATE(date_time) AS only_date,
            MAX(date_time) AS max_date_time
          FROM table_test_data
          WHERE profile_id = ?
            AND dietitian_id = ?
          GROUP BY DATE(date_time)
          ORDER BY only_date DESC
          LIMIT ?
        ) t2
          ON DATE(t1.date_time) = t2.only_date
          AND t1.date_time = t2.max_date_time
        WHERE t1.profile_id = ?
          AND t1.dietitian_id = ?
        ORDER BY test_date DESC
      `,
      [profileId, dieticianId, limitValue, profileId, dieticianId]
    );

    const dates = (rows || []).map((row) => {
      const score = toFloatOrNull(row.fat_loss_metabolism_score);
      const finalMacroSummary = getFinalMacroSummary(row.test_json);

      return {
        test_id: row.test_id,
        date: toIsoDate(row.test_date),
        display_date: formatDisplayDate(row.test_date),
        latest_test_datetime: row.date_time,
        fat_loss_metabolism_score: score,
        fat_loss_metabolism_score_text:
          score !== null ? `${Math.round(score)}%` : 'NA',
        zone: getZone(score),
        final_macro_summary: finalMacroSummary,
      };
    });

    if (dates.length === 0) {
      return sendResponse(
        res,
        404,
        false,
        'No test dates found for this profile and dietitian',
        {
          profile_id: profileId,
          dietitian_id: dieticianId,
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
      'Test dates with fat loss score and macro summary fetched successfully',
      {
        profile_id: profileId,
        dietitian_id: dieticianId,
        total_test_taken: totalTestTaken,
        total_dates: dates.length,
        dates,
      }
    );
  } catch (err) {
    // Log full error server-side; do NOT leak details to client (HIPAA / VAPT).
    console.error(
      '[get_profile_details_dates_taken] error:',
      err && err.message ? err.message : err
    );
    return sendResponse(res, 500, false, 'Internal server error');
  }
}

module.exports = { get_profile_details_dates_taken };