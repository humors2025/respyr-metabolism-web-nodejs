const pool = require("../../../../config/db");
const { requireDieticianSelfAccess } = require("../../../../utils/accessControl");

const ALLOWED_TYPES = ["all", "tested", "missed"];
const SEARCH_MIN_LENGTH = 3;
const SEARCH_MAX_LENGTH = 100;

/**
 * VAPT note:
 * Keep API_DEBUG_ERRORS=true ONLY for debugging.
 * In production / VAPT runs it must be unset or "false" so that
 * SQL / stack details are never returned to the client.
 */
const SHOULD_EXPOSE_DEBUG = process.env.API_DEBUG_ERRORS === "true";

/* ===============================
   Helpers
================================ */

const normalizeDieticianId = (value) => {
  return String(value || "").trim().toUpperCase();
};

const parseBodyIfNeeded = (req) => {
  if (typeof req.body === "string") {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      req.body = {};
    }
  }

  if (!req.body || typeof req.body !== "object") {
    req.body = {};
  }

  return req.body;
};

const isValidDate = (str) => {
  if (typeof str !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(str)) {
    return false;
  }

  const d = new Date(`${str}T00:00:00Z`);

  if (Number.isNaN(d.getTime())) {
    return false;
  }

  return d.toISOString().slice(0, 10) === str;
};

const todayIso = () => {
  return new Date().toISOString().slice(0, 10);
};

const toDateOnly = (value) => {
  if (!value) return null;

  const d = new Date(value);

  if (Number.isNaN(d.getTime())) {
    return null;
  }

  return d.toISOString().slice(0, 10);
};

const monthsBetween = (fromDate, toDate) => {
  return (
    (toDate.getUTCFullYear() - fromDate.getUTCFullYear()) * 12 +
    (toDate.getUTCMonth() - fromDate.getUTCMonth())
  );
};

const getLastLoggedText = (lastDateTime, selectedDate) => {
  if (!lastDateTime) return "No test yet";

  const lastDateOnly = toDateOnly(lastDateTime);
  if (!lastDateOnly) return "No test yet";

  const last = new Date(`${lastDateOnly}T00:00:00Z`);
  const selected = new Date(`${selectedDate}T00:00:00Z`);

  if (Number.isNaN(last.getTime()) || Number.isNaN(selected.getTime())) {
    return "No test yet";
  }

  const threeMonthsAgo = new Date(selected);
  threeMonthsAgo.setUTCMonth(threeMonthsAgo.getUTCMonth() - 3);

  if (last < threeMonthsAgo) {
    return "More than 3 months";
  }

  const diffMs = selected.getTime() - last.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays <= 0) return "Today";
  if (diffDays === 1) return "1 day ago";
  if (diffDays < 30) return `${diffDays} days ago`;

  const months = monthsBetween(last, selected);

  return months <= 1 ? "1 month ago" : `${months} months ago`;
};

const isValidHttpUrl = (str) => {
  try {
    const url = new URL(str);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
};

const getProfileImageUrl = (row) => {
  if (!row.profile_image) return null;

  if (
    typeof row.profile_image === "string" &&
    isValidHttpUrl(row.profile_image)
  ) {
    return row.profile_image;
  }

  return `/dietitian/api/web/get_profile_image?dietician_id=${encodeURIComponent(
    row.dietician_id
  )}&profile_id=${encodeURIComponent(row.profile_id)}`;
};

const formatClientRows = (rows, selectedDate) => {
  return rows.map((row) => {
    const rawScore = row.metabolism_score;

    const score =
      rawScore !== null && rawScore !== undefined && rawScore !== ""
        ? Number(rawScore)
        : null;

    const safeScore = Number.isNaN(score) ? null : score;

    return {
      dietician_id: normalizeDieticianId(row.dietician_id),
      profile_id: row.profile_id,
      client_name: row.client_name,
      phone_no: row.phone_no,
      email: row.email,
      dob: row.dob,
      age: row.age !== null && row.age !== undefined ? Number(row.age) : null,
      gender: row.gender,
      height: row.height,
      weight: row.weight,
      region: row.region,
      location: row.location,
      fitness_goal: row.fitness_goal ?? "",
      metabolism_score: safeScore,
      last_logged_date: row.last_logged_date,
      last_logged: getLastLoggedText(row.last_logged_date, selectedDate),
      p_created: row.dttm,
      p_image: getProfileImageUrl(row),
    };
  });
};

const getAuthorizedDieticianId = (req, requestedDieticianId) => {
  const access = requireDieticianSelfAccess(req, requestedDieticianId);

  if (!access.allowed) {
    return {
      allowed: false,
      statusCode: access.statusCode || 403,
      message: access.message || "Access denied",
    };
  }

  const dieticianId = normalizeDieticianId(
    access.dieticianId ||
      req.user?.dietician_id ||
      req.user?.dietician?.dietician_id ||
      req.user?.sub ||
      requestedDieticianId
  );

  if (!dieticianId) {
    return {
      allowed: false,
      statusCode: 401,
      message: "Invalid authentication token",
    };
  }

  return { allowed: true, dieticianId };
};

/* ===============================
   Controller
================================ */

exports.get_search_clients_details = async (req, res) => {
  let debugStep = "controller_started";

  try {
    res.setHeader("X-Controller-Version", "search-clients-v1");

    debugStep = "parse_body";
    const body = parseBodyIfNeeded(req);

    debugStep = "validate_dietician_id";
    const requestedDieticianId = normalizeDieticianId(body.dietician_id);

    if (!requestedDieticianId) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "dietician_id is required",
      });
    }

    debugStep = "access_check";
    const authResult = getAuthorizedDieticianId(req, requestedDieticianId);

    if (!authResult.allowed) {
      return res.status(authResult.statusCode).json({
        status: false,
        ok: false,
        message: authResult.message,
      });
    }

    const dieticianId = authResult.dieticianId;

    debugStep = "validate_inputs";

    const rawType = String(body.type ?? "all").trim().toLowerCase();
    if (!ALLOWED_TYPES.includes(rawType)) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "Invalid type. Allowed values: all, tested, missed",
      });
    }
    const type = rawType;

    const rawDate = typeof body.date === "string" ? body.date.trim() : "";
    if (rawDate !== "" && !isValidDate(rawDate)) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "Invalid date format. Use YYYY-MM-DD",
      });
    }
    const selectedDate = rawDate !== "" ? rawDate : todayIso();

    const rawSearch = typeof body.search === "string" ? body.search.trim() : "";
    if (rawSearch.length > SEARCH_MAX_LENGTH) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: `Search string must be ${SEARCH_MAX_LENGTH} characters or fewer`,
      });
    }
    if (rawSearch !== "" && rawSearch.length < SEARCH_MIN_LENGTH) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: `Minimum ${SEARCH_MIN_LENGTH} letters required for search`,
      });
    }

    /**
     * Escape LIKE wildcards in the user-supplied search term so that a
     * user cannot use `%` or `_` to widen a search beyond what they typed.
     * mysql2 still parameter-binds the value, so this is purely about
     * preserving the intent of the search.
     */
    const escapedSearch = rawSearch.replace(/[\\%_]/g, "\\$&");

    debugStep = "filter_condition";

    let filterCondition = "";

    if (type === "tested") {
      filterCondition += " AND ttd.profile_id IS NOT NULL ";
    } else if (type === "missed") {
      filterCondition += " AND ttd.profile_id IS NULL ";
    }

    if (rawSearch !== "") {
      filterCondition += " AND tc.profile_name LIKE ? ";
    }

    debugStep = "main_query_build";

    const sql = `
      SELECT
        tc.dietician_id,
        tc.profile_id,
        tc.profile_name AS client_name,
        tc.phone_no,
        tc.email,
        tc.dob,
        tc.age,
        tc.gender,
        tc.height,
        tc.weight,
        tc.region,
        tc.location,
        tc.dttm,
        tc.profile_image,

        IFNULL(uh.goal, '') AS fitness_goal,

        CASE
          WHEN ttd.profile_id IS NOT NULL THEN 'tested'
          ELSE 'missed'
        END AS test_status,

        ttd.fat_loss_metabolism_score AS metabolism_score,
        ttd.date_time AS last_logged_date

      FROM table_clients tc

      LEFT JOIN (
        SELECT uh1.*
        FROM user_habits uh1
        INNER JOIN (
          SELECT profile_id, MAX(id) AS max_id
          FROM user_habits
          GROUP BY profile_id
        ) uh2
          ON uh1.id = uh2.max_id
      ) uh
        ON uh.profile_id = tc.profile_id

      LEFT JOIN (
        SELECT
          profile_id,
          MAX(date_time) AS date_time,
          MAX(fat_loss_metabolism_score) AS fat_loss_metabolism_score
        FROM table_test_data
        WHERE DATE(date_time) = ?
          AND UPPER(TRIM(dietitian_id)) = ?
        GROUP BY profile_id
      ) ttd
        ON ttd.profile_id = tc.profile_id

      WHERE UPPER(TRIM(tc.dietician_id)) = ?
      ${filterCondition}

      ORDER BY tc.profile_name ASC
    `;

    const params = [selectedDate, dieticianId, dieticianId];

    if (rawSearch !== "") {
      params.push(`%${escapedSearch}%`);
    }

    debugStep = "main_query_execute";

    const [rows] = await pool.execute(sql, params);

    debugStep = "format_response";

    const clients = formatClientRows(rows, selectedDate);

    return res.status(200).json({
      status: true,
      ok: true,
      message: "Dashboard data fetched successfully",
      dietician_id: dieticianId,
      selected_date: selectedDate,
      type,
      search: rawSearch,
      total_clients: clients.length,
      clients,
    });
  } catch (error) {
    const safeLog = {
      step: debugStep,
      message: error?.message,
      code: error?.code,
      errno: error?.errno,
      sqlState: error?.sqlState,
      sqlMessage: error?.sqlMessage,
      dietician_id: req.body?.dietician_id,
      method: req.method,
      path: req.originalUrl,
    };

    console.error("get_search_clients_details error:", safeLog);

    const response = {
      status: false,
      ok: false,
      message: "Internal server error",
    };

    if (SHOULD_EXPOSE_DEBUG) {
      response.debug = {
        step: debugStep,
        error: error?.sqlMessage || error?.message || "Unknown error",
        code: error?.code || null,
      };
    }

    return res.status(500).json(response);
  }
};
