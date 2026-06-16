const pool = require("../../../../config/db");
const { requireDieticianSelfAccess } = require("../../../../utils/accessControl");
const { buildPublicBaseUrl } = require("../../../../utils/publicUrl");

const ALLOWED_TYPES = ["all", "tested", "missed"];
const PAGE_LIMIT = 10;
const MAX_PAGE = 10000;

/**
 * TEMP DEBUG:
 * Keep API_DEBUG_ERRORS=true only while debugging.
 * For VAPT/production, remove it or set it to false.
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

const getMetabolismZone = (score) => {
  if (score === null || score === undefined || score === "") {
    return null;
  }

  const numericScore = Number(score);

  if (Number.isNaN(numericScore)) {
    return null;
  }

  if (numericScore >= 80) return "Strong";
  if (numericScore >= 70) return "Steady";

  return "Building";
};

const formatFitnessGoal = (raw) => {
  let goal = String(raw ?? "").trim();

  if (goal === "") {
    goal = "fat_loss";
  }

  return goal
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
};

const toDateOnly = (value) => {
  if (!value) return null;

  const d = new Date(value);

  if (Number.isNaN(d.getTime())) {
    return null;
  }

  return d.toISOString().slice(0, 10);
};

const getLastLoggedText = (lastDateTime, selectedDate) => {
  if (!lastDateTime) {
    return "No test yet";
  }

  const lastDateOnly = toDateOnly(lastDateTime);

  if (!lastDateOnly) {
    return "No test yet";
  }

  const today = todayIso();

  if (selectedDate === today && lastDateOnly === selectedDate) {
    return "Today";
  }

  return lastDateOnly;
};

const isValidHttpUrl = (str) => {
  try {
    const url = new URL(str);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
};

const getProfileImageUrl = (row, baseUrl) => {
  if (!row.profile_image) {
    return null;
  }

  if (
    typeof row.profile_image === "string" &&
    isValidHttpUrl(row.profile_image)
  ) {
    return row.profile_image;
  }

  return `${baseUrl}/dietitian/api/web/get_profile_image?dietician_id=${encodeURIComponent(
    row.dietician_id
  )}&profile_id=${encodeURIComponent(row.profile_id)}`;
};

const formatClientRows = (rows, selectedDate, baseUrl) => {
  return rows.map((row) => {
    const rawScore = row.metabolism_score;

    const score =
      rawScore !== null && rawScore !== undefined && rawScore !== ""
        ? Number(rawScore)
        : null;

    const safeScore = Number.isNaN(score) ? null : score;

    const fitnessGoalRaw = row.fitness_goal ?? "";

    const fitnessGoalValue =
      String(fitnessGoalRaw).trim() !== "" ? fitnessGoalRaw : "weight_loss";

    const dietPlanGeneratedAt = row.diet_plan_generated_at ?? null;

    return {
      dietician_id: normalizeDieticianId(row.dietician_id),
      profile_id: row.profile_id,
      client_name: row.client_name,
      phone_no: row.phone_no,
      email: row.email,
      dob: row.dob,
      age: row.age,
      gender: row.gender,
      height: row.height,
      weight: row.weight,
      region: row.region,
      location: row.location,

      fitness_goal: fitnessGoalValue,
      fitness_goal_display: formatFitnessGoal(fitnessGoalRaw),

      metabolism_score: safeScore,
      zone: getMetabolismZone(safeScore),

      test_taken_count: Number(row.test_taken_count ?? 0),
      last_logged_date: row.last_logged_date,
      last_logged: getLastLoggedText(row.last_logged_date, selectedDate),

      // NEW: latest diet plan generated date from weekly_food_json_suggestions
      diet_plan_generated_at: dietPlanGeneratedAt,
      diet_plan_generated_date: dietPlanGeneratedAt
        ? toDateOnly(dietPlanGeneratedAt)
        : null,

      p_created: row.dttm,
      p_image: getProfileImageUrl(row, baseUrl),

      level_type: Number(row.level_type ?? 1),
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
      access,
    };
  }

  const dieticianId = normalizeDieticianId(
    access.dieticianId ||
      access.dietician_id ||
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
      access,
    };
  }

  return {
    allowed: true,
    dieticianId,
    access,
  };
};

/* ===============================
   Controller
================================ */

exports.get_clients_data_total_missed_test = async (req, res) => {
  let debugStep = "controller_started";

  try {
    // HIPAA: this endpoint returns UNMASKED client PHI (only ever to the owning
    // dietitian — see requireDieticianSelfAccess). Never let intermediaries or
    // the browser cache it.
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");

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

    const type = ALLOWED_TYPES.includes(body.type) ? body.type : "all";

    const pageNum = Number.parseInt(body.page, 10);

    const page =
      Number.isInteger(pageNum) && pageNum >= 1 && pageNum <= MAX_PAGE
        ? pageNum
        : 1;

    const selectedDate =
      body.date && isValidDate(body.date) ? body.date : todayIso();

    const limit = PAGE_LIMIT;
    const offset = (page - 1) * limit;

    /**
     * Important:
     * Do not pass LIMIT/OFFSET as prepared-statement params in this API.
     * Some MySQL/mysql2 prepared statement combinations throw:
     * ER_WRONG_ARGUMENTS: Incorrect arguments to mysqld_stmt_execute
     *
     * This is still safe because limit/offset are generated by backend code
     * after strict validation, not directly from user input.
     */
    const safeLimit = Number.isInteger(limit) && limit > 0 ? limit : PAGE_LIMIT;
    const safeOffset =
      Number.isInteger(offset) && offset >= 0 ? offset : 0;

    debugStep = "summary_query_build";

    const summarySql = `
      SELECT
        COUNT(DISTINCT tc.profile_id) AS all_total,

        COUNT(DISTINCT CASE
          WHEN DATE(tt.date_time) = ?
          THEN tc.profile_id
        END) AS tested_total,

        COUNT(DISTINCT tc.profile_id)
        - COUNT(DISTINCT CASE
          WHEN DATE(tt.date_time) = ?
          THEN tc.profile_id
        END) AS missed_total

      FROM table_clients tc

      LEFT JOIN table_test_data tt
        ON tt.profile_id = tc.profile_id
        AND UPPER(TRIM(tt.dietitian_id)) = ?
        AND tt.date_time >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)

      WHERE UPPER(TRIM(tc.dietician_id)) = ?
    `;

    const summaryParams = [
      selectedDate,
      selectedDate,
      dieticianId,
      dieticianId,
    ];

    debugStep = "summary_query_execute";

    const [summaryRows] = await pool.execute(summarySql, summaryParams);

    const summary = summaryRows[0] || {};

    debugStep = "filter_condition";

    let filterCondition = "";

    if (type === "tested") {
      filterCondition = "AND ttd.profile_id IS NOT NULL";
    } else if (type === "missed") {
      filterCondition = "AND ttd.profile_id IS NULL";
    }

    debugStep = "main_query_build";

    const mainSql = `
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
        tc.level_type,

        wfj.diet_plan_generated_at,

        IFNULL(uh.goal, '') AS fitness_goal,

        CASE
          WHEN ttd.profile_id IS NOT NULL THEN 'tested'
          ELSE 'missed'
        END AS test_status,

        ttd.fat_loss_metabolism_score AS metabolism_score,
        ttd.date_time AS last_logged_date,

        IFNULL(ttc.test_taken_count, 0) AS test_taken_count

      FROM table_clients tc

      LEFT JOIN (
        SELECT uh1.*
        FROM user_habits uh1
        INNER JOIN (
          SELECT
            profile_id,
            MAX(id) AS max_id
          FROM user_habits
          GROUP BY profile_id
        ) uh2
          ON uh1.id = uh2.max_id
      ) uh
        ON uh.profile_id = tc.profile_id

      LEFT JOIN (
        SELECT
          t1.profile_id,
          t1.date_time,
          t1.fat_loss_metabolism_score
        FROM table_test_data t1
        INNER JOIN (
          SELECT
            profile_id,
            MAX(date_time) AS max_date_time
          FROM table_test_data
          WHERE DATE(date_time) = ?
            AND UPPER(TRIM(dietitian_id)) = ?
          GROUP BY profile_id
        ) t2
          ON t1.profile_id = t2.profile_id
          AND t1.date_time = t2.max_date_time
        WHERE UPPER(TRIM(t1.dietitian_id)) = ?
      ) ttd
        ON ttd.profile_id = tc.profile_id

      LEFT JOIN (
        SELECT
          profile_id,
          COUNT(DISTINCT DATE(date_time)) AS test_taken_count
        FROM table_test_data
        WHERE UPPER(TRIM(dietitian_id)) = ?
          AND date_time >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
        GROUP BY profile_id
      ) ttc
        ON ttc.profile_id = tc.profile_id

      LEFT JOIN (
        SELECT
          UPPER(TRIM(dietician_id)) AS dietician_id,
          profile_id,
          MAX(created_at) AS diet_plan_generated_at
        FROM weekly_food_json_suggestions
        GROUP BY UPPER(TRIM(dietician_id)), profile_id
      ) wfj
        ON wfj.profile_id = tc.profile_id
        AND wfj.dietician_id = UPPER(TRIM(tc.dietician_id))

      WHERE UPPER(TRIM(tc.dietician_id)) = ?
      ${filterCondition}

      ORDER BY
        ttd.date_time DESC,
        tc.dttm DESC

      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `;

    const mainParams = [
      selectedDate,
      dieticianId,
      dieticianId,
      dieticianId,
      dieticianId,
    ];

    debugStep = "main_query_execute";

    const [rows] = await pool.execute(mainSql, mainParams);

    debugStep = "format_response";

    return res.status(200).json({
      status: true,
      ok: true,
      message: "Dashboard data fetched successfully",
      dietician_id: dieticianId,
      selected_date: selectedDate,
      type,
      pagination: {
        page,
        limit: safeLimit,
      },
      summary: {
        all_total: Number(summary.all_total ?? 0),
        tested_total: Number(summary.tested_total ?? 0),
        missed_total: Number(summary.missed_total ?? 0),
      },
      clients: formatClientRows(rows, selectedDate, "https://api.respyr.ai"),
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

    console.error("get_clients_data_total_missed_test error:", safeLog);

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


