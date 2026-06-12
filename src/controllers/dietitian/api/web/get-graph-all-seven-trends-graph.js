"use strict";

/**
 * get-graph-all-seven-trends-graph.js
 *
 * Converted from: get-graph-all-seven-trends-graph.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : GET /dietitian/api/web/get-graph-all-seven-trends-graph
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 *
 * Behaviour parity with the PHP:
 *  - Returns the seven metabolism trend graphs for a (profile_id, dietitian_id)
 *    pair over a `range` window (weekly / monthly / all_time). For each graph it
 *    returns the latest test per calendar day in the window, as
 *    { date, label, value } points, plus the recommended_trend_range
 *    (min_range / max_range from the most recent test in the window). Same JSON
 *    keys/ordering as the PHP. Envelope is { status, message, data } to match the
 *    PHP sendResponse().
 *  - GET-only (matches the PHP REQUEST_METHOD gate).
 *  - 404 when no graph has any point in the window.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor dietitian is taken from the verified JWT
 *    (sub = dietician_id), NOT from the request query. The requested
 *    dietitian_id must equal the token dietitian, and profile_id must belong to
 *    that dietitian (requireProfileAccess). The PHP trusted query-supplied
 *    profile_id/dietitian_id with no ownership check — an IDOR hole this closes.
 *  - Fully parameterized queries (? placeholders). The only non-placeholder
 *    fragments (the score column and the date-window interval) come from fixed
 *    server-side allowlists keyed by a validated enum — never from user input.
 *  - Internal error details are suppressed in production responses; server logs
 *    carry only error metadata, never row data or PHI. (The PHP echoed the raw
 *    DB/exception message — an information-disclosure finding.)
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns only.
 *  - Every read (grant or denial) is recorded in app_auth_logs. PHI in the audit
 *    trail (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - The audit writer is fail-safe: an audit failure never breaks the request
 *    and never leaks to the client.
 *
 * NOTE: No DB tables are added or removed vs. the PHP data flow — same
 * table_test_data (and table_clients via requireProfileAccess). app_auth_logs is
 * the shared audit sink used across these controllers.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

/**
 * Server-side allowlist for the range → date-window mapping. Keyed by a validated
 * enum, so `intervalSql` is safe to inline into the query (never user input).
 */
const RANGE_CONFIG = {
  weekly: { intervalSql: "INTERVAL 7 DAY", label: "Last 7 Days" },
  monthly: { intervalSql: "INTERVAL 30 DAY", label: "Last 30 Days" },
  all_time: { intervalSql: "INTERVAL 3 MONTH", label: "Last 3 Months" },
};

/**
 * Server-side allowlist for the seven trend graphs. `column` is a literal column
 * name from this fixed list — never user input — so it is safe to inline into the
 * SELECT. Order is preserved to match the PHP response.
 */
const GRAPH_MAPPINGS = [
  {
    key: "nutrient_utilization_trend",
    column: "absorptive_metabolism_score",
    title: "Nutrient Utilization Trend",
  },
  {
    key: "digestive_activity_trend",
    column: "fermentative_metabolism_score",
    title: "Digestive Activity Trend",
  },
  {
    key: "fuel_utilization_trend",
    column: "fat_metabolism_score",
    title: "Fuel Utilization Trend",
  },
  {
    key: "energy_source_trend",
    column: "glucose_metabolism_score",
    title: "Energy Source Trend",
  },
  {
    key: "metabolic_load_trend",
    column: "hepatic_stress_metabolism_score",
    title: "Metabolic Load Trend",
  },
  {
    key: "recovery_activity_trend",
    column: "detoxification_metabolism_score",
    title: "Recovery Activity Trend",
  },
  {
    key: "overall_fat_loss_score",
    column: "fat_loss_metabolism_score",
    title: "Overall Fat Loss Score",
  },
];

// Defensive: every allowlisted column must be a bare identifier before it ever
// reaches a query string. Guards against an accidental edit introducing an
// injectable value.
const SAFE_COLUMN = /^[a-z_]+$/;

const SHORT_MONTHS = [
  "",
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

// ─── Response envelope ───────────────────────────────────────────────────────

const sendResponse = (res, httpCode, status, message, data = null) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  const response = { status, message };

  if (status === true && data !== null) {
    response.data = data;
  }

  return res.status(httpCode).json(response);
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

const cleanFloatOrNull = (value) => {
  if (value === null || value === undefined || value === "") {
    return null;
  }

  const number = Number(value);

  return Number.isFinite(number) ? number : null;
};

/**
 * Faithful port of the PHP `(float)$row["graph_score"]` with the `!== null ? : 0`
 * default — a non-numeric/empty score becomes 0.
 */
const cleanFloatOrZero = (value) => {
  if (value === null || value === undefined || value === "") {
    return 0;
  }

  const number = Number(value);

  return Number.isFinite(number) ? number : 0;
};

/**
 * Normalize a DATE(...) result to a "YYYY-MM-DD" string. mysql2 returns DATE
 * columns as JS Date objects (built at local midnight) unless dateStrings is set;
 * handle both that and the string case.
 */
const toDateOnly = (value) => {
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return null;

    const pad = (n) => String(n).padStart(2, "0");

    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(
      value.getDate()
    )}`;
  }

  if (typeof value === "string") {
    const trimmed = value.trim();
    const match = trimmed.match(/^(\d{4}-\d{2}-\d{2})/);

    return match ? match[1] : null;
  }

  return null;
};

/**
 * Port of PHP `date("d M", strtotime($test_date))` — e.g. "05 Jun".
 */
const formatDayLabel = (dateOnly) => {
  if (!dateOnly) return "NA";

  const [year, month, day] = dateOnly.split("-").map(Number);

  if (!month || month < 1 || month > 12 || !day) return "NA";

  return `${String(day).padStart(2, "0")} ${SHORT_MONTHS[month]}`;
};

// ─── Audit log (HIPAA accountability) ────────────────────────────────────────

const getClientIp = (req) => {
  const ip =
    (typeof req.ip === "string" && req.ip) ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "0.0.0.0";

  return String(ip).slice(0, 64);
};

const getUserAgent = (req) => {
  const ua =
    (typeof req.get === "function" && req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";

  return String(ua).slice(0, 500);
};

const authLogHash = (value) => {
  if (value === null || value === undefined) return null;

  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
};

/**
 * Fail-safe audit writer mirroring the sibling controllers. Never throws — audit
 * failures must not surface to the client.
 *   app_auth_logs(event_type, user_id, role, partner_code, identifier_hash,
 *                 ip_hash, user_agent_hash, session_id_hash, success, failure_reason)
 */
const writeAuthLogSafe = async (
  req,
  { eventType, userId, identifier, success, failureReason }
) => {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined
        ? authLogHash(identifier)
        : null;

    await pool.execute(
      `INSERT INTO app_auth_logs (
         event_type,
         user_id,
         role,
         partner_code,
         identifier_hash,
         ip_hash,
         user_agent_hash,
         session_id_hash,
         success,
         failure_reason
       )
       VALUES (?, ?, NULL, NULL, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined
          ? String(userId).slice(0, 191)
          : null,
        identifierHash,
        ipHash,
        userAgentHash,
        success ? 1 : 0,
        failureReason !== null && failureReason !== undefined
          ? String(failureReason).slice(0, 255)
          : null,
      ]
    );
  } catch (err) {
    console.error("SEVEN_TRENDS_GRAPH_AUDIT_FAILED:", err?.code || err?.message);
  }
};

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * GET /dietitian/api/web/get-graph-all-seven-trends-graph
 *
 * Headers: Authorization: Bearer <JWT>
 * Query:
 *   profile_id   = PRF1001       (required)
 *   dietitian_id = RespyrD03     (required; must match token dietitian)
 *   range        = weekly | monthly | all_time   (required)
 */
const getGraphAllSevenTrendsGraph = async (req, res) => {
  // VAPT: method gate (matches the PHP).
  if (req.method !== "GET") {
    return sendResponse(res, 405, false, "Method not allowed. Use GET only");
  }

  const query = req.query || {};

  const profileId = normalizeId(query.profile_id);
  const dietitianId = normalizeDieticianId(query.dietitian_id);
  const range =
    query.range === undefined || query.range === null
      ? ""
      : String(query.range).trim();

  // Match the PHP "field is required" aggregation, but reject malformed ids the
  // same way (normalize* returns null for empty OR invalid → still "required").
  const missingFields = [];

  if (!dietitianId) missingFields.push("dietitian_id");
  if (!profileId) missingFields.push("profile_id");
  if (!range) missingFields.push("range");

  if (missingFields.length) {
    return sendResponse(
      res,
      400,
      false,
      `${missingFields.join(", ")} are required`
    );
  }

  const rangeConfig = RANGE_CONFIG[range];

  if (!rangeConfig) {
    return sendResponse(
      res,
      400,
      false,
      "Invalid range. Use weekly, monthly, or all_time"
    );
  }

  // Hashed before storage by writeAuthLogSafe — never persisted in clear text.
  const auditIdentifier = `${profileId}|${dietitianId}|${range}`;

  try {
    /**
     * VAPT / IDOR protection:
     * 1. Token dietitian must match the requested dietitian_id.
     * 2. profile_id must belong to that dietitian.
     */
    const access = await requireProfileAccess(req, dietitianId, profileId);

    if (!access.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "seven_trends_graph_access_denied",
        userId: dietitianId,
        identifier: auditIdentifier,
        success: false,
        failureReason: access.message || "access denied",
      });

      return sendResponse(res, access.statusCode, false, access.message);
    }

    // Interval fragment comes from a fixed server-side map keyed by a validated
    // enum — safe to inline. The dietitian_id column on table_test_data is
    // compared case-insensitively to match the normalized token id.
    const dateCondition = `AND date_time >= DATE_SUB(NOW(), ${rangeConfig.intervalSql})`;

    // =========================
    // RECOMMENDED TREND RANGE
    // (min/max from the latest test in the window)
    // =========================
    const [rangeRows] = await pool.execute(
      `
        SELECT min_range, max_range
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(TRIM(dietitian_id)) = ?
          ${dateCondition}
        ORDER BY date_time DESC
        LIMIT 1
      `,
      [access.profileId, access.dieticianId]
    );

    let minRange = null;
    let maxRange = null;
    let rangeText = "";

    if (rangeRows.length) {
      minRange = cleanFloatOrNull(rangeRows[0].min_range);
      maxRange = cleanFloatOrNull(rangeRows[0].max_range);

      if (minRange !== null && maxRange !== null) {
        rangeText = `${minRange}%-${maxRange}%`;
      }
    }

    const recommendedTrendRange = {
      min: minRange,
      max: maxRange,
      label: rangeText,
    };

    // =========================
    // SEVEN TREND GRAPHS
    // =========================
    const allGraphs = {};
    let hasAnyData = false;

    for (const graph of GRAPH_MAPPINGS) {
      const { key: graphKey, column: selectedColumn, title: graphTitle } = graph;

      // Defensive guard — selectedColumn comes from GRAPH_MAPPINGS only.
      if (!SAFE_COLUMN.test(selectedColumn)) {
        throw new Error(`Unsafe graph column: ${selectedColumn}`);
      }

      // For each calendar day in the window, take the row with the latest
      // date_time on that day, then read the selected score column from it.
      const [pointRows] = await pool.execute(
        `
          SELECT
            DATE(t1.date_time) AS test_date,
            t1.${selectedColumn} AS graph_score
          FROM table_test_data t1
          INNER JOIN (
            SELECT
              DATE(date_time) AS only_date,
              MAX(date_time) AS max_date_time
            FROM table_test_data
            WHERE profile_id = ?
              AND UPPER(TRIM(dietitian_id)) = ?
              ${dateCondition}
            GROUP BY DATE(date_time)
          ) t2 ON t1.date_time = t2.max_date_time
          WHERE t1.profile_id = ?
            AND UPPER(TRIM(t1.dietitian_id)) = ?
          ORDER BY t1.date_time ASC
        `,
        [
          access.profileId,
          access.dieticianId,
          access.profileId,
          access.dieticianId,
        ]
      );

      const graphPoints = pointRows.map((row) => {
        const dateOnly = toDateOnly(row.test_date);

        return {
          date: dateOnly,
          label: formatDayLabel(dateOnly),
          value: cleanFloatOrZero(row.graph_score),
        };
      });

      if (graphPoints.length) {
        hasAnyData = true;
      }

      allGraphs[graphKey] = {
        title: graphTitle,
        column_name: selectedColumn,
        recommended_trend_range: recommendedTrendRange,
        total_points: graphPoints.length,
        graph_points: graphPoints,
      };
    }

    if (!hasAnyData) {
      await writeAuthLogSafe(req, {
        eventType: "seven_trends_graph_read",
        userId: access.dieticianId,
        identifier: auditIdentifier,
        success: false,
        failureReason: "No graph data found for range",
      });

      return sendResponse(
        res,
        404,
        false,
        "No graph data found for the given dietitian_id, profile_id, and range"
      );
    }

    await writeAuthLogSafe(req, {
      eventType: "seven_trends_graph_read",
      userId: access.dieticianId,
      identifier: auditIdentifier,
      success: true,
      failureReason: null,
    });

    return sendResponse(
      res,
      200,
      true,
      "All graph data fetched successfully",
      {
        dietitian_id: access.dieticianId,
        profile_id: access.profileId,
        range,
        range_label: rangeConfig.label,
        graphs: allGraphs,
      }
    );
  } catch (error) {
    console.error("getGraphAllSevenTrendsGraph error:", {
      message: error.message,
      stack: isProduction ? undefined : error.stack,
    });

    return sendResponse(
      res,
      500,
      false,
      isProduction ? "Internal server error" : "Something went wrong"
    );
  }
};

module.exports = {
  getGraphAllSevenTrendsGraph,
};
