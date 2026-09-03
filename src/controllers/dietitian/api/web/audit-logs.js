"use strict";

/**
 * audit-logs.js
 *
 * Endpoint:
 *   GET /dietitian/api/web/audit-logs
 *
 * Production URL:
 *   GET /v1/dietitian/api/web/audit-logs
 *
 * Source table:
 *   app_auth_logs — the fail-safe audit table every controller in this
 *   backend writes to (login/logout, invites, PHI reads, denials, ...).
 *
 *   Columns: id, event_type, user_id, role, partner_code, identifier_hash,
 *            ip_hash, user_agent_hash, session_id_hash, success,
 *            failure_reason, created_at
 *
 *   IP / user-agent / identifier are HMAC-SHA256(SECURITY_PEPPER) hashes.
 *   Raw PHI never lands in this table, so the dashboard returns the hashes
 *   as-is for correlation only. Filtering by ip_address hashes the supplied
 *   value with the same pepper and matches ip_hash.
 *
 * Auth:
 *   Bearer JWT via existing authMiddleware
 *
 * Authorized:
 *   super_admin only, further restricted to an email allowlist:
 *     AUDIT_LOG_ALLOWED_EMAILS=connect@respyr.in,another@respyr.in
 *   (defaults to connect@respyr.in when unset)
 *
 * Supported query params (all optional):
 *   page          1..MAX_PAGE
 *   limit         1..MAX_LIMIT
 *   search        substring over event_type / user_id / role /
 *                 partner_code / failure_reason (LIKE-escaped)
 *   event_type    exact
 *   user_id       exact (email, case-insensitive)
 *   role          exact
 *   partner_code  exact
 *   success       1 | 0 | true | false
 *   ip_address    exact (hashed before comparison)
 *   date_from     YYYY-MM-DD inclusive
 *   date_to       YYYY-MM-DD inclusive
 *
 * Security:
 *   - Identity is token-bound and re-checked in the DB (role + status)
 *   - Every read of the audit trail is itself audited to app_auth_logs
 *     (audit_logs_viewed / audit_logs_denied)
 *   - Parameterized SQL; LIKE wildcards escaped; LIMIT/OFFSET only ever
 *     inlined from strictly validated integers
 *   - Bounded pagination, strict query validation, no-store cache
 *   - Internal DB errors never reach the client
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const AUDIT_TABLE = "app_auth_logs";

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_PAGE = 1000000;

const MAX_SEARCH_LENGTH = 200;
const MAX_EVENT_TYPE_LENGTH = 60; // matches writeAuthLogSafe truncation
const MAX_USER_ID_LENGTH = 255;
const MAX_ROLE_LENGTH = 64;
const MAX_PARTNER_CODE_LENGTH = 64;
const MAX_IP_LENGTH = 64;

/**
 * Same pepper the writers use, so hashing a filter value here produces the
 * same digest that was stored.
 */
const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const AUDIT_LOG_ALLOWED_EMAILS = String(
  process.env.AUDIT_LOG_ALLOWED_EMAILS || "connect@respyr.in"
)
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

function normalizeEmail(value) {
  return typeof value === "string" ? value.trim().toLowerCase() : "";
}

function isPlainScalar(value) {
  return (
    value === undefined ||
    value === null ||
    typeof value === "string" ||
    typeof value === "number"
  );
}

/** Escape LIKE wildcards so a caller cannot widen the search beyond their term. */
function escapeLike(term) {
  return String(term).replace(/[\\%_]/g, "\\$&");
}

function getClientIp(req) {
  const ip =
    (typeof req.ip === "string" && req.ip) ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "0.0.0.0";
  return String(ip).slice(0, 64);
}

function getUserAgent(req) {
  const ua =
    (typeof req.get === "function" && req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";
  return String(ua).slice(0, 500);
}

/** Mirrors authLogHash() in the sibling controllers. */
function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

/**
 * Strict positive integer parser.
 */
function parsePositiveInteger(value, fallback, max) {
  if (value === undefined || value === null || value === "") {
    return { ok: true, value: fallback };
  }

  if (!isPlainScalar(value)) {
    return { ok: false, message: "Invalid numeric parameter" };
  }

  const raw = String(value).trim();

  if (!/^\d+$/.test(raw)) {
    return { ok: false, message: "Invalid numeric parameter" };
  }

  const parsed = Number.parseInt(raw, 10);

  if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > max) {
    return { ok: false, message: "Numeric parameter is out of range" };
  }

  return { ok: true, value: parsed };
}

/**
 * Validates YYYY-MM-DD and confirms the date actually exists
 * (rejects e.g. 2026-02-31).
 */
function isValidDateOnly(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return false;
  }

  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function cleanOptionalString(value, maxLength) {
  if (value === undefined || value === null || value === "") {
    return { ok: true, value: "" };
  }

  if (typeof value !== "string") {
    return { ok: false, message: "Invalid parameter" };
  }

  const cleaned = value.trim();

  if (cleaned.length > maxLength) {
    return { ok: false, message: "Parameter is too long" };
  }

  // Reject control characters.
  if (/[\x00-\x1f\x7f]/.test(cleaned)) {
    return { ok: false, message: "Invalid characters in parameter" };
  }

  return { ok: true, value: cleaned };
}

/**
 * success filter: 1 | 0 | true | false (case-insensitive). Returns
 * { ok, value } where value is 1, 0, or null when not supplied.
 */
function parseSuccessFlag(value) {
  if (value === undefined || value === null || value === "") {
    return { ok: true, value: null };
  }

  if (!isPlainScalar(value)) {
    return { ok: false };
  }

  const raw = String(value).trim().toLowerCase();

  if (raw === "1" || raw === "true") return { ok: true, value: 1 };
  if (raw === "0" || raw === "false") return { ok: true, value: 0 };

  return { ok: false };
}

// -----------------------------------------------------------------------------
// Fail-safe audit writer (schema mirrors writeAuthLogSafe() in siblings)
// -----------------------------------------------------------------------------

async function writeAuthLogSafe(req, {
  eventType,
  userId,
  role,
  partnerCode,
  identifier,
  success,
  failureReason,
}) {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined
        ? authLogHash(identifier)
        : null;

    const truncatedEvent = String(eventType || "").slice(0, 60);
    const truncatedReason =
      failureReason !== null && failureReason !== undefined
        ? String(failureReason).slice(0, 255)
        : null;

    await pool.execute(
      `INSERT INTO ${AUDIT_TABLE} (
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
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        truncatedEvent,
        userId ?? null,
        role ?? null,
        partnerCode ?? null,
        identifierHash,
        ipHash,
        userAgentHash,
        success ? 1 : 0,
        truncatedReason,
      ]
    );
  } catch (err) {
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// -----------------------------------------------------------------------------
// Resolve authenticated actor
// -----------------------------------------------------------------------------

/**
 * authMiddleware has already verified the JWT before this runs.
 *
 * We still re-fetch the account from the database so a previously issued
 * token cannot retain audit access after the user's role/status changes.
 */
async function resolveAuditActor(req) {
  const payload = req.user || {};

  /**
   * This backend's JWTs carry dietician_id in sub; email may be top-level
   * (user_id) or nested under dietician.email.
   */
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload?.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && !tokenEmail) {
    return {
      error: { status: 401, message: "Invalid authenticated user" },
    };
  }

  const selectSql = `
    SELECT
      td.id,
      td.dietician_id,
      td.email,
      td.name,
      aur.user_id,
      aur.role,
      aur.partner_code,
      aur.parent_user_id,
      aur.status
    FROM table_dietician td
    INNER JOIN app_user_roles aur
      ON LOWER(aur.user_id) = LOWER(td.email)
  `;

  let rows;

  if (dieticianId) {
    [rows] = await pool.execute(
      `${selectSql} WHERE td.dietician_id = ? LIMIT 1`,
      [dieticianId]
    );
  } else {
    [rows] = await pool.execute(
      `${selectSql} WHERE LOWER(td.email) = LOWER(?) LIMIT 1`,
      [tokenEmail]
    );
  }

  const actor = rows[0];

  if (!actor) {
    return {
      error: { status: 401, message: "Authenticated user not found" },
    };
  }

  if (String(actor.status || "").toLowerCase() !== "active") {
    return {
      error: { status: 403, message: "Account is not active" },
    };
  }

  if (String(actor.role || "").toLowerCase() !== "super_admin") {
    return {
      error: {
        status: 403,
        message: "You are not authorized to view audit logs",
      },
    };
  }

  const actorEmail = normalizeEmail(actor.user_id || actor.email);

  if (!AUDIT_LOG_ALLOWED_EMAILS.includes(actorEmail)) {
    return {
      error: {
        status: 403,
        message: "You are not authorized to view audit logs",
      },
    };
  }

  return { actor, actorEmail };
}

// -----------------------------------------------------------------------------
// Validate query parameters
// -----------------------------------------------------------------------------

function validateQuery(query) {
  const source =
    query && typeof query === "object" && !Array.isArray(query) ? query : {};

  /*
   * Reject repeated parameters such as ?limit=20&limit=100 —
   * Express turns those into arrays.
   */
  const supportedParams = [
    "page",
    "limit",
    "search",
    "event_type",
    "user_id",
    "role",
    "partner_code",
    "success",
    "ip_address",
    "date_from",
    "date_to",
  ];

  for (const key of supportedParams) {
    if (!isPlainScalar(source[key])) {
      return { ok: false, status: 400, message: `Invalid ${key} parameter` };
    }
  }

  const parsedPage = parsePositiveInteger(source.page, 1, MAX_PAGE);
  if (!parsedPage.ok) {
    return { ok: false, status: 400, message: "Invalid page parameter" };
  }

  const parsedLimit = parsePositiveInteger(source.limit, DEFAULT_LIMIT, MAX_LIMIT);
  if (!parsedLimit.ok) {
    return {
      ok: false,
      status: 400,
      message: `limit must be between 1 and ${MAX_LIMIT}`,
    };
  }

  const stringFields = [
    ["search", MAX_SEARCH_LENGTH],
    ["event_type", MAX_EVENT_TYPE_LENGTH],
    ["user_id", MAX_USER_ID_LENGTH],
    ["role", MAX_ROLE_LENGTH],
    ["partner_code", MAX_PARTNER_CODE_LENGTH],
    ["ip_address", MAX_IP_LENGTH],
  ];

  const strings = {};

  for (const [key, maxLength] of stringFields) {
    const result = cleanOptionalString(
      source[key] === undefined || source[key] === null
        ? ""
        : String(source[key]),
      maxLength
    );

    if (!result.ok) {
      return { ok: false, status: 400, message: `Invalid ${key} parameter` };
    }

    strings[key] = result.value;
  }

  const successFlag = parseSuccessFlag(source.success);
  if (!successFlag.ok) {
    return {
      ok: false,
      status: 400,
      message: "success must be 1, 0, true or false",
    };
  }

  const dateFrom = String(source.date_from || "").trim();
  const dateTo = String(source.date_to || "").trim();

  if (dateFrom && !isValidDateOnly(dateFrom)) {
    return {
      ok: false,
      status: 400,
      message: "date_from must use YYYY-MM-DD format",
    };
  }

  if (dateTo && !isValidDateOnly(dateTo)) {
    return {
      ok: false,
      status: 400,
      message: "date_to must use YYYY-MM-DD format",
    };
  }

  if (dateFrom && dateTo && dateFrom > dateTo) {
    return {
      ok: false,
      status: 400,
      message: "date_from cannot be later than date_to",
    };
  }

  return {
    ok: true,
    value: {
      page: parsedPage.value,
      limit: parsedLimit.value,
      search: strings.search,
      eventType: strings.event_type,
      userId: normalizeEmail(strings.user_id),
      role: strings.role,
      partnerCode: strings.partner_code,
      success: successFlag.value,
      ipAddress: strings.ip_address,
      dateFrom,
      dateTo,
    },
  };
}

// -----------------------------------------------------------------------------
// SQL filter builder
// -----------------------------------------------------------------------------

function buildFilters(filters) {
  const conditions = [];
  const params = [];

  if (filters.search) {
    const pattern = `%${escapeLike(filters.search)}%`;

    conditions.push(`
      (
        event_type LIKE ?
        OR user_id LIKE ?
        OR role LIKE ?
        OR partner_code LIKE ?
        OR failure_reason LIKE ?
      )
    `);

    params.push(pattern, pattern, pattern, pattern, pattern);
  }

  if (filters.eventType) {
    conditions.push("event_type = ?");
    params.push(filters.eventType);
  }

  if (filters.userId) {
    conditions.push("LOWER(user_id) = ?");
    params.push(filters.userId);
  }

  if (filters.role) {
    conditions.push("role = ?");
    params.push(filters.role);
  }

  if (filters.partnerCode) {
    conditions.push("partner_code = ?");
    params.push(filters.partnerCode);
  }

  if (filters.success !== null) {
    conditions.push("success = ?");
    params.push(filters.success);
  }

  if (filters.ipAddress) {
    /*
     * IPs are stored hashed. Hash the filter with the same pepper and
     * compare digests — the raw IP never touches the query.
     */
    conditions.push("ip_hash = ?");
    params.push(authLogHash(filters.ipAddress));
  }

  if (filters.dateFrom) {
    conditions.push("created_at >= ?");
    params.push(`${filters.dateFrom} 00:00:00`);
  }

  if (filters.dateTo) {
    /*
     * Exclusive next-day comparison rather than 23:59:59 so fractional
     * seconds remain correct.
     */
    conditions.push("created_at < DATE_ADD(?, INTERVAL 1 DAY)");
    params.push(`${filters.dateTo} 00:00:00`);
  }

  return {
    sql: conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "",
    params,
  };
}

// -----------------------------------------------------------------------------
// Controller
// -----------------------------------------------------------------------------

async function auditLogs(req, res) {
  /*
   * Do not allow audit data to be cached.
   */
  res.setHeader("Cache-Control", "no-store, private, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("Vary", "Authorization");

  try {
    // -------------------------------------------------------------------------
    // 1. Resolve + authorize actor (super_admin + allowlist)
    // -------------------------------------------------------------------------

    const resolved = await resolveAuditActor(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "audit_logs_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: String(req.user?.sub || req.user?.dietician_id || ""),
        success: false,
        failureReason: resolved.error.message,
      });

      return res.status(resolved.error.status).json({
        ok: false,
        message: resolved.error.message,
      });
    }

    const { actor, actorEmail } = resolved;

    // -------------------------------------------------------------------------
    // 2. Validate request
    // -------------------------------------------------------------------------

    const validation = validateQuery(req.query);

    if (!validation.ok) {
      return res.status(validation.status).json({
        ok: false,
        message: validation.message,
      });
    }

    const filters = validation.value;
    const { sql: whereSql, params: whereParams } = buildFilters(filters);
    const offset = (filters.page - 1) * filters.limit;

    // -------------------------------------------------------------------------
    // 3. Filtered count
    // -------------------------------------------------------------------------

    const [countRows] = await pool.execute(
      `SELECT COUNT(*) AS total FROM ${AUDIT_TABLE} ${whereSql}`,
      whereParams
    );

    const total = Number(countRows?.[0]?.total || 0);
    const totalPages = total === 0 ? 0 : Math.ceil(total / filters.limit);

    // -------------------------------------------------------------------------
    // 4. Requested page
    // -------------------------------------------------------------------------

    /*
     * LIMIT/OFFSET are inlined, not bound. mysqld_stmt_execute rejects bound
     * LIMIT parameters on this MySQL build (ER_WRONG_ARGUMENTS, errno 1210).
     * Both values are strictly validated integers (parsePositiveInteger:
     * digits only, 1..MAX_LIMIT / 1..MAX_PAGE), so inlining is injection-safe.
     *
     * DATE_FORMAT is intentional: created_at is MySQL DATETIME; returning a
     * formatted string avoids Node/MySQL timezone conversion.
     */
    const [logRows] = await pool.execute(
      `
        SELECT
          id,
          event_type,
          user_id,
          role,
          partner_code,
          success,
          failure_reason,
          ip_hash,
          user_agent_hash,
          DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') AS created_at
        FROM ${AUDIT_TABLE}
        ${whereSql}
        ORDER BY created_at DESC, id DESC
        LIMIT ${filters.limit}
        OFFSET ${offset}
      `,
      whereParams
    );

    // -------------------------------------------------------------------------
    // 5. Dashboard summary
    // -------------------------------------------------------------------------

    const [
      [todayRows],
      [eventTypeCountRows],
      [failedRows],
      [eventTypeRows],
    ] = await Promise.all([
      /**
       * MySQL server date is used so "Today" follows the same clock as
       * created_at.
       */
      pool.execute(
        `
          SELECT COUNT(*) AS total
          FROM ${AUDIT_TABLE}
          WHERE created_at >= CURDATE()
            AND created_at < DATE_ADD(CURDATE(), INTERVAL 1 DAY)
        `
      ),

      pool.execute(
        `SELECT COUNT(DISTINCT event_type) AS total FROM ${AUDIT_TABLE}`
      ),

      /**
       * Security-relevant events = every row the writers flagged as a
       * failure/denial (success = 0). Exact column match; no LIKE chain.
       */
      pool.execute(
        `SELECT COUNT(*) AS total FROM ${AUDIT_TABLE} WHERE success = 0`
      ),

      pool.execute(
        `
          SELECT DISTINCT event_type
          FROM ${AUDIT_TABLE}
          WHERE event_type IS NOT NULL AND event_type <> ''
          ORDER BY event_type ASC
          LIMIT 500
        `
      ),
    ]);

    const todayTotal = Number(todayRows?.[0]?.total || 0);
    const uniqueEventTypes = Number(eventTypeCountRows?.[0]?.total || 0);
    const securityEvents = Number(failedRows?.[0]?.total || 0);

    const eventTypes = eventTypeRows
      .map((row) => String(row.event_type || "").trim())
      .filter(Boolean);

    const logs = logRows.map((row) => ({
      id: row.id,
      event_type: row.event_type,
      user_id: row.user_id,
      role: row.role,
      partner_code: row.partner_code,
      success: Number(row.success) === 1,
      failure_reason: row.failure_reason,
      ip_hash: row.ip_hash,
      user_agent_hash: row.user_agent_hash,
      created_at: row.created_at,
    }));

    // -------------------------------------------------------------------------
    // 6. Audit the read itself (fire-and-forget, never blocks the response)
    // -------------------------------------------------------------------------

    writeAuthLogSafe(req, {
      eventType: "audit_logs_viewed",
      userId: actorEmail,
      role: "super_admin",
      partnerCode: actor.partner_code ?? null,
      identifier: actorEmail,
      success: true,
      failureReason: `page=${filters.page} limit=${filters.limit} filtered=${total}`,
    });

    // -------------------------------------------------------------------------
    // 7. Response
    // -------------------------------------------------------------------------

    return res.status(200).json({
      ok: true,

      summary: {
        filtered_total: total,
        today_total: todayTotal,
        unique_event_types: uniqueEventTypes,
        security_events: securityEvents,
      },

      event_types: eventTypes,

      logs,

      pagination: {
        page: filters.page,
        limit: filters.limit,
        total,
        total_pages: totalPages,
        has_next: filters.page < totalPages,
        has_prev: filters.page > 1,
      },
    });
  } catch (error) {
    /*
     * Do not expose SQL/database details to the frontend.
     */
    console.error("AUDIT_LOGS_ERROR:", {
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      message: error?.message || "Unknown error",
    });

    return res.status(500).json({
      ok: false,
      message: "Unable to load audit logs",
    });
  }
}

// -----------------------------------------------------------------------------
// Export
// -----------------------------------------------------------------------------

module.exports = {
  auditLogs,
};
