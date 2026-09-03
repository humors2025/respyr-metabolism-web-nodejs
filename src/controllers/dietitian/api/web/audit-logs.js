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
 * Auth:
 *   Bearer JWT via existing authMiddleware
 *
 * Authorized:
 *   super_admin only
 *
 * By default, access is restricted to:
 *   connect@respyr.in
 *
 * Optional environment override:
 *   AUDIT_LOG_ALLOWED_EMAILS=connect@respyr.in,another@respyr.in
 *
 * Supported query params:
 *   page
 *   limit
 *   search
 *   event_type
 *   date_from
 *   date_to
 *   user_id
 *   ip_address
 *
 * Example:
 *   /dietitian/api/web/audit-logs?page=1&limit=20
 *
 * Security:
 *   - Uses authenticated JWT identity only
 *   - Re-checks actor in database
 *   - Requires active super_admin account
 *   - Optional email allowlist
 *   - Parameterized SQL
 *   - Strict query validation
 *   - Bounded pagination
 *   - Cache disabled
 */

const pool = require("../../../../config/db");

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_PAGE = 1000000;

const MAX_SEARCH_LENGTH = 200;
const MAX_EVENT_TYPE_LENGTH = 64;
const MAX_IP_LENGTH = 45;

/**
 * If AUDIT_LOG_ALLOWED_EMAILS is not set,
 * only connect@respyr.in may access the audit dashboard.
 *
 * Example:
 *
 * AUDIT_LOG_ALLOWED_EMAILS=connect@respyr.in,kushal@respyr.in
 */
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
  return typeof value === "string"
    ? value.trim().toLowerCase()
    : "";
}

function isPlainScalar(value) {
  return (
    value === undefined ||
    value === null ||
    typeof value === "string" ||
    typeof value === "number"
  );
}

/**
 * Strict positive integer parser.
 */
function parsePositiveInteger(value, fallback, max) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return {
      ok: true,
      value: fallback,
    };
  }

  if (!isPlainScalar(value)) {
    return {
      ok: false,
      message: "Invalid numeric parameter",
    };
  }

  const raw = String(value).trim();

  if (!/^\d+$/.test(raw)) {
    return {
      ok: false,
      message: "Invalid numeric parameter",
    };
  }

  const parsed = Number.parseInt(raw, 10);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 1 ||
    parsed > max
  ) {
    return {
      ok: false,
      message: "Numeric parameter is out of range",
    };
  }

  return {
    ok: true,
    value: parsed,
  };
}

/**
 * Validates YYYY-MM-DD and also confirms that
 * the date actually exists.
 *
 * Rejects values such as 2026-02-31.
 */
function isValidDateOnly(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(value)
  ) {
    return false;
  }

  const [year, month, day] = value
    .split("-")
    .map(Number);

  const date = new Date(
    Date.UTC(year, month - 1, day)
  );

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

function cleanOptionalString(value, maxLength) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return {
      ok: true,
      value: "",
    };
  }

  if (typeof value !== "string") {
    return {
      ok: false,
      message: "Invalid parameter",
    };
  }

  const cleaned = value.trim();

  if (cleaned.length > maxLength) {
    return {
      ok: false,
      message: "Parameter is too long",
    };
  }

  // Reject control characters.
  if (/[\x00-\x1f\x7f]/.test(cleaned)) {
    return {
      ok: false,
      message: "Invalid characters in parameter",
    };
  }

  return {
    ok: true,
    value: cleaned,
  };
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
   * This backend's JWTs normally use dietician_id as sub.
   * Email may also be nested inside dietician.
   */
  const dieticianId = String(
    payload.sub ||
      payload.dietician_id ||
      ""
  ).trim();

  const tokenEmail = normalizeEmail(
    payload.email ||
      payload.user_id ||
      payload?.dietician?.email ||
      ""
  );

  if (
    (!dieticianId || dieticianId.length > 64) &&
    !tokenEmail
  ) {
    return {
      error: {
        status: 401,
        message: "Invalid authenticated user",
      },
    };
  }

  let rows;

  if (dieticianId) {
    [rows] = await pool.execute(
      `
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
          ON LOWER(aur.user_id) =
             LOWER(td.email)

        WHERE td.dietician_id = ?

        LIMIT 1
      `,
      [dieticianId]
    );
  } else {
    [rows] = await pool.execute(
      `
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
          ON LOWER(aur.user_id) =
             LOWER(td.email)

        WHERE LOWER(td.email) =
              LOWER(?)

        LIMIT 1
      `,
      [tokenEmail]
    );
  }

  const actor = rows[0];

  if (!actor) {
    return {
      error: {
        status: 401,
        message: "Authenticated user not found",
      },
    };
  }

  if (
    String(actor.status || "").toLowerCase() !==
    "active"
  ) {
    return {
      error: {
        status: 403,
        message: "Account is not active",
      },
    };
  }

  if (
    String(actor.role || "").toLowerCase() !==
    "super_admin"
  ) {
    return {
      error: {
        status: 403,
        message:
          "You are not authorized to view audit logs",
      },
    };
  }

  const actorEmail = normalizeEmail(
    actor.user_id || actor.email
  );

  if (
    !AUDIT_LOG_ALLOWED_EMAILS.includes(
      actorEmail
    )
  ) {
    return {
      error: {
        status: 403,
        message:
          "You are not authorized to view audit logs",
      },
    };
  }

  return {
    actor,
    actorEmail,
  };
}

// -----------------------------------------------------------------------------
// Validate query parameters
// -----------------------------------------------------------------------------

function validateQuery(query) {
  const source =
    query &&
    typeof query === "object" &&
    !Array.isArray(query)
      ? query
      : {};

  /*
   * Reject repeated parameters such as:
   *
   * ?limit=20&limit=100
   *
   * Express may turn those into arrays.
   */
  const supportedParams = [
    "page",
    "limit",
    "search",
    "event_type",
    "date_from",
    "date_to",
    "user_id",
    "ip_address",
  ];

  for (const key of supportedParams) {
    if (!isPlainScalar(source[key])) {
      return {
        ok: false,
        status: 400,
        message: `Invalid ${key} parameter`,
      };
    }
  }

  const parsedPage = parsePositiveInteger(
    source.page,
    1,
    MAX_PAGE
  );

  if (!parsedPage.ok) {
    return {
      ok: false,
      status: 400,
      message: "Invalid page parameter",
    };
  }

  const parsedLimit = parsePositiveInteger(
    source.limit,
    DEFAULT_LIMIT,
    MAX_LIMIT
  );

  if (!parsedLimit.ok) {
    return {
      ok: false,
      status: 400,
      message:
        `limit must be between 1 and ${MAX_LIMIT}`,
    };
  }

  const searchResult = cleanOptionalString(
    source.search,
    MAX_SEARCH_LENGTH
  );

  if (!searchResult.ok) {
    return {
      ok: false,
      status: 400,
      message: "Invalid search parameter",
    };
  }

  const eventTypeResult =
    cleanOptionalString(
      source.event_type,
      MAX_EVENT_TYPE_LENGTH
    );

  if (!eventTypeResult.ok) {
    return {
      ok: false,
      status: 400,
      message: "Invalid event_type parameter",
    };
  }

  const ipResult = cleanOptionalString(
    source.ip_address,
    MAX_IP_LENGTH
  );

  if (!ipResult.ok) {
    return {
      ok: false,
      status: 400,
      message: "Invalid ip_address parameter",
    };
  }

  const dateFrom = String(
    source.date_from || ""
  ).trim();

  const dateTo = String(
    source.date_to || ""
  ).trim();

  if (
    dateFrom &&
    !isValidDateOnly(dateFrom)
  ) {
    return {
      ok: false,
      status: 400,
      message:
        "date_from must use YYYY-MM-DD format",
    };
  }

  if (
    dateTo &&
    !isValidDateOnly(dateTo)
  ) {
    return {
      ok: false,
      status: 400,
      message:
        "date_to must use YYYY-MM-DD format",
    };
  }

  if (
    dateFrom &&
    dateTo &&
    dateFrom > dateTo
  ) {
    return {
      ok: false,
      status: 400,
      message:
        "date_from cannot be later than date_to",
    };
  }

  let userId = null;

  if (
    source.user_id !== undefined &&
    source.user_id !== null &&
    String(source.user_id).trim() !== ""
  ) {
    const parsedUserId =
      parsePositiveInteger(
        source.user_id,
        null,
        Number.MAX_SAFE_INTEGER
      );

    if (!parsedUserId.ok) {
      return {
        ok: false,
        status: 400,
        message:
          "user_id must be a positive integer",
      };
    }

    userId = parsedUserId.value;
  }

  return {
    ok: true,

    value: {
      page: parsedPage.value,
      limit: parsedLimit.value,

      search: searchResult.value,

      eventType:
        eventTypeResult.value,

      dateFrom,
      dateTo,

      userId,

      ipAddress:
        ipResult.value,
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
    const pattern =
      `%${filters.search}%`;

    conditions.push(`
      (
        event_type LIKE ?
        OR email LIKE ?
        OR ip_address LIKE ?
        OR device_info LIKE ?
        OR detail LIKE ?
        OR CAST(user_id AS CHAR) LIKE ?
      )
    `);

    params.push(
      pattern,
      pattern,
      pattern,
      pattern,
      pattern,
      pattern
    );
  }

  if (filters.eventType) {
    conditions.push(
      "event_type = ?"
    );

    params.push(
      filters.eventType
    );
  }

  if (filters.userId !== null) {
    conditions.push(
      "user_id = ?"
    );

    params.push(
      filters.userId
    );
  }

  if (filters.ipAddress) {
    conditions.push(
      "ip_address = ?"
    );

    params.push(
      filters.ipAddress
    );
  }

  if (filters.dateFrom) {
    conditions.push(
      "created_at >= ?"
    );

    params.push(
      `${filters.dateFrom} 00:00:00`
    );
  }

  if (filters.dateTo) {
    /*
     * Use exclusive next-day comparison rather than
     * 23:59:59 so fractional seconds remain correct.
     */
    conditions.push(
      "created_at < DATE_ADD(?, INTERVAL 1 DAY)"
    );

    params.push(
      `${filters.dateTo} 00:00:00`
    );
  }

  return {
    sql:
      conditions.length > 0
        ? `WHERE ${conditions.join(
            " AND "
          )}`
        : "",

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
  res.setHeader(
    "Cache-Control",
    "no-store, private, max-age=0"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Vary",
    "Authorization"
  );

  try {
    // -------------------------------------------------------------------------
    // 1. Resolve authenticated user
    // -------------------------------------------------------------------------

    const resolved =
      await resolveAuditActor(req);

    if (resolved.error) {
      return res
        .status(resolved.error.status)
        .json({
          ok: false,
          message:
            resolved.error.message,
        });
    }

    // -------------------------------------------------------------------------
    // 2. Validate request
    // -------------------------------------------------------------------------

    const validation =
      validateQuery(req.query);

    if (!validation.ok) {
      return res
        .status(validation.status)
        .json({
          ok: false,
          message:
            validation.message,
        });
    }

    const filters =
      validation.value;

    const {
      sql: whereSql,
      params: whereParams,
    } = buildFilters(filters);

    const offset =
      (filters.page - 1) *
      filters.limit;

    // -------------------------------------------------------------------------
    // 3. Get filtered count
    // -------------------------------------------------------------------------

    const [countRows] =
      await pool.execute(
        `
          SELECT COUNT(*) AS total

          FROM app_audit_log

          ${whereSql}
        `,
        whereParams
      );

    const total =
      Number(
        countRows?.[0]?.total || 0
      );

    const totalPages =
      total === 0
        ? 0
        : Math.ceil(
            total / filters.limit
          );

    /*
     * If filters reduce the result set and the requested
     * page no longer exists, return an empty page rather
     * than silently changing the requested page.
     */

    // -------------------------------------------------------------------------
    // 4. Load requested page
    // -------------------------------------------------------------------------

    /**
     * DATE_FORMAT is intentional.
     *
     * app_audit_log.created_at is MySQL DATETIME. Returning a formatted
     * string prevents Node/MySQL timezone conversion from unexpectedly
     * changing what appears on the audit dashboard.
     */
    const [logRows] =
      await pool.execute(
        `
          SELECT
            id,
            event_type,
            email,
            user_id,
            ip_address,
            device_info,
            detail,

            DATE_FORMAT(
              created_at,
              '%Y-%m-%d %H:%i:%s'
            ) AS created_at

          FROM app_audit_log

          ${whereSql}

          ORDER BY
            created_at DESC,
            id DESC

          LIMIT ?
          OFFSET ?
        `,
        [
          ...whereParams,
          filters.limit,
          offset,
        ]
      );

    // -------------------------------------------------------------------------
    // 5. Dashboard summary
    // -------------------------------------------------------------------------

    const [
      [todayRows],
      [eventTypeCountRows],
      [securityRows],
      [eventTypeRows],
    ] = await Promise.all([
      /**
       * MySQL server date is used here so "Today" follows
       * the same clock as app_audit_log.created_at.
       */
      pool.execute(
        `
          SELECT COUNT(*) AS total

          FROM app_audit_log

          WHERE created_at >= CURDATE()
            AND created_at <
                DATE_ADD(
                  CURDATE(),
                  INTERVAL 1 DAY
                )
        `
      ),

      pool.execute(
        `
          SELECT
            COUNT(
              DISTINCT event_type
            ) AS total

          FROM app_audit_log
        `
      ),

      /**
       * Security-related events.
       *
       * This includes the token_rejected events already present
       * in app_audit_log and catches common failure/denial names.
       */
      pool.execute(
        `
          SELECT COUNT(*) AS total

          FROM app_audit_log

          WHERE
            LOWER(event_type) LIKE '%reject%'
            OR LOWER(event_type) LIKE '%fail%'
            OR LOWER(event_type) LIKE '%denied%'
            OR LOWER(event_type) LIKE '%unauthorized%'
            OR LOWER(event_type) LIKE '%forbidden%'
            OR LOWER(event_type) LIKE '%blocked%'
            OR LOWER(event_type) LIKE '%locked%'
            OR LOWER(event_type) LIKE '%security%'
        `
      ),

      pool.execute(
        `
          SELECT DISTINCT
            event_type

          FROM app_audit_log

          WHERE event_type IS NOT NULL
            AND event_type <> ''

          ORDER BY event_type ASC

          LIMIT 500
        `
      ),
    ]);

    const todayTotal =
      Number(
        todayRows?.[0]?.total || 0
      );

    const uniqueEventTypes =
      Number(
        eventTypeCountRows?.[0]
          ?.total || 0
      );

    const securityEvents =
      Number(
        securityRows?.[0]?.total || 0
      );

    const eventTypes =
      eventTypeRows
        .map((row) =>
          String(
            row.event_type || ""
          ).trim()
        )
        .filter(Boolean);

    // -------------------------------------------------------------------------
    // 6. Response
    // -------------------------------------------------------------------------

    return res
      .status(200)
      .json({
        ok: true,

        summary: {
          filtered_total: total,
          today_total: todayTotal,
          unique_event_types:
            uniqueEventTypes,
          security_events:
            securityEvents,
        },

        event_types:
          eventTypes,

        logs: logRows,

        pagination: {
          page: filters.page,
          limit: filters.limit,
          total,
          total_pages:
            totalPages,

          has_next:
            filters.page <
            totalPages,

          has_prev:
            filters.page > 1,
        },
      });
  } catch (error) {
    /*
     * Do not expose SQL/database details to the frontend.
     */
    console.error(
      "AUDIT_LOGS_ERROR:",
      {
        code:
          error?.code || null,

        errno:
          error?.errno || null,

        sqlState:
          error?.sqlState || null,

        message:
          error?.message ||
          "Unknown error",
      }
    );

    return res
      .status(500)
      .json({
        ok: false,
        message:
          "Unable to load audit logs",
      });
  }
}

// -----------------------------------------------------------------------------
// Export
// -----------------------------------------------------------------------------

module.exports = {
  auditLogs,
};