"use strict";

/**
 * audit-logs.js
 *
 * Endpoints:
 *   GET /dietitian/api/web/audit-logs
 *   GET /dietitian/api/web/audit-logs/live?after_id=<last_seen_id>
 *
 * Production URLs:
 *   GET /v1/dietitian/api/web/audit-logs
 *   GET /v1/dietitian/api/web/audit-logs/live?after_id=<last_seen_id>
 *
 * Source table:
 *   app_auth_logs
 *
 * Auth:
 *   Existing Bearer JWT through authMiddleware
 *
 * Authorized:
 *   - Active super_admin
 *   - Email included in AUDIT_LOG_ALLOWED_EMAILS
 *
 * Default allowed email:
 *   connect@respyr.in
 *
 * Normal API:
 *   Loads complete dashboard information:
 *   - logs
 *   - summary
 *   - event types
 *   - pagination
 *   - filters
 *
 * Live API:
 *   Loads ONLY records newer than after_id.
 *
 * IMPORTANT:
 *   Live polling does NOT generate audit_logs_viewed.
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
const MAX_EVENT_TYPE_LENGTH = 60;
const MAX_USER_ID_LENGTH = 255;
const MAX_ROLE_LENGTH = 64;
const MAX_PARTNER_CODE_LENGTH = 64;
const MAX_IP_LENGTH = 64;

/**
 * Maximum number of new records returned by one live request.
 */
const LIVE_LIMIT = 100;

/**
 * Same pepper used by the rest of the backend when writing
 * identifier_hash / ip_hash / user_agent_hash.
 */
const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER ||
  process.env.JWT_SECRET ||
  "";

/**
 * Users allowed to access the Audit Dashboard.
 *
 * Example:
 *
 * AUDIT_LOG_ALLOWED_EMAILS=
 * connect@respyr.in,another@respyr.in
 */
const AUDIT_LOG_ALLOWED_EMAILS = String(
  process.env.AUDIT_LOG_ALLOWED_EMAILS ||
    "connect@respyr.in"
)
  .split(",")
  .map((email) =>
    email.trim().toLowerCase()
  )
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
 * Escape LIKE wildcards.
 */
function escapeLike(term) {
  return String(term).replace(
    /[\\%_]/g,
    "\\$&"
  );
}

/**
 * Get requester IP.
 */
function getClientIp(req) {
  const ip =
    (typeof req.ip === "string" &&
      req.ip) ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "0.0.0.0";

  return String(ip).slice(0, 64);
}

/**
 * Get requester user-agent.
 */
function getUserAgent(req) {
  const ua =
    (typeof req.get === "function" &&
      req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";

  return String(ua).slice(0, 500);
}

/**
 * Same hashing logic used by app_auth_logs writers.
 */
function authLogHash(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  return crypto
    .createHmac(
      "sha256",
      SECURITY_PEPPER
    )
    .update(
      String(value)
        .trim()
        .toLowerCase()
    )
    .digest("hex");
}

/**
 * Parse positive integer.
 *
 * Used for:
 * page
 * limit
 */
function parsePositiveInteger(
  value,
  fallback,
  max
) {
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
      message:
        "Invalid numeric parameter",
    };
  }

  const raw =
    String(value).trim();

  if (!/^\d+$/.test(raw)) {
    return {
      ok: false,
      message:
        "Invalid numeric parameter",
    };
  }

  const parsed =
    Number.parseInt(raw, 10);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 1 ||
    parsed > max
  ) {
    return {
      ok: false,
      message:
        "Numeric parameter is out of range",
    };
  }

  return {
    ok: true,
    value: parsed,
  };
}

/**
 * Parse non-negative integer.
 *
 * Used for:
 * after_id
 *
 * after_id=0 is allowed.
 */
function parseNonNegativeInteger(
  value
) {
  if (!isPlainScalar(value)) {
    return {
      ok: false,
      message:
        "Invalid numeric parameter",
    };
  }

  const raw =
    String(value ?? "").trim();

  if (!/^\d+$/.test(raw)) {
    return {
      ok: false,
      message:
        "Invalid numeric parameter",
    };
  }

  const parsed =
    Number.parseInt(raw, 10);

  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 0
  ) {
    return {
      ok: false,
      message:
        "Numeric parameter is out of range",
    };
  }

  return {
    ok: true,
    value: parsed,
  };
}

/**
 * Validate YYYY-MM-DD.
 */
function isValidDateOnly(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(
      value
    )
  ) {
    return false;
  }

  const [year, month, day] =
    value
      .split("-")
      .map(Number);

  const date = new Date(
    Date.UTC(
      year,
      month - 1,
      day
    )
  );

  return (
    date.getUTCFullYear() ===
      year &&
    date.getUTCMonth() ===
      month - 1 &&
    date.getUTCDate() ===
      day
  );
}

/**
 * Validate optional string.
 */
function cleanOptionalString(
  value,
  maxLength
) {
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
      message:
        "Invalid parameter",
    };
  }

  const cleaned = value.trim();

  if (
    cleaned.length >
    maxLength
  ) {
    return {
      ok: false,
      message:
        "Parameter is too long",
    };
  }

  /**
   * Reject control characters.
   */
  if (
    /[\x00-\x1f\x7f]/.test(
      cleaned
    )
  ) {
    return {
      ok: false,
      message:
        "Invalid characters in parameter",
    };
  }

  return {
    ok: true,
    value: cleaned,
  };
}

/**
 * Parse success:
 *
 * 1
 * 0
 * true
 * false
 */
function parseSuccessFlag(value) {
  if (
    value === undefined ||
    value === null ||
    value === ""
  ) {
    return {
      ok: true,
      value: null,
    };
  }

  if (!isPlainScalar(value)) {
    return {
      ok: false,
    };
  }

  const raw =
    String(value)
      .trim()
      .toLowerCase();

  if (
    raw === "1" ||
    raw === "true"
  ) {
    return {
      ok: true,
      value: 1,
    };
  }

  if (
    raw === "0" ||
    raw === "false"
  ) {
    return {
      ok: true,
      value: 0,
    };
  }

  return {
    ok: false,
  };
}

// -----------------------------------------------------------------------------
// Audit log writer
// -----------------------------------------------------------------------------

/**
 * Used only by the FULL audit endpoint.
 *
 * The live endpoint does NOT call this function.
 */
async function writeAuthLogSafe(
  req,
  {
    eventType,
    userId,
    role,
    partnerCode,
    identifier,
    success,
    failureReason,
  }
) {
  try {
    const ipHash =
      authLogHash(
        getClientIp(req)
      );

    const userAgentHash =
      authLogHash(
        getUserAgent(req)
      );

    const identifierHash =
      identifier !== null &&
      identifier !== undefined
        ? authLogHash(identifier)
        : null;

    const truncatedEvent =
      String(
        eventType || ""
      ).slice(0, 60);

    const truncatedReason =
      failureReason !== null &&
      failureReason !== undefined
        ? String(
            failureReason
          ).slice(0, 255)
        : null;

    await pool.execute(
      `
        INSERT INTO ${AUDIT_TABLE}
        (
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
        VALUES
        (
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          NULL,
          ?,
          ?
        )
      `,
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
    console.error(
      "AUTH_LOG_WRITE_FAILED:",
      err?.code ||
        err?.message
    );
  }
}

// -----------------------------------------------------------------------------
// Resolve authenticated actor
// -----------------------------------------------------------------------------

/**
 * authMiddleware already validates JWT.
 *
 * We still re-check user in database.
 *
 * This protects against:
 * - disabled account
 * - changed role
 * - removed user
 */
async function resolveAuditActor(
  req
) {
  const payload =
    req.user || {};

  const dieticianId =
    String(
      payload.sub ||
        payload.dietician_id ||
        ""
    ).trim();

  const tokenEmail =
    normalizeEmail(
      payload.email ||
        payload.user_id ||
        payload?.dietician
          ?.email ||
        ""
    );

  if (
    (
      !dieticianId ||
      dieticianId.length > 64
    ) &&
    !tokenEmail
  ) {
    return {
      error: {
        status: 401,
        message:
          "Invalid authenticated user",
      },
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
      ON LOWER(aur.user_id) =
         LOWER(td.email)
  `;

  let rows;

  if (dieticianId) {
    [rows] =
      await pool.execute(
        `
          ${selectSql}

          WHERE td.dietician_id = ?

          LIMIT 1
        `,
        [dieticianId]
      );
  } else {
    [rows] =
      await pool.execute(
        `
          ${selectSql}

          WHERE LOWER(td.email)
                = LOWER(?)

          LIMIT 1
        `,
        [tokenEmail]
      );
  }

  const actor =
    rows?.[0];

  if (!actor) {
    return {
      error: {
        status: 401,
        message:
          "Authenticated user not found",
      },
    };
  }

  /**
   * Account must be active.
   */
  if (
    String(
      actor.status || ""
    ).toLowerCase() !==
    "active"
  ) {
    return {
      error: {
        status: 403,
        message:
          "Account is not active",
      },
    };
  }

  /**
   * Only super_admin.
   */
  if (
    String(
      actor.role || ""
    ).toLowerCase() !==
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

  const actorEmail =
    normalizeEmail(
      actor.user_id ||
        actor.email
    );

  /**
   * Email allow-list.
   */
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
// Validate normal audit query
// -----------------------------------------------------------------------------

function validateQuery(query) {
  const source =
    query &&
    typeof query ===
      "object" &&
    !Array.isArray(query)
      ? query
      : {};

  /**
   * Supported parameters.
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

  /**
   * Reject arrays / repeated parameters.
   */
  for (
    const key of
    supportedParams
  ) {
    if (
      !isPlainScalar(
        source[key]
      )
    ) {
      return {
        ok: false,
        status: 400,
        message:
          `Invalid ${key} parameter`,
      };
    }
  }

  // ---------------------------------------------------------------------------
  // page
  // ---------------------------------------------------------------------------

  const parsedPage =
    parsePositiveInteger(
      source.page,
      1,
      MAX_PAGE
    );

  if (!parsedPage.ok) {
    return {
      ok: false,
      status: 400,
      message:
        "Invalid page parameter",
    };
  }

  // ---------------------------------------------------------------------------
  // limit
  // ---------------------------------------------------------------------------

  const parsedLimit =
    parsePositiveInteger(
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

  // ---------------------------------------------------------------------------
  // Strings
  // ---------------------------------------------------------------------------

  const stringFields = [
    [
      "search",
      MAX_SEARCH_LENGTH,
    ],
    [
      "event_type",
      MAX_EVENT_TYPE_LENGTH,
    ],
    [
      "user_id",
      MAX_USER_ID_LENGTH,
    ],
    [
      "role",
      MAX_ROLE_LENGTH,
    ],
    [
      "partner_code",
      MAX_PARTNER_CODE_LENGTH,
    ],
    [
      "ip_address",
      MAX_IP_LENGTH,
    ],
  ];

  const strings = {};

  for (
    const [
      key,
      maxLength,
    ] of stringFields
  ) {
    const result =
      cleanOptionalString(
        source[key] ===
            undefined ||
          source[key] ===
            null
          ? ""
          : String(
              source[key]
            ),
        maxLength
      );

    if (!result.ok) {
      return {
        ok: false,
        status: 400,
        message:
          `Invalid ${key} parameter`,
      };
    }

    strings[key] =
      result.value;
  }

  // ---------------------------------------------------------------------------
  // success
  // ---------------------------------------------------------------------------

  const successFlag =
    parseSuccessFlag(
      source.success
    );

  if (!successFlag.ok) {
    return {
      ok: false,
      status: 400,
      message:
        "success must be 1, 0, true or false",
    };
  }

  // ---------------------------------------------------------------------------
  // Dates
  // ---------------------------------------------------------------------------

  const dateFrom =
    String(
      source.date_from || ""
    ).trim();

  const dateTo =
    String(
      source.date_to || ""
    ).trim();

  if (
    dateFrom &&
    !isValidDateOnly(
      dateFrom
    )
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
    !isValidDateOnly(
      dateTo
    )
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

  return {
    ok: true,

    value: {
      page:
        parsedPage.value,

      limit:
        parsedLimit.value,

      search:
        strings.search,

      eventType:
        strings.event_type,

      userId:
        normalizeEmail(
          strings.user_id
        ),

      role:
        strings.role,

      partnerCode:
        strings.partner_code,

      success:
        successFlag.value,

      ipAddress:
        strings.ip_address,

      dateFrom,

      dateTo,
    },
  };
}

// -----------------------------------------------------------------------------
// SQL filters
// -----------------------------------------------------------------------------

function buildFilters(filters) {
  const conditions = [];
  const params = [];

  // ---------------------------------------------------------------------------
  // Search
  // ---------------------------------------------------------------------------

  if (filters.search) {
    const pattern =
      `%${escapeLike(
        filters.search
      )}%`;

    conditions.push(`
      (
        event_type LIKE ?
        OR user_id LIKE ?
        OR role LIKE ?
        OR partner_code LIKE ?
        OR failure_reason LIKE ?
      )
    `);

    params.push(
      pattern,
      pattern,
      pattern,
      pattern,
      pattern
    );
  }

  // ---------------------------------------------------------------------------
  // Event type
  // ---------------------------------------------------------------------------

  if (filters.eventType) {
    conditions.push(
      "event_type = ?"
    );

    params.push(
      filters.eventType
    );
  }

  // ---------------------------------------------------------------------------
  // User
  // ---------------------------------------------------------------------------

  if (filters.userId) {
    conditions.push(
      "LOWER(user_id) = ?"
    );

    params.push(
      filters.userId
    );
  }

  // ---------------------------------------------------------------------------
  // Role
  // ---------------------------------------------------------------------------

  if (filters.role) {
    conditions.push(
      "role = ?"
    );

    params.push(
      filters.role
    );
  }

  // ---------------------------------------------------------------------------
  // Partner code
  // ---------------------------------------------------------------------------

  if (filters.partnerCode) {
    conditions.push(
      "partner_code = ?"
    );

    params.push(
      filters.partnerCode
    );
  }

  // ---------------------------------------------------------------------------
  // Success/failure
  // ---------------------------------------------------------------------------

  if (
    filters.success !==
    null
  ) {
    conditions.push(
      "success = ?"
    );

    params.push(
      filters.success
    );
  }

  // ---------------------------------------------------------------------------
  // IP address
  // ---------------------------------------------------------------------------

  if (filters.ipAddress) {
    /**
     * app_auth_logs stores IP as HMAC hash.
     *
     * Hash supplied IP first, then compare.
     */
    conditions.push(
      "ip_hash = ?"
    );

    params.push(
      authLogHash(
        filters.ipAddress
      )
    );
  }

  // ---------------------------------------------------------------------------
  // From date
  // ---------------------------------------------------------------------------

  if (filters.dateFrom) {
    conditions.push(
      "created_at >= ?"
    );

    params.push(
      `${filters.dateFrom} 00:00:00`
    );
  }

  // ---------------------------------------------------------------------------
  // To date
  // ---------------------------------------------------------------------------

  if (filters.dateTo) {
    /**
     * Exclusive next-day check.
     *
     * Better than <= 23:59:59.
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

// =============================================================================
// NORMAL / FULL AUDIT LOG API
// =============================================================================

async function auditLogs(
  req,
  res
) {
  /**
   * Never cache audit information.
   */
  res.setHeader(
    "Cache-Control",
    "private, no-cache, no-store, must-revalidate, max-age=0"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Expires",
    "0"
  );

  res.setHeader(
    "Vary",
    "Authorization"
  );

  try {
    // -------------------------------------------------------------------------
    // 1. Authorization
    // -------------------------------------------------------------------------

    const resolved =
      await resolveAuditActor(
        req
      );

    if (resolved.error) {
      /**
       * Record denied audit access.
       *
       * This is the FULL endpoint only.
       */
      await writeAuthLogSafe(
        req,
        {
          eventType:
            "audit_logs_denied",

          userId: null,

          role: null,

          partnerCode: null,

          identifier:
            String(
              req.user?.sub ||
                req.user
                  ?.dietician_id ||
                ""
            ),

          success: false,

          failureReason:
            resolved.error
              .message,
        }
      );

      return res
        .status(
          resolved.error
            .status
        )
        .json({
          ok: false,
          message:
            resolved.error
              .message,
        });
    }

    const {
      actor,
      actorEmail,
    } = resolved;

    // -------------------------------------------------------------------------
    // 2. Validate filters
    // -------------------------------------------------------------------------

    const validation =
      validateQuery(
        req.query
      );

    if (!validation.ok) {
      return res
        .status(
          validation.status
        )
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
    } = buildFilters(
      filters
    );

    const offset =
      (filters.page - 1) *
      filters.limit;

    // -------------------------------------------------------------------------
    // 3. Filtered total
    // -------------------------------------------------------------------------

    const [countRows] =
      await pool.execute(
        `
          SELECT
            COUNT(*) AS total

          FROM ${AUDIT_TABLE}

          ${whereSql}
        `,
        whereParams
      );

    const total =
      Number(
        countRows?.[0]
          ?.total || 0
      );

    const totalPages =
      total === 0
        ? 0
        : Math.ceil(
            total /
              filters.limit
          );

    // -------------------------------------------------------------------------
    // 4. Get requested page
    // -------------------------------------------------------------------------

    /**
     * LIMIT and OFFSET are safe to inline because both values
     * are validated integers.
     *
     * DATE_FORMAT prevents timezone conversion of MySQL DATETIME.
     */
    const [logRows] =
      await pool.execute(
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

            DATE_FORMAT(
              created_at,
              '%Y-%m-%d %H:%i:%s'
            ) AS created_at

          FROM ${AUDIT_TABLE}

          ${whereSql}

          ORDER BY
            created_at DESC,
            id DESC

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
       * Today's logs
       */
      pool.execute(
        `
          SELECT
            COUNT(*) AS total

          FROM ${AUDIT_TABLE}

          WHERE
            created_at >=
              CURDATE()

          AND created_at <
              DATE_ADD(
                CURDATE(),
                INTERVAL 1 DAY
              )
        `
      ),

      /**
       * Unique event types
       */
      pool.execute(
        `
          SELECT
            COUNT(
              DISTINCT event_type
            ) AS total

          FROM ${AUDIT_TABLE}
        `
      ),

      /**
       * Failed/security events
       */
      pool.execute(
        `
          SELECT
            COUNT(*) AS total

          FROM ${AUDIT_TABLE}

          WHERE success = 0
        `
      ),

      /**
       * Event type dropdown
       */
      pool.execute(
        `
          SELECT DISTINCT
            event_type

          FROM ${AUDIT_TABLE}

          WHERE
            event_type IS NOT NULL

          AND event_type <> ''

          ORDER BY
            event_type ASC

          LIMIT 500
        `
      ),
    ]);

    const todayTotal =
      Number(
        todayRows?.[0]
          ?.total || 0
      );

    const uniqueEventTypes =
      Number(
        eventTypeCountRows?.[0]
          ?.total || 0
      );

    const securityEvents =
      Number(
        failedRows?.[0]
          ?.total || 0
      );

    const eventTypes =
      eventTypeRows
        .map((row) =>
          String(
            row.event_type ||
              ""
          ).trim()
        )
        .filter(Boolean);

    /**
     * Convert success from MySQL 0/1 to boolean.
     */
    const logs =
      logRows.map(
        (row) => ({
          id:
            Number(row.id),

          event_type:
            row.event_type,

          user_id:
            row.user_id,

          role:
            row.role,

          partner_code:
            row.partner_code,

          success:
            Number(
              row.success
            ) === 1,

          failure_reason:
            row.failure_reason,

          ip_hash:
            row.ip_hash,

          user_agent_hash:
            row.user_agent_hash,

          created_at:
            row.created_at,
        })
      );

    // -------------------------------------------------------------------------
    // 6. Record full audit dashboard read
    // -------------------------------------------------------------------------

    /**
     * IMPORTANT:
     *
     * This is allowed here because this endpoint is used for:
     * - initial dashboard load
     * - manual refresh
     * - filter
     * - pagination
     *
     * The LIVE endpoint below DOES NOT write audit_logs_viewed.
     */
    writeAuthLogSafe(
      req,
      {
        eventType:
          "audit_logs_viewed",

        userId:
          actorEmail,

        role:
          "super_admin",

        partnerCode:
          actor.partner_code ??
          null,

        identifier:
          actorEmail,

        success:
          true,

        failureReason:
          `page=${filters.page} limit=${filters.limit} filtered=${total}`,
      }
    );

    // -------------------------------------------------------------------------
    // 7. Response
    // -------------------------------------------------------------------------

    return res
      .status(200)
      .json({
        ok: true,

        summary: {
          filtered_total:
            total,

          today_total:
            todayTotal,

          unique_event_types:
            uniqueEventTypes,

          security_events:
            securityEvents,
        },

        event_types:
          eventTypes,

        logs,

        pagination: {
          page:
            filters.page,

          limit:
            filters.limit,

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
    /**
     * Never expose DB details to frontend.
     */
    console.error(
      "AUDIT_LOGS_ERROR:",
      {
        code:
          error?.code ||
          null,

        errno:
          error?.errno ||
          null,

        sqlState:
          error?.sqlState ||
          null,

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

// =============================================================================
// LIVE AUDIT API
// =============================================================================

/**
 * Near-real-time audit feed.
 *
 * Frontend calls:
 *
 * /audit-logs/live?after_id=61580
 *
 * every 5 seconds.
 *
 * It returns only records with:
 *
 * id > 61580
 *
 * IMPORTANT:
 *
 * This endpoint DOES NOT:
 *
 * - calculate dashboard summary
 * - calculate total count
 * - calculate event types
 * - create audit_logs_viewed
 *
 * Therefore it is much lighter than repeatedly calling the normal API.
 */
async function auditLogsLive(
  req,
  res
) {
  res.setHeader(
    "Cache-Control",
    "private, no-cache, no-store, must-revalidate, max-age=0"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  res.setHeader(
    "Expires",
    "0"
  );

  res.setHeader(
    "Vary",
    "Authorization"
  );

  try {
    // -------------------------------------------------------------------------
    // 1. Authorization
    // -------------------------------------------------------------------------

    const resolved =
      await resolveAuditActor(
        req
      );

    if (resolved.error) {
      /**
       * IMPORTANT:
       *
       * Don't write audit_logs_denied on every failed polling request.
       *
       * Otherwise a broken/expired browser session could flood
       * app_auth_logs every 5 seconds.
       */
      return res
        .status(
          resolved.error
            .status
        )
        .json({
          ok: false,

          message:
            resolved.error
              .message,
        });
    }

    // -------------------------------------------------------------------------
    // 2. Validate after_id
    // -------------------------------------------------------------------------

    const parsedAfterId =
      parseNonNegativeInteger(
        req.query?.after_id
      );

    if (!parsedAfterId.ok) {
      return res
        .status(400)
        .json({
          ok: false,

          message:
            "after_id must be a non-negative integer",
        });
    }

    const afterId =
      parsedAfterId.value;

    // -------------------------------------------------------------------------
    // 3. Get NEW records only
    // -------------------------------------------------------------------------

    /**
     * id is PRIMARY KEY.
     *
     * Therefore:
     *
     * WHERE id > ?
     *
     * is efficient for live polling.
     *
     * audit_logs_viewed is intentionally excluded from the LIVE feed.
     *
     * It still remains stored in app_auth_logs and can be viewed using
     * the normal audit API / event filter.
     */
    const [rows] =
      await pool.execute(
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

            DATE_FORMAT(
              created_at,
              '%Y-%m-%d %H:%i:%s'
            ) AS created_at

          FROM ${AUDIT_TABLE}

          WHERE id > ?

          AND event_type <>
              'audit_logs_viewed'

          ORDER BY
            id ASC

          LIMIT ${LIVE_LIMIT}
        `,
        [afterId]
      );

    /**
     * Convert MySQL result.
     */
    const logs =
      rows.map(
        (row) => ({
          id:
            Number(row.id),

          event_type:
            row.event_type,

          user_id:
            row.user_id,

          role:
            row.role,

          partner_code:
            row.partner_code,

          success:
            Number(
              row.success
            ) === 1,

          failure_reason:
            row.failure_reason,

          ip_hash:
            row.ip_hash,

          user_agent_hash:
            row.user_agent_hash,

          created_at:
            row.created_at,
        })
      );

    // -------------------------------------------------------------------------
    // 4. Cursor
    // -------------------------------------------------------------------------

    let nextAfterId =
      afterId;

    if (logs.length > 0) {
      nextAfterId =
        logs[
          logs.length - 1
        ].id;
    }

    /**
     * Example:
     *
     * after_id = 61580
     *
     * DB:
     * 61581 audit_logs_viewed
     * 61582 audit_logs_viewed
     *
     * Both are excluded.
     *
     * Without advancing the cursor, every poll would keep checking
     * those same rows forever.
     *
     * Therefore, when fewer than LIVE_LIMIT normal records are returned,
     * advance to the current maximum DB id.
     */
    if (
      logs.length <
      LIVE_LIMIT
    ) {
      const [maxRows] =
        await pool.execute(
          `
            SELECT
              COALESCE(
                MAX(id),
                ?
              ) AS max_id

            FROM ${AUDIT_TABLE}
          `,
          [afterId]
        );

      const tableMaxId =
        Number(
          maxRows?.[0]
            ?.max_id ||
            afterId
        );

      if (
        Number.isSafeInteger(
          tableMaxId
        ) &&
        tableMaxId >
          nextAfterId
      ) {
        nextAfterId =
          tableMaxId;
      }
    }

    // -------------------------------------------------------------------------
    // 5. Response
    // -------------------------------------------------------------------------

    return res
      .status(200)
      .json({
        ok: true,

        logs,

        new_count:
          logs.length,

        after_id:
          afterId,

        next_after_id:
          nextAfterId,

        /**
         * If exactly LIVE_LIMIT rows were returned,
         * there may be additional logs waiting.
         *
         * Frontend may immediately call the endpoint again.
         */
        has_more:
          logs.length ===
          LIVE_LIMIT,
      });
  } catch (error) {
    console.error(
      "AUDIT_LOGS_LIVE_ERROR:",
      {
        code:
          error?.code ||
          null,

        errno:
          error?.errno ||
          null,

        sqlState:
          error?.sqlState ||
          null,

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
          "Unable to load live audit logs",
      });
  }
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  auditLogs,
  auditLogsLive,
};