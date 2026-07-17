"use strict";

/**
 * get_latest_72hr_tests.js
 *
 * Converted from: the 72-hour latest-test cursor-pagination PHP.
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : GET /dietitian/api/web/get_latest_72hr_tests?limit=100&cursor=0
 * Auth     : HMAC-signed service key (serviceAuthMiddleware) — NOT a dietitian JWT.
 *
 * Purpose  : Feed the meal-plan generator. Returns, for every client with a test
 *            in the last 72 hours, that client's newest test plus the inputs the
 *            generator needs (macro summary, scores, level_type, location, habits).
 *            Cursor-paginated on test_id ASC. The generator writes its output back
 *            via store_weekly_food_json_suggestion.js, which shares this auth.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  THIS IS A BULK PHI EXPORT — THE RISK PROFILE IS DIFFERENT
 * ──────────────────────────────────────────────────────────────────────────
 * Unlike the per-client endpoints, this one is a firehose: the PHP applied NO
 * dietitian filter and NO authentication, so a single unauthenticated GET walked
 * the metabolism scores, location and habits of every client of every practice on
 * the platform, 500 rows at a time, with a cursor helpfully returned for the next
 * page. One curl loop drains the client base. Authentication is the primary fix;
 * key scoping is the blast-radius fix.
 *
 * Authorization (no actor exists, so the JWT-era model does not apply):
 *  - The service key authenticates the caller (HIPAA §164.312(d)).
 *  - Its SERVICE_API_KEYS `dietician_codes` list, if present, restricts the export
 *    to those practices (minimum necessary). Unrestricted keys (["*"] or omitted)
 *    see every practice — which is what a platform-wide generator needs, but it
 *    means the key IS the whole client base. Scope it if you can.
 *
 * Behaviour parity with the PHP:
 *  - Identical SQL: the FORCE INDEX (idx_72hr_fetch_unique_user) 72-hour subquery,
 *    the MAX(test_id)-per-(dietitian_id, profile_id) join, the latest-habit-row
 *    join, and the level_type IS NOT NULL / != '' / != '1' filters.
 *  - limit defaults to 100, clamps to 1..500; cursor defaults to 0.
 *  - next_cursor advances past rows that are then skipped for unusable test_json —
 *    deliberate in the PHP, and preserved: otherwise a single unparseable row would
 *    wedge the cursor and the pager would loop on it forever.
 *  - has_more compares the RAW row count to limit (not the filtered count).
 *  - Rows are skipped when test_json is empty, unparseable, or has no top-level
 *    final_macro_summary object.
 *  - PHP's (float) cast semantics are reproduced exactly (see phpFloat): missing or
 *    null macros become 0, missing scores stay null, "12abc" becomes 12, "abc" → 0.
 *  - Response keys unchanged: { success, limit, cursor, next_cursor, has_more,
 *    total_returned, data }.
 *  - Same tables only: table_test_data, table_clients, user_habits. app_auth_logs
 *    is written for the access trail, as on every converted PHI endpoint.
 *
 * NOTE — column spelling is not a typo: table_test_data uses `dietitian_id`
 * (with a "t"), while table_clients uses `dietician_id` (with a "c"). Both the PHP
 * and the sibling controllers rely on this.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Authentication + key scoping, replacing "anyone with the URL".
 *  - PDO exception text no longer echoed (it leaked DSN, credentials and schema).
 *    Gated behind APP_DEBUG; server logs carry only error metadata.
 *  - LIMIT is an inlined, validated integer — mysql2's prepared statements reject
 *    a bound LIMIT on some MySQL builds. cursor stays a bound parameter.
 *  - limit/cursor are rejected when non-numeric rather than silently coerced to 0.
 *    The PHP's (int) cast turned a typo'd cursor into 0, silently restarting the
 *    whole export from the beginning — expensive and easy to miss.
 *  - The habits sub-select is narrowed from `uh1.*` to the three columns actually
 *    used (minimum necessary; also less row width to haul).
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; test_json is read to extract the macro summary but
 *    is never returned.
 *  - Every export (with the row count) and every denial is recorded in
 *    app_auth_logs with identifier / IP / user-agent HMAC-SHA256 hashed using
 *    SECURITY_PEPPER. Fail-safe: audit failures never break the request.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * OPEN QUESTION for the project owner (behaviour preserved as-is):
 *   This PHP reads ONLY a TOP-LEVEL final_macro_summary, but
 *   get_macro_summary_by_date.js reads respyr_response.final_macro_summary FIRST
 *   and only then falls back to top-level. If any test_json nests it, those rows
 *   are silently skipped here and those clients never get a plan generated. Left
 *   exactly as the PHP had it — this changes who gets fed, so it is not a call to
 *   make silently.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

// ─── PHP cast semantics ──────────────────────────────────────────────────────

/**
 * PHP's (float) cast, reproduced:
 *   (float)null    === 0.0     (float)"abc"   === 0.0
 *   (float)"12abc" === 12.0    (float)true    === 1.0
 * parseFloat matches PHP's leading-numeric behaviour; NaN collapses to 0.
 */
function phpFloat(value) {
  if (value === null || value === undefined) return 0;
  if (typeof value === "number") return Number.isFinite(value) ? value : 0;
  if (typeof value === "boolean") return value ? 1 : 0;
  const n = parseFloat(String(value));
  return Number.isFinite(n) ? n : 0;
}

/** PHP: isset($macro[k]) ? (float)$macro[k] : 0 — absent AND null both yield 0. */
function macroFloat(macro, key) {
  const value = macro?.[key];
  return value === undefined || value === null ? 0 : phpFloat(value);
}

/** PHP: isset($row[k]) ? (float)$row[k] : null — absent/null stay null. */
function scoreFloat(value) {
  return value === undefined || value === null ? null : phpFloat(value);
}

// ─── JSON column decoding ────────────────────────────────────────────────────

/**
 * Decode a JSON column that mysql2 may hand back as a string, a Buffer (LONGTEXT /
 * BLOB), or an already-parsed object (native JSON column type). Mirrors the
 * parseTestJson helper in get_macro_summary_by_date.js.
 */
function decodeJsonColumn(raw) {
  if (raw === null || raw === undefined) return null;

  let value = raw;
  if (Buffer.isBuffer(value)) value = value.toString("utf8");

  if (typeof value === "object") return value;
  if (typeof value !== "string") return null;

  // PHP empty(): both "" and the string "0" count as empty.
  if (value === "" || value === "0") return null;

  try {
    return JSON.parse(value);
  } catch (err) {
    return null;
  }
}

/**
 * PHP built food_type from any is_array() decode, so a JSON array decodes to an
 * all-null triple rather than to null. Preserved.
 */
function extractFoodType(raw) {
  const decoded = decodeJsonColumn(raw);
  if (decoded === null || typeof decoded !== "object") return null;

  return {
    diet_type: decoded.diet_type ?? null,
    primary_cuisine: decoded.primary_cuisine ?? null,
    secondary_cuisine: decoded.secondary_cuisine ?? null,
  };
}

// ─── Query-parameter validation ──────────────────────────────────────────────

class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

/** Accepts an optional non-negative integer; rejects anything else. */
function parseIntParam(value, label, fallback) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return fallback;
  }
  // A repeated param (?limit=1&limit=2) arrives as an array — reject rather than
  // silently pick one, since the two would sign and behave differently.
  if (typeof value !== "string") {
    throw new ApiError(422, `${label} must be a single integer value`);
  }
  const text = value.trim();
  if (!/^-?\d{1,10}$/.test(text)) {
    throw new ApiError(422, `${label} must be an integer`);
  }
  return Number.parseInt(text, 10);
}

// ─── Audit log (fail-safe, HMAC-hashed PII) ──────────────────────────────────

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

function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

async function writeAuthLogSafe(req, { eventType, userId, identifier, success, failureReason }) {
  try {
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
       VALUES (?, ?, 'service', NULL, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
        identifier !== null && identifier !== undefined ? authLogHash(identifier) : null,
        authLogHash(getClientIp(req)),
        authLogHash(getUserAgent(req)),
        success ? 1 : 0,
        failureReason !== null && failureReason !== undefined
          ? String(failureReason).slice(0, 255)
          : null,
      ]
    );
  } catch (err) {
    console.error("LATEST_72HR_TESTS_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * GET /dietitian/api/web/get_latest_72hr_tests
 *
 * Headers (see serviceAuthMiddleware.js — the query string IS part of the signature):
 *   x-respyr-key-id, x-respyr-timestamp, x-respyr-nonce, x-respyr-signature
 *
 * Query:
 *   limit   optional, default 100, clamped to 1..500
 *   cursor  optional, default 0 — pass the previous response's next_cursor
 */
const getLatest72hrTests = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (the PHP read $_GET).
  if (req.method !== "GET") {
    return res.status(405).json({
      success: false,
      message: "Only GET method is allowed",
    });
  }

  const serviceKeyId = req.serviceClient?.keyId || null;

  try {
    // ── 1. Validate pagination inputs ───────────────────────────────────────
    let limit = parseIntParam(req.query.limit, "limit", DEFAULT_LIMIT);
    const cursor = parseIntParam(req.query.cursor, "cursor", 0);

    // PHP clamp order: <=0 becomes the default, then cap at MAX_LIMIT.
    if (limit <= 0) limit = DEFAULT_LIMIT;
    if (limit > MAX_LIMIT) limit = MAX_LIMIT;

    // The PHP allowed a negative cursor, which made `test_id > -5` match
    // everything — identical to 0 for a positive-keyed column. Clamped for clarity;
    // no behavioural change.
    const safeCursor = cursor < 0 ? 0 : cursor;

    // ── 2. Key scoping (minimum necessary) ──────────────────────────────────
    const scopedCodes = req.serviceClient?.dieticianCodes ?? null; // null === unrestricted
    const codeList = scopedCodes === null ? [] : [...scopedCodes];

    // A scoped key with an empty list can address nothing. Return an empty page
    // rather than building `IN ()`, which is a MySQL syntax error.
    if (scopedCodes !== null && codeList.length === 0) {
      await writeAuthLogSafe(req, {
        eventType: "latest_72hr_tests_denied",
        userId: serviceKeyId,
        identifier: "scope:empty",
        success: false,
        failureReason: "service key has an empty dietician scope",
      });
      return res.status(403).json({
        success: false,
        message: "This service key is not scoped to any dietitian",
      });
    }

    // ── 3. Fetch ────────────────────────────────────────────────────────────
    // LIMIT is inlined because mysql2 prepared statements reject a bound LIMIT on
    // some MySQL builds. It is safe ONLY because `limit` is now a validated
    // integer clamped to 1..500 — never interpolate an unvalidated value here.
    const scopeClause =
      scopedCodes === null
        ? ""
        : `AND UPPER(TRIM(t.dietitian_id)) IN (${codeList.map(() => "?").join(", ")})`;

    const params = [safeCursor, ...codeList];

    const [rows] = await pool.execute(
      `
        SELECT
          t.dietitian_id,
          t.profile_id,
          t.test_id AS latest_test_id,
          DATE_FORMAT(t.date_time, '%Y-%m-%d %H:%i:%s') AS latest_date_time,
          t.level_type,
          t.fermentative_metabolism_score AS digestive_score,
          t.detoxification_metabolism_score AS recovery_score,
          t.test_json,

          c.location,

          uh.activity,
          uh.food_type

        FROM table_test_data t

        INNER JOIN (
            SELECT
                dietitian_id,
                profile_id,
                MAX(test_id) AS latest_test_id
            FROM table_test_data FORCE INDEX (idx_72hr_fetch_unique_user)
            WHERE date_time >= (NOW() - INTERVAL 72 HOUR)
            GROUP BY dietitian_id, profile_id
        ) latest
            ON latest.dietitian_id = t.dietitian_id
            AND latest.profile_id = t.profile_id
            AND latest.latest_test_id = t.test_id

        LEFT JOIN table_clients c
            ON c.profile_id = t.profile_id

        LEFT JOIN (
            SELECT uh1.profile_id, uh1.activity, uh1.food_type
            FROM user_habits uh1
            INNER JOIN (
                SELECT profile_id, MAX(id) AS latest_habit_id
                FROM user_habits
                GROUP BY profile_id
            ) uh2
                ON uh2.profile_id = uh1.profile_id
                AND uh2.latest_habit_id = uh1.id
        ) uh
            ON uh.profile_id = t.profile_id

        WHERE t.test_id > ?
        AND t.level_type IS NOT NULL
        AND t.level_type != ''
        AND t.level_type != '1'
        ${scopeClause}

        ORDER BY t.test_id ASC
        LIMIT ${limit}
      `,
      params
    );

    // ── 4. Shape the rows ───────────────────────────────────────────────────
    let nextCursor = safeCursor;
    const data = [];

    for (const row of rows) {
      const latestTestId = Number.parseInt(row.latest_test_id, 10) || 0;

      // Advance the cursor BEFORE any skip, exactly as the PHP did — a row that
      // can never be parsed must not become a permanent pagination wall.
      if (latestTestId > nextCursor) {
        nextCursor = latestTestId;
      }

      const decodedJson = decodeJsonColumn(row.test_json);

      if (decodedJson === null || typeof decodedJson !== "object") continue;

      const macro = decodedJson.final_macro_summary;

      // PHP required final_macro_summary to be is_array() — an object or array,
      // never a scalar.
      if (macro === null || macro === undefined || typeof macro !== "object") continue;

      data.push({
        dietitian_id: row.dietitian_id,
        profile_id: row.profile_id,
        latest_test_id: latestTestId,
        latest_date_time: row.latest_date_time,

        level_type: row.level_type,
        location: row.location ?? null,
        activity: row.activity ?? null,
        food_type: extractFoodType(row.food_type),

        digestive_score: scoreFloat(row.digestive_score),
        recovery_score: scoreFloat(row.recovery_score),

        final_macro_summary: {
          calories: macroFloat(macro, "calories"),
          protein_g: macroFloat(macro, "protein_g"),
          carbs_g: macroFloat(macro, "carbs_g"),
          fat_g: macroFloat(macro, "fat_g"),
          fiber_g: macroFloat(macro, "fiber_g"),
        },
      });
    }

    // ── 5. Audit the bulk PHI read ──────────────────────────────────────────
    // Awaited, not fire-and-forget: on Lambda the environment can freeze as soon as
    // the response is flushed. This row is the §164.312(b) record of how much PHI
    // left the system, which is exactly what an auditor asks for after an incident.
    await writeAuthLogSafe(req, {
      eventType: "latest_72hr_tests_exported",
      userId: serviceKeyId,
      identifier: `cursor:${safeCursor}|limit:${limit}|rows:${data.length}`,
      success: true,
      failureReason: `Exported ${data.length} of ${rows.length} rows`,
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      success: true,
      limit,
      cursor: safeCursor,
      next_cursor: nextCursor,
      // Deliberately the RAW row count, not data.length: filtered-out rows still
      // consumed a page, so `has_more` must reflect the page, not the payload.
      has_more: rows.length === limit,
      total_returned: data.length,
      data,
    });
  } catch (err) {
    if (err instanceof ApiError) {
      return res.status(err.statusCode).json({
        success: false,
        message: err.message,
      });
    }

    console.error("LATEST_72HR_TESTS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "latest_72hr_tests_error",
      userId: serviceKeyId,
      identifier: null,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      success: false,
      message: "Query failed",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { getLatest72hrTests };
