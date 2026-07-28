"use strict";

/**
 * fetch-single-client-worker-job-test.js
 *
 * Converted from: fetch-single-client-worker-job-test.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : GET /dietitian/api/web/fetch-single-client-worker-job-test
 * Auth     : HMAC-signed service key (serviceAuthMiddleware) — NOT a dietitian JWT.
 *
 * Purpose  : The meal-plan worker's test harness. Same feed as
 *            get_latest_72hr_tests.js, plus a single-profile mode that lets an
 *            operator re-run the worker against one named client on demand.
 *
 *            batch_72hrs    — no dietitian_id/profile_id given. Byte-for-byte the
 *                             production feed: last 72 hours, level_type != '1',
 *                             cursor-paginated on test_id ASC.
 *            single_profile — dietitian_id + profile_id given (BOTH required).
 *                             Newest test for that one client, level_type = '1'
 *                             allowed, optionally restricted to the last 72 hours
 *                             with only_72hrs=1.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  THIS IS A PHI EXPORT — AND THE PHP HAD NO AUTHENTICATION AT ALL
 * ──────────────────────────────────────────────────────────────────────────
 * In batch mode the PHP is the same firehose as get_latest_72hr_tests: an
 * unauthenticated GET walked the metabolism scores, location and habits of every
 * client of every practice, 500 rows at a time, handing back a cursor for the
 * next page. Single-profile mode is worse in kind, if not in volume: any caller
 * could name any (dietitian_id, profile_id) pair and read that client's newest
 * test directly — a targeted IDOR rather than a bulk drain, and one that lets an
 * attacker confirm whether a specific person is a client of a specific practice.
 *
 * "Test endpoint" is not a security posture. It reads live production PHI from
 * the same tables as the production feed, so it is authenticated identically.
 *
 * Authorization (no actor exists, so the JWT-era model does not apply):
 *  - The service key authenticates the caller (HIPAA §164.312(d)).
 *  - batch mode    : the key's SERVICE_API_KEYS `dietician_codes` list, if
 *                    present, restricts the export to those practices.
 *  - single mode   : the requested dietitian_id must be inside that same list —
 *                    serviceKeyCanUseDieticianCode(), the identical gate
 *                    store_weekly_food_json_suggestion.js applies on the write
 *                    side of this pipeline.
 *  Unrestricted keys (["*"] or omitted) still see every practice; that is what a
 *  platform-wide worker needs, but it means the key IS the whole client base.
 *  Scope this endpoint's key harder than the production one if you can — a test
 *  harness rarely needs more than a handful of practices.
 *
 * NOTE — no extra table_clients ownership gate in single mode, deliberately.
 * Unlike the weight-tracking / store-plan endpoints, the tenant boundary here is
 * already the bound dietitian_id in the WHERE clause, and the key-scope check is
 * what authorizes it. Requiring a matching table_clients row on top would add no
 * authorization (an unrestricted key passes both; a scoped key fails at the
 * scope check first) while 404-ing legitimate tests whose client row is missing —
 * rows the PHP returned, because it LEFT JOINs table_clients.
 *
 * Behaviour parity with the PHP:
 *  - Mode selection: single_profile iff dietitian_id OR profile_id is non-empty
 *    after trim; supplying only one of the two is a 400 that echoes what was
 *    received. `dietitian_id` wins over the `dietician_id` spelling when both
 *    are sent (the PHP's isset() chain).
 *  - limit defaults to 100, clamps to 1..500; cursor defaults to 0. Both are
 *    parsed and echoed in single mode too, where they do not affect the query.
 *  - only_72hrs is on when the value loosely equals "1" (PHP 8 numeric-string
 *    comparison, so "1", "01" and "1.0" all count; "true" and "yes" do not).
 *  - next_cursor advances past rows that are then skipped for unusable
 *    test_json — deliberate in the PHP, and preserved: otherwise one
 *    unparseable row would wedge the cursor and the pager would loop on it.
 *  - has_more compares the RAW row count to limit, and is hard false in single
 *    mode.
 *  - Rows are skipped when test_json is empty, unparseable, or has no top-level
 *    final_macro_summary object.
 *  - PHP's (float) cast semantics reproduced exactly (see phpFloat): missing or
 *    null macros become 0, missing scores stay null, "12abc" → 12, "abc" → 0.
 *  - Response keys and order unchanged: { success, mode, limit, cursor,
 *    next_cursor, has_more, total_returned, filter, data }.
 *  - Same tables only: table_test_data, table_clients, user_habits.
 *    app_auth_logs is written for the access trail, as on every converted PHI
 *    endpoint here.
 *
 * NOTE — column spelling is not a typo: table_test_data uses `dietitian_id`
 * (with a "t"), while table_clients uses `dietician_id` (with a "c"). Both the
 * PHP and the sibling controllers rely on this.
 *
 * ⚠️ SOURCE ASYMMETRY PRESERVED, NOT CORRECTED — digestive_score
 * The PHP reads a DIFFERENT column per mode:
 *     single_profile → t.fermentative_metabolism_score  AS digestive_score
 *     batch_72hrs    → t.absorptive_metabolism_score    AS digestive_score
 * Both columns exist (see get_graph_all_seven_trends_graph.js), so neither is a
 * typo MySQL would have caught. Its own production sibling
 * get_latest_72hr_tests.js uses `fermentative` in BATCH mode — so this file's
 * batch mode disagrees with the endpoint it is supposed to be a test harness
 * for, which defeats the point of the harness. Reproduced verbatim regardless:
 * picking one would silently change the number the worker plans meals from.
 * Flag for the project owner — see FETCH_SINGLE_CLIENT_WORKER_JOB_TEST below.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Authentication + key scoping, replacing "anyone with the URL".
 *  - PDO exception text no longer echoed (it leaked DSN, credentials and
 *    schema — the PHP printed getMessage() on both connect and query failure).
 *    Gated behind APP_DEBUG; server logs carry only error metadata.
 *  - LIMIT is an inlined, validated integer — mysql2's prepared statements
 *    reject a bound LIMIT on some MySQL builds. cursor stays a bound parameter.
 *  - limit/cursor are rejected when non-numeric rather than silently coerced to
 *    0. The PHP's (int) cast turned a typo'd cursor into 0, silently restarting
 *    the whole export from the beginning — expensive and easy to miss.
 *  - dietitian_id / profile_id are length- and charset-checked, and repeated
 *    query params (?profile_id=a&profile_id=b) are rejected rather than
 *    silently resolved — they would sign and behave differently.
 *  - The habits sub-select is narrowed from `uh1.*` to the three columns
 *    actually used (minimum necessary; also less row width to haul).
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; test_json is read to extract the macro summary
 *    but is never returned.
 *  - Every export (with the row count) and every denial is recorded in
 *    app_auth_logs with identifier / IP / user-agent HMAC-SHA256 hashed using
 *    SECURITY_PEPPER. Fail-safe: audit failures never break the request.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * OPEN QUESTION for the project owner (behaviour preserved as-is):
 *   Both modes read ONLY a TOP-LEVEL final_macro_summary, but
 *   get_macro_summary_by_date.js reads respyr_response.final_macro_summary
 *   FIRST and only then falls back to top-level. If any test_json nests it,
 *   those rows are silently skipped here and those clients never get a plan
 *   generated. Left exactly as the PHP had it — this changes who gets fed, so
 *   it is not a call to make silently.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  serviceKeyCanUseDieticianCode,
} = require("../../../../middlewares/serviceAuthMiddleware");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

// Matches the identifier bounds used across the converted controllers.
const ID_MAX_LENGTH = 100;

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
 * Decode a JSON column that mysql2 may hand back as a string, a Buffer
 * (LONGTEXT / BLOB), or an already-parsed object (native JSON column type).
 * Mirrors the helper in get_latest_72hr_tests.js.
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
  constructor(statusCode, message, extra) {
    super(message);
    this.statusCode = statusCode;
    this.extra = extra || null;
  }
}

/** Accepts an optional integer; rejects anything else. */
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

/**
 * PHP's trim() on a $_GET value, with the array case rejected. Returns "" when
 * the param is absent — which is exactly how the PHP decides the mode.
 */
function parseIdParam(value, label) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") {
    throw new ApiError(422, `${label} must be a single value`);
  }

  const text = value.trim();
  if (text === "") return "";

  if (text.length > ID_MAX_LENGTH) {
    throw new ApiError(422, `${label} must be at most ${ID_MAX_LENGTH} characters`);
  }
  // Identifiers in this schema are codes/uuids. Control characters have no
  // business here and are the usual vehicle for log-injection.
  if (!/^[A-Za-z0-9._@:+\-]+$/.test(text)) {
    throw new ApiError(422, `${label} contains unsupported characters`);
  }

  return text;
}

/**
 * PHP: $_GET["only_72hrs"] == "1" — a LOOSE comparison. In PHP 8 two numeric
 * strings compare numerically, so "1", "01" and "1.0" are all true, while
 * non-numeric strings ("true", "yes") compare as strings and are false.
 */
function parseOnly72hrs(value) {
  if (value === undefined || value === null) return false;
  if (typeof value !== "string") {
    throw new ApiError(422, "only_72hrs must be a single value");
  }
  const text = value.trim();
  if (text === "1") return true;
  if (!/^[+-]?(\d+(\.\d*)?|\.\d+)$/.test(text)) return false;
  return Number.parseFloat(text) === 1;
}

// ─── Audit log (fail-safe, HMAC-hashed PII) ──────────────────────────────────

function normalizeCode(value) {
  return String(value ?? "").trim().toUpperCase();
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

function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

async function writeAuthLogSafe(
  req,
  { eventType, userId, partnerCode, identifier, success, failureReason }
) {
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
       VALUES (?, ?, 'service', ?, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
        partnerCode ? String(partnerCode).slice(0, 100) : null,
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
    console.error("WORKER_JOB_TEST_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * GET /dietitian/api/web/fetch-single-client-worker-job-test
 *
 * Headers (see serviceAuthMiddleware.js — the query string IS part of the
 * signature; sign it with tools/signServiceRequest.js):
 *   x-respyr-key-id, x-respyr-timestamp, x-respyr-nonce, x-respyr-signature
 *
 * Query — batch mode (no ids):
 *   limit         optional, default 100, clamped to 1..500
 *   cursor        optional, default 0 — pass the previous response's next_cursor
 *
 * Query — single-profile mode:
 *   dietitian_id  required (alias: dietician_id)
 *   profile_id    required — supplying only one of the two is a 400
 *   only_72hrs    optional, "1" restricts to tests from the last 72 hours
 */
const fetchSingleClientWorkerJobTest = async (req, res) => {
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
    // ── 1. Validate inputs ──────────────────────────────────────────────────
    let limit = parseIntParam(req.query.limit, "limit", DEFAULT_LIMIT);
    const cursor = parseIntParam(req.query.cursor, "cursor", 0);

    // PHP clamp order: <=0 becomes the default, then cap at MAX_LIMIT.
    if (limit <= 0) limit = DEFAULT_LIMIT;
    if (limit > MAX_LIMIT) limit = MAX_LIMIT;

    // The PHP allowed a negative cursor, which made `test_id > -5` match
    // everything — identical to 0 for a positive-keyed column. Clamped for
    // clarity; no behavioural change.
    const safeCursor = cursor < 0 ? 0 : cursor;

    // PHP's isset() chain: `dietitian_id` is preferred, `dietician_id` is the
    // fallback spelling. A present-but-blank value reads as absent.
    const dietitianIdRaw = parseIdParam(req.query.dietitian_id, "dietitian_id");
    const dietitianId =
      req.query.dietitian_id !== undefined
        ? dietitianIdRaw
        : parseIdParam(req.query.dietician_id, "dietician_id");

    const profileId = parseIdParam(req.query.profile_id, "profile_id");

    const singleProfileMode = dietitianId !== "" || profileId !== "";

    if (singleProfileMode && (dietitianId === "" || profileId === "")) {
      throw new ApiError(400, "Both dietitian_id and profile_id are required", {
        received: {
          dietitian_id: dietitianId,
          profile_id: profileId,
        },
      });
    }

    const only72hrs = parseOnly72hrs(req.query.only_72hrs);

    // Echoed verbatim in the response, exactly as the PHP did.
    const filter = {
      dietitian_id: dietitianId,
      profile_id: profileId,
      only_72hrs: only72hrs,
    };

    // ── 2. Key scoping (minimum necessary) ──────────────────────────────────
    const scopedCodes = req.serviceClient?.dieticianCodes ?? null; // null === unrestricted

    if (singleProfileMode) {
      // A named client: the requested practice must be inside the key's scope.
      // Same gate as the write side of this pipeline
      // (store_weekly_food_json_suggestion.js).
      if (!serviceKeyCanUseDieticianCode(req.serviceClient, dietitianId)) {
        await writeAuthLogSafe(req, {
          eventType: "worker_job_test_denied",
          userId: serviceKeyId,
          partnerCode: normalizeCode(dietitianId),
          identifier: `${profileId}|${dietitianId}`,
          success: false,
          failureReason: "service key not scoped to this dietitian_id",
        });
        return res.status(403).json({
          success: false,
          message: "This service key is not permitted to read tests for this dietitian",
        });
      }
    } else if (scopedCodes !== null && scopedCodes.size === 0) {
      // A scoped key with an empty list can address nothing. Deny rather than
      // build `IN ()`, which is a MySQL syntax error.
      await writeAuthLogSafe(req, {
        eventType: "worker_job_test_denied",
        userId: serviceKeyId,
        partnerCode: null,
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
    // The habits sub-select is shared by both modes: the newest user_habits row
    // per profile_id, narrowed to the two columns actually used.
    const latestHabitsJoin = `
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
            ON uh.profile_id = t.profile_id`;

    let rows;

    if (singleProfileMode) {
      /*
        Single-profile test mode:
         - level_type = '1' is ALLOWED here (that is the point of the harness —
           batch mode excludes those rows, so this is the only way to see them).
         - digestive_score comes from fermentative_metabolism_score; see the
           SOURCE ASYMMETRY note in the header.
         - only_72hrs=1 restricts the inner MAX(test_id) subquery to the last
           72 hours, so "latest" means "latest within the window", not "latest
           overall, if it happens to be recent".
         - No ORDER BY on the outer query: the inner GROUP BY yields at most one
           row for the pair, so LIMIT 1 is already deterministic.
      */
      const dateFilterSql = only72hrs
        ? "AND date_time >= (NOW() - INTERVAL 72 HOUR)"
        : "";

      [rows] = await pool.execute(
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
            FROM table_test_data
            WHERE dietitian_id = ?
            AND profile_id = ?
            ${dateFilterSql}
            GROUP BY dietitian_id, profile_id
        ) latest
            ON latest.dietitian_id = t.dietitian_id
            AND latest.profile_id = t.profile_id
            AND latest.latest_test_id = t.test_id

        LEFT JOIN table_clients c
            ON c.profile_id = t.profile_id
${latestHabitsJoin}

        LIMIT 1
        `,
        [dietitianId, profileId]
      );
    } else {
      /*
        Batch mode — the production 72-hour feed, unchanged from
        get_latest_72hr_tests.js apart from the digestive_score column (see the
        SOURCE ASYMMETRY note in the header) and the extra mode/filter keys.

        LIMIT is inlined because mysql2 prepared statements reject a bound LIMIT
        on some MySQL builds. It is safe ONLY because `limit` is a validated
        integer clamped to 1..500 — never interpolate an unvalidated value here.
      */
      const codeList = scopedCodes === null ? [] : [...scopedCodes];

      const scopeClause =
        scopedCodes === null
          ? ""
          : `AND UPPER(TRIM(t.dietitian_id)) IN (${codeList.map(() => "?").join(", ")})`;

      [rows] = await pool.execute(
        `
        SELECT
            t.dietitian_id,
            t.profile_id,
            t.test_id AS latest_test_id,
            DATE_FORMAT(t.date_time, '%Y-%m-%d %H:%i:%s') AS latest_date_time,
            t.level_type,
            t.absorptive_metabolism_score AS digestive_score,
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
${latestHabitsJoin}

        WHERE t.test_id > ?
        AND t.level_type IS NOT NULL
        AND t.level_type != ''
        AND t.level_type != '1'
        ${scopeClause}

        ORDER BY t.test_id ASC
        LIMIT ${limit}
        `,
        [safeCursor, ...codeList]
      );
    }

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

    // ── 5. Audit the PHI read ───────────────────────────────────────────────
    // Awaited, not fire-and-forget: on Lambda the environment can freeze as soon
    // as the response is flushed. This row is the §164.312(b) record of how much
    // PHI left the system, which is exactly what an auditor asks for after an
    // incident.
    await writeAuthLogSafe(req, {
      eventType: "worker_job_test_exported",
      userId: serviceKeyId,
      partnerCode: singleProfileMode ? normalizeCode(dietitianId) : null,
      identifier: singleProfileMode
        ? `${profileId}|${dietitianId}|only72:${only72hrs ? 1 : 0}`
        : `cursor:${safeCursor}|limit:${limit}|rows:${data.length}`,
      success: true,
      failureReason: `mode=${
        singleProfileMode ? "single_profile" : "batch_72hrs"
      } exported ${data.length} of ${rows.length} rows`,
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      success: true,
      mode: singleProfileMode ? "single_profile" : "batch_72hrs",
      limit,
      cursor: safeCursor,
      next_cursor: nextCursor,
      // Deliberately the RAW row count, not data.length: filtered-out rows still
      // consumed a page, so `has_more` must reflect the page, not the payload.
      has_more: singleProfileMode ? false : rows.length === limit,
      total_returned: data.length,
      filter,
      data,
    });
  } catch (err) {
    if (err instanceof ApiError) {
      return res.status(err.statusCode).json({
        success: false,
        message: err.message,
        ...(err.extra || {}),
      });
    }

    console.error("FETCH_SINGLE_CLIENT_WORKER_JOB_TEST_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "worker_job_test_error",
      userId: serviceKeyId,
      partnerCode: null,
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

module.exports = { fetchSingleClientWorkerJobTest };
