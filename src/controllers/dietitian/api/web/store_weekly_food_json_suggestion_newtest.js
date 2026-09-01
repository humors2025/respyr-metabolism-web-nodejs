"use strict";

/**
 * store_weekly_food_json_suggestion_newtest.js
 *
 * Cloned from: store_weekly_food_json_suggestion.js — identical logic, but the
 * business table is weekly_food_json_suggestions_newtest instead of
 * weekly_food_json_suggestions. Keep the two files in sync.
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/store_weekly_food_json_suggestion_newtest
 * Auth     : HMAC-signed service key (serviceAuthMiddleware) — NOT a dietitian JWT.
 *
 * Purpose  : Upsert the current week's generated meal plan (food_json + macro
 *            rollups) for one client into weekly_food_json_suggestions_newtest.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  WHY SERVICE-KEY AUTH INSTEAD OF JWT
 * ──────────────────────────────────────────────────────────────────────────
 * This endpoint is driven by a backend plan generator, not by a signed-in
 * dietitian, so there is no JWT to bind identity to and authMiddleware cannot
 * apply. HIPAA §164.312(d) still requires the *entity* to be authenticated
 * before it writes PHI, so the caller proves itself with an HMAC-SHA256
 * signature over a timestamped, single-use-nonced canonical request. See
 * middlewares/serviceAuthMiddleware.js for the scheme.
 *
 * Because there is no actor, the JWT-era authorization model (own code + child
 * trainers + admin-group peers) has no meaning here. It is replaced by two
 * gates that together do the same job:
 *   1. Key scoping     — the service key may only act for the dietician codes
 *                        listed in its SERVICE_API_KEYS entry (minimum necessary).
 *   2. Ownership gate  — (profile_id, dietician_id) MUST be a real pairing in
 *                        table_clients. This is the same ownership gate applied
 *                        to weight-tracking.js, and it is what stops a caller
 *                        from writing a plan onto an arbitrary or cross-tenant
 *                        profile_id. The PHP had no check of any kind: any body
 *                        with any two ids wrote PHI (textbook IDOR).
 * The canonical dietician_id is then taken from the matched table_clients row,
 * not from the body, so stored casing always agrees with the rest of the schema.
 *
 * Behaviour parity with the PHP:
 *  - Week window is IST (the PHP set date_default_timezone_set("Asia/Kolkata")).
 *    week_start_date = the most recent Sunday (today if today IS Sunday),
 *    week_end_date = week_start + 6 days, month_no/year_no from week_start,
 *    source_api_date = today.
 *  - Upsert key: (dietician_id, profile_id, week_start_date, week_end_date).
 *  - status is reset to 0 on BOTH insert and update — so regenerating a plan
 *    un-approves it. That is the PHP's behaviour and is preserved deliberately;
 *    see the note at the status assignment below.
 *  - Macro aliases honoured exactly: cal|calories, cabs|carbs_g, fats|fat_g,
 *    Protein|protein_g, Fibre|fiber_g, plus digestive_score / recovery_score.
 *  - food_json accepted as an object/array OR a JSON string, re-encoded on the
 *    way in. JSON.stringify already matches PHP's JSON_UNESCAPED_UNICODE |
 *    JSON_UNESCAPED_SLASHES (it escapes neither).
 *  - Response keys unchanged: { success, message, id, week_start_date, week_end_date }.
 *  - Same business table only: weekly_food_json_suggestions_newtest. table_clients is
 *    read for the ownership gate and app_auth_logs is written for the access
 *    trail — the same two additions every converted PHI endpoint here makes.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Identity is the signed service key; the body can no longer nominate who is
 *    writing. Body ids are validated against table_clients, never trusted.
 *  - Real HTTP status codes. The PHP echoed every error — including failures —
 *    with HTTP 200, which defeats monitoring and alerting.
 *  - Connection-failure and PDOException messages are no longer returned to the
 *    caller (they leaked DSN, schema and credentials). Gated behind APP_DEBUG;
 *    server logs carry only error metadata (code/errno/sqlState).
 *  - Macro/score inputs are validated as finite, non-negative numbers instead of
 *    being passed through to decimal columns unchecked.
 *  - The read-then-write upsert runs in one transaction with SELECT ... FOR
 *    UPDATE, so two concurrent generations for the same week cannot both miss
 *    the existence check and insert duplicate rows.
 *  - food_json size is capped before it reaches the column.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - Every write and every denial is recorded in app_auth_logs with identifier /
 *    IP / user-agent HMAC-SHA256 hashed using SECURITY_PEPPER — never clear text.
 *    Fail-safe: audit failures never break the request.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * OPTIONAL HARDENING (schema change, not applied here):
 *   ALTER TABLE weekly_food_json_suggestions_newtest
 *     ADD UNIQUE KEY uq_week (dietician_id, profile_id, week_start_date, week_end_date);
 *   That makes the upsert key enforceable by the DB, lets this become a single
 *   INSERT ... ON DUPLICATE KEY UPDATE, and removes reliance on gap locking to
 *   serialise concurrent inserts.
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

// Matches the identifier bounds used across the converted controllers.
const ID_MAX_LENGTH = 100;

// Ceiling on the encoded plan. The global express.json limit is 1mb; this is the
// column-level guard so an oversized plan fails as 413 rather than as a MySQL
// truncation error.
const FOOD_JSON_MAX_CHARS = 512_000;

// Upper bound on macro / score values. Generous enough for any real weekly plan,
// tight enough that a garbage value cannot silently land in a decimal column.
const MAX_NUMERIC_VALUE = 1_000_000;

const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;

// ─── ApiError ────────────────────────────────────────────────────────────────

class ApiError extends Error {
  constructor(statusCode, message) {
    super(message);
    this.statusCode = statusCode;
  }
}

function fail(statusCode, message) {
  throw new ApiError(statusCode, message);
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeCode(value) {
  return String(value ?? "").trim().toUpperCase();
}

/**
 * PHP getValue(): present, not null, not empty string → value, else null.
 * Accepts a list of keys and returns the first that qualifies, which is how the
 * PHP's `cal ?? calories` alias chain behaves.
 *
 * Hardening vs. the PHP: the PHP's fallback leg used a bare isset(), so
 * {"calories": ""} would push an empty string into a decimal column. Here an
 * empty string is uniformly treated as absent.
 */
function pickValue(payload, keys) {
  for (const key of keys) {
    const value = payload[key];
    if (value === undefined || value === null) continue;
    if (typeof value === "string" && value.trim() === "") continue;
    return value;
  }
  return null;
}

/**
 * Validate an optional numeric field. Returns a JS number or null.
 * The PHP passed these straight to the driver; a non-numeric value would reach
 * the column as a string and be silently coerced (or truncated) by MySQL.
 */
function optionalNumber(payload, keys, label) {
  const raw = pickValue(payload, keys);
  if (raw === null) return null;

  if (typeof raw !== "number" && typeof raw !== "string") {
    fail(422, `${label} must be a number`);
  }

  const n = Number(raw);

  if (!Number.isFinite(n)) {
    fail(422, `${label} must be a finite number`);
  }
  if (n < 0) {
    fail(422, `${label} cannot be negative`);
  }
  if (n > MAX_NUMERIC_VALUE) {
    fail(422, `${label} is out of range`);
  }

  return n;
}

function requiredId(payload, key) {
  const raw = payload[key];
  const value = typeof raw === "string" ? raw.trim() : String(raw ?? "").trim();

  if (value === "") {
    fail(422, `${key} and profile_id are required`);
  }
  if (value.length > ID_MAX_LENGTH) {
    fail(422, `${key} is too long`);
  }
  return value;
}

// ─── IST week window (mirrors the PHP's Asia/Kolkata DateTime maths) ─────────

function pad(n) {
  return String(n).padStart(2, "0");
}

/** Format an IST-shifted Date as YYYY-MM-DD. Read with getUTC* — see istNow(). */
function formatIstDate(date) {
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

/**
 * "Now" shifted into IST. The returned Date must be read with getUTC* accessors:
 * those then yield IST wall-clock values regardless of the server's own zone.
 * This is the pattern used by the other IST-preserving controllers.
 */
function istNow() {
  return new Date(Date.now() + IST_OFFSET_MS);
}

/**
 * PHP:
 *   $today = new DateTime();                       // Asia/Kolkata
 *   if ($today->format('w') != 0) $today->modify('last sunday');
 *   $weekStart = clone $today; $weekEnd = $weekStart + 6 days;
 *
 * i.e. the week runs Sunday → Saturday, and on a Sunday the window starts today.
 */
function computeWeekWindow() {
  const now = istNow();

  const weekStart = new Date(now.getTime());
  const dayOfWeek = now.getUTCDay(); // 0 = Sunday, in IST wall-clock terms
  if (dayOfWeek !== 0) {
    weekStart.setUTCDate(weekStart.getUTCDate() - dayOfWeek);
  }

  const weekEnd = new Date(weekStart.getTime());
  weekEnd.setUTCDate(weekEnd.getUTCDate() + 6);

  return {
    week_start_date: formatIstDate(weekStart),
    week_end_date: formatIstDate(weekEnd),
    month_no: weekStart.getUTCMonth() + 1,
    year_no: weekStart.getUTCFullYear(),
    // PHP used date('Y-m-d') — today, not the week start.
    source_api_date: formatIstDate(now),
  };
}

// ─── food_json ───────────────────────────────────────────────────────────────

/**
 * Accept food_json as an object/array (already parsed by express.json) or as a
 * JSON string, and return the canonical encoded text to store.
 *
 * Hardening vs. the PHP: the PHP's string branch accepted any valid JSON,
 * including scalars — json_decode("5") succeeds, so "5" could be stored as a
 * whole meal plan. A plan is a structure; scalars are rejected here.
 */
function encodeFoodJson(payload) {
  if (!Object.prototype.hasOwnProperty.call(payload, "food_json")) {
    fail(422, "food_json is required");
  }

  const input = payload.food_json;
  let decoded;

  if (isPlainObject(input) || Array.isArray(input)) {
    decoded = input;
  } else if (typeof input === "string") {
    const text = input.trim();
    if (text === "") {
      fail(422, "food_json is required");
    }
    try {
      decoded = JSON.parse(text);
    } catch (err) {
      fail(422, "food_json is not valid JSON");
    }
    if (!isPlainObject(decoded) && !Array.isArray(decoded)) {
      fail(422, "food_json must decode to an object or array");
    }
  } else {
    fail(422, "food_json must be an object, an array, or a JSON string");
  }

  let encoded;
  try {
    // JSON.stringify escapes neither slashes nor non-ASCII, matching the PHP's
    // JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE.
    encoded = JSON.stringify(decoded);
  } catch (err) {
    // Circular structures cannot arrive via express.json, but BigInt can't encode.
    fail(422, "Failed to encode food_json");
  }

  if (encoded === undefined) {
    fail(422, "Failed to encode food_json");
  }
  if (encoded.length > FOOD_JSON_MAX_CHARS) {
    fail(413, "food_json is too large");
  }

  return encoded;
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

async function writeAuthLogSafe(req, {
  eventType,
  userId,
  partnerCode,
  identifier,
  success,
  failureReason,
}) {
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
        partnerCode ?? null,
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
    console.error("STORE_WEEKLY_FOOD_JSON_NEWTEST_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Ownership gate ──────────────────────────────────────────────────────────

/**
 * Confirm (profile_id, dietician_id) is a real client pairing and return the
 * dietician_id EXACTLY as stored, so the row we write agrees with the schema's
 * casing rather than with whatever the caller sent.
 */
async function resolveClientPair(profileId, dieticianId) {
  const [rows] = await pool.execute(
    `
      SELECT dietician_id
      FROM table_clients
      WHERE profile_id = ?
        AND UPPER(TRIM(dietician_id)) = ?
      LIMIT 1
    `,
    [profileId, normalizeCode(dieticianId)]
  );

  return rows.length > 0 ? String(rows[0].dietician_id) : null;
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/store_weekly_food_json_suggestion_newtest
 *
 * Headers (see serviceAuthMiddleware.js):
 *   x-respyr-key-id, x-respyr-timestamp, x-respyr-nonce, x-respyr-signature
 *   Content-Type: application/json
 *
 * Body:
 *   {
 *     "dietitian_id": "RESPYRD05",     // required; must own the profile
 *     "profile_id":   "PRF10023",      // required
 *     "food_json":    { ... },         // required; object/array or JSON string
 *     "cal": 1850,        // or "calories"
 *     "cabs": 210,        // or "carbs_g"
 *     "fats": 60,         // or "fat_g"
 *     "Protein": 120,     // or "protein_g"
 *     "Fibre": 30,        // or "fiber_g"
 *     "digestive_score": 72,
 *     "recovery_score": 68
 *   }
 */
const storeWeeklyFoodJsonSuggestionNewtest = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate.
  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      message: "Only POST method is allowed",
    });
  }

  let connection = null;
  let auditDieticianId = null;
  let auditProfileId = null;

  const serviceKeyId = req.serviceClient?.keyId || null;

  try {
    const payload = req.body;

    if (!isPlainObject(payload)) {
      fail(400, "Invalid JSON input");
    }

    // ── 1. Validate inputs ──────────────────────────────────────────────────
    // Payload spelling is dietitian_id; the DB column is dietician_id.
    const dietitianId = requiredId(payload, "dietitian_id");
    const profileId = requiredId(payload, "profile_id");

    auditProfileId = profileId;

    const foodJson = encodeFoodJson(payload);

    const cal = optionalNumber(payload, ["cal", "calories"], "cal");
    const cabs = optionalNumber(payload, ["cabs", "carbs_g"], "cabs");
    const fats = optionalNumber(payload, ["fats", "fat_g"], "fats");
    const protein = optionalNumber(payload, ["Protein", "protein_g"], "Protein");
    const fibre = optionalNumber(payload, ["Fibre", "fiber_g"], "Fibre");
    const digestiveScore = optionalNumber(payload, ["digestive_score"], "digestive_score");
    const recoveryScore = optionalNumber(payload, ["recovery_score"], "recovery_score");

    // ── 2. Key scoping (minimum necessary) ──────────────────────────────────
    if (!serviceKeyCanUseDieticianCode(req.serviceClient, dietitianId)) {
      await writeAuthLogSafe(req, {
        eventType: "weekly_plan_store_denied",
        userId: serviceKeyId,
        partnerCode: normalizeCode(dietitianId),
        identifier: `${profileId}|${dietitianId}`,
        success: false,
        failureReason: "service key not scoped to this dietician_id",
      });
      return res.status(403).json({
        success: false,
        message: "This service key is not permitted to write plans for this dietitian",
      });
    }

    // ── 3. Ownership gate (IDOR fix — the PHP had no check at all) ──────────
    const canonicalDieticianId = await resolveClientPair(profileId, dietitianId);

    if (canonicalDieticianId === null) {
      await writeAuthLogSafe(req, {
        eventType: "weekly_plan_store_denied",
        userId: serviceKeyId,
        partnerCode: normalizeCode(dietitianId),
        identifier: `${profileId}|${dietitianId}`,
        success: false,
        failureReason: "client not found for dietitian",
      });
      // 404 rather than 403: the pairing does not exist, and the caller is a
      // trusted service, so there is no enumeration signal to protect here.
      return res.status(404).json({
        success: false,
        message: "Client not found for this dietitian",
      });
    }

    auditDieticianId = normalizeCode(canonicalDieticianId);

    // ── 4. Week window (IST) ────────────────────────────────────────────────
    const week = computeWeekWindow();

    // The PHP resets status to 0 on insert AND on update, so regenerating a plan
    // silently un-approves a plan the dietitian had already approved. Preserved
    // for behavioural parity — flag it if that is not the intent, because it is a
    // data-integrity question rather than a security one.
    const status = 0;

    // ── 5. Transaction: lock the week row, then upsert ──────────────────────
    connection = await pool.getConnection();
    await connection.beginTransaction();

    // Deliberately NO `SET time_zone = '+05:30'` here. The PHP's
    // date_default_timezone_set("Asia/Kolkata") only affected PHP-side date maths,
    // never its MySQL session — and every IST-derived value above is computed in
    // JS and bound as a literal string, so the session zone cannot affect it.
    // The only thing pinning the zone WOULD change is `updated_at = NOW()`, and
    // trainer-update-weekly-food-json.js writes that same column on this same
    // table at the server zone. Pinning it here would put two different
    // wall-clocks in one column.

    const [existingRows] = await connection.execute(
      `
        SELECT id
        FROM weekly_food_json_suggestions_newtest
        WHERE UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
          AND week_start_date = ?
          AND week_end_date = ?
        LIMIT 1
        FOR UPDATE
      `,
      [auditDieticianId, profileId, week.week_start_date, week.week_end_date]
    );

    const existing = existingRows[0];

    if (existing) {
      await connection.execute(
        `
          UPDATE weekly_food_json_suggestions_newtest
          SET
            month_no = ?,
            year_no = ?,
            food_json = ?,
            source_api_date = ?,
            status = ?,
            cal = ?,
            cabs = ?,
            fats = ?,
            \`Protein\` = ?,
            \`Fibre\` = ?,
            digestive_score = ?,
            recovery_score = ?,
            updated_at = NOW()
          WHERE id = ?
          LIMIT 1
        `,
        [
          week.month_no,
          week.year_no,
          foodJson,
          week.source_api_date,
          status,
          cal,
          cabs,
          fats,
          protein,
          fibre,
          digestiveScore,
          recoveryScore,
          existing.id,
        ]
      );

      await connection.commit();

      // Awaited, not fire-and-forget: on Lambda the environment can freeze as soon
      // as the response is flushed, so a detached INSERT may never run — and this
      // row IS the §164.312(b) record that this PHI write happened.
      await writeAuthLogSafe(req, {
        eventType: "weekly_plan_updated",
        userId: serviceKeyId,
        partnerCode: auditDieticianId,
        identifier: `${profileId}|${auditDieticianId}|${week.week_start_date}`,
        success: true,
        failureReason: "Weekly plan updated",
      });

      return res.status(200).json({
        success: true,
        message: "Weekly plan updated successfully",
        id: Number(existing.id),
        week_start_date: week.week_start_date,
        week_end_date: week.week_end_date,
      });
    }

    const [insertResult] = await connection.execute(
      `
        INSERT INTO weekly_food_json_suggestions_newtest
        (
          dietician_id,
          profile_id,
          week_start_date,
          week_end_date,
          month_no,
          year_no,
          food_json,
          source_api_date,
          status,
          cal,
          cabs,
          fats,
          \`Protein\`,
          \`Fibre\`,
          digestive_score,
          recovery_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        canonicalDieticianId,
        profileId,
        week.week_start_date,
        week.week_end_date,
        week.month_no,
        week.year_no,
        foodJson,
        week.source_api_date,
        status,
        cal,
        cabs,
        fats,
        protein,
        fibre,
        digestiveScore,
        recoveryScore,
      ]
    );

    await connection.commit();

    // Awaited for the same reason as the update path above.
    await writeAuthLogSafe(req, {
      eventType: "weekly_plan_stored",
      userId: serviceKeyId,
      partnerCode: auditDieticianId,
      identifier: `${profileId}|${auditDieticianId}|${week.week_start_date}`,
      success: true,
      failureReason: "Weekly plan stored",
    });

    return res.status(201).json({
      success: true,
      message: "Weekly plan stored successfully",
      id: Number(insertResult.insertId),
      week_start_date: week.week_start_date,
      week_end_date: week.week_end_date,
    });
  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackErr) {
        console.error(
          "STORE_WEEKLY_FOOD_JSON_NEWTEST_ROLLBACK_FAILED:",
          rollbackErr?.code || rollbackErr?.message
        );
      }
    }

    if (err instanceof ApiError) {
      await writeAuthLogSafe(req, {
        eventType: "weekly_plan_store_rejected",
        userId: serviceKeyId,
        partnerCode: auditDieticianId,
        identifier: auditProfileId,
        success: false,
        failureReason: err.message,
      });
      return res.status(err.statusCode).json({
        success: false,
        message: err.message,
      });
    }

    console.error("STORE_WEEKLY_FOOD_JSON_NEWTEST_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "weekly_plan_store_error",
      userId: serviceKeyId,
      partnerCode: auditDieticianId,
      identifier: auditProfileId,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      success: false,
      message: "Failed to store weekly plan",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  } finally {
    if (connection) connection.release();
  }
};

module.exports = { storeWeeklyFoodJsonSuggestionNewtest };
