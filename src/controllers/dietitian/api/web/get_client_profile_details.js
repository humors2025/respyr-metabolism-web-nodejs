"use strict";

/**
 * get_client_profile_details.js
 *
 * Converted from: get_client_profile_details.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/get_client_profile_details
 * Auth     : Bearer JWT (authMiddleware runs before this handler)
 *
 * Behaviour parity with the PHP:
 *  - Reads one client's profile from table_clients LEFT JOIN user_habits
 *    (latest habit row by u.id DESC), keyed by profile_id.
 *  - Decodes user_habits.food_type JSON into diet_type / primary_cuisine /
 *    secondary_cuisine (both nested under dietary_preferences and flattened
 *    at the top level, exactly as the PHP).
 *  - fitness_goal_display = ucwords(str_replace("_", " ", fitness_goal)).
 *  - level_type defaults to "1" when absent; activity_level / fitness_goal
 *    fall back to "NA" when empty.
 *  - Same { status, message, data } envelope and the same data keys/ordering
 *    as the PHP sendResponse() success body.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The PHP treated dietitian_id as OPTIONAL, so any
 *    authenticated caller could read ANY profile_id's PHI — an IDOR/BOLA hole.
 *    Here the actor dietitian comes from the verified JWT (sub = dietician_id),
 *    dietitian_id is REQUIRED and must equal the token dietitian, and the
 *    profile must belong to that dietitian (requireProfileAccess against
 *    table_clients). The read query is additionally scoped to the authorized
 *    dietitian as defense-in-depth.
 *  - Fully parameterized queries (? placeholders); zero string interpolation.
 *  - POST-only method gate; strict body / id validation before any DB call.
 *  - Internal error details are suppressed in production; server logs carry
 *    only error metadata, never row data or PHI. (The PHP leaked DB messages.)
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - p_image is built from an env-configurable base (PROFILE_IMAGE_BASE_URL);
 *    profile_id is URL-encoded. Defaults to the legacy URL for parity.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns only (no SELECT *).
 *  - Every read (grant or denial) is recorded in app_auth_logs. PHI in the
 *    audit trail (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - The audit writer is fail-safe: a failure never breaks the request and
 *    never leaks to the client.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_clients and
 * user_habits. table_clients is also read by requireProfileAccess for the
 * ownership check. app_auth_logs is the shared audit sink for these controllers.
 *
 * NOTE on dietitian/dietician spelling: the DB column is the legacy
 * `dietician_id`; accessControl.js accepts both spellings from body/JWT.
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

// Legacy default preserves PHP behaviour; override per-environment.
const PROFILE_IMAGE_BASE_URL =
  process.env.PROFILE_IMAGE_BASE_URL ||
  "https://humorstech.com/dietitian/api/web/get_profile_image.php";

/* ===============================
   Helpers
================================ */

/** PHP `$x ?? "NA"` — null/undefined become "NA"; empty string is preserved. */
function naIfNull(value) {
  return value === null || value === undefined ? "NA" : value;
}

/** PHP `!empty($x) ? $x : "NA"` — "", "0", 0, false, null, undefined → "NA". */
function naIfEmpty(value) {
  if (
    value === null ||
    value === undefined ||
    value === false ||
    value === "" ||
    value === 0 ||
    value === "0"
  ) {
    return "NA";
  }
  return value;
}

/** PHP `ucwords(str_replace("_", " ", $s))`. */
function ucwordsFromSnake(value) {
  return String(value)
    .replace(/_/g, " ")
    .replace(/(^|\s)([a-z])/g, (_m, lead, ch) => lead + ch.toUpperCase());
}

/**
 * Decode user_habits.food_type into an object. mysql2 may return the column as
 * a string, a Buffer, or (if the column is JSON-typed) an already-parsed object.
 * Mirrors the PHP: on any decode failure, fall back to an empty object.
 */
function parseFoodType(raw) {
  try {
    if (raw === null || raw === undefined || raw === "") return {};

    if (Buffer.isBuffer(raw)) raw = raw.toString("utf8");

    if (typeof raw === "object") {
      return Array.isArray(raw) ? {} : raw;
    }

    if (typeof raw !== "string") return {};

    const decoded = JSON.parse(raw);

    return decoded && typeof decoded === "object" && !Array.isArray(decoded)
      ? decoded
      : {};
  } catch (_err) {
    return {};
  }
}

/* ===============================
   Audit log (HIPAA accountability)
================================ */

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
    console.error("CLIENT_PROFILE_AUDIT_FAILED:", err?.code || err?.message);
  }
};

/* ===============================
   Controller
================================ */

const get_client_profile_details = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate.
  if (req.method !== "POST") {
    return res
      .status(405)
      .json({ status: false, message: "Only POST method allowed", data: null });
  }

  const body = req.body || {};

  if (typeof body !== "object" || Array.isArray(body)) {
    return res
      .status(400)
      .json({ status: false, message: "Invalid request body", data: null });
  }

  // dietitian_id is REQUIRED here (the PHP left it optional → IDOR). Identity is
  // bound to the JWT; the body value is only cross-checked, never trusted.
  const rawDietitianId = body.dietitian_id ?? body.dietician_id;
  const profile_id = normalizeId(body.profile_id);
  const requestedDietitianId = normalizeDieticianId(rawDietitianId);

  if (!body.profile_id) {
    return res
      .status(422)
      .json({ status: false, message: "profile_id is required", data: null });
  }

  if (!profile_id) {
    return res
      .status(400)
      .json({ status: false, message: "Invalid profile_id", data: null });
  }

  if (!rawDietitianId) {
    return res
      .status(422)
      .json({ status: false, message: "dietitian_id is required", data: null });
  }

  if (!requestedDietitianId) {
    return res
      .status(400)
      .json({ status: false, message: "Invalid dietitian_id", data: null });
  }

  // Hashed before storage by writeAuthLogSafe — never persisted in clear text.
  const auditIdentifier = `${profile_id}|${requestedDietitianId}`;

  try {
    /**
     * VAPT / object-level authorization:
     *  1. JWT dietician id must match the requested dietitian_id
     *  2. profile_id must belong to this dietitian in table_clients
     * Blocks IDOR — a dietitian cannot read another dietitian's client PHI.
     */
    const access = await requireProfileAccess(
      req,
      requestedDietitianId,
      profile_id
    );

    if (!access.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "client_profile_access_denied",
        userId: requestedDietitianId,
        identifier: auditIdentifier,
        success: false,
        failureReason: access.message || "access denied",
      });

      return res.status(access.statusCode || 403).json({
        status: false,
        message: access.message || "Access denied",
        data: null,
      });
    }

    const dietitianId = access.dieticianId;
    const authorizedProfileId = access.profileId;

    /**
     * Same shape as the PHP (table_clients LEFT JOIN user_habits, latest habit
     * row by u.id DESC), additionally scoped to the authorized dietitian.
     */
    const sql = `
      SELECT
        c.dietician_id,
        c.profile_id,
        c.profile_name,
        c.phone_no,
        c.email,
        c.age,
        c.gender,
        c.height,
        c.weight,
        c.region,
        c.location,
        c.level_type,
        u.goal,
        u.activity,
        u.food_type
      FROM table_clients c
      LEFT JOIN user_habits u
        ON c.profile_id = u.profile_id
      WHERE c.profile_id = ?
        AND UPPER(TRIM(c.dietician_id)) = ?
      ORDER BY u.id DESC
      LIMIT 1
    `;

    const [rows] = await pool.execute(sql, [authorizedProfileId, dietitianId]);

    const row = rows[0];

    if (!row) {
      await writeAuthLogSafe(req, {
        eventType: "client_profile_read",
        userId: dietitianId,
        identifier: auditIdentifier,
        success: false,
        failureReason: "Client not found",
      });

      return res
        .status(404)
        .json({ status: false, message: "Client not found", data: null });
    }

    const foodTypeData = parseFoodType(row.food_type);

    const fitnessGoal = naIfEmpty(row.goal);

    const dietType = naIfNull(foodTypeData.diet_type);
    const primaryCuisine = naIfNull(foodTypeData.primary_cuisine);
    const secondaryCuisine = naIfNull(foodTypeData.secondary_cuisine);

    const data = {
      dietician_id: naIfNull(row.dietician_id),
      profile_id: naIfNull(row.profile_id),
      client_name: naIfNull(row.profile_name),
      phone_no: naIfNull(row.phone_no),
      email: naIfNull(row.email),

      age: naIfNull(row.age),
      gender: naIfNull(row.gender),
      height: naIfNull(row.height),
      weight: naIfNull(row.weight),
      region: naIfNull(row.region),
      location: naIfNull(row.location),

      fitness_goal: fitnessGoal,
      fitness_goal_display:
        fitnessGoal === "NA" ? "NA" : ucwordsFromSnake(fitnessGoal),

      level_type:
        row.level_type === null || row.level_type === undefined
          ? "1"
          : String(row.level_type),

      activity_level: naIfEmpty(row.activity),

      dietary_preferences: {
        diet_type: dietType,
        primary_cuisine: primaryCuisine,
        secondary_cuisine: secondaryCuisine,
      },

      diet_type: dietType,
      primary_cuisine: primaryCuisine,
      secondary_cuisine: secondaryCuisine,

      p_image: row.profile_id
        ? `${PROFILE_IMAGE_BASE_URL}?profile_id=${encodeURIComponent(
            row.profile_id
          )}`
        : "NA",
    };

    await writeAuthLogSafe(req, {
      eventType: "client_profile_read",
      userId: dietitianId,
      identifier: auditIdentifier,
      success: true,
      failureReason: null,
    });

    return res.status(200).json({
      status: true,
      message: "Client profile fetched successfully",
      data,
    });
  } catch (error) {
    console.error("get_client_profile_details error:", {
      message: error.message,
      code: error.code,
      stack: isProduction ? undefined : error.stack,
    });

    return res
      .status(500)
      .json({ status: false, message: "Internal server error", data: null });
  }
};

module.exports = {
  get_client_profile_details,
};
