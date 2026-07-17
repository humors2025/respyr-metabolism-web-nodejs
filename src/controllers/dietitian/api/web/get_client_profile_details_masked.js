"use strict";

/**
 * get_client_profile_details_masked.js
 *
 * Masked variant of: get_client_profile_details.js
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/get_client_profile_details_masked
 * Auth     : Bearer JWT (authMiddleware runs before this handler)
 *
 * Difference vs. get_client_profile_details:
 *  - client_name and email are MASKED before they leave the server:
 *      "Emilio Aguilar"          → "Emxxxo Agxxxxr"
 *      "emilioaguilar10@yahoo.com" → "emxxxxxxxxxxxx0@yahoo.com"
 *  - dob / age / region / location are the constant literal "hidden". They are
 *    re-identifying, so their columns are NOT selected from the DB at all —
 *    the value never enters the process rather than being fetched and dropped.
 *    `dob` has no counterpart in the unmasked endpoint; it exists here purely
 *    as a "hidden" placeholder so the masked shape is self-describing.
 *  - Every remaining key keeps the unmasked endpoint's name and ordering.
 *  - The read is audited under its own event type (client_profile_masked_read).
 *  - A `privacy` block sits alongside `data` (NOT inside it) declaring what was
 *    masked; keeping it out of `data` avoids disturbing the payload shape.
 *
 * Masking rules (maskToken — shared with the sibling masked controllers, so the
 * output is consistent across every masked endpoint):
 *    len <= 1 → "x"
 *    len <= 2 → first char + "x"
 *    len <= 4 → first 2 chars + "x" per remaining char
 *    else     → first 2 chars + max(3, len-3) "x" + last char
 *  - Names: applied per whitespace-separated token; blank/"NA" → "Client".
 *  - Emails: applied to the local part only; the domain is kept in clear so the
 *    dietitian can still recognise the provider. Blank / "NA" / no "@" → "NA".
 *    Masking is one-way: no length-preserving reversal, no partial local part
 *    beyond the 2-char prefix and 1-char suffix the sibling endpoints expose.
 *
 * All VAPT + HIPAA controls from the unmasked controller are retained verbatim:
 *  - Token-bound identity; dietitian_id REQUIRED and cross-checked against the
 *    JWT; profile must belong to that dietitian (requireProfileAccess). The read
 *    query is additionally scoped to the authorized dietitian (defense-in-depth).
 *  - Fully parameterized queries; POST-only gate; strict input validation.
 *  - Internal error details suppressed in production; logs carry no PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Every read (grant or denial) written to app_auth_logs with identifier / IP /
 *    user-agent HMAC-SHA256 hashed under SECURITY_PEPPER. Fail-safe writer.
 *
 * NOTE: No DB tables are added vs. the unmasked controller — same table_clients
 * and user_habits, plus app_auth_logs as the shared audit sink.
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

// Points at the Node get_profile_image route on the API host (NOT the
// admin.respyr.ai dashboard, which is a separate Next.js app and 404s here).
// Override per-environment. NOTE: that route is behind authMiddleware and needs
// both profile_id and dietician_id query params — see p_image construction below.
const PROFILE_IMAGE_BASE_URL =
  process.env.PROFILE_IMAGE_BASE_URL ||
  "https://api.respyr.ai/v1/dietitian/api/web/get_profile_image";

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
 * On any decode failure, fall back to an empty object.
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
   Masking (identical rules to the sibling masked controllers)
================================ */

function maskToken(part) {
  const len = part.length;
  if (len <= 1) return "x";
  if (len <= 2) return part.slice(0, 1) + "x";
  if (len <= 4) return part.slice(0, 2) + "x".repeat(len - 2);
  return part.slice(0, 2) + "x".repeat(Math.max(3, len - 3)) + part.slice(-1);
}

/** "Emilio Aguilar" → "Emxxxo Agxxxxr". Blank / "NA" → "Client". */
function maskName(name) {
  const trimmed = String(name ?? "").trim();
  if (trimmed === "" || trimmed.toUpperCase() === "NA") return "Client";
  return trimmed.split(/\s+/).map(maskToken).join(" ");
}

/** "emilioaguilar10@yahoo.com" → "emxxxxxxxxxxxx0@yahoo.com". Domain kept. */
function maskEmail(email) {
  const normalized = String(email ?? "").trim().toLowerCase();

  if (
    normalized === "" ||
    normalized.toUpperCase() === "NA" ||
    !normalized.includes("@")
  ) {
    return "NA";
  }

  const atIdx = normalized.indexOf("@");
  const local = normalized.slice(0, atIdx);
  const domain = normalized.slice(atIdx + 1);

  return maskToken(local) + "@" + domain;
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
    console.error(
      "CLIENT_PROFILE_MASKED_AUDIT_FAILED:",
      err?.code || err?.message
    );
  }
};

/* ===============================
   Controller
================================ */

const get_client_profile_details_masked = async (req, res) => {
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

  // Identity is bound to the JWT; the body value is only cross-checked, never
  // trusted. dietitian_id is REQUIRED (leaving it optional would be an IDOR).
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
        eventType: "client_profile_masked_denied",
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
     * table_clients LEFT JOIN user_habits (latest habit row by u.id DESC),
     * scoped to the authorized dietitian. Minimum-necessary columns only.
     */
    const sql = `
      SELECT
        c.dietician_id,
        c.profile_id,
        c.profile_name,
        c.phone_no,
        c.email,
        c.gender,
        c.height,
        c.weight,
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
        eventType: "client_profile_masked_read",
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

    // Key ordering matches the unmasked endpoint; `dob` is additional (the
    // unmasked endpoint has no such key) and is always the literal "hidden".
    const data = {
      dietician_id: naIfNull(row.dietician_id),
      profile_id: naIfNull(row.profile_id),
      client_name: maskName(row.profile_name),
      phone_no: naIfNull(row.phone_no),
      email: maskEmail(row.email),

      // Constant "hidden" — these are re-identifying, so the columns are not
      // selected at all above rather than fetched and then discarded.
      dob: "hidden",
      age: "hidden",

      gender: naIfNull(row.gender),
      height: naIfNull(row.height),
      weight: naIfNull(row.weight),

      region: "hidden",
      location: "hidden",

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
          )}&dietician_id=${encodeURIComponent(dietitianId)}`
        : "NA",
    };

    await writeAuthLogSafe(req, {
      eventType: "client_profile_masked_read",
      userId: dietitianId,
      identifier: auditIdentifier,
      success: true,
      failureReason: null,
    });

    return res.status(200).json({
      status: true,
      message: "Client profile fetched successfully",
      privacy: {
        client_identity_masked: true,
        raw_name_returned: false,
        raw_email_returned: false,
        dob_returned: false,
        age_returned: false,
        location_returned: false,
        audit_logged: true,
      },
      data,
    });
  } catch (error) {
    console.error("get_client_profile_details_masked error:", {
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
  get_client_profile_details_masked,
};
