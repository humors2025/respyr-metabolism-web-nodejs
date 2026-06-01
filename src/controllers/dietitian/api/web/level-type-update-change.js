"use strict";

/**
 * level-type-update-change.js
 *
 * Converted from: level-type-update-change.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/level-type-update-change
 * Auth     : Bearer JWT (authMiddleware must run before this handler)
 *
 * Purpose  : Update table_clients.level_type for one client (dietician_id +
 *            profile_id), returning the old and new level_type.
 *
 * Behaviour parity with the PHP:
 *  - Payload spelling is dietitian_id; DB column remains dietician_id.
 *  - Requires dietitian_id, profile_id, level_type; level_type must be numeric
 *    and is cast to an integer (matches (int)$level_type).
 *  - "Client not found" when no table_clients row matches.
 *  - Same DB table only: table_clients (read for old value + ownership, write
 *    for the new value). app_auth_logs is the house access trail, not new domain
 *    data. Nothing else added or removed.
 *  - Response data echoes dietitian_id, profile_id, old_level_type,
 *    new_level_type. Top-level keys are mapped to the house shape
 *    (status -> ok, message, data) used by the sibling controllers.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. dietitian_id from the body is honoured only after the
 *    JWT proves the caller IS that dietician AND the target profile_id is proven
 *    to belong to that dietician (requireProfileAccess against table_clients).
 *    The PHP trusted the body keys outright, letting any authenticated caller
 *    flip another tenant's client level_type (IDOR).
 *  - All queries parameterized (already true in the PHP — preserved).
 *  - Internal error detail suppressed in production; gated behind APP_DEBUG.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - The access trail (who changed which client's level) is written to
 *    app_auth_logs with IP / user-agent / identifier HMAC-SHA256 hashed using
 *    SECURITY_PEPPER — never stored in clear text. Never throws (fail-safe).
 *  - Server logs carry only error metadata (code/errno/sqlState), never PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const { requireProfileAccess } = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

// ─── ApiError ────────────────────────────────────────────────────────────────

class ApiError extends Error {
  constructor(statusCode, message, extra = {}) {
    super(message);
    this.statusCode = statusCode;
    this.payload = { ok: false, message, ...extra };
  }
}

function fail(statusCode, message, extra = {}) {
  throw new ApiError(statusCode, message, extra);
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNumericValue(value) {
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed !== "" && Number.isFinite(Number(trimmed));
  }
  return false;
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
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined ? authLogHash(identifier) : null;

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
       VALUES (?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
        partnerCode ?? null,
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
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/level-type-update-change
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "dietitian_id": "<code>",          // must match the token dietician
 *     "profile_id":   "<client profile>",// must belong to that dietician
 *     "level_type":   <int|numeric str>  // new level value
 *   }
 */
const levelTypeUpdateChange = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Only POST method is allowed" });
  }

  let auditDietitianId = null;
  let auditProfileId = null;

  try {
    const payload = req.body;

    if (!isPlainObject(payload)) {
      fail(400, "Invalid JSON payload");
    }

    // ── 1. Validate identity / target fields ────────────────────────────────
    // Payload spelling is dietitian_id; DB column remains dietician_id.
    const dietitianId = String(payload.dietitian_id ?? "").trim();
    if (dietitianId === "") {
      fail(400, "dietitian_id is required");
    }

    const profileId = String(payload.profile_id ?? "").trim();
    if (profileId === "") {
      fail(400, "profile_id is required");
    }

    const levelTypeRaw = String(payload.level_type ?? "").trim();
    if (levelTypeRaw === "") {
      fail(400, "level_type is required");
    }
    if (!isNumericValue(levelTypeRaw)) {
      fail(400, "level_type must be numeric");
    }

    // Matches (int)$level_type — truncate toward zero like PHP's int cast.
    const newLevelType = Math.trunc(Number(levelTypeRaw));

    // ── 2. Token-bound authorization (IDOR fix) ─────────────────────────────
    // The JWT must prove the caller IS this dietician, and the target profile
    // must belong to that dietician — verified against table_clients, the same
    // table the PHP filtered on. No extra table introduced.
    const access = await requireProfileAccess(req, dietitianId, profileId);
    if (!access.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "level_type_update_denied",
        userId: String(req.user?.sub || req.user?.dietician?.dietician_id || ""),
        partnerCode: null,
        identifier: profileId,
        success: false,
        failureReason: access.message,
      });
      return res.status(access.statusCode).json({ ok: false, message: access.message });
    }

    auditDietitianId = access.dieticianId;
    auditProfileId = access.profileId;

    // ── 3. Read the current row (old value + existence) ─────────────────────
    const [rows] = await pool.execute(
      `
        SELECT id, dietician_id, profile_id, level_type
        FROM table_clients
        WHERE UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
      `,
      [access.dieticianId, access.profileId]
    );

    const client = rows[0];
    if (!client) {
      fail(404, "Client not found");
    }

    const oldLevelType = Number.parseInt(client.level_type, 10) || 0;

    // ── 4. Persist the new value ────────────────────────────────────────────
    await pool.execute(
      `
        UPDATE table_clients
        SET level_type = ?
        WHERE UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
      `,
      [newLevelType, access.dieticianId, access.profileId]
    );

    // Audit — success (fire-and-forget).
    writeAuthLogSafe(req, {
      eventType: "level_type_update",
      userId: access.dieticianId,
      partnerCode: access.dieticianId,
      identifier: access.profileId,
      success: true,
      failureReason: `level_type ${oldLevelType} -> ${newLevelType}`,
    });

    return res.status(200).json({
      ok: true,
      message: "Level type updated successfully",
      data: {
        dietitian_id: access.dieticianId,
        profile_id: access.profileId,
        old_level_type: oldLevelType,
        new_level_type: newLevelType,
      },
    });
  } catch (err) {
    if (err instanceof ApiError) {
      await writeAuthLogSafe(req, {
        eventType: "level_type_update_failed",
        userId: auditDietitianId || String(req.user?.sub || ""),
        partnerCode: auditDietitianId,
        identifier: auditProfileId,
        success: false,
        failureReason: err.message,
      });
      return res.status(err.statusCode).json(err.payload);
    }

    console.error("LEVEL_TYPE_UPDATE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "level_type_update_error",
      userId: auditDietitianId || String(req.user?.sub || ""),
      partnerCode: auditDietitianId,
      identifier: auditProfileId,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok: false,
      message: "Something went wrong while updating level type",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { levelTypeUpdateChange };
