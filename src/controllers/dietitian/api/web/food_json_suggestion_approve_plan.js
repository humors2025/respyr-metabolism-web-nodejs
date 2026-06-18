"use strict";

/**
 * food_json_suggestion_approve_plan.js
 *
 * Converted from: food_json_suggestion_approve_plan.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/food_json_suggestion_approve_plan
 * Auth     : Bearer JWT (authMiddleware must run before this handler)
 *
 * Purpose  : Approve (status=1) / un-approve (status=0) a weekly food plan row
 *            in weekly_food_json_suggestions.
 *
 * Behaviour parity with the PHP:
 *  - POST only.
 *  - Body: { id, dietician_id, profile_id, status }  (payload spelling is
 *    dietician_id; DB column is also dietician_id).
 *  - Validates: id positive integer; status ∈ {0,1}; dietician_id / profile_id
 *    present and ≤ 100 chars.
 *  - Verifies the row exists for (id, dietician_id, profile_id) → 404 if not.
 *  - Short-circuits with "already approved/unapproved" (changed:false) when the
 *    stored status already equals the requested status.
 *  - Otherwise updates status + updated_at, returns previous/new status and
 *    rows_affected (changed:true).
 *  - Response envelope matches the PHP exactly:
 *      { status: "success"|"error", code, message, data?: {...} }
 *  - Same DB table only: weekly_food_json_suggestions (read+write), plus the
 *    house audit table app_auth_logs for the access trail. Nothing else added.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. The dietician_id from the body is only honoured once
 *    the JWT proves the caller IS that dietician (requireDieticianSelfAccess).
 *    Object-level ownership of the target row is enforced by the WHERE filter
 *    (dietician_id + profile_id), exactly as the PHP did — no extra table. The
 *    PHP trusted the body keys outright, so any authenticated caller could flip
 *    another tenant's plan status (IDOR).
 *  - Read + update run inside one transaction with SELECT ... FOR UPDATE so two
 *    concurrent approve/un-approve calls on the same row can't race.
 *  - All queries are parameterized (already true in the PHP — preserved).
 *  - Internal error detail is suppressed in production; gated behind APP_DEBUG.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - The access trail (who flipped which plan) is written to app_auth_logs with
 *    IP / user-agent / identifier HMAC-SHA256 hashed using SECURITY_PEPPER —
 *    never stored in clear text. Never throws (fail-safe).
 *  - Server logs carry only error metadata (code/errno/sqlState), never PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  requireDieticianSelfAccess,
  normalizeId,
} = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

// ─── Response helper (mirrors the PHP respond()) ─────────────────────────────

/**
 * Standardised JSON response, identical shape to the PHP:
 *   { status, code, message, data? }
 * `code` defaults to the HTTP status unless an explicit errorCode is given.
 */
function respond(res, httpCode, status, message, data = null, errorCode = null) {
  const payload = {
    status,
    code: errorCode || httpCode,
    message,
  };
  if (data !== null) {
    payload.data = data;
  }
  return res.status(httpCode).json(payload);
}

// ─── ApiError (carries the PHP-shaped envelope) ──────────────────────────────

class ApiError extends Error {
  constructor(httpCode, message, errorCode = null) {
    super(message);
    this.httpCode = httpCode;
    this.errorCode = errorCode;
  }
}

function fail(httpCode, message, errorCode = null) {
  throw new ApiError(httpCode, message, errorCode);
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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
 * POST /dietitian/api/web/food_json_suggestion_approve_plan
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "id": <int>,                 // weekly_food_json_suggestions.id
 *     "dietician_id": "<code>",    // must match the token dietician
 *     "profile_id": "<client>",    // must own the target row
 *     "status": 0 | 1              // 0 = un-approve, 1 = approve
 *   }
 */
const foodJsonSuggestionApprovePlan = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return respond(res, 405, "error", "Only POST method is allowed");
  }

  let connection = null;
  let auditDietitianId = null;
  let auditProfileId = null;

  try {
    const payload = req.body;

    if (!isPlainObject(payload)) {
      fail(400, "JSON body must be an object");
    }

    // ── 1. Extract + validate required fields ───────────────────────────────
    // Payload spelling is dietician_id (DB column is also dietician_id); accept
    // dietitian_id as a tolerant alias for front-end back-compat.
    const idRaw = payload.id === undefined || payload.id === null ? "" : String(payload.id).trim();
    const dieticianIdRaw = String(payload.dietician_id ?? payload.dietitian_id ?? "").trim();
    const profileIdRaw = String(payload.profile_id ?? "").trim();
    const statusParam = Object.prototype.hasOwnProperty.call(payload, "status")
      ? payload.status
      : null;

    const missing = [];
    if (idRaw === "") missing.push("id");
    if (dieticianIdRaw === "") missing.push("dietician_id");
    if (profileIdRaw === "") missing.push("profile_id");
    if (statusParam === null || statusParam === "") missing.push("status");

    if (missing.length > 0) {
      fail(400, "Missing required field(s): " + missing.join(", "));
    }

    // id must be a positive integer.
    if (!/^\d+$/.test(idRaw) || Number.parseInt(idRaw, 10) <= 0) {
      fail(400, "id must be a positive integer");
    }

    // status must be 0 or 1.
    const statusNum = Number(statusParam);
    if (!Number.isFinite(statusNum) || ![0, 1].includes(statusNum)) {
      fail(400, "status must be 0 (not approved) or 1 (approved)");
    }

    // Length guards (avoid abuse / accidental huge strings) — PHP used 100.
    if (dieticianIdRaw.length > 100) {
      fail(400, "dietician_id is too long (max 100 chars)");
    }
    if (profileIdRaw.length > 100) {
      fail(400, "profile_id is too long (max 100 chars)");
    }

    const idInt = Number.parseInt(idRaw, 10);
    const newStatus = statusNum;

    // ── 2. Token-bound authorization (IDOR fix) ─────────────────────────────
    // The JWT must prove the caller IS this dietician. Object-level ownership of
    // the target row is then enforced by the WHERE filter below
    // (dietician_id + profile_id), exactly as the PHP did — no extra table.
    const self = requireDieticianSelfAccess(req, dieticianIdRaw);
    if (!self.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "approve_plan_denied",
        userId: String(req.user?.sub || req.user?.dietician?.dietician_id || ""),
        partnerCode: null,
        identifier: profileIdRaw,
        success: false,
        failureReason: self.message,
      });
      return respond(res, self.statusCode, "error", self.message);
    }

    const normalizedProfileId = normalizeId(profileIdRaw);
    if (!normalizedProfileId) {
      fail(400, "Invalid profile_id");
    }

    const dieticianId = self.dieticianId;
    const profileId = normalizedProfileId;

    auditDietitianId = dieticianId;
    auditProfileId = profileId;

    const actionLabel = newStatus === 1 ? "approved" : "unapproved";

    // ── 3. Transaction: lock the row, verify, update ────────────────────────
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [rows] = await connection.execute(
      `
        SELECT id, status
        FROM weekly_food_json_suggestions
        WHERE id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [idInt, dieticianId, profileId]
    );

    const row = rows[0];

    if (!row) {
      await connection.rollback();
      await writeAuthLogSafe(req, {
        eventType: "approve_plan_not_found",
        userId: dieticianId,
        partnerCode: dieticianId,
        identifier: profileId,
        success: false,
        failureReason: "no matching record",
      });
      return respond(
        res,
        404,
        "error",
        "No matching record found for the given id, dietician_id and profile_id"
      );
    }

    const currentStatus = Number(row.status);

    // ── 4. Short-circuit if already in the requested state ──────────────────
    if (currentStatus === newStatus) {
      await connection.commit();
      return respond(res, 200, "success", `Plan is already ${actionLabel}`, {
        id: idInt,
        dietician_id: dieticianId,
        profile_id: profileId,
        previous_status: currentStatus,
        new_status: newStatus,
        changed: false,
      });
    }

    // ── 5. Perform the update ───────────────────────────────────────────────
    const [updateResult] = await connection.execute(
      `
        UPDATE weekly_food_json_suggestions
        SET status = ?, updated_at = NOW()
        WHERE id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
      `,
      [newStatus, idInt, dieticianId, profileId]
    );

    const rowsAffected = updateResult.affectedRows || 0;

    if (rowsAffected <= 0) {
      await connection.rollback();
      return respond(
        res,
        409,
        "error",
        "Update did not affect any row. The record may have been modified or removed."
      );
    }

    await connection.commit();

    // Audit — success (fire-and-forget).
    writeAuthLogSafe(req, {
      eventType: `approve_plan_${actionLabel}`,
      userId: dieticianId,
      partnerCode: dieticianId,
      identifier: profileId,
      success: true,
      failureReason: `Plan ${actionLabel} successfully`,
    });

    return respond(res, 200, "success", `Plan ${actionLabel} successfully`, {
      id: idInt,
      dietician_id: dieticianId,
      profile_id: profileId,
      previous_status: currentStatus,
      new_status: newStatus,
      rows_affected: rowsAffected,
      changed: true,
    });
  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackErr) {
        console.error(
          "APPROVE_PLAN_ROLLBACK_FAILED:",
          rollbackErr?.code || rollbackErr?.message
        );
      }
    }

    if (err instanceof ApiError) {
      return respond(res, err.httpCode, "error", err.message, null, err.errorCode);
    }

    console.error("APPROVE_PLAN_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "approve_plan_error",
      userId: auditDietitianId || String(req.user?.sub || ""),
      partnerCode: auditDietitianId,
      identifier: auditProfileId,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    const payload = {
      status: "error",
      code: 500,
      message: "Failed to update record",
    };
    if (APP_DEBUG) payload.debug_error = err?.message;
    return res.status(500).json(payload);
  } finally {
    if (connection) connection.release();
  }
};

module.exports = { foodJsonSuggestionApprovePlan };
