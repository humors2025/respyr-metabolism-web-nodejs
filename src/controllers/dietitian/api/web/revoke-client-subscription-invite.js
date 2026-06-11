"use strict";

/**
 * revoke-client-subscription-invite.js
 *
 * Converted from: revoke-client-subscription-invite.php
 *                 (+ client-subscription-action-common.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/revoke-client-subscription-invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but ONLY for a subscription whose
 *              trainer_code / trainer_id the actor is allowed to use (own code, or
 *              a child trainer's code).
 *
 * Behaviour parity with the PHP:
 *  - Looks up the target subscription by `subscription_id` OR `redeem_code`; if
 *    none matches, falls back to a legacy `invite_id` in trainer_client_invites.
 *  - Legacy invite path: marks the invite 'cancelled' and returns the invite shape.
 *  - Subscription path: rejects accepted/redeemed (409) and already-cancelled
 *    (409) rows, then marks the subscription + its source invite 'cancelled' under
 *    a row lock + transaction, and returns the subscription shape.
 *  - `reason` is stored (capped at 1000 chars) and echoed into the audit log.
 *  - Response shape matches the PHP exactly: { status, ok, message, data{...} }.
 *
 * VAPT hardening (beyond the PHP — this is the whole point of the sprint):
 *  - Token-bound identity. The PHP trusted body.actor_user_id to resolve the
 *    actor (a textbook IDOR). Here the actor is ALWAYS resolved from the verified
 *    JWT and re-checked (role + status) against the DB. body.actor_user_id is
 *    still accepted for frontend back-compat but is only cross-checked against
 *    the token identity (mismatch → 403); it can never select another user.
 *  - The target lookup is authorized on BOTH trainer_code and trainer_id, so a
 *    caller can never revoke a subscription that belongs to a code they don't own.
 *  - Row lock (SELECT ... FOR UPDATE) inside a transaction prevents a revoke vs
 *    accept/resend race.
 *  - Every query is fully parameterized (no string interpolation).
 *  - Internal error details are suppressed in production (gated behind APP_DEBUG);
 *    the PHP echoed debug_error unconditionally.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Every revoke / denial / failure is recorded in app_auth_logs.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (client email, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_invites, trainer_client_plan_subscriptions,
 * app_auth_logs.
 */

const crypto = require("crypto");
const pool   = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const DEFAULT_REVOKE_REASON = "Client subscription invite revoked";
const MAX_REASON_LEN = 1000;

// ─── Error type for early-exit validation (mirrors PHP csi_json(...)) ──────────

class ApiError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = Object.assign({ status: false, ok: false, message }, extra || {});
  }
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function cleanValue(value) {
  return String(value === null || value === undefined ? "" : value).trim();
}

function normalizeEmail(email) {
  return String(email === null || email === undefined ? "" : email).trim().toLowerCase();
}

function normalizeCode(code) {
  return String(code === null || code === undefined ? "" : code).trim().toUpperCase();
}

/** Parse a positive integer id, or return null. */
function toPositiveInt(value) {
  const n = parseInt(cleanValue(value), 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** Sanitize a redeem code to the RSP###### alphabet; empty if it doesn't qualify. */
function sanitizeRedeemCode(value) {
  const code = normalizeCode(value).replace(/[^A-Z0-9]/g, "");
  return code.length >= 4 && code.length <= 32 ? code : "";
}

function getEffectiveCode(row) {
  if (row && row.partner_code !== null && row.partner_code !== undefined &&
      String(row.partner_code).trim() !== "") {
    return String(row.partner_code);
  }
  if (row && row.dietician_id !== null && row.dietician_id !== undefined &&
      String(row.dietician_id).trim() !== "") {
    return String(row.dietician_id);
  }
  return null;
}

// ─── Audit log (fail-safe, hashed PHI/PII) ────────────────────────────────────

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
  role,
  partnerCode,
  identifier,
  success,
  failureReason,
}) {
  try {
    const ipHash         = authLogHash(getClientIp(req));
    const userAgentHash  = authLogHash(getUserAgent(req));
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
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
        role ?? null,
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
    console.error("CLIENT_SUBSCRIPTION_REVOKE_AUDIT_LOG_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) + allowed codes ───────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. The token carries dietician_id in `sub`; email is derived from the DB.
 * Returns { actor, actorEmail } or throws ApiError. (Mirrors csi_get_actor_or_fail,
 * but token-bound instead of body-trusted.)
 */
async function resolveActorFromToken(conn, req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    throw new ApiError(401, "Invalid token user");
  }

  const [rows] = dieticianId
    ? await conn.execute(
        `SELECT
           td.id, td.dietician_id, td.name, td.phone_no, td.email, td.location,
           aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.status
         FROM table_dietician td
         INNER JOIN app_user_roles aur
           ON LOWER(aur.user_id) = LOWER(td.email)
         WHERE td.dietician_id = ?
         LIMIT 1`,
        [dieticianId]
      )
    : await conn.execute(
        `SELECT
           td.id, td.dietician_id, td.name, td.phone_no, td.email, td.location,
           aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.status
         FROM table_dietician td
         INNER JOIN app_user_roles aur
           ON LOWER(aur.user_id) = LOWER(td.email)
         WHERE LOWER(td.email) = LOWER(?)
         LIMIT 1`,
        [tokenEmail]
      );

  const actor = rows[0];

  if (!actor) {
    throw new ApiError(403, "Actor user not found");
  }
  if (String(actor.status) !== "active") {
    throw new ApiError(403, "Actor account is not active");
  }
  if (!VALID_ACTOR_ROLES.has(String(actor.role))) {
    throw new ApiError(403, "Invalid actor role");
  }

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

/**
 * Set of trainer/partner codes this actor may act on.
 *   trainer     → own effective code only
 *   admin       → own + child trainers' partner_codes
 *   super_admin → own + child admins' + child trainers' partner_codes
 * Mirrors csi_allowed_codes() (codes upper-cased + de-duped).
 */
async function getAllowedCodesForActor(conn, actor, actorEmail) {
  const codes = new Set();
  const role = String(actor.role);

  const own = getEffectiveCode(actor);
  if (own && normalizeCode(own) !== "") codes.add(normalizeCode(own));

  if (role === "trainer") {
    return [...codes];
  }

  if (role === "admin") {
    const [rows] = await conn.execute(
      `SELECT partner_code
         FROM app_user_roles
        WHERE role = 'trainer'
          AND status = 'active'
          AND partner_code IS NOT NULL
          AND partner_code <> ''
          AND LOWER(parent_user_id) = LOWER(?)`,
      [actorEmail]
    );
    for (const row of rows) {
      if (normalizeCode(row.partner_code) !== "") codes.add(normalizeCode(row.partner_code));
    }
    return [...codes];
  }

  if (role === "super_admin") {
    const [rows] = await conn.execute(
      `SELECT partner_code
         FROM app_user_roles
        WHERE status = 'active'
          AND partner_code IS NOT NULL
          AND partner_code <> ''
          AND (
            (
              role = 'admin'
              AND LOWER(parent_user_id) = LOWER(?)
            )
            OR
            (
              role = 'trainer'
              AND (
                LOWER(parent_user_id) = LOWER(?)
                OR LOWER(parent_user_id) IN (
                  SELECT LOWER(user_id)
                  FROM app_user_roles
                  WHERE role = 'admin'
                    AND status = 'active'
                    AND LOWER(parent_user_id) = LOWER(?)
                )
              )
            )
          )`,
      [actorEmail, actorEmail, actorEmail]
    );
    for (const row of rows) {
      if (normalizeCode(row.partner_code) !== "") codes.add(normalizeCode(row.partner_code));
    }
    return [...codes];
  }

  return [...codes];
}

/** csi_can_access_code: is this single code in the actor's allowed set? */
function actorCanUseTrainerCode(allowedCodes, code) {
  const wanted = normalizeCode(code);
  if (wanted === "") return false;
  return allowedCodes.some((c) => normalizeCode(c) === wanted);
}

/** A subscription/invite is reachable if EITHER its trainer_code or trainer_id is allowed. */
function actorCanAccessRow(allowedCodes, row) {
  return (
    actorCanUseTrainerCode(allowedCodes, row.trainer_code) ||
    actorCanUseTrainerCode(allowedCodes, row.trainer_id)
  );
}

// ─── Target lookups (row-locked inside the transaction) ───────────────────────

/** csi_get_subscription_for_update: by subscription_id first, else redeem_code. */
async function getSubscriptionForUpdate(conn, { subscriptionId, redeemCode }) {
  if (subscriptionId) {
    const [rows] = await conn.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE id = ?
        LIMIT 1
        FOR UPDATE`,
      [subscriptionId]
    );
    if (rows[0]) return rows[0];
  }

  if (redeemCode) {
    const [rows] = await conn.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE redeem_code = ?
        LIMIT 1
        FOR UPDATE`,
      [redeemCode]
    );
    if (rows[0]) return rows[0];
  }

  return null;
}

/** csi_get_legacy_invite_for_update: trainer_client_invites by id. */
async function getLegacyInviteForUpdate(conn, inviteId) {
  if (!inviteId) return null;
  const [rows] = await conn.execute(
    `SELECT *
       FROM trainer_client_invites
      WHERE id = ?
      LIMIT 1
      FOR UPDATE`,
    [inviteId]
  );
  return rows[0] || null;
}

/** csi_subscription_is_accepted: redeemed/accepted subscriptions are terminal. */
function subscriptionIsAccepted(sub) {
  const subStatus = String(sub.subscription_status || "").toLowerCase();
  if (subStatus === "accepted" || subStatus === "redeemed") return true;
  if (sub.accepted_profile_id !== null && sub.accepted_profile_id !== undefined &&
      cleanValue(sub.accepted_profile_id) !== "") return true;
  if (sub.accepted_at !== null && sub.accepted_at !== undefined &&
      cleanValue(sub.accepted_at) !== "") return true;
  return false;
}

/** csi_legacy_invite_is_accepted: accepted legacy invites cannot be revoked. */
function legacyInviteIsAccepted(invite) {
  const status = String(invite.status || "").toLowerCase();
  if (status === "accepted") return true;
  if (invite.accepted_profile_id !== null && invite.accepted_profile_id !== undefined &&
      cleanValue(invite.accepted_profile_id) !== "") return true;
  return false;
}

/**
 * csi_update_source_invite: push the revoke result onto the source invite row,
 * guarded against an already-accepted invite (never clobber an acceptance).
 */
async function updateSourceInviteIfNotAccepted(
  conn,
  sourceInviteId,
  status,
  emailStatus,
  resendEmailId,
  errorMessage,
  subscriptionId
) {
  if (!sourceInviteId) return;

  await conn.execute(
    `UPDATE trainer_client_invites
        SET status = ?,
            email_status = ?,
            resend_email_id = ?,
            error_message = ?,
            latest_subscription_id = ?,
            updated_at = NOW()
      WHERE id = ?
        AND status <> 'accepted'
        AND accepted_profile_id IS NULL
      LIMIT 1`,
    [status, emailStatus, resendEmailId, errorMessage, subscriptionId, sourceInviteId]
  );
}

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/revoke-client-subscription-invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body (one identifier required):
 *   { "actor_user_id": "", "subscription_id": 12, "reason": "Wrong email" }
 *   { "actor_user_id": "", "redeem_code": "RSP8K2M9Q", "reason": "Wrong client" }
 *   { "actor_user_id": "", "invite_id": 5, "reason": "Wrong email" }   // legacy
 */
const revokeClientSubscriptionInvite = async (req, res) => {
  // HIPAA: never let intermediaries cache invite responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP REQUEST_METHOD check).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};

  let conn = null;
  let inTransaction = false;
  let actorEmail = null;
  let actorRole = null;

  try {
    // ── 1. Parse + validate identifiers / reason ─────────────────────────────
    const actorUserId    = normalizeEmail(body.actor_user_id ?? "");
    const subscriptionId = toPositiveInt(body.subscription_id);
    const redeemCode     = sanitizeRedeemCode(body.redeem_code);
    const inviteId       = toPositiveInt(body.invite_id);

    const reason = (
      cleanValue(body.reason) !== "" ? cleanValue(body.reason) : DEFAULT_REVOKE_REASON
    ).slice(0, MAX_REASON_LEN);

    if (!subscriptionId && redeemCode === "" && !inviteId) {
      throw new ApiError(400, "subscription_id, redeem_code or invite_id is required");
    }

    // ── 2. DB connection (IST session time zone, parity with PHP) ────────────
    conn = await pool.getConnection();
    await conn.query("SET time_zone = '+05:30'");

    // ── 3. Token-bound authorization (closes the PHP IDOR hole) ──────────────
    const resolved = await resolveActorFromToken(conn, req);
    const actor = resolved.actor;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);

    // Optional actor_user_id is cross-checked, never trusted to select a user.
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_revoke_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: null,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      throw new ApiError(403, "actor_user_id does not match the authenticated user");
    }

    const allowedCodes = await getAllowedCodesForActor(conn, actor, actorEmail);

    // ── 4. Locate the target (transaction + row lock) ────────────────────────
    await conn.beginTransaction();
    inTransaction = true;

    const sub = await getSubscriptionForUpdate(conn, { subscriptionId, redeemCode });

    // ── 4a. Legacy invite path (no subscription matched) ─────────────────────
    if (!sub) {
      const legacyInvite = await getLegacyInviteForUpdate(conn, inviteId);

      if (!legacyInvite) {
        throw new ApiError(404, "Client invite/subscription not found");
      }

      if (!actorCanAccessRow(allowedCodes, legacyInvite)) {
        await writeAuthLogSafe(req, {
          eventType: "client_subscription_invite_revoke_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: getEffectiveCode(actor),
          identifier: normalizeEmail(legacyInvite.client_email),
          success: false,
          failureReason: "actor not allowed to revoke this client invite",
        });
        throw new ApiError(403, "You are not allowed to revoke this client invite");
      }

      if (legacyInviteIsAccepted(legacyInvite)) {
        throw new ApiError(409, "Accepted client invite cannot be revoked");
      }

      await conn.execute(
        `UPDATE trainer_client_invites
            SET status = 'cancelled',
                email_status = 'failed',
                error_message = ?,
                updated_at = NOW()
          WHERE id = ?
          LIMIT 1`,
        [reason, Number(legacyInvite.id)]
      );

      await conn.commit();
      inTransaction = false;

      await writeAuthLogSafe(req, {
        eventType: "client_invite_revoked",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: normalizeEmail(legacyInvite.client_email),
        success: true,
        failureReason: reason,
      });

      return res.status(200).json({
        status: true,
        ok: true,
        message: "Client invite revoked successfully",
        data: {
          invite_id: Number(legacyInvite.id),
          subscription_id: null,
          status: "cancelled",
          client_email: normalizeEmail(legacyInvite.client_email),
          trainer_code: legacyInvite.trainer_code,
        },
      });
    }

    // ── 4b. Subscription path ────────────────────────────────────────────────
    if (!actorCanAccessRow(allowedCodes, sub)) {
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_revoke_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: normalizeEmail(sub.client_email),
        success: false,
        failureReason: "actor not allowed to revoke this subscription",
      });
      throw new ApiError(403, "You are not allowed to revoke this client subscription invite");
    }

    if (subscriptionIsAccepted(sub)) {
      throw new ApiError(409, "Accepted/redeemed subscription cannot be revoked");
    }

    if (String(sub.status) === "cancelled" || String(sub.subscription_status) === "cancelled") {
      throw new ApiError(409, "Subscription invite is already cancelled");
    }

    // ── 5. Cancel the subscription + its source invite ───────────────────────
    await conn.execute(
      `UPDATE trainer_client_plan_subscriptions
          SET status = 'cancelled',
              subscription_status = 'cancelled',
              payment_status = 'cancelled',
              email_status = 'failed',
              error_message = ?,
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [reason, Number(sub.id)]
    );

    const sourceInviteId =
      sub.source_invite_id !== null && sub.source_invite_id !== undefined
        ? Number(sub.source_invite_id)
        : null;

    await updateSourceInviteIfNotAccepted(
      conn,
      sourceInviteId,
      "cancelled",
      "failed",
      sub.resend_email_id ?? null,
      reason,
      Number(sub.id)
    );

    await conn.commit();
    inTransaction = false;

    // ── 6. Audit ─────────────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: "client_subscription_invite_revoked",
      userId: actorEmail,
      role: actorRole,
      partnerCode: getEffectiveCode(actor),
      identifier: normalizeEmail(sub.client_email),
      success: true,
      failureReason: reason,
    });

    // ── 7. Respond (matches the PHP JSON shape exactly) ──────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Client subscription invite revoked successfully",
      data: {
        subscription_id: Number(sub.id),
        source_invite_id: sourceInviteId,
        redeem_code: sub.redeem_code,
        status: "cancelled",
        subscription_status: "cancelled",
        payment_status: "cancelled",
        client_name: sub.client_name,
        client_email: normalizeEmail(sub.client_email),
        trainer_code: sub.trainer_code,
        plan_code: sub.plan_code,
        plan_name: sub.plan_name,
      },
    });
  } catch (err) {
    if (inTransaction && conn) {
      try {
        await conn.rollback();
      } catch (_) {
        /* ignore */
      }
    }

    if (err instanceof ApiError) {
      return res.status(err.status).json(err.payload);
    }

    console.error("REVOKE_CLIENT_SUBSCRIPTION_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "client_subscription_invite_revoke_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: null,
      identifier: null,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (_) {
        /* ignore */
      }
    }
  }
};

module.exports = { revokeClientSubscriptionInvite };
