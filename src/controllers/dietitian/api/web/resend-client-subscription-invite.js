"use strict";

/**
 * resend-client-subscription-invite.js
 *
 * Converted from: resend-client-subscription-invite.php
 *                 (+ client-subscription-action-common.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/resend-client-subscription-invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but ONLY for a subscription whose
 *              trainer_code / trainer_id the actor is allowed to use (own code, or
 *              a child trainer's code).
 *
 * Behaviour parity with the PHP:
 *  - Looks up the target subscription by `subscription_id`, then `redeem_code`,
 *    then the latest subscription for an `invite_id`; if none matches, falls back
 *    to a legacy `invite_id` in trainer_client_invites and (when found +
 *    resendable) creates a fresh subscription row from it.
 *  - Rejects accepted/redeemed invites (409) and cancelled ones (409).
 *  - Regenerates the redeem code + expiry on every resend (clean mobile flow),
 *    flips the row to status='failed'/subscription_status='pending' under a row
 *    lock + transaction, commits, then sends the email and writes the result
 *    back to the subscription and its source invite row.
 *  - Sends the SAME Resend template payload as the PHP csi_send_email
 *    (template id + variables) — see client-subscription-action-common.sendEmail.
 *  - Response shape matches the PHP exactly: { status, ok, message, data{...} }
 *    with the same keys; success → 200, email-failed → 502.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The PHP trusted body.actor_user_id to resolve the
 *    actor (a textbook IDOR). Here the actor is ALWAYS resolved from the verified
 *    JWT and re-checked (role + status). body.actor_user_id is still accepted for
 *    frontend back-compat but is only cross-checked against the token identity
 *    (mismatch → 403); it can never select another user.
 *  - The target lookup is authorized on BOTH trainer_code and trainer_id.
 *  - Row lock (SELECT ... FOR UPDATE) inside a transaction prevents a double
 *    resend / code-regeneration race.
 *  - Every query is fully parameterized; redeem codes use a CSPRNG.
 *  - Internal error / email-provider details are suppressed in production
 *    (gated behind APP_DEBUG).
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (client email, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *  - Every resend / denial / failure is recorded in app_auth_logs.
 *
 * All shared logic lives in client-subscription-action-common.js (the Node port
 * of client-subscription-action-common.php). This file is the thin controller.
 */

const pool = require("../../../../config/db");
const csi  = require("./client-subscription-action-common");

const {
  ApiError,
  APP_DEBUG,
  RESEND_API_KEY,
} = csi;

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/resend-client-subscription-invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body (one identifier required):
 *   { "actor_user_id": "", "subscription_id": 12 }
 *   { "actor_user_id": "", "redeem_code": "RSP8K2M9Q" }
 *   { "actor_user_id": "", "invite_id": 5 }          // legacy
 */
const resendClientSubscriptionInvite = async (req, res) => {
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
    if (!RESEND_API_KEY) {
      throw new ApiError(500, "RESEND_API_KEY is not configured");
    }

    // ── 1. Parse + validate identifiers ──────────────────────────────────────
    const actorUserId    = csi.email(body.actor_user_id ?? "");
    const subscriptionId = csi.toInt(body.subscription_id);
    const redeemCode     = csi.code(body.redeem_code ?? "");
    const inviteId       = csi.toInt(body.invite_id);

    if (subscriptionId <= 0 && redeemCode === "" && inviteId <= 0) {
      throw new ApiError(400, "subscription_id, redeem_code or invite_id is required");
    }

    // ── 2. DB connection (IST session time zone, parity with PHP) ────────────
    conn = await pool.getConnection();
    await conn.query("SET time_zone = '+05:30'");

    // ── 3. Token-bound authorization (closes the PHP IDOR hole) ──────────────
    const { actor, actorEmail: resolvedEmail } = await csi.resolveActorFromToken(conn, req);
    actorEmail = resolvedEmail;
    actorRole = String(actor.role);

    // Optional actor_user_id is cross-checked, never trusted to select a user.
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await csi.audit(
        pool, req, "client_subscription_invite_resend_denied",
        actorEmail, actorRole, csi.effectiveCode(actor),
        null, false, "actor_user_id does not match token identity"
      );
      throw new ApiError(403, "actor_user_id does not match the authenticated user");
    }

    const allowedCodes = await csi.allowedCodes(conn, actor, actorEmail);

    // ── 4. Locate the target (transaction + row lock) ────────────────────────
    await conn.beginTransaction();
    inTransaction = true;

    let sub = await csi.getSubscriptionForUpdate(conn, body);

    if (!sub) {
      // Legacy path: resolve an invite_id and spawn a subscription from it.
      const legacyInvite = await csi.getLegacyInviteForUpdate(conn, body);

      if (!legacyInvite) {
        throw new ApiError(404, "Client invite/subscription not found");
      }

      if (!csi.canAccessRow(allowedCodes, legacyInvite)) {
        await csi.audit(
          pool, req, "client_subscription_invite_resend_denied",
          actorEmail, actorRole, csi.effectiveCode(actor),
          csi.email(legacyInvite.client_email), false,
          "actor not allowed to resend this client invite"
        );
        throw new ApiError(403, "You are not allowed to resend this client invite");
      }

      if (csi.legacyInviteIsAccepted(legacyInvite)) {
        throw new ApiError(409, "Accepted client invite cannot be resent");
      }

      sub = await csi.createSubscriptionFromLegacyInvite(conn, legacyInvite, actorEmail);
    }

    // ── 5. Authorize + state guards on the subscription ──────────────────────
    if (!csi.canAccessRow(allowedCodes, sub)) {
      await csi.audit(
        pool, req, "client_subscription_invite_resend_denied",
        actorEmail, actorRole, csi.effectiveCode(actor),
        csi.email(sub.client_email), false,
        "actor not allowed to resend this subscription"
      );
      throw new ApiError(403, "You are not allowed to resend this client subscription invite");
    }

    if (csi.subscriptionIsAccepted(sub)) {
      throw new ApiError(409, "Accepted/redeemed subscription cannot be resent");
    }

    if (String(sub.status) === "cancelled" || String(sub.subscription_status) === "cancelled") {
      throw new ApiError(409, "Cancelled subscription cannot be resent. Create a new invite.");
    }

    // ── 6. Regenerate the redeem code + expiry, flip state to pending ────────
    const newRedeemCode = await csi.uniqueRedeemCode(conn);
    const newExpiresAt = csi.redeemCodeExpiry();

    await conn.execute(
      `UPDATE trainer_client_plan_subscriptions
          SET redeem_code = ?,
              code_expires_at = ?,
              status = 'failed',
              email_status = 'failed',
              subscription_status = 'pending',
              error_message = 'Email resend started',
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [newRedeemCode, newExpiresAt, Number(sub.id)]
    );

    sub.redeem_code = newRedeemCode;
    sub.code_expires_at = newExpiresAt;

    await conn.commit();
    inTransaction = false;

    // ── 7. Send the email (outside the transaction) ──────────────────────────
    await csi.hydrateTrainerName(conn, sub);

    const emailResult = await csi.sendEmail(sub);

    const newStatus      = emailResult.success ? "sent" : "failed";
    const newEmailStatus = emailResult.success ? "sent" : "failed";
    const newError       = emailResult.error;
    const resendEmailId  = emailResult.resend_email_id;

    // ── 8. Persist the email result on the subscription + source invite ──────
    await conn.execute(
      `UPDATE trainer_client_plan_subscriptions
          SET status = ?,
              email_status = ?,
              resend_email_id = ?,
              error_message = ?,
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [newStatus, newEmailStatus, resendEmailId, newError, Number(sub.id)]
    );

    const sourceInviteId =
      sub.source_invite_id !== null && sub.source_invite_id !== undefined
        ? Number(sub.source_invite_id)
        : null;

    await csi.updateSourceInvite(
      conn,
      sourceInviteId,
      newStatus,
      newEmailStatus,
      resendEmailId,
      newError,
      Number(sub.id)
    );

    // ── 9. Audit ─────────────────────────────────────────────────────────────
    await csi.audit(
      pool, req,
      emailResult.success
        ? "client_subscription_invite_resent"
        : "client_subscription_invite_resend_failed",
      actorEmail, actorRole, csi.effectiveCode(actor),
      csi.email(sub.client_email), emailResult.success,
      emailResult.success
        ? "Client subscription invite resent"
        : "Client subscription invite resend failed"
    );

    // ── 10. Respond (matches the PHP JSON shape exactly) ─────────────────────
    return res.status(emailResult.success ? 200 : 502).json({
      status: emailResult.success,
      ok: emailResult.success,
      message: emailResult.success
        ? "Client subscription invite resent successfully"
        : "Client subscription invite saved but email resend failed",
      data: {
        subscription_id: Number(sub.id),
        source_invite_id: sourceInviteId,
        redeem_code: newRedeemCode,
        code_expires_at: newExpiresAt,
        client_name: sub.client_name,
        client_email: csi.email(sub.client_email),
        trainer_code: sub.trainer_code,
        plan_code: sub.plan_code,
        plan_name: sub.plan_name,
        plan_price_label: sub.plan_price_label,
        invite_status: newStatus,
        email_status: newEmailStatus,
        resend_email_id: resendEmailId,
        // VAPT: provider error is suppressed from clients in production.
        error_message: APP_DEBUG ? newError : (emailResult.success ? null : "Email resend failed"),
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

    console.error("RESEND_CLIENT_SUBSCRIPTION_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await csi.audit(
      pool, req, "client_subscription_invite_resend_error",
      actorEmail, actorRole, null,
      null, false, err?.code || "internal_error"
    );

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

module.exports = { resendClientSubscriptionInvite };
