"use strict";

/**
 * invite-preview.js
 *
 * Converted from: invite-preview.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/invite-preview
 * Auth       : NONE (public). The single-use invite TOKEN is the credential —
 *              this is the read-only lookup the accept-invite screen calls to
 *              pre-fill the invited person's name/email/role before they set a
 *              password. authMiddleware must NOT be mounted here.
 *
 * Flow (read-only — parity with the PHP):
 *   1. Validate the token is present.
 *   2. Look the invitation up by its SECURITY_PEPPER-keyed token_hash.
 *   3. 404 (generic) if not found.
 *   4. If it is a stale `pending` row (expires_at <= now, evaluated in SQL/UTC),
 *      lazily flip it to `expired` and reflect that in the response.
 *   5. Return the invite snapshot. can_accept = (status === 'pending').
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  HARDENING DIFFERENCES FROM THE PHP (intentional)
 * ──────────────────────────────────────────────────────────────────────────
 *  - Expiry is evaluated IN SQL (`expires_at <= UTC_TIMESTAMP()`). The PHP set
 *    date_default_timezone_set('Asia/Kolkata') and compared with PHP strtotime/
 *    time(), but invites are STORED in UTC (auth_common writes UTC_TIMESTAMP()).
 *    That tz mismatch could mark a valid invite expired (or vice-versa).
 *    Comparing in the DB removes all Node/MySQL timezone drift.
 *  - The lazy-expire UPDATE also matches on status='pending' AND expiry in SQL,
 *    so a concurrent accept can't be clobbered by this read path.
 *  - The raw token NEVER appears in logs or the response; only its
 *    SECURITY_PEPPER-keyed HMAC (secureHash) is used to look the invite up.
 *  - Fail-closed on a missing SECURITY_PEPPER (without it secureHash would key
 *    on an empty string and the token lookup would be forgeable). Unlike the
 *    invite-SENDING endpoints this read-only path needs NO Resend config, so it
 *    deliberately does not require those keys.
 *  - Fully parameterized queries; zero string interpolation.
 *  - Generic 404 for "not found" (no oracle distinguishing a malformed token
 *    from a revoked/deleted one). Internal error detail is gated behind
 *    APP_DEBUG; production returns a generic 500.
 *  - Every preview / failure is audit-logged with PHI hashed (writeAuthLogSafe).
 *
 * VAPT controls:
 *  - High-entropy token_hash lookup (not guessable); endpoint is IP rate-limited
 *    at the route to blunt enumeration / DB-abuse.
 *  - No-store security headers; method gate; parameterized SQL.
 *
 * HIPAA note: the response echoes the invited person's name / email / phone.
 * This is minimum-necessary — it is returned ONLY to a caller already holding
 * that invite's single-use token, exactly as the accept screen requires.
 *
 * Tables touched (identical to the PHP — none added/removed):
 *   app_user_invitations, app_auth_logs (audit).
 */

const pool = require("../../../../config/db");

const {
  APP_DEBUG,
  SECURITY_PEPPER,
  applySecurityHeaders,
  sendJson,
  ensurePostOrReject,
  getJsonBody,
  normalizeEmail,
  cleanName,
  secureHash,
  writeAuthLogSafe,
} = require("./auth_common");

/**
 * POST /dietitian/api/web/invite-preview
 *
 * Body: { token }
 */
const invitePreview = async (req, res) => {
  applySecurityHeaders(res);

  if (ensurePostOrReject(req, res)) return;

  // Fail closed if the pepper is missing — secureHash would otherwise key on an
  // empty string, making the token_hash lookup forgeable. (Resend keys are NOT
  // required here: this endpoint never sends mail.)
  if (!SECURITY_PEPPER) {
    return sendJson(res, 500, {
      ok: false,
      message: "Server configuration missing",
      ...(APP_DEBUG ? { missing: ["SECURITY_PEPPER"] } : {}),
    });
  }

  const parsed = getJsonBody(req);
  if (!parsed.ok) {
    return sendJson(res, parsed.status, { ok: false, message: parsed.message });
  }
  const body = parsed.body;

  const token = typeof body.token === "string" ? body.token.trim() : "";

  if (token === "") {
    return sendJson(res, 400, {
      ok: false,
      message: "Invite token is required",
    });
  }

  const tokenHash = secureHash(token);

  try {
    // Look the invitation up by token hash. Expiry is computed in SQL (UTC) so
    // the response is correct regardless of the Node/MySQL server timezone.
    const [inviteRows] = await pool.execute(
      `
        SELECT
          id,
          invited_email,
          invited_first_name,
          invited_last_name,
          invited_phone,
          invited_role,
          partner_code,
          invited_by_user_id,
          parent_user_id,
          status,
          expires_at,
          sent_at,
          accepted_at,
          created_at,
          updated_at,
          (status = 'pending' AND expires_at <= UTC_TIMESTAMP()) AS should_expire
        FROM app_user_invitations
        WHERE token_hash = ?
        LIMIT 1
      `,
      [tokenHash]
    );

    const invite = inviteRows[0];

    if (!invite) {
      await writeAuthLogSafe(req, {
        eventType: "invite_preview_failed",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: null,
        success: false,
        failureReason: "invalid_token",
      });
      return sendJson(res, 404, {
        ok: false,
        message: "Invalid invitation link",
      });
    }

    let status = String(invite.status || "");

    // Lazily expire a stale pending invite (parity with the PHP). The WHERE
    // clause re-checks status + expiry in SQL so we never overwrite a row that
    // was accepted/revoked between the SELECT and this UPDATE.
    if (Number(invite.should_expire) === 1) {
      await pool.execute(
        `
          UPDATE app_user_invitations
          SET status = 'expired',
              updated_at = UTC_TIMESTAMP()
          WHERE id = ?
            AND status = 'pending'
            AND expires_at <= UTC_TIMESTAMP()
          LIMIT 1
        `,
        [invite.id]
      );
      status = "expired";
    }

    const firstName = cleanName(invite.invited_first_name);
    const lastName = cleanName(invite.invited_last_name);
    let fullName = `${firstName} ${lastName}`.trim();
    if (fullName === "") fullName = "User";

    const email = normalizeEmail(invite.invited_email);

    await writeAuthLogSafe(req, {
      eventType: "invite_previewed",
      userId: email,
      role: String(invite.invited_role || ""),
      partnerCode: invite.partner_code ?? null,
      identifier: email,
      success: true,
      failureReason: `status_${status}`,
    });

    // Response shape matches the PHP exactly.
    return sendJson(res, 200, {
      ok: true,
      message: "Invitation details fetched successfully",
      data: {
        invitation_id: Number(invite.id),
        email,
        first_name: firstName,
        last_name: lastName,
        name: fullName,
        phone_no:
          invite.invited_phone === null || invite.invited_phone === undefined
            ? ""
            : String(invite.invited_phone),
        role: String(invite.invited_role || ""),
        partner_code: String(invite.partner_code || ""),
        parent_user_id: normalizeEmail(invite.parent_user_id),
        status,
        expires_at: invite.expires_at,
        can_accept: status === "pending",
      },
    });
  } catch (err) {
    console.error("INVITE_PREVIEW_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "invite_preview_error",
      userId: null,
      role: null,
      partnerCode: null,
      identifier: null,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return sendJson(res, 500, {
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && {
        debug_error: err?.message,
        debug_file: err?.stack?.split("\n")[1]?.trim(),
      }),
    });
  }
};

module.exports = { invitePreview };
