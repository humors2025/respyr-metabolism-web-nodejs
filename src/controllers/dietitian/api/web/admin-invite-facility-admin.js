"use strict";

/**
 * POST /dietitian/api/web/admin-invite-facility-admin
 *
 * A Rysflo admin (trainer-admin) — or a super_admin — invites the owner of a
 * gym / studio as a facility_admin. The invite carries the facility name; the
 * facilities row itself is created when the invite is accepted
 * (see accept-invite.js), so an unaccepted invite never leaves an orphan.
 *
 * The facility_admin's partner code doubles as the facility's wall / front
 * desk QR code, so it is generated here with the FAC prefix and must be
 * unique across app_user_roles, app_user_invitations and facilities.
 *
 * Body:
 *  {
 *    "first_name":    "...",
 *    "last_name":     "...",
 *    "email":         "...",
 *    "phone":         "...",           // optional
 *    "facility_name": "Iron Works Gym",
 *    "actor_user_id": "<inviter email>" // optional, must match the token
 *  }
 *
 * Shares validation, invite persistence, email delivery and audit logging with
 * admin-invite-trainer.js via its exported helpers, so the two invite paths
 * cannot drift apart.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const { escapeHtml } = require("../../../../utils/securityValidation");
const {
  _helpers: H,
} = require("./admin-invite-trainer");

const FACILITY_CODE_PREFIX = "FAC";
const FACILITY_CODE_RANDOM_LEN = 7;
const FACILITY_CODE_MAX_ATTEMPTS = 10;
// No 0/1: matches the code shape auth_common.js accepts in invite emails.
const FACILITY_CODE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ23456789";
const FACILITY_NAME_MAX_LENGTH = 150;
const ALLOWED_INVITER_ROLES = ["super_admin", "admin"];

function randomFacilityCodeSuffix() {
  const bytes = crypto.randomBytes(FACILITY_CODE_RANDOM_LEN);
  let out = "";
  for (let i = 0; i < FACILITY_CODE_RANDOM_LEN; i++) {
    out += FACILITY_CODE_ALPHABET[bytes[i] % FACILITY_CODE_ALPHABET.length];
  }
  return out;
}

/**
 * Unique across every table that can hold a partner code, including
 * facilities (the code is also the facility's public QR code).
 */
async function generateUniqueFacilityCode() {
  for (let attempt = 0; attempt < FACILITY_CODE_MAX_ATTEMPTS; attempt++) {
    const candidate = FACILITY_CODE_PREFIX + randomFacilityCodeSuffix();

    const [hits] = await pool.execute(
      `
        SELECT 1 AS hit FROM app_user_roles       WHERE UPPER(partner_code) = UPPER(?)
        UNION ALL
        SELECT 1 AS hit FROM app_user_invitations WHERE UPPER(partner_code) = UPPER(?)
        UNION ALL
        SELECT 1 AS hit FROM facilities           WHERE UPPER(partner_code) = UPPER(?)
        LIMIT 1
      `,
      [candidate, candidate, candidate]
    );

    if (!hits.length) {
      return candidate;
    }
  }

  throw new Error("Unable to generate a unique facility code");
}

/**
 * Facility name: reject rather than clean, like every other input here.
 * Letters, digits, spaces and the punctuation a real business name uses.
 */
function validateFacilityName(raw) {
  const value = typeof raw === "string" ? raw.trim() : "";

  if (value === "") {
    return { ok: false, message: "facility_name is required" };
  }

  if (value.length > FACILITY_NAME_MAX_LENGTH) {
    return {
      ok: false,
      message: `facility_name must be at most ${FACILITY_NAME_MAX_LENGTH} characters`,
    };
  }

  if (!/^[\p{L}\p{N} .,'&()\-]+$/u.test(value)) {
    return { ok: false, message: "facility_name contains invalid characters" };
  }

  return { ok: true, value };
}

const adminInviteFacilityAdmin = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  let invitationId = null;
  let actorEmail = null;
  let actorCode = null;
  let actorRole = null;

  try {
    const resolved = await H.resolveActorFromToken(req, ALLOWED_INVITER_ROLES);

    if (resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "invite_facility_admin_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: H.normalizeEmail(
          req.user?.email || req.user?.user_id || req.user?.sub || ""
        ),
        success: false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = actor.partner_code ?? null;

    // actor_user_id is optional and only kept for frontend compatibility; it
    // must never disagree with the token.
    const bodyActorUserId =
      typeof req.body?.actor_user_id === "string"
        ? H.normalizeEmail(req.body.actor_user_id)
        : "";

    if (bodyActorUserId !== "" && bodyActorUserId !== actorEmail) {
      await H.writeAuthLogSafe(req, {
        eventType: "invite_facility_admin_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorEmail,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return res.status(403).json({
        ok: false,
        message: "actor_user_id does not match the authenticated user",
      });
    }

    const validation = H.validateInviteInput(req.body);

    if (!validation.ok) {
      await H.writeAuthLogSafe(req, {
        eventType: "invite_facility_admin_validation_failed",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorEmail,
        success: false,
        failureReason: validation.message,
      });
      return res.status(validation.status).json({ ok: false, message: validation.message });
    }

    const facilityNameResult = validateFacilityName(req.body?.facility_name);

    if (!facilityNameResult.ok) {
      await H.writeAuthLogSafe(req, {
        eventType: "invite_facility_admin_validation_failed",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorEmail,
        success: false,
        failureReason: facilityNameResult.message,
      });
      return res.status(422).json({ ok: false, message: facilityNameResult.message });
    }

    const { first_name: firstName, last_name: lastName, email, phone } = validation.value;
    const phoneOrNull = phone || null;
    const facilityName = facilityNameResult.value;

    const canCreate = await H.ensureInviteCanBeCreated(email);

    if (!canCreate.ok) {
      await H.writeAuthLogSafe(req, {
        eventType: "invite_facility_admin_duplicate",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: email,
        success: false,
        failureReason: canCreate.message,
      });
      return res.status(canCreate.status).json({ ok: false, message: canCreate.message });
    }

    const partnerCode = await generateUniqueFacilityCode();

    // Raw token goes only into the link; the database stores its HMAC.
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = H.secureHash(rawToken);
    const inviteLink = `${H.FRONTEND_ACCEPT_INVITE_URL}?token=${encodeURIComponent(rawToken)}`;
    const expiresAt = H.toUtcMysqlDateTime(
      new Date(Date.now() + H.INVITE_EXPIRY_HOURS * 60 * 60 * 1000)
    );

    invitationId = await H.createPendingInvite({
      email,
      firstName,
      lastName,
      phone: phoneOrNull,
      invitedRole: "facility_admin",
      partnerCode,
      invitedByUserId: actorEmail,
      parentUserId: actorEmail,
      facilityId: null, // created on acceptance
      facilityName,
      tokenHash,
      expiresAt,
    });

    const fullName = `${firstName} ${lastName}`.trim();

    const emailResult = await H.sendResendTemplateEmail(
      email,
      "You have been invited to Respyr",
      H.RESEND_INVITE_TEMPLATE_ID,
      {
        INVITED_NAME: escapeHtml(fullName),
        INVITER_EMAIL: escapeHtml(actorEmail),
        INVITED_EMAIL: escapeHtml(email),
        INVITED_ROLE: "facility_admin",
        FACILITY_NAME: escapeHtml(facilityName),
        PARTNER_CODE: escapeHtml(partnerCode),
        EXPIRES_IN: escapeHtml(`${H.INVITE_EXPIRY_HOURS} hours`),
        INVITE_LINK: inviteLink,
      }
    );

    if (!emailResult.ok) {
      await H.markInviteRevoked(invitationId);

      console.error("RESEND_FACILITY_ADMIN_INVITE_FAILED:", {
        invitation_id: invitationId,
        status: emailResult.status,
        error: H.APP_DEBUG ? emailResult.error : undefined,
      });

      await H.writeAuthLogSafe(req, {
        eventType: "invite_facility_admin_email_failed",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: email,
        success: false,
        failureReason: "resend_failed",
      });

      return res.status(502).json({
        ok: false,
        message: "Invitation could not be emailed. Please try again.",
      });
    }

    await H.markInviteSent(invitationId);

    await H.writeAuthLogSafe(req, {
      eventType: "invite_facility_admin_sent",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: email,
      success: true,
      failureReason: `Facility admin invite sent to ${email}`,
    });

    const response = {
      ok: true,
      message: "Facility admin invitation sent successfully",
      data: {
        invitation_id: invitationId,
        invited_first_name: firstName,
        invited_last_name: lastName,
        invited_name: fullName,
        invited_email: email,
        invited_phone: phoneOrNull,
        invited_role: "facility_admin",
        facility_name: facilityName,
        partner_code: partnerCode,
        invited_by_user_id: actorEmail,
        parent_user_id: actorEmail,
        status: "pending",
        expires_at: expiresAt,
      },
    };

    if (H.RETURN_INVITE_LINK_FOR_TESTING) {
      response.debug_invite_link = inviteLink;
    }

    return res.status(201).json(response);
  } catch (err) {
    // Never leave a half-created invite that could be accepted later.
    if (invitationId !== null) {
      await H.markInviteRevoked(invitationId);
    }

    console.error("ADMIN_INVITE_FACILITY_ADMIN_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await H.writeAuthLogSafe(req, {
      eventType: "invite_facility_admin_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { adminInviteFacilityAdmin };
