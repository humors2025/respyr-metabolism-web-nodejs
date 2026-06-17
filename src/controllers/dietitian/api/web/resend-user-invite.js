"use strict";

/**
 * resend-user-invite.js
 *
 * Converted from: resend-user-invite.php (+ user-invite-action-common.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/resend-user-invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin | super_admin (a trainer can never resend)
 *
 * Behaviour parity with the PHP:
 *  - Looks up the invitation by invite_id (row-locked inside a transaction),
 *    validates the actor may manage it, then:
 *      • 404 if the invite does not exist,
 *      • 403 if the actor is not allowed to manage it,
 *      • 409 if it is already accepted (status='accepted' or accepted_at set),
 *      • 409 if it is revoked (must create a new invite instead).
 *  - Generates a FRESH raw token (the old raw token is never stored), emails the
 *    invite via Resend, then updates the row: token_hash, status='pending', new
 *    expires_at, sent_at/updated_at = UTC now — guarded by
 *    `status <> 'accepted' AND accepted_at IS NULL` so a concurrent accept wins.
 *  - On email failure: audit `user_invite_resend_failed` and return 502 (the row
 *    is left untouched — nothing is updated until the email succeeds).
 *  - Response shape matches the PHP: { ok, message, data }.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT and
 *    re-fetched from the DB on every call — NOT from body.actor_user_id as the
 *    PHP did. role + status are re-checked server-side. body.actor_user_id is
 *    still accepted for frontend/back-compat, but it is only cross-checked
 *    against the token email (mismatch → 403); it can never select another user.
 *  - Fully parameterized queries; the invite is read FOR UPDATE in a transaction
 *    and the resend UPDATE is guarded against the accepted state.
 *  - Fresh token is crypto.randomBytes(32); only its SECURITY_PEPPER-keyed
 *    HMAC-SHA256 is stored. A DB dump cannot be used to accept an invite.
 *  - Internal error / email-provider details are suppressed in production
 *    (gated behind APP_DEBUG). The PHP echoed raw errors — an info-disclosure
 *    finding that is closed here.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (identifier, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *  - Every resend (success, denial, failure, error) is recorded in app_auth_logs.
 *
 * ASSUMPTION (documented): the original ui_actor_can_manage_invite() lived in
 * user-invite-action-common.php (not provided). It is reimplemented here using
 * the SAME network model as the rest of this codebase: an actor may manage an
 * invite they created (invited_by_user_id) or that is parented to them
 * (parent_user_id); a super_admin may additionally manage invites parented to one
 * of its own active admins (one level — no extra recursion). Tighten/loosen this
 * if your common file differed.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, app_user_invitations, app_auth_logs.
 */

const crypto = require("crypto");
const axios = require("axios");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const INVITE_EXPIRY_HOURS = Math.max(
  1,
  parseInt(process.env.INVITE_EXPIRY_HOURS, 10) || 24
);

const FRONTEND_ACCEPT_INVITE_URL =
  process.env.FRONTEND_ACCEPT_INVITE_URL ||
  "https://api.respyr.ai/signup";
  // "https://api.respyr.ai/dietitian/api/web/accept-invite";
  // "https://app.respyr.ai/accept-invite";

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_INVITE_TEMPLATE_ID = process.env.RESEND_INVITE_TEMPLATE_ID || "admin_trainer_invitation";
const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL || "Respyr <no-reply@respyr.ai>";

const RETURN_INVITE_LINK_FOR_TESTING =
  String(process.env.RETURN_INVITE_LINK_FOR_TESTING || "").toLowerCase() === "true";

const ALLOWED_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return String(val ?? "").trim().toLowerCase();
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

/** SHA-256 HMAC keyed by SECURITY_PEPPER — used to hash the invite token. */
function secureHash(value) {
  return crypto.createHmac("sha256", SECURITY_PEPPER).update(String(value)).digest("hex");
}

/** Format a Date (UTC) as "YYYY-MM-DD HH:MM:SS" — matches PHP gmdate(). */
function toUtcMysqlDateTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

/** Format a mysql2 DATETIME value as a UTC "YYYY-MM-DD HH:MM:SS" string. */
function formatDbDateTime(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    return toUtcMysqlDateTime(val);
  }
  return String(val);
}

function getActorEffectivePartnerCode(actor) {
  if (actor.partner_code !== null && actor.partner_code !== undefined &&
      String(actor.partner_code).trim() !== "") {
    return String(actor.partner_code);
  }
  if (actor.dietician_id !== null && actor.dietician_id !== undefined &&
      String(actor.dietician_id).trim() !== "") {
    return String(actor.dietician_id);
  }
  return null;
}

function invitedFullName(invite) {
  const first = String(invite.invited_first_name ?? "").trim();
  const last = String(invite.invited_last_name ?? "").trim();
  const name = `${first} ${last}`.trim();
  return name !== "" ? name : normalizeEmail(invite.invited_email);
}

function buildInviteLink(rawToken) {
  return `${FRONTEND_ACCEPT_INVITE_URL}?token=${encodeURIComponent(rawToken)}`;
}

function formatInviteResponse(invite) {
  return {
    invitation_id: Number(invite.id),
    invited_first_name: invite.invited_first_name ?? null,
    invited_last_name: invite.invited_last_name ?? null,
    invited_name: invitedFullName(invite),
    invited_email: normalizeEmail(invite.invited_email),
    invited_phone: invite.invited_phone ?? null,
    invited_role: invite.invited_role ?? null,
    partner_code: invite.partner_code ?? null,
    invited_by_user_id: normalizeEmail(invite.invited_by_user_id),
    parent_user_id: normalizeEmail(invite.parent_user_id),
    status: invite.status ?? null,
    expires_at: formatDbDateTime(invite.expires_at),
    sent_at: formatDbDateTime(invite.sent_at),
    created_at: formatDbDateTime(invite.created_at),
    updated_at: formatDbDateTime(invite.updated_at),
    email_sent: true,
  };
}

// ─── Audit log ───────────────────────────────────────────────────────────────

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
    console.error("RESEND_USER_INVITE_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. Returns { actor, actorEmail } or { error: { status, message } }.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(payload.email || payload.user_id || "");

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    return { error: { status: 401, message: "Invalid token user" } };
  }

  // Prefer dietician_id (token subject); fall back to email.
  const [rows] = dieticianId
    ? await pool.execute(
        `
          SELECT
            td.id, td.dietician_id, td.name, td.email,
            aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.status
          FROM table_dietician td
          INNER JOIN app_user_roles aur
            ON LOWER(aur.user_id) = LOWER(td.email)
          WHERE td.dietician_id = ?
          LIMIT 1
        `,
        [dieticianId]
      )
    : await pool.execute(
        `
          SELECT
            td.id, td.dietician_id, td.name, td.email,
            aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.status
          FROM table_dietician td
          INNER JOIN app_user_roles aur
            ON LOWER(aur.user_id) = LOWER(td.email)
          WHERE LOWER(td.email) = LOWER(?)
          LIMIT 1
        `,
        [tokenEmail]
      );

  const actor = rows[0];

  if (!actor) {
    return { error: { status: 403, message: "Actor user not found" } };
  }
  if (String(actor.status) !== "active") {
    return { error: { status: 403, message: "Actor account is not active" } };
  }
  if (!ALLOWED_ACTOR_ROLES.has(String(actor.role))) {
    return { error: { status: 403, message: "Invalid actor role" } };
  }

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

// ─── Invite resolution + manage permission ───────────────────────────────────

/**
 * Read the invitation row (locked) on a transaction connection. Minimum-necessary
 * columns only.
 */
async function getInviteForUpdate(conn, inviteId) {
  const [rows] = await conn.execute(
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
        updated_at
      FROM app_user_invitations
      WHERE id = ?
      LIMIT 1
      FOR UPDATE
    `,
    [inviteId]
  );
  return rows[0] || null;
}

/**
 * Reimplementation of ui_actor_can_manage_invite() using this codebase's network
 * model (see file header ASSUMPTION). Uses the transaction connection so the
 * check is consistent with the locked read.
 */
async function actorCanManageInvite(conn, actor, actorEmail, invite) {
  const role = String(actor.role);
  if (role === "trainer") return false;

  const invitedBy = normalizeEmail(invite.invited_by_user_id);
  const parent = normalizeEmail(invite.parent_user_id);

  if (actorEmail !== "" && (actorEmail === invitedBy || actorEmail === parent)) {
    return true;
  }

  // A super_admin may also manage invites parented to one of its active admins.
  if (role === "super_admin" && parent !== "") {
    const [rows] = await conn.execute(
      `
        SELECT 1 AS hit
        FROM app_user_roles
        WHERE role = 'admin'
          AND status = 'active'
          AND LOWER(user_id) = LOWER(?)
          AND LOWER(parent_user_id) = LOWER(?)
        LIMIT 1
      `,
      [parent, actorEmail]
    );
    if (rows.length > 0) return true;
  }

  return false;
}

// ─── Email via Resend ────────────────────────────────────────────────────────

/**
 * Sends the invite email via Resend. Returns { ok, status?, error?, id? }.
 * Uses the published "admin_trainer_invitation" template; Resend substitutes
 * the {{{VAR}}} placeholders server-side, so no HTML is rendered here.
 */
async function sendResendTemplateEmail(toEmail, subject, templateId, vars) {
  if (!RESEND_API_KEY) {
    return { ok: false, status: 0, error: "RESEND_API_KEY not configured" };
  }

  try {

    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: RESEND_FROM_EMAIL,
        to: [toEmail],
        subject,
        // Send via the published Resend "admin_trainer_invitation" template.
        // Resend rejects html/text/react when a template is supplied; every
        // {{VAR}} the template uses must be present in `vars` or Resend
        // returns 422 (extra variables are ignored). from/subject here
        // override the template's own defaults.
        template: {
          id: templateId,
          variables: vars,
        },
        headers: { "X-Entity-Ref-ID": `invite-${vars.PARTNER_CODE}` },
        tags: [
          { name: "kind", value: "invite_resend" },
          { name: "invited_role", value: String(vars.INVITED_ROLE || "") },
          { name: "template_id", value: String(templateId || "inline") },
        ],
      },
      {
        timeout: 10_000,
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        validateStatus: () => true,
      }
    );

    if (response.status >= 200 && response.status < 300) {
      return { ok: true, status: response.status, id: response.data?.id ?? null };
    }
    return { ok: false, status: response.status, error: response.data ?? "Resend non-2xx response" };
  } catch (err) {
    return { ok: false, status: 0, error: err?.code || err?.message || "Resend request failed" };
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/resend-user-invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "invite_id": 1,                 // required, positive integer
 *     "actor_user_id": ""             // optional; if set, must match token email
 *   }
 */
const resendUserInvite = async (req, res) => {
  // HIPAA: never let intermediaries cache invite responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP validateMethodPost()).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  const body = req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? req.body
    : {};

  const actorUserId = normalizeEmail(body.actor_user_id);
  const inviteId = Number.parseInt(body.invite_id, 10);

  if (!Number.isInteger(inviteId) || inviteId <= 0) {
    return res.status(422).json({ ok: false, message: "Valid invite_id is required" });
  }

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;
  let conn = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "user_invite_resend_denied",
        userId: actorUserId || null,
        role: null,
        partnerCode: null,
        identifier: `invite:${inviteId}`,
        success: false,
        failureReason: resolved.error.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json({ ok: false, message: resolved.error.message });
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getActorEffectivePartnerCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "user_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: `invite:${inviteId}`,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return res.status(403).json({
        ok: false,
        message: "actor_user_id does not match the authenticated user",
      });
    }

    // ── 2. Locked read + validation inside a transaction ────────────────────
    conn = await pool.getConnection();
    await conn.beginTransaction();

    const invite = await getInviteForUpdate(conn, inviteId);

    if (!invite) {
      await conn.rollback();
      conn.release();
      conn = null;
      await writeAuthLogSafe(req, {
        eventType: "user_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: `invite:${inviteId}`,
        success: false,
        failureReason: "Invitation not found",
      });
      return res.status(404).json({ ok: false, message: "Invitation not found" });
    }

    const canManage = await actorCanManageInvite(conn, actor, actorEmail, invite);

    if (!canManage) {
      await conn.rollback();
      conn.release();
      conn = null;
      await writeAuthLogSafe(req, {
        eventType: "user_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: normalizeEmail(invite.invited_email),
        success: false,
        failureReason: "Actor not allowed to resend this invitation",
      });
      return res.status(403).json({ ok: false, message: "You are not allowed to resend this invitation" });
    }

    const status = String(invite.status || "");

    if (status === "accepted" || invite.accepted_at) {
      await conn.rollback();
      conn.release();
      conn = null;
      return res.status(409).json({ ok: false, message: "Accepted invitation cannot be resent" });
    }

    if (status === "revoked") {
      await conn.rollback();
      conn.release();
      conn = null;
      return res.status(409).json({
        ok: false,
        message: "Revoked invitation cannot be resent. Create a new invitation.",
      });
    }

    // Release the lock before the (slow) network email call — same ordering as
    // the PHP. The guarded UPDATE below is the real concurrency protection.
    await conn.commit();
    conn.release();
    conn = null;

    // ── 3. Fresh token + link + expiry (raw token never stored) ─────────────
    const rawToken = crypto.randomBytes(32).toString("hex");
    const tokenHash = secureHash(rawToken);
    const inviteLink = buildInviteLink(rawToken);
    const expiresAt = toUtcMysqlDateTime(
      new Date(Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000)
    );

    const invitedEmail = normalizeEmail(invite.invited_email);
    const invitedRole = String(invite.invited_role || "");
    const fullName = invitedFullName(invite);

    // ── 4. Send the email (nothing is updated until this succeeds) ──────────
    const emailResult = await sendResendTemplateEmail(
      invitedEmail,
      "You have been invited to Respyr",
      RESEND_INVITE_TEMPLATE_ID,
      {
        INVITED_NAME: fullName,
        INVITER_EMAIL: actorEmail,
        INVITED_EMAIL: invitedEmail,
        INVITED_ROLE: invitedRole,
        PARTNER_CODE: invite.partner_code,
        EXPIRES_IN: `${INVITE_EXPIRY_HOURS} hours`,
        INVITE_LINK: inviteLink,
      }
    );

    if (!emailResult.ok) {
      console.error("RESEND_USER_INVITE_EMAIL_FAILED:", {
        invitation_id: inviteId,
        status: emailResult.status,
        error: APP_DEBUG ? emailResult.error : undefined,
      });
      await writeAuthLogSafe(req, {
        eventType: "user_invite_resend_failed",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actor.partner_code ?? null,
        identifier: invitedEmail,
        success: false,
        failureReason: "Invitation email resend failed",
      });
      return res.status(502).json({
        ok: false,
        message: "Invitation email could not be resent",
        ...(APP_DEBUG && { debug_resend_error: emailResult }),
      });
    }

    // ── 5. Persist the resend — guarded against a concurrent accept ─────────
    const [updateResult] = await pool.execute(
      `
        UPDATE app_user_invitations
        SET token_hash = ?,
            status     = 'pending',
            expires_at = ?,
            sent_at    = UTC_TIMESTAMP(),
            updated_at = UTC_TIMESTAMP()
        WHERE id = ?
          AND status <> 'accepted'
          AND accepted_at IS NULL
        LIMIT 1
      `,
      [tokenHash, expiresAt, inviteId]
    );

    if (updateResult.affectedRows === 0) {
      // The invite was accepted between our read and this write — do not claim
      // success. (Belt-and-braces beyond the PHP.)
      await writeAuthLogSafe(req, {
        eventType: "user_invite_resend_failed",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actor.partner_code ?? null,
        identifier: invitedEmail,
        success: false,
        failureReason: "Invite no longer resendable (accepted concurrently)",
      });
      return res.status(409).json({ ok: false, message: "Accepted invitation cannot be resent" });
    }

    // ── 6. Audit success ────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: "user_invite_resent",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actor.partner_code ?? null,
      identifier: invitedEmail,
      success: true,
      failureReason: "Invitation email resent",
    });

    // ── 7. Respond (matches the PHP JSON shape) ─────────────────────────────
    const updatedInvite = {
      ...invite,
      status: "pending",
      expires_at: expiresAt,
      sent_at: toUtcMysqlDateTime(new Date()),
    };

    const response = {
      ok: true,
      message: "Invitation resent successfully",
      data: formatInviteResponse(updatedInvite),
    };

    if (RETURN_INVITE_LINK_FOR_TESTING) {
      response.debug_invite_link = inviteLink;
    }

    return res.status(200).json(response);
  } catch (err) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (_) {
        /* ignore */
      }
      try {
        conn.release();
      } catch (_) {
        /* ignore */
      }
      conn = null;
    }

    console.error("RESEND_USER_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "user_invite_resend_error",
      userId: actorEmail || actorUserId || null,
      role: actorRole,
      partnerCode: actorCode,
      identifier: `invite:${inviteId}`,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { resendUserInvite };