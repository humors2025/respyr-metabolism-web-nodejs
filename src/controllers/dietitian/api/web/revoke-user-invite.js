"use strict";

/**
 * revoke-user-invite.js
 *
 * Converted from: revoke-user-invite.php (+ user-invite-action-common.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/revoke-user-invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin | super_admin (a trainer can never revoke)
 *
 * Behaviour parity with the PHP:
 *  - Looks up the invitation by invite_id (row-locked inside a transaction),
 *    validates the actor may manage it, then:
 *      • 422 if invite_id is missing / not a positive integer,
 *      • 404 if the invite does not exist,
 *      • 403 if the actor is not allowed to manage it,
 *      • 409 if it is already accepted (status='accepted' or accepted_at set)
 *            → "Accepted invitation cannot be revoked",
 *      • 409 if it is already revoked → "Invitation is already revoked".
 *  - Otherwise sets status='revoked', updated_at=UTC now, commits, audits
 *    `user_invite_revoked`, and returns the formatted invite.
 *  - Response shape matches the PHP: { ok, message, data }.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT and
 *    re-fetched from the DB on every call — NOT from body.actor_user_id as the
 *    PHP did (that was an IDOR hole). role + status are re-checked server-side.
 *    body.actor_user_id is still accepted for frontend/back-compat, but it is
 *    only cross-checked against the token email (mismatch → 403); it can never
 *    select another user.
 *  - Fully parameterized queries; the invite is read FOR UPDATE in a transaction
 *    and the revoke UPDATE is guarded against the accepted state so a concurrent
 *    accept always wins (affectedRows === 0 → 409 rather than a false success).
 *  - Internal error details are suppressed in production (gated behind
 *    APP_DEBUG). The PHP echoed raw errors — an info-disclosure finding closed
 *    here.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (identifier, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *  - Every revoke (success, denial, error) is recorded in app_auth_logs, with
 *    the caller-supplied `reason` carried into failure_reason for traceability.
 *
 * ASSUMPTION (documented): the original ui_actor_can_manage_invite() and
 * ui_format_invite_response() lived in user-invite-action-common.php (not
 * provided). They are reimplemented here identically to the already-shipped
 * resend-user-invite.js sibling, using this codebase's network model: an actor
 * may manage an invite they created (invited_by_user_id) or that is parented to
 * them (parent_user_id); a super_admin may additionally manage invites parented
 * to one of its own active admins (one level — no extra recursion). The revoke
 * response intentionally omits the `email_sent` flag the resend formatter adds,
 * since revoking sends no email.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, app_user_invitations, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  resolveActorByDieticianId: sharedResolveActorByDieticianId,
  resolveActorByEmail: sharedResolveActorByEmail,
} = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const DEFAULT_REVOKE_REASON = "Invite revoked";

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

/** Format a mysql2 DATETIME value as a UTC "YYYY-MM-DD HH:MM:SS" string. */
function toUtcMysqlDateTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

function formatDbDateTime(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    return toUtcMysqlDateTime(val);
  }
  return String(val);
}

function getActorEffectivePartnerCode(actor) {
  if (
    actor.partner_code !== null &&
    actor.partner_code !== undefined &&
    String(actor.partner_code).trim() !== ""
  ) {
    return String(actor.partner_code);
  }
  if (
    actor.dietician_id !== null &&
    actor.dietician_id !== undefined &&
    String(actor.dietician_id).trim() !== ""
  ) {
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

/**
 * Mirrors ui_format_invite_response() from the PHP common file (same shape as
 * resend-user-invite.js). The `email_sent` flag is intentionally omitted — this
 * action sends no email.
 */
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
    console.error("REVOKE_USER_INVITE_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. Returns { actor, actorEmail } or { error: { status, message } }.
 *
 * JWT shape: dietician_id in sub/dietician_id; email nested under
 * dietician.email — there is NO top-level email/user_id claim. Resolve by
 * dietician_id first, fall back to email, derive actorEmail from the DB row.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    return { error: { status: 401, message: "Invalid token user" } };
  }

  // Prefer dietician_id (token subject); fall back to email. Dispatched exactly
  // as before, with the shared module performing the lookup + role/status gate.
  const resolved = dieticianId
    ? await sharedResolveActorByDieticianId(dieticianId, ALLOWED_ACTOR_ROLES)
    : await sharedResolveActorByEmail(tokenEmail, ALLOWED_ACTOR_ROLES);

  if (resolved.ok) {
    return { actor: resolved.actor, actorEmail: resolved.actorEmail };
  }

  const REASON_BODY = {
    invalid_token:    { status: 401, message: "Invalid token user" },
    not_found:        { status: 403, message: "Actor user not found" },
    inactive:         { status: 403, message: "Actor account is not active" },
    role_not_allowed: { status: 403, message: "Invalid actor role" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, message: m.message } };
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

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/revoke-user-invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "invite_id": 1,                 // required, positive integer
 *     "reason": "Wrong email",        // optional; defaults to "Invite revoked"
 *     "actor_user_id": ""             // optional; if set, must match token email
 *   }
 */
const revokeUserInvite = async (req, res) => {
  // HIPAA: never let intermediaries cache invite responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP validateMethodPost()).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body)
      ? req.body
      : {};

  const actorUserId = normalizeEmail(body.actor_user_id);
  const inviteId = Number.parseInt(body.invite_id, 10);

  let reason = String(body.reason ?? "").trim();
  if (reason === "") reason = DEFAULT_REVOKE_REASON;
  reason = reason.slice(0, 255);

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
        eventType: "user_invite_revoke_denied",
        userId: actorUserId || null,
        role: null,
        partnerCode: null,
        identifier: `invite:${inviteId}`,
        success: false,
        failureReason: resolved.error.message || "actor resolution failed",
      });
      return res
        .status(resolved.error.status)
        .json({ ok: false, message: resolved.error.message });
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getActorEffectivePartnerCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "user_invite_revoke_denied",
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
        eventType: "user_invite_revoke_denied",
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
        eventType: "user_invite_revoke_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: normalizeEmail(invite.invited_email),
        success: false,
        failureReason: "Actor not allowed to revoke this invitation",
      });
      return res
        .status(403)
        .json({ ok: false, message: "You are not allowed to revoke this invitation" });
    }

    const status = String(invite.status || "");

    if (status === "accepted" || invite.accepted_at) {
      await conn.rollback();
      conn.release();
      conn = null;
      return res
        .status(409)
        .json({ ok: false, message: "Accepted invitation cannot be revoked" });
    }

    if (status === "revoked") {
      await conn.rollback();
      conn.release();
      conn = null;
      return res
        .status(409)
        .json({ ok: false, message: "Invitation is already revoked" });
    }

    // ── 3. Revoke — guarded against a concurrent accept ─────────────────────
    const [updateResult] = await conn.execute(
      `
        UPDATE app_user_invitations
        SET status     = 'revoked',
            updated_at = UTC_TIMESTAMP()
        WHERE id = ?
          AND status <> 'accepted'
          AND accepted_at IS NULL
        LIMIT 1
      `,
      [inviteId]
    );

    if (updateResult.affectedRows === 0) {
      // The invite was accepted between our read and this write — do not claim
      // success. (Belt-and-braces beyond the PHP.)
      await conn.rollback();
      conn.release();
      conn = null;
      await writeAuthLogSafe(req, {
        eventType: "user_invite_revoke_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: normalizeEmail(invite.invited_email),
        success: false,
        failureReason: "Invite no longer revocable (accepted concurrently)",
      });
      return res
        .status(409)
        .json({ ok: false, message: "Accepted invitation cannot be revoked" });
    }

    await conn.commit();
    conn.release();
    conn = null;

    // ── 4. Audit success ────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: "user_invite_revoked",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actor.partner_code ?? null,
      identifier: normalizeEmail(invite.invited_email),
      success: true,
      failureReason: reason,
    });

    // ── 5. Respond (matches the PHP JSON shape) ─────────────────────────────
    const updatedInvite = {
      ...invite,
      status: "revoked",
      updated_at: toUtcMysqlDateTime(new Date()),
    };

    return res.status(200).json({
      ok: true,
      message: "Invitation revoked successfully",
      data: formatInviteResponse(updatedInvite),
    });
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

    console.error("REVOKE_USER_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "user_invite_revoke_error",
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

module.exports = { revokeUserInvite };
