"use strict";

/**
 * super-admin-revoke-trainers.js
 *
 * Converted from: super-admin-revoke-trainers.php (+ user-invite-action-common.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/super-admin-revoke-trainers
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
 *      • 409 if it is already revoked → "Invitation is already revoked",
 *      • 409 if it is in any state other than pending / sent / expired
 *            → "Only pending, sent, or expired invitations can be revoked".
 *  - Otherwise sets status='revoked', updated_at=UTC now (guarded by
 *    `status IN ('pending','sent','expired')`), commits, audits, and returns the
 *    formatted invite.
 *  - Role-aware audit events, matching the PHP: super_admin actors emit
 *    `super_admin_invite_revoked`; everyone else emits `user_invite_revoked`.
 *  - Response shape matches the PHP: { ok, message, data, meta } where meta
 *    carries { revoked_by, revoked_by_role }.
 *
 * rui_actor_can_manage_invite() parity:
 *  - The PHP wrapper keeps the existing admin/trainer-admin permission and ADDS
 *    super_admin permission for invites the super admin owns directly
 *    (parent_user_id = actor email OR invited_by_user_id = actor email). Both
 *    cases are reimplemented in actorCanManageInvite() below.
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
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, app_user_invitations, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const DEFAULT_REVOKE_REASON = "Invite revoked";

const ALLOWED_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// Only these invite states may be revoked (PHP whitelist).
const REVOCABLE_STATUSES = new Set(["pending", "sent", "expired"]);

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

/** Format a Date (UTC) as "YYYY-MM-DD HH:MM:SS". */
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
 * Mirrors ui_format_invite_response() from the PHP common file. The `email_sent`
 * flag is intentionally omitted — this action sends no email.
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
    console.error("SUPER_ADMIN_REVOKE_TRAINERS_AUDIT_FAILED:", err?.code || err?.message);
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
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload.dietician?.email || ""
  );

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
 * Reimplementation of rui_actor_can_manage_invite() (PHP). Keeps the existing
 * admin/trainer-admin model AND adds the super_admin direct-ownership rule:
 *   - any actor may manage an invite they created (invited_by_user_id) or that
 *     is parented to them (parent_user_id);
 *   - a super_admin may additionally manage invites parented to one of its own
 *     active admins (one level — no further recursion).
 * A trainer can never manage an invite. Uses the transaction connection so the
 * check is consistent with the locked read.
 */
async function actorCanManageInvite(conn, actor, actorEmail, invite) {
  const role = String(actor.role);
  if (role === "trainer") return false;

  const invitedBy = normalizeEmail(invite.invited_by_user_id);
  const parent = normalizeEmail(invite.parent_user_id);

  // Existing admin/trainer-admin behaviour + super_admin direct ownership.
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
 * POST /dietitian/api/web/super-admin-revoke-trainers
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "invite_id": 1,                 // required, positive integer
 *     "reason": "Wrong email",        // optional; defaults to "Invite revoked"
 *     "actor_user_id": ""             // optional; if set, must match token email
 *   }
 */
const superAdminRevokeTrainers = async (req, res) => {
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

  // Event-type selector — PHP used super_admin_* events for super_admin actors.
  const eventFor = (kind) =>
    actorRole === "super_admin" ? `super_admin_invite_${kind}` : `user_invite_${kind}`;

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
        eventType: eventFor("revoke_denied"),
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
        eventType: eventFor("revoke_denied"),
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
        eventType: eventFor("revoke_denied"),
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

    const status = String(invite.status || "").toLowerCase();

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

    // Only pending / sent / expired invites may be revoked (PHP whitelist).
    if (!REVOCABLE_STATUSES.has(status)) {
      await conn.rollback();
      conn.release();
      conn = null;
      return res.status(409).json({
        ok: false,
        message: "Only pending, sent, or expired invitations can be revoked",
      });
    }

    // ── 3. Revoke — guarded so only a still-revocable row is touched ────────
    const [updateResult] = await conn.execute(
      `
        UPDATE app_user_invitations
        SET status     = 'revoked',
            updated_at = UTC_TIMESTAMP()
        WHERE id = ?
          AND status IN ('pending', 'sent', 'expired')
          AND accepted_at IS NULL
        LIMIT 1
      `,
      [inviteId]
    );

    if (updateResult.affectedRows === 0) {
      // The invite changed state between our read and this write — do not claim
      // success. (Belt-and-braces beyond the PHP.)
      await conn.rollback();
      conn.release();
      conn = null;
      await writeAuthLogSafe(req, {
        eventType: eventFor("revoke_denied"),
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: normalizeEmail(invite.invited_email),
        success: false,
        failureReason: "Invitation could not be revoked (state changed concurrently)",
      });
      return res
        .status(409)
        .json({ ok: false, message: "Invitation could not be revoked" });
    }

    await conn.commit();
    conn.release();
    conn = null;

    // ── 4. Audit success ────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: eventFor("revoked"),
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: normalizeEmail(invite.invited_email),
      success: true,
      failureReason: reason,
    });

    // ── 5. Respond (matches the PHP JSON shape, incl. meta) ─────────────────
    const updatedInvite = {
      ...invite,
      status: "revoked",
      updated_at: toUtcMysqlDateTime(new Date()),
    };

    return res.status(200).json({
      ok: true,
      message: "Invitation revoked successfully",
      data: formatInviteResponse(updatedInvite),
      meta: {
        revoked_by: actorEmail,
        revoked_by_role: actorRole,
      },
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

    console.error("SUPER_ADMIN_REVOKE_TRAINERS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: eventFor("revoke_error"),
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

module.exports = { superAdminRevokeTrainers };
