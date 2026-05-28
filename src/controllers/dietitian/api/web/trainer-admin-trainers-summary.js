"use strict";

/**
 * trainer-admin-trainers-summary.js
 *
 * Converted from: trainer-admin-trainers-summary.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/trainer-admin-trainers-summary
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin (trainer admin) only
 *
 * Behaviour parity with the PHP:
 *  - Expires stale pending trainer invites, then returns four buckets for the
 *    actor's network: accepted trainers + pending/expired/revoked invites, each
 *    paginated independently with the same page/limit/offset.
 *  - Accepted-trainer rows carry per-trainer clients_count and
 *    client_invites_count. Invite rows carry can_resend / can_revoke flags
 *    (true for pending|expired).
 *  - summary block totals each bucket + grand total; pagination block exposes a
 *    *_has_more flag per bucket.
 *  - Response keys/shape match the PHP (ok, mode, title, actor, summary,
 *    pagination, accepted_trainers, pending_invites, expired_invites,
 *    revoked_invites). limit is clamped to 1..10, page floored at 1 — same as
 *    the PHP.
 *  - Same DB tables only: table_dietician, app_user_roles, app_user_invitations,
 *    table_clients, trainer_client_invites, app_auth_logs. Nothing added/removed.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (sub = dietician_id) and re-checked against the DB on every call. The PHP
 *    trusted body.actor_user_id (IDOR / privilege escalation). actor_user_id is
 *    still accepted for frontend/back-compat, but only cross-checked against the
 *    token email (mismatch → 403); it can never select a different user. role,
 *    status, and partner-code presence are re-verified server-side.
 *  - LIMIT/OFFSET are hard-coerced to non-negative integers and inlined (mysql2
 *    prepared statements reject bound LIMIT/OFFSET on some MySQL builds). All
 *    other values are bound parameters — no string interpolation of user input.
 *  - Internal error details suppressed in production (PHP echoed debug_error) —
 *    gated behind APP_DEBUG here.
 *  - Pending-invite expiry uses UTC_TIMESTAMP() (how this app stores invites)
 *    instead of the PHP NOW(), which is TZ-dependent on a shared pool.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT * over PHI rows.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text.
 *  - Server logs carry only error metadata (code/errno/sqlState), never row data.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const MAX_LIMIT = 10;
const DEFAULT_LIMIT = 10;

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string"
    ? val.trim().toLowerCase()
    : String(val ?? "").trim().toLowerCase();
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

/** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS" (matches PHP string output). */
function toMysqlDateTime(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return (
      `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
      `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
    );
  }
  return String(val);
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

/** PHP get_actor_effective_partner_code(): partner_code, else dietician_id, else null. */
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

/** PHP get_effective_code_from_row(): partner_code, else dietician_id, else null. */
function getEffectiveCodeFromRow(row) {
  if (row.partner_code !== null && row.partner_code !== undefined &&
      String(row.partner_code).trim() !== "") {
    return String(row.partner_code);
  }
  if (row.dietician_id !== null && row.dietician_id !== undefined &&
      String(row.dietician_id).trim() !== "") {
    return String(row.dietician_id);
  }
  return null;
}

// ─── Audit log ───────────────────────────────────────────────────────────────

/**
 * Fail-safe audit writer mirroring the sibling controllers. Never throws.
 *   app_auth_logs(event_type, user_id, role, partner_code, identifier_hash,
 *                 ip_hash, user_agent_hash, session_id_hash, success, failure_reason)
 */
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
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and enforce
 * the same gates as PHP get_actor_by_email_or_fail(): active, role = admin, and
 * a usable partner code. Returns { actor, actorEmail } or { error }.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return { error: { status: 401, body: { ok: false, error: "Invalid token user" } } };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.id,
        td.dietician_id,
        td.name,
        td.phone_no,
        td.email,
        td.location,
        td.is_reset_password,

        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        aur.status,
        aur.email_verified_at
      FROM table_dietician td
      INNER JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE td.dietician_id = ?
      LIMIT 1
    `,
    [dieticianId]
  );

  const actor = rows[0];

  if (!actor) {
    return { error: { status: 403, body: { ok: false, error: "Actor user not found" } } };
  }

  if (String(actor.status) !== "active") {
    return { error: { status: 403, body: { ok: false, error: "Actor account is not active" } } };
  }

  if (String(actor.role) !== "admin") {
    return {
      error: { status: 403, body: { ok: false, error: "Only trainer admin can access this API" } },
    };
  }

  const hasPartnerCode =
    (actor.partner_code !== null && actor.partner_code !== undefined &&
      String(actor.partner_code).trim() !== "") ||
    (actor.dietician_id !== null && actor.dietician_id !== undefined &&
      String(actor.dietician_id).trim() !== "");

  if (!hasPartnerCode) {
    return {
      error: { status: 403, body: { ok: false, error: "Trainer admin partner code missing" } },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Housekeeping ────────────────────────────────────────────────────────────

async function expireOldPendingInvites() {
  try {
    await pool.execute(
      `
        UPDATE app_user_invitations
        SET status     = 'expired',
            updated_at = UTC_TIMESTAMP()
        WHERE invited_role = 'trainer'
          AND status       = 'pending'
          AND expires_at  <= UTC_TIMESTAMP()
      `
    );
  } catch (err) {
    // Non-fatal — a stale "pending" row is better than a 500.
    console.error("EXPIRE_PENDING_INVITES_FAILED:", err?.code || err?.message);
  }
}

// ─── Counts ──────────────────────────────────────────────────────────────────

async function countAcceptedTrainers(adminEmail) {
  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM app_user_roles aur
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
      `,
      [adminEmail]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_ACCEPTED_TRAINERS_FAILED:", err?.code || err?.message);
    return 0;
  }
}

async function countTrainerInvitesByStatus(adminEmail, status) {
  try {
    if (status === "pending") {
      const [rows] = await pool.execute(
        `
          SELECT COUNT(*) AS total
          FROM app_user_invitations
          WHERE invited_role = 'trainer'
            AND status = 'pending'
            AND expires_at > UTC_TIMESTAMP()
            AND LOWER(parent_user_id) = LOWER(?)
        `,
        [adminEmail]
      );
      return toInt(rows[0]?.total);
    }

    const [rows] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM app_user_invitations
        WHERE invited_role = 'trainer'
          AND status = ?
          AND LOWER(parent_user_id) = LOWER(?)
      `,
      [status, adminEmail]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_TRAINER_INVITES_FAILED:", err?.code || err?.message);
    return 0;
  }
}

// ─── Per-trainer client counts ───────────────────────────────────────────────

async function countClientsForPartnerCode(partnerCode) {
  if (partnerCode === null || partnerCode === undefined || String(partnerCode).trim() === "") {
    return 0;
  }
  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(DISTINCT profile_id) AS total
        FROM table_clients
        WHERE UPPER(dietician_id) = UPPER(?)
      `,
      [partnerCode]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_CLIENTS_PARTNER_FAILED:", err?.code || err?.message);
    return 0;
  }
}

async function countClientInvitesForCode(partnerCode) {
  if (partnerCode === null || partnerCode === undefined || String(partnerCode).trim() === "") {
    return 0;
  }
  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM trainer_client_invites
        WHERE UPPER(trainer_code) = UPPER(?)
           OR UPPER(trainer_id) = UPPER(?)
      `,
      [partnerCode, partnerCode]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_CLIENT_INVITES_CODE_FAILED:", err?.code || err?.message);
    return 0;
  }
}

// ─── Accepted trainers list ──────────────────────────────────────────────────

async function getAcceptedTrainers(adminEmail, limit, offset) {
  const safeLimit = Math.max(0, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

  const [rows] = await pool.execute(
    `
      SELECT
        aur.id AS role_id,
        aur.user_id,
        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        aur.status,
        aur.email_verified_at,
        aur.created_at,
        aur.updated_at,

        td.dietician_id,
        td.name,
        td.email,
        td.phone_no,
        td.location,
        td.is_reset_password
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE aur.role = 'trainer'
        AND aur.status = 'active'
        AND LOWER(aur.parent_user_id) = LOWER(?)
      ORDER BY aur.created_at DESC, aur.id DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [adminEmail]
  );

  const out = [];

  // Sequential awaits mirror the PHP and keep the shared mysql2 pool unstressed.
  for (const row of rows) {
    const partnerCode = getEffectiveCodeFromRow(row);

    out.push({
      role_id: toInt(row.role_id),
      user_id: normalizeEmail(row.user_id),
      name: row.name ?? null,
      email: normalizeEmail(row.email),
      phone_no: row.phone_no ?? null,
      location: row.location ?? null,

      role: "trainer",
      actual_role: "trainer",
      display_role: "trainer",

      partner_code: partnerCode,
      dietician_id: row.dietician_id ?? null,
      parent_user_id: normalizeEmail(row.parent_user_id),
      status: row.status ?? null,
      email_verified_at: toMysqlDateTime(row.email_verified_at),

      is_reset_password: row.is_reset_password === null || row.is_reset_password === undefined
        ? null
        : toInt(row.is_reset_password),

      clients_count: await countClientsForPartnerCode(partnerCode),
      client_invites_count: await countClientInvitesForCode(partnerCode),

      created_at: toMysqlDateTime(row.created_at),
      updated_at: toMysqlDateTime(row.updated_at),

      can_resend: false,
      can_revoke: false,
    });
  }

  return out;
}

// ─── Invite lists ────────────────────────────────────────────────────────────

function formatInviteRow(row) {
  const firstName = String(row.invited_first_name ?? "").trim();
  const lastName = String(row.invited_last_name ?? "").trim();
  const name = `${firstName} ${lastName}`.trim();

  const status = String(row.status ?? "").toLowerCase();
  const canAct = status === "pending" || status === "expired";

  return {
    invitation_id: toInt(row.id),
    name,
    first_name: firstName,
    last_name: lastName,
    email: normalizeEmail(row.invited_email),
    phone_no: row.invited_phone ?? null,

    role: row.invited_role ?? null,
    partner_code: row.partner_code ?? null,
    invited_by_user_id: normalizeEmail(row.invited_by_user_id),
    parent_user_id: normalizeEmail(row.parent_user_id),
    status: row.status ?? null,

    expires_at: toMysqlDateTime(row.expires_at),
    sent_at: toMysqlDateTime(row.sent_at),
    accepted_at: toMysqlDateTime(row.accepted_at),
    created_at: toMysqlDateTime(row.created_at),
    updated_at: toMysqlDateTime(row.updated_at),

    can_resend: canAct,
    can_revoke: canAct,
  };
}

async function getTrainerInvitesByStatus(adminEmail, status, limit, offset) {
  const safeLimit = Math.max(0, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

  let rows;
  if (status === "pending") {
    [rows] = await pool.execute(
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
        WHERE invited_role = 'trainer'
          AND status = 'pending'
          AND expires_at > UTC_TIMESTAMP()
          AND LOWER(parent_user_id) = LOWER(?)
        ORDER BY created_at DESC, id DESC
        LIMIT ${safeLimit} OFFSET ${safeOffset}
      `,
      [adminEmail]
    );
  } else {
    [rows] = await pool.execute(
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
        WHERE invited_role = 'trainer'
          AND status = ?
          AND LOWER(parent_user_id) = LOWER(?)
        ORDER BY updated_at DESC, id DESC
        LIMIT ${safeLimit} OFFSET ${safeOffset}
      `,
      [status, adminEmail]
    );
  }

  return rows.map(formatInviteRow);
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(req) {
  const src = req.body && typeof req.body === "object" ? req.body : {};

  let page = parseInt(src.page, 10);
  if (!Number.isFinite(page) || page <= 0) page = 1;

  let limit = parseInt(src.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > MAX_LIMIT) {
    limit = DEFAULT_LIMIT;
  }

  // Optional. Accepted for frontend/back-compat, never authoritative — see the
  // cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);

  return { page, limit, offset: (page - 1) * limit, actorUserId };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/trainer-admin-trainers-summary
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "page": 1,
 *     "limit": 10,           // optional, clamped to 1..10
 *     "actor_user_id": ""    // optional; if set, must match the token email
 *   }
 */
const trainerAdminTrainersSummary = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const { page, limit, offset, actorUserId } = parseInputs(req);

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT (admin only) ──────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_admin_trainer_summary_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: String(req.user?.sub || req.user?.dietician_id || ""),
        success: false,
        failureReason: resolved.error.body?.error || "actor resolution failed",
      });
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getActorEffectivePartnerCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_admin_trainer_summary_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorUserId,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return res.status(403).json({
        ok: false,
        error: "actor_user_id does not match the authenticated user",
      });
    }

    // ── 2. Expire stale pending trainer invites before counting ─────────────
    await expireOldPendingInvites();

    // ── 3. Bucket totals ────────────────────────────────────────────────────
    const [acceptedTotal, pendingTotal, expiredTotal, revokedTotal] = await Promise.all([
      countAcceptedTrainers(actorEmail),
      countTrainerInvitesByStatus(actorEmail, "pending"),
      countTrainerInvitesByStatus(actorEmail, "expired"),
      countTrainerInvitesByStatus(actorEmail, "revoked"),
    ]);

    // ── 4. Paginated bucket rows ────────────────────────────────────────────
    const [acceptedTrainers, pendingInvites, expiredInvites, revokedInvites] =
      await Promise.all([
        getAcceptedTrainers(actorEmail, limit, offset),
        getTrainerInvitesByStatus(actorEmail, "pending", limit, offset),
        getTrainerInvitesByStatus(actorEmail, "expired", limit, offset),
        getTrainerInvitesByStatus(actorEmail, "revoked", limit, offset),
      ]);

    // ── 5. Audit — success (fire-and-forget) ────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "trainer_admin_trainer_summary_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: true,
      failureReason: "Trainer admin viewed trainer summary",
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      ok: true,
      mode: "trainer_admin_trainers_summary",
      title: "Trainer Summary",

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
        parent_user_id: actor.parent_user_id ?? null,
        name: actor.name ?? null,
        email: normalizeEmail(actor.email),
      },

      summary: {
        accepted_count: acceptedTotal,
        pending_count: pendingTotal,
        expired_count: expiredTotal,
        revoked_count: revokedTotal,
        total_count: acceptedTotal + pendingTotal + expiredTotal + revokedTotal,
      },

      pagination: {
        page,
        limit,
        offset,
        accepted_has_more: offset + limit < acceptedTotal,
        pending_has_more: offset + limit < pendingTotal,
        expired_has_more: offset + limit < expiredTotal,
        revoked_has_more: offset + limit < revokedTotal,
      },

      accepted_trainers: acceptedTrainers,
      pending_invites: pendingInvites,
      expired_invites: expiredInvites,
      revoked_invites: revokedInvites,
    });
  } catch (err) {
    console.error("TRAINER_ADMIN_TRAINERS_SUMMARY_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "trainer_admin_trainer_summary_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok: false,
      error: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { trainerAdminTrainersSummary };
