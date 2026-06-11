"use strict";

/**
 * super-admin-trainers-summary.js
 *
 * Converted from: super-admin-trainers-summary.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/super-admin-trainers-summary
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin only
 *
 * Behaviour parity with the PHP:
 *  - Expires stale pending *direct* trainer invites under this super admin, then
 *    returns four buckets scoped to direct reports: accepted trainers +
 *    pending/expired/revoked invites, each paginated independently with the same
 *    page/limit/offset.
 *  - The super admin is themselves the first "accepted trainer" row (when their
 *    effective partner code exists and offset === 0). That self row consumes one
 *    slot of the page; the DB offset for network trainers is shifted accordingly.
 *  - Accepted-trainer rows are de-duplicated by effective partner code (self code
 *    pre-seeded), carry per-trainer clients_count / client_invites_count, and the
 *    is_self / is_admin_as_trainer / is_super_admin_as_trainer flags.
 *  - Invite rows carry can_resend / can_revoke (true for pending|expired).
 *  - Scope: super admin self + direct trainers only. Trainer admins and trainers
 *    under trainer admins are intentionally excluded (same as PHP).
 *  - Counts: accepted = self (1 if code present) + COUNT(DISTINCT effective code)
 *    of direct active trainers; invite buckets count by status.
 *  - Response keys/shape match the PHP (ok, mode, title, actor, scope, summary,
 *    pagination, accepted_trainers, pending_invites, expired_invites,
 *    revoked_invites). limit clamped to 1..10, page floored at 1.
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
 *  - Pending-invite expiry / freshness uses UTC_TIMESTAMP() (how this app stores
 *    invites) instead of the PHP NOW(), which is TZ-dependent on a shared pool.
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

/** PHP sas_get_actor_effective_partner_code(): partner_code, else dietician_id, else null. */
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

/** PHP sas_get_effective_code_from_row(): partner_code, else dietician_id, else null. */
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
 * the same gates as PHP sas_get_super_admin_actor_by_email_or_fail(): active,
 * role = super_admin. Returns { actor, actorEmail } or { error }.
 *
 * Selects the extra role_id / role_created_at / role_updated_at /
 * dietician_joined_at columns the self-as-trainer row needs.
 */
async function resolveSuperAdminFromToken(req) {
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
        td.dttm AS dietician_joined_at,

        aur.id AS role_id,
        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        aur.status,
        aur.email_verified_at,
        aur.created_at AS role_created_at,
        aur.updated_at AS role_updated_at
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

  if (String(actor.role) !== "super_admin") {
    return {
      error: { status: 403, body: { ok: false, error: "Only super admin can access this API" } },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Housekeeping ────────────────────────────────────────────────────────────

/** Expire only the direct pending trainer invites under this super admin. */
async function expireOldPendingDirectInvites(superEmail) {
  try {
    await pool.execute(
      `
        UPDATE app_user_invitations
        SET status     = 'expired',
            updated_at = UTC_TIMESTAMP()
        WHERE invited_role = 'trainer'
          AND status       = 'pending'
          AND expires_at  <= UTC_TIMESTAMP()
          AND LOWER(parent_user_id) = LOWER(?)
      `,
      [superEmail]
    );
  } catch (err) {
    // Non-fatal — a stale "pending" row is better than a 500.
    console.error("EXPIRE_PENDING_DIRECT_INVITES_FAILED:", err?.code || err?.message);
  }
}

// ─── Counts ──────────────────────────────────────────────────────────────────

/**
 * Accepted = the super admin themselves (1 if they have an effective code) plus
 * the distinct effective codes of direct active trainers under them. Mirrors PHP
 * sas_count_direct_accepted_trainers_for_super_admin().
 */
async function countDirectAcceptedTrainers(actor, superEmail) {
  const selfCount = getActorEffectivePartnerCode(actor) !== null ? 1 : 0;

  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(DISTINCT UPPER(COALESCE(
                 NULLIF(aur.partner_code, ''),
                 NULLIF(td.dietician_id, ''),
                 aur.user_id
               ))) AS total
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
      `,
      [superEmail]
    );
    return selfCount + toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_DIRECT_ACCEPTED_TRAINERS_FAILED:", err?.code || err?.message);
    return selfCount;
  }
}

async function countDirectTrainerInvitesByStatus(superEmail, status) {
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
        [superEmail]
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
      [status, superEmail]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_DIRECT_TRAINER_INVITES_FAILED:", err?.code || err?.message);
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

// ─── Accepted direct trainers list ───────────────────────────────────────────

/**
 * The super admin as their own first "accepted trainer" row. Mirrors the
 * self-row block in PHP sas_get_direct_accepted_trainers_for_super_admin().
 */
async function buildSelfTrainerRow(actor, selfCode) {
  const joinedDate =
    (actor.role_created_at !== null && actor.role_created_at !== undefined && actor.role_created_at !== "")
      ? actor.role_created_at
      : ((actor.dietician_joined_at !== null && actor.dietician_joined_at !== undefined && actor.dietician_joined_at !== "")
        ? actor.dietician_joined_at
        : null);

  const joinedDateStr = toMysqlDateTime(joinedDate);

  return {
    role_id: actor.role_id !== null && actor.role_id !== undefined ? toInt(actor.role_id) : 0,
    user_id: normalizeEmail(actor.email),
    name: actor.name ?? null,
    email: normalizeEmail(actor.email),
    phone_no: actor.phone_no ?? null,
    location: actor.location ?? null,

    role: "trainer",
    actual_role: "super_admin",
    display_role: "trainer",

    partner_code: selfCode,
    dietician_id: actor.dietician_id ?? selfCode,
    parent_user_id: actor.parent_user_id !== null && actor.parent_user_id !== undefined
      ? normalizeEmail(actor.parent_user_id)
      : null,
    status: actor.status ?? "active",
    email_verified_at: toMysqlDateTime(actor.email_verified_at),

    is_reset_password: actor.is_reset_password === null || actor.is_reset_password === undefined
      ? null
      : toInt(actor.is_reset_password),

    clients_count: await countClientsForPartnerCode(selfCode),
    client_invites_count: await countClientInvitesForCode(selfCode),

    created_at: joinedDateStr,
    joined_date: joinedDateStr,
    updated_at: toMysqlDateTime(actor.role_updated_at),

    is_self: true,
    is_admin_as_trainer: false,
    is_super_admin_as_trainer: true,

    can_resend: false,
    can_revoke: false,
  };
}

async function getDirectAcceptedTrainers(actor, superEmail, limit, offset) {
  const rows = [];

  const selfCode = getActorEffectivePartnerCode(actor);
  const hasSelfCode = selfCode !== null && String(selfCode).trim() !== "";

  // The super admin occupies the first accepted-trainer slot (page 1 only).
  if (offset === 0 && hasSelfCode) {
    rows.push(await buildSelfTrainerRow(actor, selfCode));
    limit = limit - 1;
  }

  if (limit <= 0) {
    return rows;
  }

  // Shift the DB offset because the self row consumed one slot.
  let networkOffset = offset;
  if (hasSelfCode) {
    networkOffset = offset === 0 ? 0 : Math.max(0, offset - 1);
  }

  const safeLimit = Math.max(0, toInt(limit));
  const safeOffset = Math.max(0, toInt(networkOffset));

  const [dbRows] = await pool.execute(
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
    [superEmail]
  );

  // De-dup by effective partner code; pre-seed the self code (PHP parity).
  const seenCodes = new Set();
  if (hasSelfCode) {
    seenCodes.add(String(selfCode).toUpperCase());
  }

  // Sequential awaits mirror the PHP and keep the shared mysql2 pool unstressed.
  for (const row of dbRows) {
    const partnerCode = getEffectiveCodeFromRow(row);
    const codeKey = String(partnerCode ?? "").toUpperCase();

    if (codeKey !== "" && seenCodes.has(codeKey)) {
      continue;
    }
    if (codeKey !== "") {
      seenCodes.add(codeKey);
    }

    rows.push({
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
      joined_date: toMysqlDateTime(row.created_at),
      updated_at: toMysqlDateTime(row.updated_at),

      is_self: false,
      is_admin_as_trainer: false,
      is_super_admin_as_trainer: false,

      can_resend: false,
      can_revoke: false,
    });
  }

  return rows;
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
    joined_date: toMysqlDateTime(row.created_at),
    updated_at: toMysqlDateTime(row.updated_at),

    can_resend: canAct,
    can_revoke: canAct,
  };
}

async function getDirectTrainerInvitesByStatus(superEmail, status, limit, offset) {
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
      [superEmail]
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
      [status, superEmail]
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
 * POST /dietitian/api/web/super-admin-trainers-summary
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "page": 1,
 *     "limit": 10,           // optional, clamped to 1..10
 *     "actor_user_id": ""    // optional; if set, must match the token email
 *   }
 */
const superAdminTrainersSummary = async (req, res) => {
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
    // ── 1. Resolve + authorize actor from JWT (super_admin only) ────────────
    const resolved = await resolveSuperAdminFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "super_admin_dir_trainer_sum_denied",
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
        eventType: "super_admin_dir_trainer_sum_denied",
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

    // ── 2. Expire stale pending direct trainer invites before counting ──────
    await expireOldPendingDirectInvites(actorEmail);

    // ── 3. Bucket totals ────────────────────────────────────────────────────
    const [acceptedTotal, pendingTotal, expiredTotal, revokedTotal] = await Promise.all([
      countDirectAcceptedTrainers(actor, actorEmail),
      countDirectTrainerInvitesByStatus(actorEmail, "pending"),
      countDirectTrainerInvitesByStatus(actorEmail, "expired"),
      countDirectTrainerInvitesByStatus(actorEmail, "revoked"),
    ]);

    // ── 4. Paginated bucket rows ────────────────────────────────────────────
    // accepted-trainers list awaits sequentially internally; run the three
    // invite lists in parallel alongside it.
    const [acceptedTrainers, pendingInvites, expiredInvites, revokedInvites] =
      await Promise.all([
        getDirectAcceptedTrainers(actor, actorEmail, limit, offset),
        getDirectTrainerInvitesByStatus(actorEmail, "pending", limit, offset),
        getDirectTrainerInvitesByStatus(actorEmail, "expired", limit, offset),
        getDirectTrainerInvitesByStatus(actorEmail, "revoked", limit, offset),
      ]);

    // ── 5. Audit — success (fire-and-forget) ────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "super_admin_dir_trainer_sum_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: true,
      failureReason: "Super admin viewed direct trainer summary",
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      ok: true,
      mode: "super_admin_direct_trainers_summary",
      title: "Super Admin Direct Trainer Summary",

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
        parent_user_id: actor.parent_user_id ?? null,
        name: actor.name ?? null,
        email: normalizeEmail(actor.email),
      },

      scope: {
        includes_super_admin_self_as_trainer: true,
        includes_direct_trainers_under_super_admin: true,
        includes_trainer_admins: false,
        includes_trainers_under_trainer_admins: false,
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
    console.error("SUPER_ADMIN_DIRECT_TRAINERS_SUMMARY_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "super_admin_dir_trainer_sum_error",
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

module.exports = { superAdminTrainersSummary };
