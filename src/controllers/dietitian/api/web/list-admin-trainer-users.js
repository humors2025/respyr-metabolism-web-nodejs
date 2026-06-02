"use strict";

/**
 * list-admin-trainer-users.js
 *
 * Converted from: list-admin-trainer-users.php  (the "no-JWT" testing variant)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/list-admin-trainer-users
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin (sees self + admins) | admin (sees self + trainers)
 *
 * Behaviour parity with PHP:
 *  - super_admin → self trainer-admin row (first) + accepted admins under them
 *                  + pending/expired/revoked admin invites + rich totals.
 *  - admin       → self trainer row (first) + accepted trainers under them
 *                  + pending/expired/revoked trainer invites + rich totals.
 *  - trainer / any other role → 403.
 *  - JSON shape (keys, ordering, totals block, datetime strings) matches PHP.
 *
 * Hardening differences from PHP (intentional):
 *  - The PHP file is explicitly a "Temporary no-JWT version" that trusts a
 *    body-supplied `actor_user_id`. That is a privilege-escalation / IDOR
 *    vector — any caller could read another tenant's whole network. This Node
 *    version derives the actor from the VERIFIED JWT (sub = dietician_id),
 *    re-checks role/status against the DB on every call, and ignores
 *    req.body.actor_user_id entirely.
 *  - Internal error details are suppressed in production. The PHP always
 *    echoed `debug_error` (raw exception text) — gated behind APP_DEBUG here.
 *  - Invite expiry comparisons use UTC_TIMESTAMP() to match how this app
 *    stores invites, instead of the PHP NOW() (TZ-dependent).
 *  - Fully parameterized queries — zero string interpolation.
 *
 * RECONSTRUCTED FUNCTION (please review):
 *  - getAdminSelfTrainerRow() — the PHP calls get_admin_self_trainer_row()
 *    in the admin branch, but that function is NOT defined in the source you
 *    provided. It has been reconstructed by analogy with
 *    get_super_admin_self_row(): the admin appears as the first "trainer" row
 *    (is_self=true) with clients counted from their own partner_code. Adjust
 *    the role/display_role/flags below if your intended shape differs.
 *
 * HIPAA Controls applied:
 *  - Minimum-necessary data: only required columns selected. No SELECT *.
 *  - PHI in audit logs (email, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER. Raw PHI never lands in app_auth_logs.
 *  - Structured server-side logs contain only error metadata, never row data.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 */

const crypto = require("crypto");
const pool   = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string" ? val.trim().toLowerCase() : "";
}

function lowerStr(val) {
  return val === null || val === undefined ? "" : String(val).toLowerCase();
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Format a mysql2 DATETIME value as "YYYY-MM-DD HH:MM:SS" to match the PHP
 * response shape. Accepts Date objects (mysql2 default) and strings.
 */
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

function nullableInt(val) {
  return val === null || val === undefined ? null : Number(val);
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

/**
 * Effective partner code: partner_code if set, else dietician_id, else null.
 * Mirrors PHP get_actor_effective_partner_code().
 */
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

/**
 * Fail-safe audit log writer. Schema mirrors writeAuthLogSafe() in the sibling
 * controllers. Never throws — audit failures must not surface to clients.
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
    const ipHash         = authLogHash(getClientIp(req));
    const userAgentHash  = authLogHash(getUserAgent(req));
    const identifierHash = identifier !== null && identifier !== undefined
      ? authLogHash(identifier)
      : null;

    const truncatedEvent = String(eventType || "").slice(0, 60);
    const truncatedReason =
      failureReason !== null && failureReason !== undefined
        ? String(failureReason).slice(0, 255)
        : null;

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
        truncatedEvent,
        userId ?? null,
        role ?? null,
        partnerCode ?? null,
        identifierHash,
        ipHash,
        userAgentHash,
        success ? 1 : 0,
        truncatedReason,
      ]
    );
  } catch (err) {
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution ────────────────────────────────────────────────────────

/**
 * Re-fetch the authenticated actor from DB using the JWT subject
 * (sub = dietician_id). Requires an active super_admin OR admin, and a valid
 * admin hierarchy (partner_code + parent_user_id) when the actor is an admin.
 * Returns { actor, actorEmail } on success or { error: { status, body } }.
 *
 * Mirrors PHP get_actor_by_email_or_fail(), but bound to the JWT rather than a
 * body-supplied actor_user_id.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};

  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return {
      error: { status: 401, body: { ok: false, error: "Invalid token user" } },
    };
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
    return {
      error: { status: 401, body: { ok: false, error: "Token user not found" } },
    };
  }

  if (String(actor.status) !== "active") {
    return {
      error: { status: 403, body: { ok: false, error: "Account is not active" } },
    };
  }

  const role = String(actor.role);

  if (role !== "super_admin" && role !== "admin") {
    return {
      error: {
        status: 403,
        body: { ok: false, error: "Only super admin or admin can view this list" },
      },
    };
  }

  if (role === "admin") {
    const hasPartnerCode = actor.partner_code !== null &&
      actor.partner_code !== undefined && String(actor.partner_code).trim() !== "";
    const hasParent = actor.parent_user_id !== null &&
      actor.parent_user_id !== undefined && String(actor.parent_user_id).trim() !== "";

    if (!hasPartnerCode || !hasParent) {
      return {
        error: {
          status: 403,
          body: { ok: false, error: "Invalid admin hierarchy configuration" },
        },
      };
    }
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
        WHERE status     = 'pending'
          AND expires_at <= UTC_TIMESTAMP()
      `
    );
  } catch (err) {
    // Non-fatal — a stale "pending" row is better than a 500.
    console.error("EXPIRE_PENDING_INVITES_FAILED:", err?.code || err?.message);
  }
}

// ─── Count helpers ───────────────────────────────────────────────────────────

async function countTrainersForAdmin(adminEmail) {
  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM app_user_roles
        WHERE role   = 'trainer'
          AND status = 'active'
          AND LOWER(parent_user_id) = LOWER(?)
      `,
      [adminEmail]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_TRAINERS_FAILED:", err?.code || err?.message);
    return 0;
  }
}

async function countClientsForPartnerCode(partnerCode) {
  if (partnerCode === null || partnerCode === undefined ||
      String(partnerCode).trim() === "") {
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

async function countClientsForAdminNetwork(adminEmail, adminPartnerCode) {
  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(DISTINCT tc.profile_id) AS total
        FROM table_clients tc
        WHERE
          UPPER(tc.dietician_id) = UPPER(?)
          OR UPPER(tc.dietician_id) IN (
            SELECT UPPER(aur.partner_code)
            FROM app_user_roles aur
            WHERE aur.role         = 'trainer'
              AND aur.status       = 'active'
              AND aur.partner_code IS NOT NULL
              AND LOWER(aur.parent_user_id) = LOWER(?)
          )
      `,
      [adminPartnerCode ?? "", adminEmail]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_CLIENTS_NETWORK_FAILED:", err?.code || err?.message);
    return 0;
  }
}

// ─── Self rows ───────────────────────────────────────────────────────────────

/**
 * Synthetic "first row" representing the super admin as a trainer-admin.
 * Mirrors PHP get_super_admin_self_row().
 */
async function getSuperAdminSelfRow(actor, actorEmail) {
  const effectivePartnerCode = getActorEffectivePartnerCode(actor);

  let ownClientsCount = 0;
  if (effectivePartnerCode !== null && String(effectivePartnerCode).trim() !== "") {
    ownClientsCount = await countClientsForPartnerCode(effectivePartnerCode);
  }

  // Counts any trainer directly parented to the super admin (usually 0).
  const directTrainersCount = await countTrainersForAdmin(actorEmail);

  return {
    role_id: actor.id != null ? Number(actor.id) : 0,

    user_id:  actorEmail,
    name:     actor.name ?? null,
    email:    actorEmail,
    phone_no: actor.phone_no ?? null,
    location: actor.location ?? null,

    // Surfaced as an admin/trainer_admin row; actual_role keeps real authority.
    role:         "admin",
    actual_role:  "super_admin",
    display_role: "trainer_admin",

    partner_code:      effectivePartnerCode,
    parent_user_id:    null,
    status:            actor.status ?? null,
    email_verified_at: toMysqlDateTime(actor.email_verified_at),

    dietician_id:      actor.dietician_id ?? null,
    is_reset_password: nullableInt(actor.is_reset_password),

    real_trainers_count: directTrainersCount,
    self_trainer_count:  1,
    trainers_count:      1 + directTrainersCount,

    clients_count: ownClientsCount,

    override_monthly: null,
    created_at:       null,
    updated_at:       null,

    is_self:                         true,
    is_super_admin_as_trainer_admin: true,
    can_invite_clients:              true,
    can_resend:                      false,
    can_revoke:                      false,
  };
}

/**
 * RECONSTRUCTED — not present in the PHP source provided.
 *
 * Synthetic "first row" representing the admin as a trainer in their own
 * trainer list. Built by analogy with getSuperAdminSelfRow(): the admin owns
 * clients under their own partner_code and so appears as a trainer-like owner.
 * Review the role/display_role/flags if your intended shape differs.
 */
async function getAdminSelfTrainerRow(actor, actorEmail) {
  const effectivePartnerCode = getActorEffectivePartnerCode(actor);

  let ownClientsCount = 0;
  if (effectivePartnerCode !== null && String(effectivePartnerCode).trim() !== "") {
    ownClientsCount = await countClientsForPartnerCode(effectivePartnerCode);
  }

  return {
    role_id: actor.id != null ? Number(actor.id) : 0,

    user_id:  actorEmail,
    name:     actor.name ?? null,
    email:    actorEmail,
    phone_no: actor.phone_no ?? null,
    location: actor.location ?? null,

    // Surfaced as a trainer row; actual_role keeps real authority (admin).
    role:         "trainer",
    actual_role:  "admin",
    display_role: "trainer_admin",

    partner_code:      effectivePartnerCode,
    parent_user_id:    actor.parent_user_id != null
      ? normalizeEmail(actor.parent_user_id)
      : null,
    status:            actor.status ?? null,
    email_verified_at: toMysqlDateTime(actor.email_verified_at),

    dietician_id:      actor.dietician_id ?? null,
    is_reset_password: nullableInt(actor.is_reset_password),

    trainers_count: 0,
    clients_count:  ownClientsCount,

    override_monthly: null,
    created_at:       null,
    updated_at:       null,

    is_self:             true,
    is_admin_as_trainer: true,
    self_trainer_count:  1,
    can_invite_clients:  true,
    can_resend:          false,
    can_revoke:          false,
  };
}

// ─── Accepted user lists ─────────────────────────────────────────────────────

async function getExistingAdminsForSuperAdmin(superAdminEmail) {
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
      WHERE aur.role = 'admin'
        AND LOWER(aur.parent_user_id) = LOWER(?)
      ORDER BY aur.created_at DESC, aur.id DESC
    `,
    [superAdminEmail]
  );

  const out = [];

  for (const row of rows) {
    const adminEmail       = normalizeEmail(row.user_id);
    const adminPartnerCode = row.partner_code;

    // Sequential awaits — admin list is small. Switch to batched Promise.all
    // if this grows large.
    const realTrainersCount = await countTrainersForAdmin(adminEmail);
    const clientsCount      = await countClientsForAdminNetwork(adminEmail, adminPartnerCode);

    // Trainer admin is also a trainer/client owner → display = self + children.
    const trainersCount = 1 + realTrainersCount;

    out.push({
      role_id:  Number(row.role_id),
      user_id:  adminEmail,
      name:     row.name ?? null,
      email:    normalizeEmail(row.email),
      phone_no: row.phone_no ?? null,
      location: row.location ?? null,

      role:         row.role,
      actual_role:  row.role,
      display_role: "trainer_admin",

      partner_code:      row.partner_code,
      parent_user_id:    normalizeEmail(row.parent_user_id),
      status:            row.status,
      email_verified_at: toMysqlDateTime(row.email_verified_at),

      dietician_id:      row.dietician_id ?? null,
      is_reset_password: nullableInt(row.is_reset_password),

      real_trainers_count: realTrainersCount,
      self_trainer_count:  1,
      trainers_count:      trainersCount,

      clients_count: clientsCount,

      override_monthly: null,
      created_at:       toMysqlDateTime(row.created_at),
      updated_at:       toMysqlDateTime(row.updated_at),

      is_self:                         false,
      is_super_admin_as_trainer_admin: false,
      can_invite_clients:              true,
      can_resend:                      false,
      can_revoke:                      false,
    });
  }

  return out;
}

async function getExistingTrainersForAdmin(adminEmail) {
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
        AND LOWER(aur.parent_user_id) = LOWER(?)
      ORDER BY aur.created_at DESC, aur.id DESC
    `,
    [adminEmail]
  );

  const out = [];

  for (const row of rows) {
    const clientsCount = await countClientsForPartnerCode(row.partner_code);

    out.push({
      role_id:  Number(row.role_id),
      user_id:  normalizeEmail(row.user_id),
      name:     row.name ?? null,
      email:    normalizeEmail(row.email),
      phone_no: row.phone_no ?? null,
      location: row.location ?? null,

      role:         row.role,
      actual_role:  row.role,
      display_role: "trainer",

      partner_code:      row.partner_code,
      parent_user_id:    normalizeEmail(row.parent_user_id),
      status:            row.status,
      email_verified_at: toMysqlDateTime(row.email_verified_at),

      dietician_id:      row.dietician_id ?? null,
      is_reset_password: nullableInt(row.is_reset_password),

      trainers_count: 0,
      clients_count:  clientsCount,

      override_monthly: null,
      created_at:       toMysqlDateTime(row.created_at),
      updated_at:       toMysqlDateTime(row.updated_at),

      is_self:            false,
      can_invite_clients: true,
      can_resend:         false,
      can_revoke:         false,
    });
  }

  return out;
}

// ─── Invites by status ───────────────────────────────────────────────────────

function formatInviteRow(row) {
  const firstName = String(row.invited_first_name ?? "").trim();
  const lastName  = String(row.invited_last_name  ?? "").trim();
  const name      = `${firstName} ${lastName}`.trim();

  const status = lowerStr(row.status);

  let canResend = false;
  let canRevoke = false;

  if (status === "pending" || status === "expired") {
    canResend = true;
    canRevoke = true;
  }
  // 'revoked' (and any other terminal status) keeps both false.

  return {
    invitation_id: Number(row.id),
    name,
    first_name: firstName,
    last_name:  lastName,
    email:      normalizeEmail(row.invited_email),
    phone_no:   row.invited_phone ?? null,

    role:               row.invited_role,
    partner_code:       row.partner_code,
    invited_by_user_id: normalizeEmail(row.invited_by_user_id),
    parent_user_id:     normalizeEmail(row.parent_user_id),
    status:             row.status,

    expires_at:  toMysqlDateTime(row.expires_at),
    sent_at:     toMysqlDateTime(row.sent_at),
    accepted_at: toMysqlDateTime(row.accepted_at),
    created_at:  toMysqlDateTime(row.created_at),
    updated_at:  toMysqlDateTime(row.updated_at),

    can_resend: canResend,
    can_revoke: canRevoke,
  };
}

async function getInvitesByStatus(invitedRole, parentUserId, status) {
  const columns = `
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
  `;

  let rows;

  if (status === "pending") {
    [rows] = await pool.execute(
      `
        SELECT ${columns}
        FROM app_user_invitations
        WHERE invited_role = ?
          AND status       = 'pending'
          AND expires_at   > UTC_TIMESTAMP()
          AND LOWER(parent_user_id) = LOWER(?)
        ORDER BY created_at DESC, id DESC
      `,
      [invitedRole, parentUserId]
    );
  } else {
    [rows] = await pool.execute(
      `
        SELECT ${columns}
        FROM app_user_invitations
        WHERE invited_role = ?
          AND status       = ?
          AND LOWER(parent_user_id) = LOWER(?)
        ORDER BY updated_at DESC, id DESC
      `,
      [invitedRole, status, parentUserId]
    );
  }

  return rows.map(formatInviteRow);
}

// ─── Totals ──────────────────────────────────────────────────────────────────

/**
 * `existingAdmins` includes the super admin self row plus real admins.
 * Mirrors PHP build_admin_totals().
 */
function buildAdminTotals(existingAdmins, pendingAdmins, expiredAdmins, revokedAdmins) {
  let realChildTrainers = 0;
  let totalClients      = 0;
  let selfCount         = 0;
  let realAdminCount    = 0;

  for (const admin of existingAdmins) {
    // Use real_trainers_count (NOT trainers_count, which includes self) to
    // avoid double-counting.
    realChildTrainers += toInt(admin.real_trainers_count);
    totalClients      += toInt(admin.clients_count);

    if (admin.is_self) {
      selfCount = 1;
    } else {
      realAdminCount++;
    }
  }

  const trainerAdminDisplayCount = existingAdmins.length;
  const trainerDisplayCount      = trainerAdminDisplayCount + realChildTrainers;

  return {
    accepted_count: existingAdmins.length,
    pending_count:  pendingAdmins.length,
    expired_count:  expiredAdmins.length,
    revoked_count:  revokedAdmins.length,

    real_admin_count:            realAdminCount,
    self_admin_count:            selfCount,
    total_admins:                trainerAdminDisplayCount,
    total_admins_including_self: trainerAdminDisplayCount,

    real_total_trainers: realChildTrainers,

    total_trainers:               trainerDisplayCount,
    total_trainers_in_network:    trainerDisplayCount,
    total_trainers_display_count: trainerDisplayCount,
    total_trainer_like_owners:    trainerDisplayCount,

    trainer_admin_display_count: trainerAdminDisplayCount,
    trainer_only_count:          realChildTrainers,

    total_clients: totalClients,
  };
}

/**
 * `existingTrainers` includes the admin self trainer row plus real trainers.
 * Mirrors PHP build_trainer_totals().
 */
function buildTrainerTotals(existingTrainers, pendingTrainers, expiredTrainers, revokedTrainers) {
  let totalClients     = 0;
  let selfCount        = 0;
  let realTrainerCount = 0;

  for (const trainer of existingTrainers) {
    totalClients += toInt(trainer.clients_count);

    if (trainer.is_self) {
      selfCount = 1;
    } else {
      realTrainerCount++;
    }
  }

  const trainerDisplayCount = selfCount + realTrainerCount;

  return {
    accepted_count: existingTrainers.length,
    pending_count:  pendingTrainers.length,
    expired_count:  expiredTrainers.length,
    revoked_count:  revokedTrainers.length,

    real_total_trainers: realTrainerCount,

    total_trainers:               trainerDisplayCount,
    total_trainers_including_self: trainerDisplayCount,
    total_trainers_display_count: trainerDisplayCount,
    total_trainer_like_owners:    trainerDisplayCount,

    total_clients: totalClients,
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/list-admin-trainer-users
 *
 * Headers: Authorization: Bearer <JWT>
 * Body   : {} (ignored — actor identity comes from JWT, NOT body.actor_user_id)
 *
 * Returns:
 *   super_admin → { mode: "super_admin_admins", existing: [self + admins], ... }
 *   admin       → { mode: "admin_trainers",     existing: [self + trainers], ... }
 *   trainer/other → 403
 */
const listAdminTrainerUsers = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches PHP behavior).
  if (req.method !== "POST") {
    return res.status(405).json({
      ok:    false,
      error: "Method not allowed",
    });
  }

  let actorEmail = null;
  let actorRole  = null;

  try {
    // ── 1. Resolve + authorize actor from JWT (super_admin or admin) ────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType:     "user_list_denied",
        userId:        null,
        role:          null,
        partnerCode:   null,
        identifier:    String(req.user?.sub || req.user?.dietician_id || ""),
        success:       false,
        failureReason: resolved.error.body?.error || "actor resolution failed",
      });

      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole  = String(actor.role);

    // ── 2. Housekeeping: expire stale pending invites (best-effort) ─────────
    await expireOldPendingInvites();

    // ── 3. super_admin branch ───────────────────────────────────────────────
    if (actorRole === "super_admin") {
      const selfRow        = await getSuperAdminSelfRow(actor, actorEmail);
      const acceptedAdmins = await getExistingAdminsForSuperAdmin(actorEmail);

      // Super admin appears first as a trainer admin.
      const existingRows = [selfRow, ...acceptedAdmins];

      const [pendingAdmins, expiredAdmins, revokedAdmins] = await Promise.all([
        getInvitesByStatus("admin", actorEmail, "pending"),
        getInvitesByStatus("admin", actorEmail, "expired"),
        getInvitesByStatus("admin", actorEmail, "revoked"),
      ]);

      const totals = buildAdminTotals(
        existingRows, pendingAdmins, expiredAdmins, revokedAdmins
      );

      writeAuthLogSafe(req, {
        eventType:     "user_list_viewed",
        userId:        actorEmail,
        role:          actorRole,
        partnerCode:   getActorEffectivePartnerCode(actor),
        identifier:    actorEmail,
        success:       true,
        failureReason: "Super admin viewed admin list",
      });

      return res.status(200).json({
        ok:    true,
        mode:  "super_admin_admins",
        title: "Trainer Admins",
        actor: {
          user_id:        actorEmail,
          role:           actorRole,
          partner_code:   getActorEffectivePartnerCode(actor),
          parent_user_id: null,
        },
        existing:        existingRows,
        pending_invites: pendingAdmins,
        expired_invites: expiredAdmins,
        revoked_invites: revokedAdmins,
        totals,
      });
    }

    // ── 4. admin branch ─────────────────────────────────────────────────────
    if (actorRole === "admin") {
      const selfRow          = await getAdminSelfTrainerRow(actor, actorEmail);
      const acceptedTrainers = await getExistingTrainersForAdmin(actorEmail);

      // Admin appears first as a trainer (manages their own clients).
      const existingTrainerRows = [selfRow, ...acceptedTrainers];

      const [pendingTrainers, expiredTrainers, revokedTrainers] = await Promise.all([
        getInvitesByStatus("trainer", actorEmail, "pending"),
        getInvitesByStatus("trainer", actorEmail, "expired"),
        getInvitesByStatus("trainer", actorEmail, "revoked"),
      ]);

      const totals = buildTrainerTotals(
        existingTrainerRows, pendingTrainers, expiredTrainers, revokedTrainers
      );

      writeAuthLogSafe(req, {
        eventType:     "user_list_viewed",
        userId:        actorEmail,
        role:          actorRole,
        partnerCode:   actor.partner_code ?? null,
        identifier:    actorEmail,
        success:       true,
        failureReason: "Admin viewed trainer list",
      });

      return res.status(200).json({
        ok:    true,
        mode:  "admin_trainers",
        title: "Trainers",
        actor: {
          user_id:        actorEmail,
          role:           actorRole,
          partner_code:   actor.partner_code   ?? null,
          parent_user_id: actor.parent_user_id ?? null,
        },
        existing:        existingTrainerRows,
        pending_invites: pendingTrainers,
        expired_invites: expiredTrainers,
        revoked_invites: revokedTrainers,
        totals,
      });
    }

    // ── 5. Disallowed role (defense in depth — already gated above) ─────────
    return res.status(403).json({
      ok:    false,
      error: "You are not allowed to view this list",
    });

  } catch (err) {
    console.error("LIST_ADMIN_TRAINER_USERS_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType:     "user_list_error",
      userId:        actorEmail,
      role:          actorRole,
      partnerCode:   null,
      identifier:    actorEmail,
      success:       false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok:    false,
      error: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { listAdminTrainerUsers };
