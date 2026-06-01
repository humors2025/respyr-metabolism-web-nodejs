"use strict";

/**
 * list-all-trainers-for-super-admin.js
 *
 * Converted from: list-all-trainers-for-super-admin.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/list-all-trainers-for-super-admin
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer (each sees their own scope)
 *
 * Behaviour parity with PHP:
 *  - Merges "active" rows (self + network users from app_user_roles) with
 *    invite rows (pending/expired/revoked from app_user_invitations) per the
 *    requested status filter, applies trainer-admin + search filters, sorts by
 *    sort_rank then created_at DESC, builds summary counts, then paginates
 *    in-memory. Response keys/shape match the PHP exactly.
 *  - status filter allow-list: all, active, pending, expired, revoked.
 *  - page defaults to 1 (min 1); limit defaults to 10 (1..50).
 *
 * Actor identity (faithful PHP conversion):
 *  - Identity is taken from body.actor_user_id, exactly like the PHP. This is a
 *    direct 1:1 port — nothing added or removed from the request contract.
 *  - SECURITY NOTE: trusting a client-supplied actor_user_id is an IDOR /
 *    privilege-escalation risk — any caller can pass another user's email and
 *    read that user's network. For a true VAPT/HIPAA posture, gate this route
 *    behind authMiddleware and derive identity from the verified JWT instead
 *    (see the sibling *-jwt controllers). Kept as-is here at your request.
 *
 * Hardening still applied (everything except the identity source):
 *  - The invite query's parent-email IN-list is built with placeholders + bound
 *    params, not real_escape_string string interpolation as in the PHP.
 *  - Invite expiry comparisons use UTC_TIMESTAMP() (matches how this app stores
 *    invites) instead of the PHP's IST NOW().
 *  - The PHP ran `SET time_zone = '+05:30'` on the connection. That is NOT done
 *    here: this app uses a shared mysql2 pool, and mutating the session TZ would
 *    leak into other concurrent requests. Datetimes are formatted in JS instead.
 *  - Internal error details suppressed in production (PHP echoed debug_error).
 *
 * HIPAA Controls applied:
 *  - Minimum-necessary columns selected; no SELECT *.
 *  - PHI in audit logs (email, IP, UA) is HMAC-SHA256 hashed with SECURITY_PEPPER.
 *  - Server-side logs carry only error metadata, never row data.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * NOTE on action endpoint hints:
 *  - Invite rows carry resend_api / revoke_api strings copied verbatim from the
 *    PHP ("resend-user-invite.php" / "revoke-user-invite.php") to preserve the
 *    existing frontend contract. Update these once those endpoints are ported.
 */

const crypto = require("crypto");
const pool   = require("../../../../config/db");
const { resolveActorByEmail: sharedResolveActorByEmail } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_STATUSES = new Set(["all", "active", "pending", "expired", "revoked"]);
const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const MAX_LIMIT     = 50;
const DEFAULT_LIMIT = 10;

const RESEND_API_HINT = "resend-user-invite.php";
const REVOKE_API_HINT = "revoke-user-invite.php";

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string" ? val.trim().toLowerCase() : "";
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? n : 0;
}

function nullableInt(val) {
  return val === null || val === undefined ? null : Number(val);
}

/**
 * Format a mysql2 DATETIME value as "YYYY-MM-DD HH:MM:SS". Accepts Date objects
 * (mysql2 default) and strings.
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

/** Parse a formatted datetime string into ms for relative sorting. */
function parseSortTime(val) {
  if (!val) return 0;
  const t = Date.parse(String(val).replace(" ", "T"));
  return Number.isNaN(t) ? 0 : t;
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

/**
 * Fail-safe audit log writer. Schema mirrors the sibling controllers. Never
 * throws — audit failures must not surface to clients.
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
 * Re-fetch the actor from DB by email. Mirrors PHP get_actor_by_email_or_fail():
 * resolves WHERE LOWER(td.email) = LOWER(?), requires an active account whose
 * role is one of super_admin / admin / trainer.
 * Returns { actor, actorEmail } on success or { error: { status, body } }.
 *
 * NOTE: actorUserId is supplied by the client (req.body.actor_user_id) — see the
 * SECURITY NOTE in the file header.
 */
async function resolveActorByEmail(actorUserId) {
  // Identity (by email) + status/role check delegated to the shared
  // access-control module; the neutral result is mapped back into this
  // controller's error shape. NOTE: this endpoint resolves the actor from a
  // body-supplied email (the legacy "no-JWT" variant) — see the file header.
  const resolved = await sharedResolveActorByEmail(actorUserId, VALID_ACTOR_ROLES);

  if (resolved.ok) {
    return { actor: resolved.actor, actorEmail: resolved.actorEmail };
  }

  const REASON_BODY = {
    invalid_token:    { status: 403, error: "Actor user not found" },
    not_found:        { status: 403, error: "Actor user not found" },
    inactive:         { status: 403, error: "Actor account is not active" },
    role_not_allowed: { status: 403, error: "Invalid actor role" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, body: { ok: false, error: m.error } } };
}

// ─── Housekeeping ────────────────────────────────────────────────────────────

async function expireOldPendingTrainerInvites() {
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
    console.error("EXPIRE_TRAINER_INVITES_FAILED:", err?.code || err?.message);
  }
}

// ─── Count helper ────────────────────────────────────────────────────────────

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

// ─── Active trainer rows ─────────────────────────────────────────────────────

async function buildSelfTrainerRow(actor, actorEmail) {
  const actualRole  = String(actor.role);
  const partnerCode = getActorEffectivePartnerCode(actor);

  let displayRole = "trainer";
  if (actualRole === "super_admin") displayRole = "super_admin";
  if (actualRole === "admin")       displayRole = "trainer_admin";

  const createdAt = toMysqlDateTime(actor.created_at);

  return {
    source:   "app_user_roles",
    row_type: "active_user",

    role_id:       actor.id != null ? Number(actor.id) : null,
    invitation_id: null,

    user_id:  actorEmail,
    name:     actor.name ?? null,
    email:    actorEmail,
    phone_no: actor.phone_no ?? null,

    role:         "trainer",
    actual_role:  actualRole,
    display_role: displayRole,

    partner_code: partnerCode,
    dietician_id: actor.dietician_id ?? null,

    trainer_admin: {
      user_id: actorEmail,
      name:    actor.name ?? null,
      email:   actorEmail,
    },

    trainer_admin_user_id: actorEmail,
    trainer_admin_name:    actor.name ?? null,

    clients_count: await countClientsForPartnerCode(partnerCode),

    status:     "active",
    raw_status: actor.status ?? "active",
    joined:     createdAt,
    created_at: createdAt,
    updated_at: toMysqlDateTime(actor.updated_at),

    is_self:                    true,
    is_super_admin_as_trainer:  actualRole === "super_admin",
    is_admin_as_trainer:        actualRole === "admin",

    actions: {
      can_resend: false,
      can_revoke: false,
    },

    sort_rank: 0,
  };
}

async function getActiveAdminsAsTrainersUnderSuperAdmin(superAdminEmail) {
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
        td.phone_no
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE aur.role   = 'admin'
        AND aur.status = 'active'
        AND LOWER(aur.parent_user_id) = LOWER(?)
      ORDER BY aur.created_at DESC, aur.id DESC
    `,
    [superAdminEmail]
  );

  return Promise.all(dbRows.map(async (row) => {
    const code       = getEffectiveCodeFromRow(row);
    const adminEmail = normalizeEmail(row.user_id);

    return {
      source:   "app_user_roles",
      row_type: "active_user",

      role_id:       Number(row.role_id),
      invitation_id: null,

      user_id:  adminEmail,
      name:     row.name ?? null,
      email:    normalizeEmail(row.email),
      phone_no: row.phone_no ?? null,

      role:         "trainer",
      actual_role:  "admin",
      display_role: "trainer_admin",

      partner_code: code,
      dietician_id: row.dietician_id ?? null,

      trainer_admin: {
        user_id: adminEmail,
        name:    row.name ?? null,
        email:   adminEmail,
      },

      trainer_admin_user_id: adminEmail,
      trainer_admin_name:    row.name ?? null,

      clients_count: await countClientsForPartnerCode(code),

      status:     "active",
      raw_status: row.status,
      joined:     toMysqlDateTime(row.created_at),
      created_at: toMysqlDateTime(row.created_at),
      updated_at: toMysqlDateTime(row.updated_at),

      is_self:                   false,
      is_super_admin_as_trainer: false,
      is_admin_as_trainer:       true,

      actions: { can_resend: false, can_revoke: false },

      sort_rank: 10,
    };
  }));
}

async function mapActiveTrainerResult(dbRows) {
  return Promise.all(dbRows.map(async (row) => {
    const code        = getEffectiveCodeFromRow(row);
    const parentEmail = normalizeEmail(row.parent_user_id);
    const parentName  = row.parent_name && String(row.parent_name).trim() !== ""
      ? row.parent_name
      : parentEmail;

    return {
      source:   "app_user_roles",
      row_type: "active_user",

      role_id:       Number(row.role_id),
      invitation_id: null,

      user_id:  normalizeEmail(row.user_id),
      name:     row.name ?? null,
      email:    normalizeEmail(row.email),
      phone_no: row.phone_no ?? null,

      role:         "trainer",
      actual_role:  "trainer",
      display_role: "trainer",

      partner_code: code,
      dietician_id: row.dietician_id ?? null,

      trainer_admin: {
        user_id: parentEmail,
        name:    parentName,
        email:   normalizeEmail(row.parent_email ?? parentEmail),
      },

      trainer_admin_user_id: parentEmail,
      trainer_admin_name:    parentName,

      clients_count: await countClientsForPartnerCode(code),

      status:     "active",
      raw_status: row.status,
      joined:     toMysqlDateTime(row.created_at),
      created_at: toMysqlDateTime(row.created_at),
      updated_at: toMysqlDateTime(row.updated_at),

      is_self:                   false,
      is_super_admin_as_trainer: false,
      is_admin_as_trainer:       false,

      actions: { can_resend: false, can_revoke: false },

      sort_rank: 20,
    };
  }));
}

async function getActiveTrainersUnderSuperAdminNetwork(superAdminEmail) {
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

        parent_td.name  AS parent_name,
        parent_td.email AS parent_email
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      LEFT JOIN table_dietician parent_td
        ON LOWER(parent_td.email) = LOWER(aur.parent_user_id)
      WHERE aur.role   = 'trainer'
        AND aur.status = 'active'
        AND (
          LOWER(aur.parent_user_id) = LOWER(?)
          OR LOWER(aur.parent_user_id) IN (
            SELECT LOWER(user_id)
            FROM app_user_roles
            WHERE role   = 'admin'
              AND status = 'active'
              AND LOWER(parent_user_id) = LOWER(?)
          )
        )
      ORDER BY aur.created_at DESC, aur.id DESC
    `,
    [superAdminEmail, superAdminEmail]
  );

  return mapActiveTrainerResult(dbRows);
}

async function getActiveTrainersUnderAdmin(adminEmail) {
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

        parent_td.name  AS parent_name,
        parent_td.email AS parent_email
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      LEFT JOIN table_dietician parent_td
        ON LOWER(parent_td.email) = LOWER(aur.parent_user_id)
      WHERE aur.role   = 'trainer'
        AND aur.status = 'active'
        AND LOWER(aur.parent_user_id) = LOWER(?)
      ORDER BY aur.created_at DESC, aur.id DESC
    `,
    [adminEmail]
  );

  return mapActiveTrainerResult(dbRows);
}

async function getActiveTrainerRows(actor, actorEmail) {
  const role = String(actor.role);

  const rows = [await buildSelfTrainerRow(actor, actorEmail)];

  if (role === "trainer") {
    return dedupeRowsByUserOrCode(rows);
  }

  if (role === "admin") {
    const childTrainers = await getActiveTrainersUnderAdmin(actorEmail);
    rows.push(...childTrainers);
    return dedupeRowsByUserOrCode(rows);
  }

  if (role === "super_admin") {
    const adminRows   = await getActiveAdminsAsTrainersUnderSuperAdmin(actorEmail);
    rows.push(...adminRows);

    const trainerRows = await getActiveTrainersUnderSuperAdminNetwork(actorEmail);
    rows.push(...trainerRows);

    return dedupeRowsByUserOrCode(rows);
  }

  return dedupeRowsByUserOrCode(rows);
}

// ─── Invite rows ─────────────────────────────────────────────────────────────

async function getActiveAdminEmailsUnderSuperAdmin(superAdminEmail) {
  const [rows] = await pool.execute(
    `
      SELECT user_id
      FROM app_user_roles
      WHERE role   = 'admin'
        AND status = 'active'
        AND LOWER(parent_user_id) = LOWER(?)
    `,
    [superAdminEmail]
  );
  return rows.map((r) => normalizeEmail(r.user_id));
}

async function getTrainerInviteRows(actor, actorEmail, statusFilter) {
  const role = String(actor.role);

  if (role === "trainer") {
    return [];
  }

  let parentEmails = [];

  if (role === "admin") {
    parentEmails.push(actorEmail);
  }

  if (role === "super_admin") {
    parentEmails.push(actorEmail);
    const adminEmails = await getActiveAdminEmailsUnderSuperAdmin(actorEmail);
    parentEmails.push(...adminEmails);
  }

  parentEmails = [...new Set(parentEmails.map(normalizeEmail).filter((e) => e !== ""))];

  if (parentEmails.length === 0) {
    return [];
  }

  // VAPT: placeholders, not real_escape_string interpolation.
  const placeholders = parentEmails.map(() => "?").join(",");

  // statusFilter is allow-list validated before this call, so these fragments
  // are constants — no user input is interpolated into SQL.
  let statusSql;
  if (statusFilter === "pending") {
    statusSql = "AND ai.status = 'pending' AND ai.expires_at > UTC_TIMESTAMP()";
  } else if (statusFilter === "expired") {
    statusSql = "AND ai.status = 'expired'";
  } else if (statusFilter === "revoked") {
    statusSql = "AND ai.status = 'revoked'";
  } else {
    statusSql = "AND ai.status IN ('pending', 'expired', 'revoked')";
  }

  const [dbRows] = await pool.execute(
    `
      SELECT
        ai.id,
        ai.invited_email,
        ai.invited_first_name,
        ai.invited_last_name,
        ai.invited_phone,
        ai.invited_role,
        ai.partner_code,
        ai.invited_by_user_id,
        ai.parent_user_id,
        ai.status,
        ai.expires_at,
        ai.sent_at,
        ai.accepted_at,
        ai.created_at,
        ai.updated_at,

        parent_td.name  AS parent_name,
        parent_td.email AS parent_email
      FROM app_user_invitations ai
      LEFT JOIN table_dietician parent_td
        ON LOWER(parent_td.email) = LOWER(ai.parent_user_id)
      WHERE ai.invited_role = 'trainer'
        AND LOWER(ai.parent_user_id) IN (${placeholders})
        ${statusSql}
      ORDER BY ai.created_at DESC, ai.id DESC
    `,
    parentEmails
  );

  return dbRows.map((row) => {
    const firstName = String(row.invited_first_name ?? "").trim();
    const lastName  = String(row.invited_last_name  ?? "").trim();
    let name        = `${firstName} ${lastName}`.trim();
    if (name === "") name = normalizeEmail(row.invited_email);

    const parentEmail = normalizeEmail(row.parent_user_id);
    const parentName  = row.parent_name && String(row.parent_name).trim() !== ""
      ? row.parent_name
      : parentEmail;

    const status    = String(row.status).toLowerCase();
    const canResend = status === "pending" || status === "expired";
    const canRevoke = status === "pending" || status === "expired";

    let sortRank = 30;
    if (status === "pending")      sortRank = 30;
    else if (status === "expired") sortRank = 40;
    else if (status === "revoked") sortRank = 50;

    return {
      source:   "app_user_invitations",
      row_type: "invite",

      role_id:       null,
      invitation_id: Number(row.id),

      user_id:  normalizeEmail(row.invited_email),
      name,
      email:    normalizeEmail(row.invited_email),
      phone_no: row.invited_phone ?? null,

      role:         "trainer",
      actual_role:  "trainer",
      display_role: "trainer",

      partner_code: row.partner_code,
      dietician_id: null,

      trainer_admin: {
        user_id: parentEmail,
        name:    parentName,
        email:   normalizeEmail(row.parent_email ?? parentEmail),
      },

      trainer_admin_user_id: parentEmail,
      trainer_admin_name:    parentName,

      clients_count: 0,

      status,
      raw_status: row.status,
      joined:     toMysqlDateTime(row.accepted_at),
      created_at: toMysqlDateTime(row.created_at),
      updated_at: toMysqlDateTime(row.updated_at),
      expires_at: toMysqlDateTime(row.expires_at),
      sent_at:    toMysqlDateTime(row.sent_at),

      is_self:                   false,
      is_super_admin_as_trainer: false,
      is_admin_as_trainer:       false,

      actions: {
        can_resend: canResend,
        can_revoke: canRevoke,
        resend_api: canResend ? RESEND_API_HINT : null,
        revoke_api: canRevoke ? REVOKE_API_HINT : null,
      },

      sort_rank: sortRank,
    };
  });
}

// ─── Trainer-admin filter options ────────────────────────────────────────────

async function getTrainerAdminFilterOptions(actor, actorEmail) {
  const role = String(actor.role);
  const options = [];

  if (role === "super_admin" || role === "admin") {
    options.push({
      user_id:      actorEmail,
      name:         actor.name ?? null,
      email:        actorEmail,
      role,
      partner_code: getActorEffectivePartnerCode(actor),
      is_self:      true,
    });
  }

  if (role === "super_admin") {
    const [rows] = await pool.execute(
      `
        SELECT
          aur.user_id,
          aur.role,
          aur.partner_code,
          td.name,
          td.email
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role   = 'admin'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
        ORDER BY td.name ASC, aur.user_id ASC
      `,
      [actorEmail]
    );

    for (const row of rows) {
      options.push({
        user_id:      normalizeEmail(row.user_id),
        name:         row.name ?? null,
        email:        normalizeEmail(row.email),
        role:         "admin",
        partner_code: row.partner_code,
        is_self:      false,
      });
    }
  }

  return options;
}

// ─── Filters / sort / summary ────────────────────────────────────────────────

function applyTrainerAdminFilter(rows, trainerAdminUserId) {
  const target = normalizeEmail(trainerAdminUserId);
  if (target === "") return rows;

  return rows.filter(
    (row) => normalizeEmail(row.trainer_admin_user_id) === target
  );
}

function applySearchFilter(rows, search) {
  const needle = String(search ?? "").trim().toLowerCase();
  if (needle === "") return rows;

  return rows.filter((row) => {
    const haystack = [
      row.name ?? "",
      row.email ?? "",
      row.partner_code ?? "",
      row.trainer_admin_name ?? "",
      row.trainer_admin_user_id ?? "",
    ].join(" ").toLowerCase();

    return haystack.includes(needle);
  });
}

function sortTrainerRows(rows) {
  return rows.sort((a, b) => {
    const rankA = a.sort_rank != null ? toInt(a.sort_rank) : 99;
    const rankB = b.sort_rank != null ? toInt(b.sort_rank) : 99;

    if (rankA !== rankB) return rankA - rankB;

    const dateA = parseSortTime(a.created_at);
    const dateB = parseSortTime(b.created_at);

    if (dateA === dateB) return 0;
    return dateA > dateB ? -1 : 1; // newest first
  });
}

function buildSummaryCounts(rows) {
  let active = 0, pending = 0, expired = 0, revoked = 0, totalClients = 0;

  for (const row of rows) {
    const status = String(row.status ?? "").toLowerCase();

    if (status === "active")       active++;
    else if (status === "pending") pending++;
    else if (status === "expired") expired++;
    else if (status === "revoked") revoked++;

    totalClients += toInt(row.clients_count);
  }

  return {
    active_count:  active,
    pending_count: pending,
    expired_count: expired,
    revoked_count: revoked,
    total_count:   rows.length,
    total_clients: totalClients,
  };
}

function dedupeRowsByUserOrCode(rows) {
  const seen = new Set();
  const out = [];

  for (const row of rows) {
    let key = "";

    if (row.user_id && String(row.user_id).trim() !== "") {
      key = "email:" + normalizeEmail(row.user_id);
    } else if (row.partner_code && String(row.partner_code).trim() !== "") {
      key = "code:" + String(row.partner_code).trim().toUpperCase();
    }

    if (key === "") {
      out.push(row);
      continue;
    }

    if (seen.has(key)) continue;

    seen.add(key);
    out.push(row);
  }

  return out;
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(body) {
  const src = body && typeof body === "object" ? body : {};

  const actorUserId = normalizeEmail(src.actor_user_id);

  let page = parseInt(src.page, 10);
  if (!Number.isFinite(page) || page <= 0) page = 1;

  let limit = parseInt(src.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > MAX_LIMIT) {
    limit = DEFAULT_LIMIT;
  }

  const search = typeof src.search === "string" ? src.search.trim() : "";
  const trainerAdminUserId = normalizeEmail(src.trainer_admin_user_id);
  const statusFilter = typeof src.status === "string"
    ? src.status.trim().toLowerCase()
    : "all";

  return { actorUserId, page, limit, search, trainerAdminUserId, statusFilter };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/list-all-trainers-for-super-admin
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "page": 1,
 *     "limit": 10,
 *     "search": "",
 *     "trainer_admin_user_id": "",
 *     "status": "all",           // all | active | pending | expired | revoked
 *     "actor_user_id": "connect@respyr.in"
 *   }
 */
const listAllTrainersForSuperAdmin = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches PHP behavior).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const { actorUserId, page, limit, search, trainerAdminUserId, statusFilter } =
    parseInputs(req.body);

  if (!ALLOWED_STATUSES.has(statusFilter)) {
    return res.status(422).json({ ok: false, error: "Invalid status filter" });
  }

  // Mirrors PHP: actor_user_id must be a valid email (422 otherwise).
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (actorUserId === "" || !emailRegex.test(actorUserId)) {
    return res.status(422).json({
      ok:    false,
      error: "Valid actor_user_id is required",
    });
  }

  let actorEmail = null;
  let actorRole  = null;

  try {
    // ── 1. Housekeeping: expire stale pending trainer invites ───────────────
    await expireOldPendingTrainerInvites();

    // ── 2. Resolve + authorize actor by email (body.actor_user_id) ──────────
    const resolved = await resolveActorByEmail(actorUserId);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType:     "all_trainers_list_denied",
        userId:        null,
        role:          null,
        partnerCode:   null,
        identifier:    actorUserId,
        success:       false,
        failureReason: resolved.error.body?.error || "actor resolution failed",
      });

      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole  = String(actor.role);

    // ── 3. Filter options + rows ────────────────────────────────────────────
    const trainerAdminOptions = await getTrainerAdminFilterOptions(actor, actorEmail);

    let rows = [];

    if (statusFilter === "all" || statusFilter === "active") {
      const activeRows = await getActiveTrainerRows(actor, actorEmail);
      rows.push(...activeRows);
    }

    if (statusFilter === "all" || statusFilter === "pending" ||
        statusFilter === "expired" || statusFilter === "revoked") {
      const inviteRows = await getTrainerInviteRows(actor, actorEmail, statusFilter);
      rows.push(...inviteRows);
    }

    // ── 4. Filter → search → sort (in-memory, parity with PHP) ──────────────
    rows = applyTrainerAdminFilter(rows, trainerAdminUserId);
    rows = applySearchFilter(rows, search);
    rows = sortTrainerRows(rows);

    // ── 5. Summary + pagination ─────────────────────────────────────────────
    const summary   = buildSummaryCounts(rows);
    const total     = rows.length;
    const offset    = (page - 1) * limit;
    const pagedRows = rows.slice(offset, offset + limit);

    // ── 6. Audit — success (fire-and-forget) ────────────────────────────────
    writeAuthLogSafe(req, {
      eventType:     "all_trainers_list_viewed",
      userId:        actorEmail,
      role:          actorRole,
      partnerCode:   getActorEffectivePartnerCode(actor),
      identifier:    actorEmail,
      success:       true,
      failureReason: "Viewed all trainers list",
    });

    // ── 7. Respond (matches PHP JSON shape) ─────────────────────────────────
    return res.status(200).json({
      ok:    true,
      mode:  "all_trainers_list",
      title: "Trainers",

      actor: {
        user_id:        actorEmail,
        role:           actorRole,
        partner_code:   getActorEffectivePartnerCode(actor),
        parent_user_id: actor.parent_user_id ?? null,
        name:           actor.name ?? null,
      },

      filters: {
        search,
        status: statusFilter,
        trainer_admin_user_id: trainerAdminUserId !== "" ? trainerAdminUserId : null,
      },

      trainer_admin_options: trainerAdminOptions,

      summary,

      pagination: {
        page,
        limit,
        offset,
        total,
        has_more: (offset + limit) < total,
      },

      columns: [
        "name",
        "trainer_admin",
        "partner_code",
        "clients_count",
        "status",
        "joined",
        "actions",
      ],

      data: pagedRows,
    });

  } catch (err) {
    console.error("LIST_ALL_TRAINERS_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType:     "all_trainers_list_error",
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

module.exports = { listAllTrainersForSuperAdmin };
