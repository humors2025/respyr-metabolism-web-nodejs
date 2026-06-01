"use strict";

/**
 * list-admin-trainer-users-jwt.js
 *
 * Converted from: list-admin-trainer-users-jwt.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Behaviour parity:
 *  - super_admin → existing admins + pending admin invites under this super_admin
 *  - admin       → existing trainers + pending trainer invites under this admin
 *  - trainer / other roles → 403
 *  - JSON shape matches the PHP response exactly (keys, ordering, datetime
 *    strings, totals block).
 *
 * VAPT Controls applied:
 *  - Token-bound authorization. The actor identity is taken from the verified
 *    JWT (authMiddleware) — never from the request body — preventing privilege
 *    escalation and IDOR.
 *  - Actor is re-fetched from DB on every call and the role/status is re-checked
 *    server-side (defense in depth — a stale or tampered token cannot grant
 *    access to a disabled/demoted account).
 *  - Fully parameterized queries — zero string interpolation. No user-controlled
 *    input is concatenated into SQL.
 *  - Method gate: only POST is accepted (matches PHP) — returns 405 otherwise.
 *  - Internal error details suppressed in production responses (no stack /
 *    SQL state leakage).
 *  - Audit log is written via a fail-safe wrapper that never propagates
 *    exceptions to the client and never logs PHI in plain text.
 *  - Cache-Control: no-store, Pragma: no-cache enforced per-response.
 *
 * HIPAA Controls applied:
 *  - Minimum-necessary data: only the columns required for the list view are
 *    selected. No blanket SELECT *.
 *  - PHI in audit logs is HMAC-SHA256 hashed with a server-side pepper
 *    (SECURITY_PEPPER, falling back to JWT_SECRET) — identifier, IP, and
 *    user-agent are never stored in clear text.
 *  - Structured server-side logs contain only error metadata
 *    (code/errno/sqlState), never row data or PHI.
 *  - Access control: every request is bound to an authenticated super_admin
 *    or admin JWT, and that identity is verified against the DB before any
 *    network data is returned.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const { resolveActorFromToken: sharedResolveActorFromToken } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// ─── Helpers ─────────────────────────────────────────────────────────────────

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

function lowerStr(val) {
  return val === null || val === undefined ? "" : String(val).toLowerCase();
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
 * Fail-safe audit log writer. Mirrors write_auth_log_safe() in the PHP file.
 * Schema:
 *   app_auth_logs(event_type, user_id, role, partner_code,
 *                 identifier_hash, ip_hash, user_agent_hash,
 *                 session_id_hash, success, failure_reason)
 * Never throws — audit failures must not surface to clients.
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
 * Re-fetch the authenticated actor from DB using the JWT subject.
 * Returns either { actor } on success or { error: { status, body } } on failure.
 *
 * This re-check protects against:
 *  - stale tokens issued before a role demotion / account deactivation
 *  - tampered tokens that pass HMAC but reference a non-existent user
 */
async function resolveActorFromToken(req) {
  // Identity + status/role check delegated to the shared access-control module;
  // the neutral result is mapped back into this controller's error shape.
  const resolved = await sharedResolveActorFromToken(req, VALID_ACTOR_ROLES);

  if (resolved.ok) {
    return { actor: resolved.actor, actorEmail: resolved.actorEmail };
  }

  const REASON_BODY = {
    invalid_token:    { status: 401, error: "Invalid token user" },
    not_found:        { status: 401, error: "Token user not found" },
    inactive:         { status: 403, error: "Account is not active" },
    role_not_allowed: { status: 403, error: "Invalid role configuration" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, body: { ok: false, error: m.error } } };
}

// ─── Pending invite housekeeping ─────────────────────────────────────────────

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
    // Non-fatal — surfacing a stale "pending" row is better than a 500.
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
        WHERE role             = 'trainer'
          AND status           = 'active'
          AND LOWER(parent_user_id) = LOWER(?)
      `,
      [adminEmail]
    );
    return Number(rows[0]?.total) || 0;
  } catch (err) {
    console.error("COUNT_TRAINERS_FAILED:", err?.code || err?.message);
    return 0;
  }
}

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
    return Number(rows[0]?.total) || 0;
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
    return Number(rows[0]?.total) || 0;
  } catch (err) {
    console.error("COUNT_CLIENTS_NETWORK_FAILED:", err?.code || err?.message);
    return 0;
  }
}

// ─── List queries ────────────────────────────────────────────────────────────

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
    const adminEmail       = lowerStr(row.user_id);
    const adminPartnerCode = row.partner_code;

    // Sequential await is intentional here — admin list size is small (tens at
    // most). If this grows, switch to Promise.all in batches.
    const trainersCount = await countTrainersForAdmin(adminEmail);
    const clientsCount  = await countClientsForAdminNetwork(adminEmail, adminPartnerCode);

    out.push({
      role_id:           Number(row.role_id),
      user_id:           adminEmail,
      name:              row.name ?? null,
      email:             lowerStr(row.email),
      phone_no:          row.phone_no ?? null,
      location:          row.location ?? null,

      role:              row.role,
      partner_code:      row.partner_code,
      parent_user_id:    lowerStr(row.parent_user_id),
      status:            row.status,
      email_verified_at: toMysqlDateTime(row.email_verified_at),

      dietician_id:      row.dietician_id ?? null,
      is_reset_password: row.is_reset_password === null || row.is_reset_password === undefined
        ? null
        : Number(row.is_reset_password),

      trainers_count:    trainersCount,
      clients_count:     clientsCount,

      override_monthly:  null,
      created_at:        toMysqlDateTime(row.created_at),
      updated_at:        toMysqlDateTime(row.updated_at),
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
      role_id:           Number(row.role_id),
      user_id:           lowerStr(row.user_id),
      name:              row.name ?? null,
      email:             lowerStr(row.email),
      phone_no:          row.phone_no ?? null,
      location:          row.location ?? null,

      role:              row.role,
      partner_code:      row.partner_code,
      parent_user_id:    lowerStr(row.parent_user_id),
      status:            row.status,
      email_verified_at: toMysqlDateTime(row.email_verified_at),

      dietician_id:      row.dietician_id ?? null,
      is_reset_password: row.is_reset_password === null || row.is_reset_password === undefined
        ? null
        : Number(row.is_reset_password),

      trainers_count:    0,
      clients_count:     clientsCount,

      override_monthly:  null,
      created_at:        toMysqlDateTime(row.created_at),
      updated_at:        toMysqlDateTime(row.updated_at),
    });
  }

  return out;
}

async function getPendingInvites(invitedRole, parentUserId) {
  const [rows] = await pool.execute(
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
      WHERE invited_role = ?
        AND status       = 'pending'
        AND expires_at   > UTC_TIMESTAMP()
        AND LOWER(parent_user_id) = LOWER(?)
      ORDER BY created_at DESC, id DESC
    `,
    [invitedRole, parentUserId]
  );

  return rows.map((row) => {
    const firstName = String(row.invited_first_name ?? "").trim();
    const lastName  = String(row.invited_last_name  ?? "").trim();
    const fullName  = `${firstName} ${lastName}`.trim();

    return {
      invitation_id:      Number(row.id),
      name:               fullName,
      first_name:         firstName,
      last_name:          lastName,
      email:              lowerStr(row.invited_email),
      phone_no:           row.invited_phone ?? null,
      role:               row.invited_role,
      partner_code:       row.partner_code,
      invited_by_user_id: lowerStr(row.invited_by_user_id),
      parent_user_id:     lowerStr(row.parent_user_id),
      status:             row.status,
      expires_at:         toMysqlDateTime(row.expires_at),
      sent_at:            toMysqlDateTime(row.sent_at),
      accepted_at:        toMysqlDateTime(row.accepted_at),
      created_at:         toMysqlDateTime(row.created_at),
      updated_at:         toMysqlDateTime(row.updated_at),
    };
  });
}

// ─── Totals ──────────────────────────────────────────────────────────────────

function buildAdminTotals(acceptedAdmins, pendingAdmins) {
  let totalTrainers = 0;
  let totalClients  = 0;

  for (const admin of acceptedAdmins) {
    totalTrainers += Number(admin.trainers_count) || 0;
    totalClients  += Number(admin.clients_count)  || 0;
  }

  return {
    accepted_count: acceptedAdmins.length,
    pending_count:  pendingAdmins.length,
    total_trainers: totalTrainers,
    total_clients:  totalClients,
  };
}

function buildTrainerTotals(acceptedTrainers, pendingTrainers) {
  let totalClients = 0;

  for (const trainer of acceptedTrainers) {
    totalClients += Number(trainer.clients_count) || 0;
  }

  return {
    accepted_count: acceptedTrainers.length,
    pending_count:  pendingTrainers.length,
    total_trainers: acceptedTrainers.length,
    total_clients:  totalClients,
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/list-admin-trainer-users-jwt
 *
 * Headers: Authorization: Bearer <JWT>
 * Body   : {} (ignored — actor identity comes from JWT)
 *
 * Returns:
 *   super_admin → { mode: "super_admin_admins", existing: [admins], ... }
 *   admin       → { mode: "admin_trainers",     existing: [trainers], ... }
 *   trainer     → 403
 */
const listAdminTrainerUsersJwt = async (req, res) => {
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

  try {
    // ── 1. Resolve actor from JWT + DB ──────────────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor, actorEmail } = resolved;
    const actorRole = String(actor.role);

    // ── 2. Housekeeping: expire stale pending invites (best-effort) ─────────
    await expireOldPendingInvites();

    // ── 3. super_admin branch ───────────────────────────────────────────────
    if (actorRole === "super_admin") {
      const [acceptedAdmins, pendingAdmins] = await Promise.all([
        getExistingAdminsForSuperAdmin(actorEmail),
        getPendingInvites("admin", actorEmail),
      ]);

      const totals = buildAdminTotals(acceptedAdmins, pendingAdmins);

      // Fire-and-forget audit log — never block the response.
      writeAuthLogSafe(req, {
        eventType:     "user_list_viewed",
        userId:        actorEmail,
        role:          actorRole,
        partnerCode:   null,
        identifier:    actorEmail,
        success:       true,
        failureReason: "Super admin viewed admin list",
      });

      return res.status(200).json({
        ok:    true,
        mode:  "super_admin_admins",
        actor: {
          user_id:        actorEmail,
          role:           actorRole,
          partner_code:   null,
          parent_user_id: null,
        },
        title:           "Trainer Admins",
        existing:        acceptedAdmins,
        pending_invites: pendingAdmins,
        totals,
      });
    }

    // ── 4. admin branch ─────────────────────────────────────────────────────
    if (actorRole === "admin") {
      const [acceptedTrainers, pendingTrainers] = await Promise.all([
        getExistingTrainersForAdmin(actorEmail),
        getPendingInvites("trainer", actorEmail),
      ]);

      const totals = buildTrainerTotals(acceptedTrainers, pendingTrainers);

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
        actor: {
          user_id:        actorEmail,
          role:           actorRole,
          partner_code:   actor.partner_code   ?? null,
          parent_user_id: actor.parent_user_id ?? null,
        },
        title:           "Trainers",
        existing:        acceptedTrainers,
        pending_invites: pendingTrainers,
        totals,
      });
    }

    // ── 5. Disallowed role (e.g. trainer) ───────────────────────────────────
    return res.status(403).json({
      ok:    false,
      error: "You are not allowed to view this list",
    });
  } catch (err) {
    // ── 6. Error handling — never leak internals in production ──────────────
    console.error("LIST_ADMIN_TRAINER_USERS_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    return res.status(500).json({
      ok:    false,
      error: "Internal server error",
      ...(process.env.NODE_ENV !== "production" && {
        debug_error: err?.message,
      }),
    });
  }
};

module.exports = { listAdminTrainerUsersJwt };
