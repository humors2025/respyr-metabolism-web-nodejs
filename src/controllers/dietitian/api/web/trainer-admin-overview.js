"use strict";

/**
 * trainer-admin-overview.js
 *
 * Converted from: trainer-admin-overview.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/trainer-admin-overview
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin (trainer admin) | super_admin
 *
 * Behaviour parity with the PHP:
 *  - Network codes:
 *      admin       → own code + active trainers parented to the actor
 *      super_admin → own code + active admins parented to the actor + active
 *                    trainers parented to those admins
 *  - Network trainers list:
 *      admin       → active trainers parented to the actor
 *      super_admin → active trainers parented to the actor's admins
 *    Each trainer row carries clients_count and client_invites_count, exactly
 *    like the PHP.
 *  - Overview counts: total/own/trainer clients, accepted trainers, trainer
 *    invite status counts (pending/expired/revoked), and client-invite status
 *    counts from trainer_client_invites.
 *  - Response keys/shape match the PHP (ok, mode, title, actor, overview,
 *    network). mode = "super_admin_trainer_admin_overview" for a super_admin,
 *    else "trainer_admin_overview".
 *  - Same DB tables only: table_dietician, app_user_roles, table_clients,
 *    app_user_invitations, trainer_client_invites, app_auth_logs. Nothing added
 *    or removed.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (sub = dietician_id) and re-checked against the DB on every call. The PHP
 *    trusted body.actor_user_id, which let any caller read another tenant's
 *    whole-network counts (IDOR / privilege escalation). body.actor_user_id is
 *    still accepted for frontend/back-compat, but it is only cross-checked
 *    against the token email (mismatch → 403); it can never select a different
 *    user. role + status are re-verified server-side.
 *  - Every IN (...) filter uses placeholders + bound params, never
 *    real_escape_string string interpolation as in the PHP.
 *  - Internal error details are suppressed in production responses. The PHP
 *    always echoed debug_error (the raw exception) — gated behind APP_DEBUG here.
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
const { resolveActorFromToken: sharedResolveActorFromToken } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);
const OVERVIEW_ROLES = new Set(["admin", "super_admin"]);

const EMPTY_CLIENT_INVITE_TOTALS = Object.freeze({
  total: 0,
  pending: 0,
  accepted: 0,
  failed: 0,
  cancelled: 0,
});

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

/** De-dup + upper-case a code list for safe placeholder binding. */
function normalizeCodeList(codes) {
  return [
    ...new Set(
      (codes || [])
        .map((c) => String(c ?? "").trim().toUpperCase())
        .filter((c) => c !== "")
    ),
  ];
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
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or
 * { error: { status, body } }. Mirrors PHP get_actor_by_email_or_fail(), but
 * keyed off the verified token rather than a body-supplied email.
 */
async function resolveActorFromToken(req) {
  // Identity + status/role check delegated to the shared access-control module;
  // the OVERVIEW_ROLES gate downstream still narrows to admin/super_admin.
  const resolved = await sharedResolveActorFromToken(req, VALID_ACTOR_ROLES);

  if (resolved.ok) {
    return { actor: resolved.actor, actorEmail: resolved.actorEmail };
  }

  const REASON_BODY = {
    invalid_token:    { status: 401, error: "Invalid token user" },
    not_found:        { status: 403, error: "Actor user not found" },
    inactive:         { status: 403, error: "Actor account is not active" },
    role_not_allowed: { status: 403, error: "Invalid actor role" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, body: { ok: false, error: m.error } } };
}

// ─── Network codes ───────────────────────────────────────────────────────────

/**
 * PHP get_network_codes_for_overview(): own effective code plus the network
 * partner codes for the actor's role. Returns upper-cased, de-duplicated codes.
 */
async function getNetworkCodesForOverview(actor, actorEmail) {
  const role = String(actor.role);
  const codes = new Set();

  const ownCode = getActorEffectivePartnerCode(actor);
  if (ownCode !== null && String(ownCode).trim() !== "") {
    codes.add(String(ownCode).toUpperCase());
  }

  if (role === "admin") {
    const [rows] = await pool.execute(
      `
        SELECT partner_code
        FROM app_user_roles
        WHERE role = 'trainer'
          AND status = 'active'
          AND partner_code IS NOT NULL
          AND partner_code <> ''
          AND LOWER(parent_user_id) = LOWER(?)
      `,
      [actorEmail]
    );
    for (const row of rows) {
      if (row.partner_code) codes.add(String(row.partner_code).toUpperCase());
    }
  }

  if (role === "super_admin") {
    const [rows] = await pool.execute(
      `
        SELECT partner_code
        FROM app_user_roles
        WHERE status = 'active'
          AND partner_code IS NOT NULL
          AND partner_code <> ''
          AND (
            (
              role = 'admin'
              AND LOWER(parent_user_id) = LOWER(?)
            )
            OR
            (
              role = 'trainer'
              AND LOWER(parent_user_id) IN (
                SELECT LOWER(user_id)
                FROM app_user_roles
                WHERE role = 'admin'
                  AND status = 'active'
                  AND LOWER(parent_user_id) = LOWER(?)
              )
            )
          )
      `,
      [actorEmail, actorEmail]
    );
    for (const row of rows) {
      if (row.partner_code) codes.add(String(row.partner_code).toUpperCase());
    }
  }

  return [...codes];
}

// ─── Network trainers ────────────────────────────────────────────────────────

/**
 * PHP get_network_trainers(): active trainers in the actor's network with their
 * per-trainer clients_count and client_invites_count.
 */
async function getNetworkTrainers(actor, actorEmail) {
  const role = String(actor.role);

  let rows;
  if (role === "admin") {
    [rows] = await pool.execute(
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

          td.dietician_id,
          td.name,
          td.email,
          td.phone_no,
          td.location
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
        ORDER BY aur.created_at DESC, aur.id DESC
      `,
      [actorEmail]
    );
  } else {
    [rows] = await pool.execute(
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

          td.dietician_id,
          td.name,
          td.email,
          td.phone_no,
          td.location
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) IN (
            SELECT LOWER(user_id)
            FROM app_user_roles
            WHERE role = 'admin'
              AND status = 'active'
              AND LOWER(parent_user_id) = LOWER(?)
          )
        ORDER BY aur.created_at DESC, aur.id DESC
      `,
      [actorEmail]
    );
  }

  const out = [];

  // Sequential awaits mirror the PHP and keep the shared mysql2 pool unstressed.
  for (const row of rows) {
    const code = getEffectiveCodeFromRow(row);

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

      partner_code: code,
      dietician_id: row.dietician_id ?? null,
      parent_user_id: normalizeEmail(row.parent_user_id),
      status: row.status ?? null,
      email_verified_at: toMysqlDateTime(row.email_verified_at),

      clients_count: await countClientsForPartnerCode(code),
      client_invites_count: await countClientInvitesForCode(code),

      created_at: toMysqlDateTime(row.created_at),
    });
  }

  return out;
}

// ─── Client counts ───────────────────────────────────────────────────────────

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

async function countClientsForCodes(codes) {
  const upperCodes = normalizeCodeList(codes);
  if (upperCodes.length === 0) return 0;

  const placeholders = upperCodes.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT COUNT(DISTINCT profile_id) AS total
      FROM table_clients
      WHERE UPPER(dietician_id) IN (${placeholders})
    `,
    upperCodes
  );
  return toInt(rows[0]?.total);
}

// ─── Trainer-invite counts ───────────────────────────────────────────────────

async function countTrainerInvitesByStatus(parentUserId, status) {
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
        [parentUserId]
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
      [status, parentUserId]
    );
    return toInt(rows[0]?.total);
  } catch (err) {
    console.error("COUNT_TRAINER_INVITES_FAILED:", err?.code || err?.message);
    return 0;
  }
}

// ─── Client-invite counts (trainer_client_invites) ───────────────────────────

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

async function countClientInvitesForCodes(codes) {
  const upperCodes = normalizeCodeList(codes);
  if (upperCodes.length === 0) return { ...EMPTY_CLIENT_INVITE_TOTALS };

  const placeholders = upperCodes.map(() => "?").join(",");

  try {
    const [rows] = await pool.execute(
      `
        SELECT
          COUNT(*) AS total,
          SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) AS pending,
          SUM(CASE WHEN status = 'accepted' OR accepted_profile_id IS NOT NULL THEN 1 ELSE 0 END) AS accepted,
          SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
          SUM(CASE WHEN status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
        FROM trainer_client_invites
        WHERE UPPER(trainer_code) IN (${placeholders})
           OR UPPER(trainer_id) IN (${placeholders})
      `,
      [...upperCodes, ...upperCodes]
    );

    const row = rows[0] || {};
    return {
      total: toInt(row.total),
      pending: toInt(row.pending),
      accepted: toInt(row.accepted),
      failed: toInt(row.failed),
      cancelled: toInt(row.cancelled),
    };
  } catch (err) {
    console.error("COUNT_CLIENT_INVITES_CODES_FAILED:", err?.code || err?.message);
    return { ...EMPTY_CLIENT_INVITE_TOTALS };
  }
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(req) {
  const src = req.body && typeof req.body === "object" ? req.body : {};
  // Optional. Accepted for frontend/back-compat, never authoritative — see the
  // cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);
  return { actorUserId };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/trainer-admin-overview
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   { "actor_user_id": "" }   // optional; if set, must match the token email
 */
const trainerAdminOverview = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const { actorUserId } = parseInputs(req);

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_admin_overview_denied",
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
        eventType: "trainer_admin_overview_denied",
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

    // ── 1c. Role gate: only trainer admin / super admin ─────────────────────
    if (!OVERVIEW_ROLES.has(actorRole)) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_admin_overview_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorEmail,
        success: false,
        failureReason: "Only trainer admin or super admin allowed",
      });
      return res.status(403).json({
        ok: false,
        error: "Only trainer admin or super admin can view this overview",
      });
    }

    // ── 2. Network codes + trainer rows ─────────────────────────────────────
    const networkCodes = await getNetworkCodesForOverview(actor, actorEmail);
    const trainerRows = await getNetworkTrainers(actor, actorEmail);

    // ── 3. Counts ────────────────────────────────────────────────────────────
    const [
      ownClientsCount,
      totalClientsInNetwork,
      pendingTrainerInvitesCount,
      expiredTrainerInvitesCount,
      revokedTrainerInvitesCount,
      clientInviteTotals,
    ] = await Promise.all([
      countClientsForPartnerCode(actorCode),
      countClientsForCodes(networkCodes),
      countTrainerInvitesByStatus(actorEmail, "pending"),
      countTrainerInvitesByStatus(actorEmail, "expired"),
      countTrainerInvitesByStatus(actorEmail, "revoked"),
      countClientInvitesForCodes(networkCodes),
    ]);

    const acceptedTrainersCount = trainerRows.length;
    const trainerClientsCount = Math.max(0, totalClientsInNetwork - ownClientsCount);

    // ── 4. Audit — success (fire-and-forget) ────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "trainer_admin_overview_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: true,
      failureReason: "Trainer admin overview viewed",
    });

    // ── 5. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      ok: true,
      mode: actorRole === "super_admin"
        ? "super_admin_trainer_admin_overview"
        : "trainer_admin_overview",
      title: "Trainer Admin Overview",

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
        parent_user_id: actor.parent_user_id ?? null,
        name: actor.name ?? null,
        email: normalizeEmail(actor.email),
      },

      overview: {
        total_trainers: acceptedTrainersCount,
        total_clients_in_network: totalClientsInNetwork,
        own_clients_count: ownClientsCount,
        trainer_clients_count: trainerClientsCount,

        accepted_trainers_count: acceptedTrainersCount,
        pending_trainer_invites_count: pendingTrainerInvitesCount,
        expired_trainer_invites_count: expiredTrainerInvitesCount,
        revoked_trainer_invites_count: revokedTrainerInvitesCount,

        client_invites_total: clientInviteTotals.total,
        client_invites_pending: clientInviteTotals.pending,
        client_invites_accepted: clientInviteTotals.accepted,
        client_invites_failed: clientInviteTotals.failed,
        client_invites_cancelled: clientInviteTotals.cancelled,
      },

      network: {
        codes: networkCodes,
        trainers: trainerRows,
      },
    });
  } catch (err) {
    console.error("TRAINER_ADMIN_OVERVIEW_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "trainer_admin_overview_error",
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

module.exports = { trainerAdminOverview };
