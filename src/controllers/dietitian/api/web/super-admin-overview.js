"use strict";

/**
 * super-admin-overview.js
 *
 * Converted from: super-admin-overview.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/super-admin-overview
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin only
 *
 * Behaviour parity with PHP:
 *  - Verifies the actor is an active super_admin.
 *  - Expires stale pending admin invites before counting.
 *  - Returns the same overview JSON shape: actor block, network counts,
 *    admin-invite status counts, client invite/subscription counts, and the
 *    network partner-code list.
 *  - Prefers trainer_client_plan_subscriptions when that table exists, else
 *    falls back to trainer_client_invites (same as PHP).
 *
 * Hardening differences from PHP (intentional):
 *  - Actor identity is taken from the verified JWT (sub = dietician_id) and
 *    re-checked against the DB on every call — never from req.body.actor_user_id.
 *    The PHP version trusted a body-supplied `actor_user_id`, which let any
 *    caller read another tenant's whole-network counts (IDOR / privilege
 *    escalation). That parameter is now ignored entirely.
 *  - Every `IN (...)` filter is built with placeholders + bound params, not
 *    real_escape_string string interpolation as in the PHP.
 *  - Internal error details are suppressed in production responses. The PHP
 *    always echoed `debug_error` (the raw exception message) — removed here.
 *  - Invite expiry comparisons use UTC_TIMESTAMP() to match how invites are
 *    actually stored by this app (created with UTC_TIMESTAMP()), rather than
 *    the PHP NOW(), which is TZ-dependent.
 *
 * HIPAA Controls applied:
 *  - Minimum-necessary data: only counts and the columns needed for the actor
 *    block are selected. No blanket SELECT * over client/PHI rows.
 *  - PHI in audit logs (email, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER. Raw PHI never lands in app_auth_logs.
 *  - Structured server-side logs contain only error metadata, never row data.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 */

const crypto = require("crypto");
const pool   = require("../../../../config/db");
const { resolveActorFromToken: sharedResolveActorFromToken } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const SUBSCRIPTIONS_TABLE = "trainer_client_plan_subscriptions";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string" ? val.trim().toLowerCase() : "";
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? n : 0;
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
 * (sub = dietician_id) and require an active super_admin. Returns
 * { actor, actorEmail } on success or { error: { status, body } }.
 *
 * Protects against:
 *  - stale tokens issued before a role demotion / account deactivation
 *  - tampered tokens that pass HMAC but reference a non-existent user
 *  - body-supplied actor_user_id spoofing (PHP's IDOR vector)
 */
async function resolveSuperAdminFromToken(req) {
  // Delegates the JWT→DB identity + status/role check to the shared
  // access-control module, then maps the neutral result back into this
  // controller's historical error shape so behavior is unchanged.
  const resolved = await sharedResolveActorFromToken(req, ["super_admin"]);

  if (resolved.ok) {
    return { actor: resolved.actor, actorEmail: resolved.actorEmail };
  }

  const REASON_BODY = {
    invalid_token:    { status: 401, error: "Invalid token user" },
    not_found:        { status: 401, error: "Token user not found" },
    inactive:         { status: 403, error: "Account is not active" },
    role_not_allowed: { status: 403, error: "Only super admin can view this overview" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, body: { ok: false, error: m.error } } };
}

// ─── Housekeeping ────────────────────────────────────────────────────────────

async function expireOldAdminInvites() {
  try {
    await pool.execute(
      `
        UPDATE app_user_invitations
        SET status     = 'expired',
            updated_at = UTC_TIMESTAMP()
        WHERE invited_role = 'admin'
          AND status       = 'pending'
          AND expires_at  <= UTC_TIMESTAMP()
      `
    );
  } catch (err) {
    // Non-fatal — a stale "pending" count is better than a 500.
    console.error("EXPIRE_ADMIN_INVITES_FAILED:", err?.code || err?.message);
  }
}

// ─── Network codes ───────────────────────────────────────────────────────────

/**
 * Build the upper-cased, de-duplicated set of partner codes in this super
 * admin's network: own effective code + admins under them + trainers directly
 * under them or under their admins. Mirrors PHP get_super_admin_network_codes().
 */
async function getSuperAdminNetworkCodes(actor, actorEmail) {
  const codes = new Set();

  const addCode = (code) => {
    const c = String(code ?? "").trim().toUpperCase();
    if (c !== "") codes.add(c);
  };

  addCode(getActorEffectivePartnerCode(actor));

  const [rows] = await pool.execute(
    `
      SELECT partner_code
      FROM app_user_roles
      WHERE status         = 'active'
        AND partner_code IS NOT NULL
        AND partner_code  <> ''
        AND (
          (
            role = 'admin'
            AND LOWER(parent_user_id) = LOWER(?)
          )
          OR
          (
            role = 'trainer'
            AND (
              LOWER(parent_user_id) = LOWER(?)
              OR LOWER(parent_user_id) IN (
                SELECT LOWER(user_id)
                FROM app_user_roles
                WHERE role   = 'admin'
                  AND status = 'active'
                  AND LOWER(parent_user_id) = LOWER(?)
              )
            )
          )
        )
    `,
    [actorEmail, actorEmail, actorEmail]
  );

  for (const row of rows) {
    addCode(row.partner_code);
  }

  return [...codes];
}

// ─── Admin / trainer counts ──────────────────────────────────────────────────

async function countActiveAdminsUnderSuperAdmin(superAdminEmail) {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS total
      FROM app_user_roles
      WHERE role   = 'admin'
        AND status = 'active'
        AND LOWER(parent_user_id) = LOWER(?)
    `,
    [superAdminEmail]
  );
  return toInt(rows[0]?.total);
}

async function countActiveTrainersUnderSuperAdminNetwork(superAdminEmail) {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS total
      FROM app_user_roles
      WHERE role   = 'trainer'
        AND status = 'active'
        AND (
          LOWER(parent_user_id) = LOWER(?)
          OR LOWER(parent_user_id) IN (
            SELECT LOWER(user_id)
            FROM app_user_roles
            WHERE role   = 'admin'
              AND status = 'active'
              AND LOWER(parent_user_id) = LOWER(?)
          )
        )
    `,
    [superAdminEmail, superAdminEmail]
  );
  return toInt(rows[0]?.total);
}

// ─── Client counts ───────────────────────────────────────────────────────────

async function countClientsForPartnerCode(partnerCode) {
  if (partnerCode === null || partnerCode === undefined ||
      String(partnerCode).trim() === "") {
    return 0;
  }

  const [rows] = await pool.execute(
    `
      SELECT COUNT(DISTINCT profile_id) AS total
      FROM table_clients
      WHERE UPPER(dietician_id) = UPPER(?)
    `,
    [partnerCode]
  );
  return toInt(rows[0]?.total);
}

async function countClientsForAdminCodesUnderSuperAdmin(superAdminEmail) {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(DISTINCT tc.profile_id) AS total
      FROM table_clients tc
      INNER JOIN app_user_roles aur
        ON UPPER(tc.dietician_id) = UPPER(aur.partner_code)
      WHERE aur.role   = 'admin'
        AND aur.status = 'active'
        AND LOWER(aur.parent_user_id) = LOWER(?)
    `,
    [superAdminEmail]
  );
  return toInt(rows[0]?.total);
}

async function countClientsForTrainerCodesUnderSuperAdmin(superAdminEmail) {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(DISTINCT tc.profile_id) AS total
      FROM table_clients tc
      INNER JOIN app_user_roles trainer
        ON UPPER(tc.dietician_id) = UPPER(trainer.partner_code)
      WHERE trainer.role   = 'trainer'
        AND trainer.status = 'active'
        AND (
          LOWER(trainer.parent_user_id) = LOWER(?)
          OR LOWER(trainer.parent_user_id) IN (
            SELECT LOWER(user_id)
            FROM app_user_roles
            WHERE role   = 'admin'
              AND status = 'active'
              AND LOWER(parent_user_id) = LOWER(?)
          )
        )
    `,
    [superAdminEmail, superAdminEmail]
  );
  return toInt(rows[0]?.total);
}

/**
 * Count distinct clients whose dietician_id is in `codes`. The IN-list is built
 * as placeholders + bound params (NOT string interpolation as in the PHP).
 */
async function countClientsForCodes(codes) {
  const upperCodes = [...new Set(
    (codes || [])
      .map((c) => String(c ?? "").trim().toUpperCase())
      .filter((c) => c !== "")
  )];

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

// ─── Invitation counts ───────────────────────────────────────────────────────

async function countUserInvitesByStatus(parentUserId, invitedRole, status) {
  if (status === "pending") {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM app_user_invitations
        WHERE invited_role = ?
          AND status       = 'pending'
          AND expires_at   > UTC_TIMESTAMP()
          AND LOWER(parent_user_id) = LOWER(?)
      `,
      [invitedRole, parentUserId]
    );
    return toInt(rows[0]?.total);
  }

  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS total
      FROM app_user_invitations
      WHERE invited_role = ?
        AND status       = ?
        AND LOWER(parent_user_id) = LOWER(?)
    `,
    [invitedRole, status, parentUserId]
  );
  return toInt(rows[0]?.total);
}

// ─── Client invite / subscription counts ─────────────────────────────────────

const EMPTY_CLIENT_INVITE_TOTALS = Object.freeze({
  total: 0,
  pending: 0,
  accepted: 0,
  failed: 0,
  cancelled: 0,
});

async function tableExists(tableName) {
  try {
    const [rows] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME   = ?
      `,
      [tableName]
    );
    return toInt(rows[0]?.total) > 0;
  } catch (err) {
    console.error("TABLE_EXISTS_CHECK_FAILED:", err?.code || err?.message);
    return false;
  }
}

/**
 * Build a placeholder string + the upper-cased param list for an IN clause that
 * is used twice (trainer_code and trainer_id). Returns null when no usable code.
 */
function buildCodeInClause(codes) {
  const upperCodes = [...new Set(
    (codes || [])
      .map((c) => String(c ?? "").trim().toUpperCase())
      .filter((c) => c !== "")
  )];

  if (upperCodes.length === 0) return null;

  return {
    placeholders: upperCodes.map(() => "?").join(","),
    params: upperCodes,
  };
}

async function countClientSubscriptionsForCodes(codes) {
  const clause = buildCodeInClause(codes);
  if (!clause) return { ...EMPTY_CLIENT_INVITE_TOTALS };

  const { placeholders, params } = clause;

  const [rows] = await pool.execute(
    `
      SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN status = 'sent' AND subscription_status = 'pending' THEN 1 ELSE 0 END) AS pending,
        SUM(CASE WHEN status = 'accepted' OR accepted_profile_id IS NOT NULL OR redeemed_profile_id IS NOT NULL THEN 1 ELSE 0 END) AS accepted,
        SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN status = 'cancelled' OR subscription_status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled
      FROM ${SUBSCRIPTIONS_TABLE}
      WHERE UPPER(trainer_code) IN (${placeholders})
         OR UPPER(trainer_id)   IN (${placeholders})
    `,
    [...params, ...params]
  );

  const row = rows[0] || {};
  return {
    total:     toInt(row.total),
    pending:   toInt(row.pending),
    accepted:  toInt(row.accepted),
    failed:    toInt(row.failed),
    cancelled: toInt(row.cancelled),
  };
}

async function countLegacyClientInvitesForCodes(codes) {
  const clause = buildCodeInClause(codes);
  if (!clause) return { ...EMPTY_CLIENT_INVITE_TOTALS };

  const { placeholders, params } = clause;

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
         OR UPPER(trainer_id)   IN (${placeholders})
    `,
    [...params, ...params]
  );

  const row = rows[0] || {};
  return {
    total:     toInt(row.total),
    pending:   toInt(row.pending),
    accepted:  toInt(row.accepted),
    failed:    toInt(row.failed),
    cancelled: toInt(row.cancelled),
  };
}

async function countClientInvitesForCodes(codes) {
  if (!Array.isArray(codes) || codes.length === 0) {
    return { ...EMPTY_CLIENT_INVITE_TOTALS };
  }

  if (await tableExists(SUBSCRIPTIONS_TABLE)) {
    return countClientSubscriptionsForCodes(codes);
  }

  return countLegacyClientInvitesForCodes(codes);
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/super-admin-overview
 *
 * Headers: Authorization: Bearer <JWT>
 * Body   : {} (ignored — actor identity comes from JWT, NOT body.actor_user_id)
 *
 * Returns the super admin overview dashboard counts (see PHP for shape).
 */
const superAdminOverview = async (req, res) => {
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

  try {
    // ── 1. Resolve + authorize actor from JWT (super_admin only) ────────────
    const resolved = await resolveSuperAdminFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType:     "super_admin_overview_denied",
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
    const actorCode = getActorEffectivePartnerCode(actor);

    // ── 2. Expire stale pending admin invites before counting ───────────────
    await expireOldAdminInvites();

    // ── 3. Network codes (needed by several count queries) ──────────────────
    const networkCodes = await getSuperAdminNetworkCodes(actor, actorEmail);

    // ── 4. Run the independent count queries in parallel ────────────────────
    const [
      adminCount,
      trainerCount,
      totalClientsInNetwork,
      ownClientsCount,
      adminClientCount,
      trainerClientCount,
      pendingAdminInvites,
      expiredAdminInvites,
      revokedAdminInvites,
      clientInviteTotals,
    ] = await Promise.all([
      countActiveAdminsUnderSuperAdmin(actorEmail),
      countActiveTrainersUnderSuperAdminNetwork(actorEmail),
      countClientsForCodes(networkCodes),
      countClientsForPartnerCode(actorCode),
      countClientsForAdminCodesUnderSuperAdmin(actorEmail),
      countClientsForTrainerCodesUnderSuperAdmin(actorEmail),
      countUserInvitesByStatus(actorEmail, "admin", "pending"),
      countUserInvitesByStatus(actorEmail, "admin", "expired"),
      countUserInvitesByStatus(actorEmail, "admin", "revoked"),
      countClientInvitesForCodes(networkCodes),
    ]);

    // ── 5. Audit — success (fire-and-forget, never blocks the response) ─────
    writeAuthLogSafe(req, {
      eventType:     "super_admin_overview_viewed",
      userId:        actorEmail,
      role:          "super_admin",
      partnerCode:   actorCode,
      identifier:    actorEmail,
      success:       true,
      failureReason: "Super admin viewed overview",
    });

    // ── 6. Respond (matches PHP JSON shape exactly) ─────────────────────────
    const canInviteClients =
      actorCode !== null && String(actorCode).trim() !== "";

    return res.status(200).json({
      ok:    true,
      mode:  "super_admin_overview",
      title: "Super Admin Overview",

      actor: {
        user_id:        actorEmail,
        role:           "super_admin",
        actual_role:    "super_admin",
        partner_code:   actorCode,
        parent_user_id: null,
        name:           actor.name ?? null,
        email:          normalizeEmail(actor.email),
        phone_no:       actor.phone_no ?? null,
        location:       actor.location ?? null,
        dietician_id:   actor.dietician_id ?? null,

        // UI flags: super admin is also shown as trainer admin & trainer owner.
        is_super_admin_as_trainer_admin: true,
        is_super_admin_as_trainer:       true,
        can_invite_admins:               true,
        can_invite_trainers:             true,
        can_invite_clients:              canInviteClients,
      },

      overview: {
        // Raw DB counts.
        real_total_admins:              adminCount,
        real_total_trainers_in_network: trainerCount,

        // Main UI counts — super admin counts as an admin/trainer-admin too.
        total_admins: 1 + adminCount,

        // Trainer display count = super admin + admins + trainers.
        total_trainers:           1 + adminCount + trainerCount,
        total_trainers_in_network: 1 + adminCount + trainerCount,

        // networkCodes already includes the actor's own code.
        total_clients_in_network: totalClientsInNetwork,

        // Extra explicit UI aliases (parity with PHP).
        total_admins_including_self:   1 + adminCount,
        total_trainers_including_self: 1 + trainerCount,
        total_trainer_like_owners:     1 + adminCount + trainerCount,
        total_trainers_display_count:  1 + adminCount + trainerCount,

        // Client split.
        own_clients_count:     ownClientsCount,
        admin_clients_count:   adminClientCount,
        trainer_clients_count: trainerClientCount,

        // Admin invite statuses.
        pending_admin_invites_count: pendingAdminInvites,
        expired_admin_invites_count: expiredAdminInvites,
        revoked_admin_invites_count: revokedAdminInvites,

        // Client invite/subscription statuses.
        client_invites_total:     clientInviteTotals.total,
        client_invites_pending:   clientInviteTotals.pending,
        client_invites_accepted:  clientInviteTotals.accepted,
        client_invites_failed:    clientInviteTotals.failed,
        client_invites_cancelled: clientInviteTotals.cancelled,
      },

      network: {
        codes: networkCodes,
      },
    });

  } catch (err) {
    console.error("SUPER_ADMIN_OVERVIEW_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType:     "super_admin_overview_error",
      userId:        actorEmail,
      role:          "super_admin",
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

module.exports = { superAdminOverview };
