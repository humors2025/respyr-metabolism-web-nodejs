"use strict";

/**
 * list-trainer-client-invites.js
 *
 * Converted from: list-trainer-client-invites.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/list-trainer-client-invites
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin (all invites) | admin (own + child trainers) | trainer (own only)
 *
 * Behaviour parity with PHP:
 *  - super_admin → every row in trainer_client_invites
 *  - admin       → own partner_code + every trainer where parent_user_id = admin
 *  - trainer     → own partner_code / dietician_id only
 *  - Rows are split client-side into accepted / pending / failed / cancelled,
 *    matching the PHP keys, ordering, and totals block exactly.
 *
 * Hardening differences from PHP (intentional):
 *  - Actor identity is taken from the verified JWT — never from
 *    req.body.actor_user_id. The PHP file trusted a body-supplied
 *    `actor_user_id`, which is a privilege-escalation / IDOR vector
 *    (any caller could read another tenant's client list).
 *  - The `IN (...)` partner-code filter is built with placeholders, not
 *    real_escape_string interpolation as in PHP.
 *  - Audit log writes use a fail-safe wrapper that HMAC-hashes PHI/PII
 *    (identifier, IP, user-agent) before storage.
 *
 * VAPT Controls applied:
 *  - Token-bound authorization (JWT → DB re-check on every call). A stale
 *    or demoted account cannot list client invites.
 *  - Fully parameterized queries — zero string interpolation. The dynamic
 *    `IN (?,?,...)` list is built as placeholders + params.
 *  - Method gate: POST only (mirrors PHP). Returns 405 otherwise.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Internal error details suppressed in production responses
 *    (no stack / SQL state leakage).
 *  - VALID_ACTOR_ROLES allow-list enforced server-side; unknown roles 403.
 *
 * HIPAA Controls applied:
 *  - Minimum-necessary data: only the columns required for the list are
 *    selected. No SELECT *.
 *  - PHI in audit logs (email, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER. Raw PHI never lands in app_auth_logs.
 *  - Structured server-side logs contain only error metadata
 *    (code/errno/sqlState/message), never row data.
 *  - Every request is bound to an authenticated JWT and re-verified
 *    against app_user_roles before any client invite is returned.
 */

const crypto = require("crypto");
const pool   = require("../../../../config/db");
const { resolveActorFromToken: sharedResolveActorFromToken } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const APP_DEBUG = process.env.NODE_ENV !== "production";

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string" ? val.trim().toLowerCase() : "";
}

function lowerStr(val) {
  return val === null || val === undefined ? "" : String(val).toLowerCase();
}

/**
 * Format a mysql2 DATETIME value as "YYYY-MM-DD HH:MM:SS" to match the
 * PHP response shape. Accepts Date objects (mysql2 default) and strings.
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
 * Fail-safe audit log writer. Schema mirrors writeAuthLogSafe() in the
 * sibling controllers. Never throws — audit failures must not surface
 * to clients.
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
 * Re-fetch the authenticated actor from DB using the JWT subject.
 * Returns { actor, actorEmail } on success or { error: { status, body } }.
 *
 * Protects against:
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

// ─── Allowed codes ───────────────────────────────────────────────────────────

/**
 * Resolves the set of trainer / partner codes whose invites this actor
 * may see.
 *
 *   super_admin → []  (caller must branch — empty means "no filter, all rows")
 *   admin       → own partner_code + own dietician_id + child trainers'
 *                  partner_codes
 *   trainer     → own partner_code + own dietician_id
 *
 * All codes are upper-cased and de-duplicated to mirror the PHP behavior.
 */
async function getAllowedTrainerCodesForActor(actor) {
  const role       = String(actor.role);
  const actorEmail = normalizeEmail(actor.email);

  if (role === "super_admin") {
    return [];
  }

  const codes = new Set();

  if (actor.partner_code) {
    codes.add(String(actor.partner_code).toUpperCase());
  }
  if (actor.dietician_id) {
    codes.add(String(actor.dietician_id).toUpperCase());
  }

  if (role === "admin") {
    try {
      const [childRows] = await pool.execute(
        `
          SELECT partner_code
          FROM app_user_roles
          WHERE role         = 'trainer'
            AND status       = 'active'
            AND partner_code IS NOT NULL
            AND partner_code <> ''
            AND LOWER(parent_user_id) = LOWER(?)
        `,
        [actorEmail]
      );

      for (const row of childRows) {
        if (row.partner_code) {
          codes.add(String(row.partner_code).toUpperCase());
        }
      }
    } catch (err) {
      // Non-fatal: a query failure here should fall back to the codes we
      // already collected for the actor, not 500 the whole list view.
      console.error("LIST_CHILD_TRAINER_CODES_FAILED:", err?.code || err?.message);
    }
  }

  return [...codes];
}

// ─── Client invite list ──────────────────────────────────────────────────────

/**
 * Fetch trainer_client_invites rows scoped to the actor.
 *
 * super_admin → returns every row.
 * admin/trainer → filtered by an IN (...) list of partner / dietician codes.
 * If a non-super_admin has no allowed codes, returns [] (caller already
 * guarded against this, but this is defense in depth).
 */
async function getClientInvites(actorRole, allowedCodes) {
  const baseSelect = `
    SELECT
      tci.id,
      tci.trainer_id,
      tci.trainer_code,
      tci.client_name,
      tci.client_mobile,
      tci.client_email,
      tci.status,
      tci.email_status,
      tci.resend_email_id,
      tci.accepted_profile_id,
      tci.accepted_at,
      tci.error_message,
      tci.created_at,
      tci.updated_at,

      aur.user_id AS trainer_user_id,
      td.name     AS trainer_name,
      td.email    AS trainer_email,
      td.phone_no AS trainer_phone
    FROM trainer_client_invites tci
    LEFT JOIN app_user_roles aur
      ON UPPER(aur.partner_code) = UPPER(tci.trainer_code)
      OR UPPER(aur.partner_code) = UPPER(tci.trainer_id)
    LEFT JOIN table_dietician td
      ON LOWER(td.email) = LOWER(aur.user_id)
  `;

  if (actorRole === "super_admin") {
    const [rows] = await pool.execute(
      `${baseSelect}
       ORDER BY tci.created_at DESC, tci.id DESC`
    );
    return rows;
  }

  if (!Array.isArray(allowedCodes) || allowedCodes.length === 0) {
    return [];
  }

  // Build the IN-list as placeholders (NOT string interpolation) to keep
  // every value parameterized. We pass the codes twice — once for
  // tci.trainer_code, once for tci.trainer_id.
  const placeholders = allowedCodes.map(() => "?").join(",");
  const upperCodes   = allowedCodes.map((c) => String(c).toUpperCase());

  const [rows] = await pool.execute(
    `${baseSelect}
     WHERE
       UPPER(tci.trainer_code) IN (${placeholders})
       OR UPPER(tci.trainer_id) IN (${placeholders})
     ORDER BY tci.created_at DESC, tci.id DESC`,
    [...upperCodes, ...upperCodes]
  );

  return rows;
}

function formatClientInviteRow(row) {
  return {
    invite_id:        Number(row.id),

    client_name:      row.client_name ?? null,
    client_mobile:    row.client_mobile ?? null,
    client_email:     normalizeEmail(row.client_email),

    trainer_id:       row.trainer_id ?? null,
    trainer_code:     row.trainer_code ?? null,

    trainer_user_id:  row.trainer_user_id ? normalizeEmail(row.trainer_user_id) : null,
    trainer_name:     row.trainer_name ?? null,
    trainer_email:    row.trainer_email ? normalizeEmail(row.trainer_email) : null,
    trainer_phone:    row.trainer_phone ?? null,

    status:           row.status ?? null,
    email_status:     row.email_status ?? null,
    resend_email_id:  row.resend_email_id ?? null,

    accepted_profile_id: row.accepted_profile_id ?? null,
    accepted_at:         toMysqlDateTime(row.accepted_at),

    error_message:    row.error_message ?? null,

    created_at:       toMysqlDateTime(row.created_at),
    updated_at:       toMysqlDateTime(row.updated_at),
  };
}

// ─── Mode label ──────────────────────────────────────────────────────────────

function buildModeName(role) {
  if (role === "super_admin") return "super_admin_client_invites";
  if (role === "admin")       return "admin_client_invites";
  if (role === "trainer")     return "trainer_client_invites";
  return "client_invites";
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/list-trainer-client-invites
 *
 * Headers: Authorization: Bearer <JWT>
 * Body   : {} (ignored — actor identity comes from JWT, NOT body.actor_user_id)
 *
 * Returns:
 *   {
 *     ok, mode, title,
 *     actor: { user_id, role, partner_code, parent_user_id },
 *     accepted_clients:  [...],
 *     pending_invites:   [...],
 *     failed_invites:    [...],
 *     cancelled_invites: [...],
 *     totals: { accepted_count, pending_count, failed_count, cancelled_count, total_count }
 *   }
 */
const listTrainerClientInvites = async (req, res) => {
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
    // ── 1. Resolve actor from JWT + DB ──────────────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType:     "client_invites_list_denied",
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

    // ── 2. Resolve the set of codes this actor is allowed to see ────────────
    const allowedCodes = await getAllowedTrainerCodesForActor(actor);

    if (actorRole !== "super_admin" && allowedCodes.length === 0) {
      await writeAuthLogSafe(req, {
        eventType:     "client_invites_list_denied",
        userId:        actorEmail,
        role:          actorRole,
        partnerCode:   actor.partner_code ?? null,
        identifier:    actorEmail,
        success:       false,
        failureReason: "no allowed trainer codes",
      });

      return res.status(403).json({
        ok:    false,
        error: "No trainer/client code found for this user",
      });
    }

    // ── 3. Fetch rows scoped to this actor ──────────────────────────────────
    const rows = await getClientInvites(actorRole, allowedCodes);

    // ── 4. Bucket rows into the four response lists ─────────────────────────
    const acceptedClients  = [];
    const pendingInvites   = [];
    const failedInvites    = [];
    const cancelledInvites = [];

    for (const row of rows) {
      const status              = lowerStr(row.status);
      const acceptedProfileId   = String(row.accepted_profile_id ?? "").trim();
      const formatted           = formatClientInviteRow(row);

      if (status === "accepted" || acceptedProfileId !== "") {
        acceptedClients.push(formatted);
      } else if (status === "sent") {
        pendingInvites.push(formatted);
      } else if (status === "failed") {
        failedInvites.push(formatted);
      } else if (status === "cancelled") {
        cancelledInvites.push(formatted);
      }
    }

    // ── 5. Audit — success ──────────────────────────────────────────────────
    writeAuthLogSafe(req, {
      eventType:     "client_invites_list_viewed",
      userId:        actorEmail,
      role:          actorRole,
      partnerCode:   actor.partner_code ?? null,
      identifier:    actorEmail,
      success:       true,
      failureReason: "Viewed client invite list",
    });

    // ── 6. Respond (matches PHP JSON shape exactly) ─────────────────────────
    return res.status(200).json({
      ok:    true,
      mode:  buildModeName(actorRole),
      title: "Clients",
      actor: {
        user_id:        actorEmail,
        role:           actorRole,
        partner_code:   actor.partner_code   ?? null,
        parent_user_id: actor.parent_user_id ?? null,
      },
      accepted_clients:  acceptedClients,
      pending_invites:   pendingInvites,
      failed_invites:    failedInvites,
      cancelled_invites: cancelledInvites,
      totals: {
        accepted_count:  acceptedClients.length,
        pending_count:   pendingInvites.length,
        failed_count:    failedInvites.length,
        cancelled_count: cancelledInvites.length,
        total_count:     rows.length,
      },
    });

  } catch (err) {
    console.error("LIST_TRAINER_CLIENT_INVITES_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType:     "client_invites_list_error",
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
      ...(APP_DEBUG && {
        debug_error: err?.message,
      }),
    });
  }
};

module.exports = { listTrainerClientInvites };
