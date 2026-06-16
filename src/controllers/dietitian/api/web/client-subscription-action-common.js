"use strict";

/**
 * client-subscription-action-common.js
 *
 * Converted from: client-subscription-action-common.php
 *                 (+ cors.php / db_connection_pdo.php / resend_config.php deps)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Purpose
 * -------
 * Shared helpers for the client-subscription invite actions
 * (resend-client-subscription-invite, revoke-client-subscription-invite, ...).
 * This is the Node port of the PHP `csi_*` helper library. Every PHP function
 * has a 1:1 equivalent here (see the @phpparity tag on each export).
 *
 * Faithful-to-PHP behaviour:
 *  - csi_send_email() posts a Resend **template** payload
 *    (`template: { id, variables }`) — NOT inline HTML. Ported exactly. See the
 *    sendEmail() banner for the Resend-API caveat.
 *  - csi_get_subscription_for_update() resolves by subscription_id, then
 *    redeem_code, then the latest row for invite_id (source_invite_id) — all
 *    three branches, all row-locked (FOR UPDATE).
 *  - csi_create_subscription_from_legacy_invite() copies the legacy invite's
 *    status/email_status/accepted_* through to the new subscription row and back-
 *    links trainer_client_invites.latest_subscription_id, then re-selects the row.
 *  - csi_subscription_is_accepted() keys off `status='accepted'` plus
 *    accepted/redeemed profile-id / timestamp columns (PHP semantics).
 *
 * VAPT/HIPAA hardening (beyond the PHP — the point of the sprint):
 *  - Token-bound identity. The PHP `csi_get_actor_or_fail($pdo, $actorEmail)`
 *    trusted a body-supplied email to select the actor (a textbook IDOR). Here
 *    `resolveActorFromToken(db, req)` ALWAYS resolves the actor from the verified
 *    JWT and re-checks role + status against the DB. A body `actor_user_id` may
 *    only be CROSS-CHECKED against the token identity by the caller — it can
 *    never select another user.
 *  - Every query is fully parameterized (no string interpolation).
 *  - Redeem codes use crypto.randomInt (CSPRNG), not a biased PRNG.
 *  - Audit PHI/PII (client email, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text. Audit writes are fail-safe.
 *  - Early-exit "fail" paths throw `ApiError` (the Node analogue of the PHP
 *    csi_json(...); exit). The controller maps ApiError → res.status().json().
 *
 * Usage from a controller:
 *   const csi = require("./client-subscription-action-common");
 *   const conn = await pool.getConnection();
 *   await conn.query("SET time_zone = '+05:30'");          // IST parity
 *   const { actor, actorEmail } = await csi.resolveActorFromToken(conn, req);
 *   const allowed = await csi.allowedCodes(conn, actor, actorEmail);
 *   ...
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_invites, trainer_client_plan_subscriptions,
 * app_auth_logs.
 *
 * Every `db` parameter accepts either a pooled connection (inside a transaction)
 * or the pool itself (for standalone queries) — both expose .execute()/.query().
 */

const crypto = require("crypto");
const axios  = require("axios");
const pool   = require("../../../../config/db");

// ─── Constants (was the define()s + resend_config.php) ────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "CHANGE_THIS_LONG_RANDOM_PEPPER";

const APP_DEBUG = process.env.NODE_ENV !== "production";

// define('CLIENT_REDEEM_CODE_EXPIRY_DAYS', 30)
const CLIENT_REDEEM_CODE_EXPIRY_DAYS = Math.max(
  1,
  parseInt(process.env.CLIENT_REDEEM_CODE_EXPIRY_DAYS, 10) || 30
);

// resend_config.php constants. Only RESEND_API_KEY is mandatory.
const RESEND_API_KEY     = process.env.RESEND_API_KEY     || "";
const RESEND_FROM_EMAIL  =
  process.env.RESEND_FROM_EMAIL ||
  process.env.RESEND_FROM_ADDRESS ||
  "Respyr <noreply@respyr.ai>";
const RESEND_REPLY_TO    = process.env.RESEND_REPLY_TO    || "";
const RESEND_TEMPLATE_ID = process.env.RESEND_TEMPLATE_ID || "";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// IST (Asia/Kolkata, UTC+05:30) — the PHP ran date_default_timezone_set('Asia/Kolkata')
// and SET time_zone = '+05:30', so all stored timestamps are IST wall-clock.
const IST_OFFSET_MS = (5 * 60 + 30) * 60 * 1000;

// ─── ApiError: the Node analogue of PHP `csi_json($code, $payload); exit;` ─────

class ApiError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = Object.assign({ status: false, ok: false, message }, extra || {});
  }
}

// ─── Scalar helpers (csi_clean / csi_email / csi_code) ────────────────────────

/** @phpparity csi_clean */
function clean(value) {
  return String(value === null || value === undefined ? "" : value).trim();
}

/** @phpparity csi_email */
function email(value) {
  return String(value === null || value === undefined ? "" : value).trim().toLowerCase();
}

/** @phpparity csi_code */
function code(value) {
  return String(value === null || value === undefined ? "" : value).trim().toUpperCase();
}

/** filter_var(..., FILTER_VALIDATE_EMAIL) intent — conservative single-address check. */
function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/** Parse a positive integer (PHP (int) cast semantics for our id inputs). */
function toInt(value) {
  const n = parseInt(clean(value), 10);
  return Number.isInteger(n) ? n : 0;
}

/** Format a Date as IST "YYYY-MM-DD HH:MM:SS" — matches PHP date() in Asia/Kolkata. */
function istMysqlDateTime(date) {
  const ist = new Date(date.getTime() + IST_OFFSET_MS);
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${ist.getUTCFullYear()}-${pad(ist.getUTCMonth() + 1)}-${pad(ist.getUTCDate())} ` +
    `${pad(ist.getUTCHours())}:${pad(ist.getUTCMinutes())}:${pad(ist.getUTCSeconds())}`
  );
}

/** Expiry timestamp = now + CLIENT_REDEEM_CODE_EXPIRY_DAYS, IST (PHP date(...time()+...)). */
function redeemCodeExpiry() {
  return istMysqlDateTime(
    new Date(Date.now() + CLIENT_REDEEM_CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
  );
}

/** A value is "empty" the way PHP empty() treats it (null/''/'0'/0/false). */
function phpEmpty(value) {
  if (value === null || value === undefined) return true;
  const s = String(value).trim();
  return s === "" || s === "0";
}

/** @phpparity csi_effective_code — partner_code, else dietician_id, else null. */
function effectiveCode(row) {
  if (row && row.partner_code !== null && row.partner_code !== undefined &&
      String(row.partner_code).trim() !== "") {
    return String(row.partner_code);
  }
  if (row && row.dietician_id !== null && row.dietician_id !== undefined &&
      String(row.dietician_id).trim() !== "") {
    return String(row.dietician_id);
  }
  return null;
}

// ─── Actor resolution (token-bound — closes the PHP IDOR hole) ────────────────

/**
 * Resolve the authenticated actor from the verified JWT (NOT from the request
 * body) and re-check role + status against the DB.
 *
 * @phpparity csi_get_actor_or_fail — but token-bound. The PHP took the actor
 * email from the request body; trusting that is the IDOR this sprint closes.
 * Callers that still accept body.actor_user_id MUST only cross-check it against
 * the returned actorEmail (mismatch → 403); it must never select a user.
 *
 * Returns { actor, actorEmail }. Throws ApiError on any failure.
 */
async function resolveActorFromToken(db, req) {
  const payload = (req && req.user) || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = email(
    payload.email || payload.user_id || (payload.dietician && payload.dietician.email) || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    throw new ApiError(401, "Invalid token user");
  }

  const [rows] = dieticianId
    ? await db.execute(
        `SELECT
           td.id, td.dietician_id, td.name, td.phone_no, td.email, td.location,
           aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.status
         FROM table_dietician td
         INNER JOIN app_user_roles aur
           ON LOWER(aur.user_id) = LOWER(td.email)
         WHERE td.dietician_id = ?
         LIMIT 1`,
        [dieticianId]
      )
    : await db.execute(
        `SELECT
           td.id, td.dietician_id, td.name, td.phone_no, td.email, td.location,
           aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.status
         FROM table_dietician td
         INNER JOIN app_user_roles aur
           ON LOWER(aur.user_id) = LOWER(td.email)
         WHERE LOWER(td.email) = LOWER(?)
         LIMIT 1`,
        [tokenEmail]
      );

  const actor = rows[0];

  if (!actor) {
    throw new ApiError(403, "Actor user not found");
  }
  if (String(actor.status) !== "active") {
    throw new ApiError(403, "Actor account is not active");
  }
  if (!VALID_ACTOR_ROLES.has(String(actor.role))) {
    throw new ApiError(403, "Invalid actor role");
  }

  return { actor, actorEmail: email(actor.user_id || actor.email) };
}

/**
 * Set of trainer/partner codes this actor may act on.
 *   trainer     → own effective code only
 *   admin       → own + child trainers' partner_codes
 *   super_admin → own + child admins' + child trainers' partner_codes
 *
 * @phpparity csi_allowed_codes (codes upper-cased + de-duped).
 */
async function allowedCodes(db, actor, actorEmailArg) {
  const codes = new Set();
  const role = String(actor.role);
  const actorEmail = email(actorEmailArg || actor.email || actor.user_id);

  const own = effectiveCode(actor);
  if (own && code(own) !== "") codes.add(code(own));

  if (role === "trainer") {
    return [...codes];
  }

  if (role === "admin") {
    const [rows] = await db.execute(
      `SELECT partner_code
         FROM app_user_roles
        WHERE role = 'trainer'
          AND status = 'active'
          AND partner_code IS NOT NULL
          AND partner_code <> ''
          AND LOWER(parent_user_id) = LOWER(?)`,
      [actorEmail]
    );
    for (const row of rows) {
      if (code(row.partner_code) !== "") codes.add(code(row.partner_code));
    }
    return [...codes];
  }

  if (role === "super_admin") {
    const [rows] = await db.execute(
      `SELECT partner_code
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
              AND (
                LOWER(parent_user_id) = LOWER(?)
                OR LOWER(parent_user_id) IN (
                  SELECT LOWER(user_id)
                  FROM app_user_roles
                  WHERE role = 'admin'
                    AND status = 'active'
                    AND LOWER(parent_user_id) = LOWER(?)
                )
              )
            )
          )`,
      [actorEmail, actorEmail, actorEmail]
    );
    for (const row of rows) {
      if (code(row.partner_code) !== "") codes.add(code(row.partner_code));
    }
    return [...codes];
  }

  return [...codes];
}

/** @phpparity csi_can_access_code — is this single code in the actor's allowed set? */
function canAccessCode(allowed, wanted) {
  const want = code(wanted);
  if (want === "") return false;
  return allowed.some((c) => code(c) === want);
}

/** A subscription/invite row is reachable if EITHER trainer_code or trainer_id is allowed. */
function canAccessRow(allowed, row) {
  return canAccessCode(allowed, row.trainer_code) || canAccessCode(allowed, row.trainer_id);
}

// ─── Target lookups (row-locked inside the caller's transaction) ──────────────

/**
 * @phpparity csi_get_subscription_for_update — by subscription_id, then
 * redeem_code, then the latest subscription for an invite_id (source_invite_id).
 * Each branch locks the row (FOR UPDATE). Returns the row or null.
 */
async function getSubscriptionForUpdate(db, body) {
  const subscriptionId = toInt(body.subscription_id);
  const redeemCode = body.redeem_code !== undefined ? code(body.redeem_code) : "";
  const inviteId = toInt(body.invite_id);

  if (subscriptionId > 0) {
    const [rows] = await db.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE id = ?
        LIMIT 1
        FOR UPDATE`,
      [subscriptionId]
    );
    return rows[0] || null;
  }

  if (redeemCode !== "") {
    const [rows] = await db.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE redeem_code = ?
        LIMIT 1
        FOR UPDATE`,
      [redeemCode]
    );
    return rows[0] || null;
  }

  if (inviteId > 0) {
    const [rows] = await db.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE source_invite_id = ?
        ORDER BY id DESC
        LIMIT 1
        FOR UPDATE`,
      [inviteId]
    );
    return rows[0] || null;
  }

  return null;
}

/** @phpparity csi_get_legacy_invite_for_update — trainer_client_invites by id, locked. */
async function getLegacyInviteForUpdate(db, body) {
  const inviteId = toInt(body.invite_id);
  if (inviteId <= 0) return null;

  const [rows] = await db.execute(
    `SELECT *
       FROM trainer_client_invites
      WHERE id = ?
      LIMIT 1
      FOR UPDATE`,
    [inviteId]
  );
  return rows[0] || null;
}

/** @phpparity csi_subscription_is_accepted — redeemed/accepted subscriptions are terminal. */
function subscriptionIsAccepted(sub) {
  if (!sub) return false;
  if (String(sub.status) === "accepted") return true;
  if (!phpEmpty(sub.accepted_profile_id) || !phpEmpty(sub.redeemed_profile_id)) return true;
  if (!phpEmpty(sub.accepted_at) || !phpEmpty(sub.redeemed_at)) return true;
  return false;
}

/** @phpparity csi_legacy_invite_is_accepted — accepted legacy invites cannot spawn a resend. */
function legacyInviteIsAccepted(invite) {
  if (!invite) return false;
  if (String(invite.status) === "accepted") return true;
  if (!phpEmpty(invite.accepted_profile_id) || !phpEmpty(invite.accepted_at)) return true;
  return false;
}

// ─── Redeem code generation ───────────────────────────────────────────────────

/** @phpparity csi_random_code — RSP + 7 unambiguous chars, CSPRNG. */
function randomCode() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let out = "RSP";
  for (let i = 0; i < 7; i++) {
    out += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return out;
}

/** @phpparity csi_unique_redeem_code — a code not already present in the subscriptions table. */
async function uniqueRedeemCode(db) {
  for (let i = 0; i < 20; i++) {
    const candidate = randomCode();
    const [rows] = await db.execute(
      `SELECT id
         FROM trainer_client_plan_subscriptions
        WHERE redeem_code = ?
        LIMIT 1`,
      [candidate]
    );
    if (!rows[0]) return candidate;
  }
  throw new ApiError(500, "Could not generate unique redeem code");
}

/**
 * @phpparity csi_create_subscription_from_legacy_invite — spawn a subscription
 * row from a legacy trainer_client_invites row, copying the invite's
 * status/email_status/accepted_* across, back-link latest_subscription_id, and
 * re-select the new row. createdByUserId is the actor's email.
 */
async function createSubscriptionFromLegacyInvite(db, legacyInvite, createdByUserId) {
  const planCode = clean(legacyInvite.plan_code) !== "" ? legacyInvite.plan_code : "free_trial";
  const planName = clean(legacyInvite.plan_name) !== "" ? legacyInvite.plan_name : "Free Trial";
  const planPriceLabel =
    clean(legacyInvite.plan_price_label) !== "" ? legacyInvite.plan_price_label : "Free";

  const redeemCode = await uniqueRedeemCode(db);
  const expiresAt = redeemCodeExpiry();

  const inviteStatus = legacyInvite.status !== undefined && legacyInvite.status !== null
    ? legacyInvite.status
    : "sent";
  const inviteEmailStatus =
    legacyInvite.email_status !== undefined && legacyInvite.email_status !== null
      ? legacyInvite.email_status
      : "sent";
  const paymentStatus = planCode === "free_trial" ? "not_required" : "pending";

  const [result] = await db.execute(
    `INSERT INTO trainer_client_plan_subscriptions (
       source_invite_id,
       trainer_id,
       trainer_code,
       client_name,
       client_mobile,
       client_email,
       plan_code,
       plan_name,
       plan_price_label,
       redeem_code,
       code_expires_at,
       status,
       subscription_status,
       payment_status,
       email_status,
       resend_email_id,
       accepted_profile_id,
       accepted_at,
       error_message,
       created_by_user_id,
       created_at,
       updated_at
     )
     VALUES (
       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
       ?, 'pending', ?, ?, ?, ?, ?, ?, ?, NOW(), NOW()
     )`,
    [
      toInt(legacyInvite.id),
      legacyInvite.trainer_id ?? null,
      legacyInvite.trainer_code ?? null,
      legacyInvite.client_name ?? null,
      legacyInvite.client_mobile ?? null,
      email(legacyInvite.client_email),
      planCode,
      planName,
      planPriceLabel,
      redeemCode,
      expiresAt,
      inviteStatus === "accepted" ? "accepted" : "sent",
      paymentStatus,
      inviteEmailStatus === "failed" ? "failed" : "sent",
      legacyInvite.resend_email_id ?? null,
      legacyInvite.accepted_profile_id ?? null,
      legacyInvite.accepted_at ?? null,
      legacyInvite.error_message ?? null,
      createdByUserId,
    ]
  );

  const subscriptionId = Number(result.insertId);

  await db.execute(
    `UPDATE trainer_client_invites
        SET latest_subscription_id = ?,
            updated_at = NOW()
      WHERE id = ?
      LIMIT 1`,
    [subscriptionId, toInt(legacyInvite.id)]
  );

  const [rows] = await db.execute(
    `SELECT *
       FROM trainer_client_plan_subscriptions
      WHERE id = ?
      LIMIT 1`,
    [subscriptionId]
  );

  return rows[0] || null;
}

/**
 * @phpparity csi_update_source_invite — push the resend result onto the source
 * invite row, guarded against an already-accepted invite (never clobber an
 * acceptance).
 */
async function updateSourceInvite(
  db,
  sourceInviteId,
  status,
  emailStatus,
  resendEmailId,
  errorMessage,
  subscriptionId
) {
  if (!sourceInviteId) return;

  await db.execute(
    `UPDATE trainer_client_invites
        SET status = ?,
            email_status = ?,
            resend_email_id = ?,
            error_message = ?,
            latest_subscription_id = ?,
            updated_at = NOW()
      WHERE id = ?
        AND status <> 'accepted'
        AND accepted_profile_id IS NULL
      LIMIT 1`,
    [status, emailStatus, resendEmailId, errorMessage, subscriptionId, sourceInviteId]
  );
}

/** @phpparity csi_hydrate_trainer_name — attach trainer_name for the email. */
async function hydrateTrainerName(db, sub) {
  const [rows] = await db.execute(
    `SELECT name
       FROM table_dietician
      WHERE UPPER(dietician_id) = UPPER(?)
      LIMIT 1`,
    [sub.trainer_code]
  );
  const row = rows[0];
  sub.trainer_name = row && !phpEmpty(row.name) ? row.name : "Your trainer";
  return sub;
}

// ─── Email via Resend (TEMPLATE payload — faithful PHP port) ──────────────────

/**
 * @phpparity csi_send_email
 *
 * Posts the SAME Resend `template` payload the PHP sends:
 *   { from, to, subject, reply_to, template: { id, variables: {...} } }
 *
 * ⚠ CAVEAT — Resend API support:
 *   Resend's public POST /emails endpoint documents `html`, `text`, or `react`
 *   as the body source and does NOT document a `template` field. A template-only
 *   body is commonly rejected with HTTP 422 ("missing `html`/`text`/`react`").
 *   This function reproduces the PHP byte-for-byte as requested; if your Resend
 *   account does not have a private template feature, switch to the inline-HTML
 *   path used by send_trainer_client_invite.js (ask and I'll wire it in).
 *
 * Returns { success, resend_email_id, error }.
 */
async function sendEmail(sub) {
  if (RESEND_API_KEY === "") {
    return { success: false, resend_email_id: null, error: "RESEND_API_KEY is not configured" };
  }

  const payload = {
    from: RESEND_FROM_EMAIL,
    to: [email(sub.client_email)],
    subject: "You’ve been invited to Respyr", // U+2019 curly apostrophe — matches the PHP source
    reply_to: RESEND_REPLY_TO,
    template: {
      id: RESEND_TEMPLATE_ID,
      variables: {
        CLIENT_NAME: sub.client_name,
        TRAINER_NAME: sub.trainer_name !== undefined && sub.trainer_name !== null
          ? sub.trainer_name
          : "Your trainer",
        TRAINER_CODE: sub.trainer_code,
        REDEEM_CODE: sub.redeem_code,
        CODE_EXPIRES_AT: sub.code_expires_at,
        PLAN_CODE: sub.plan_code,
        PLAN_NAME: sub.plan_name,
        PLAN_PRICE_LABEL: sub.plan_price_label,
      },
    },
  };

  try {
    const response = await axios.post("https://api.resend.com/emails", payload, {
      timeout: 30_000,
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
        "User-Agent": "respyr-node-api/1.0",
      },
      // Mirror the PHP: inspect the status/body ourselves rather than throwing.
      validateStatus: () => true,
    });

    const httpCode = response.status;
    const decoded = response.data;

    if (httpCode >= 200 && httpCode < 300 && decoded && decoded.id) {
      return { success: true, resend_email_id: decoded.id, error: null };
    }

    // VAPT: in production don't leak the provider body; in debug keep parity with
    // the PHP which returned "HTTP <code> - <body>".
    const bodyStr =
      typeof decoded === "string" ? decoded : JSON.stringify(decoded || {});
    return {
      success: false,
      resend_email_id: null,
      error: APP_DEBUG
        ? `Resend API error: HTTP ${httpCode} - ${bodyStr}`
        : `Resend API error: HTTP ${httpCode}`,
    };
  } catch (err) {
    return {
      success: false,
      resend_email_id: null,
      error: `Resend request error: ${err?.code || err?.message || "unknown"}`,
    };
  }
}

// ─── Audit log (fail-safe, hashed PHI/PII) ────────────────────────────────────

function getClientIp(req) {
  const ip =
    (req && typeof req.ip === "string" && req.ip) ||
    (req && req.socket && req.socket.remoteAddress) ||
    (req && req.connection && req.connection.remoteAddress) ||
    "0.0.0.0";
  return String(ip).slice(0, 64);
}

function getUserAgent(req) {
  const ua =
    (req && typeof req.get === "function" && req.get("user-agent")) ||
    (req && req.headers && req.headers["user-agent"]) ||
    "";
  return String(ua).slice(0, 500);
}

function auditHash(value) {
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value === null || value === undefined ? "" : value).trim().toLowerCase())
    .digest("hex");
}

/**
 * @phpparity csi_audit — fail-safe insert into app_auth_logs with hashed
 * identifier/IP/UA. PHP read $_SERVER for IP/UA; here we take them from `req`.
 */
async function audit(db, req, eventType, userId, role, partnerCode, identifier, success, reason) {
  try {
    const ipHash = auditHash(getClientIp(req));
    const userAgentHash = auditHash(getUserAgent(req));
    const identifierHash = identifier !== null && identifier !== undefined ? auditHash(identifier) : null;

    await db.execute(
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
        userId !== null && userId !== undefined ? email(userId).slice(0, 191) : null,
        role ?? null,
        partnerCode ?? null,
        identifierHash,
        ipHash,
        userAgentHash,
        success ? 1 : 0,
        reason !== null && reason !== undefined ? String(reason).slice(0, 255) : null,
      ]
    );
  } catch (err) {
    console.error("CLIENT_SUBSCRIPTION_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Exports ──────────────────────────────────────────────────────────────────

module.exports = {
  // constants
  CLIENT_REDEEM_CODE_EXPIRY_DAYS,
  RESEND_API_KEY,
  RESEND_FROM_EMAIL,
  RESEND_REPLY_TO,
  RESEND_TEMPLATE_ID,
  APP_DEBUG,
  VALID_ACTOR_ROLES,

  // error type + db handle (for convenience)
  ApiError,
  pool,

  // scalar helpers
  clean,
  email,
  code,
  isValidEmail,
  toInt,
  phpEmpty,
  istMysqlDateTime,
  redeemCodeExpiry,
  effectiveCode,

  // actor / authorization
  resolveActorFromToken,
  allowedCodes,
  canAccessCode,
  canAccessRow,

  // lookups + state
  getSubscriptionForUpdate,
  getLegacyInviteForUpdate,
  subscriptionIsAccepted,
  legacyInviteIsAccepted,

  // redeem code
  randomCode,
  uniqueRedeemCode,

  // writes
  createSubscriptionFromLegacyInvite,
  updateSourceInvite,
  hydrateTrainerName,

  // email + audit
  sendEmail,
  audit,
};
