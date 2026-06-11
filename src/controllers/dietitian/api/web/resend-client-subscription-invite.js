"use strict";

/**
 * resend-client-subscription-invite.js
 *
 * Converted from: resend-client-subscription-invite.php
 *                 (+ client-subscription-action-common.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/resend-client-subscription-invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but ONLY for a subscription whose
 *              trainer_code / trainer_id the actor is allowed to use (own code, or
 *              a child trainer's code).
 *
 * Behaviour parity with the PHP:
 *  - Looks up the target subscription by `subscription_id` OR `redeem_code`; if
 *    none matches, falls back to a legacy `invite_id` in trainer_client_invites,
 *    and (when found + resendable) creates a fresh subscription row from it.
 *  - Rejects accepted/redeemed invites (409) and cancelled ones (409).
 *  - Regenerates the redeem code + expiry on every resend (clean mobile flow),
 *    flips the row to status='failed'/subscription_status='pending' under a row
 *    lock + transaction, commits, then sends the email and writes the result
 *    back to the subscription and its source invite row.
 *  - Response shape matches the PHP exactly: { status, ok, message, data{...} }
 *    with the same keys/ordering; success → 200, email-failed → 502.
 *
 * VAPT hardening (beyond the PHP — this is the whole point of the sprint):
 *  - Token-bound identity. The PHP trusted body.actor_user_id to resolve the
 *    actor (a textbook IDOR). Here the actor is ALWAYS resolved from the verified
 *    JWT and re-checked (role + status) against the DB. body.actor_user_id is
 *    still accepted for frontend back-compat but is only cross-checked against
 *    the token identity (mismatch → 403); it can never select another user.
 *  - The target lookup is authorized on BOTH trainer_code and trainer_id, so a
 *    caller can never resend a subscription that belongs to a code they don't own.
 *  - Row lock (SELECT ... FOR UPDATE) inside a transaction prevents a double
 *    resend / code-regeneration race.
 *  - Every query is fully parameterized (no string interpolation).
 *  - Redeem codes use crypto.randomInt (CSPRNG), not a biased PRNG.
 *  - Internal error / email-provider details are suppressed in production
 *    (gated behind APP_DEBUG); the PHP echoed debug_error unconditionally.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Every resend / denial / failure is recorded in app_auth_logs.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (client email, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_invites, trainer_client_plan_subscriptions,
 * app_auth_logs.
 */

const crypto = require("crypto");
const axios  = require("axios");
const pool   = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const CLIENT_REDEEM_CODE_EXPIRY_DAYS = Math.max(
  1,
  parseInt(process.env.CLIENT_REDEEM_CODE_EXPIRY_DAYS, 10) || 30
);

// Resend config (parity with send_trainer_client_invite.js). Only RESEND_API_KEY
// is mandatory; FROM has a fallback; REPLY_TO / TEMPLATE_ID are optional.
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

// ─── Error type for early-exit validation (mirrors PHP csi_json(...)) ──────────

class ApiError extends Error {
  constructor(status, message, extra) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = Object.assign({ status: false, ok: false, message }, extra || {});
  }
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function cleanValue(value) {
  return String(value === null || value === undefined ? "" : value).trim();
}

function normalizeEmail(email) {
  return String(email === null || email === undefined ? "" : email).trim().toLowerCase();
}

function normalizeCode(code) {
  return String(code === null || code === undefined ? "" : code).trim().toUpperCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/** Parse a positive integer id, or return null. */
function toPositiveInt(value) {
  const n = parseInt(cleanValue(value), 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** Sanitize a redeem code to the RSP###### alphabet; empty if it doesn't qualify. */
function sanitizeRedeemCode(value) {
  const code = normalizeCode(value).replace(/[^A-Z0-9]/g, "");
  return code.length >= 4 && code.length <= 32 ? code : "";
}

/** HTML-escape a value before interpolating into the email body (anti-injection). */
function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** Format a Date as IST "YYYY-MM-DD HH:MM:SS" — matches PHP date() in Asia/Kolkata. */
function toIstMysqlDateTime(date) {
  const ist = new Date(date.getTime() + IST_OFFSET_MS);
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${ist.getUTCFullYear()}-${pad(ist.getUTCMonth() + 1)}-${pad(ist.getUTCDate())} ` +
    `${pad(ist.getUTCHours())}:${pad(ist.getUTCMinutes())}:${pad(ist.getUTCSeconds())}`
  );
}

function getEffectiveCode(row) {
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

// ─── Audit log (fail-safe, hashed PHI/PII) ────────────────────────────────────

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
    console.error("CLIENT_SUBSCRIPTION_RESEND_AUDIT_LOG_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) + allowed codes ───────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. The token carries dietician_id in `sub`; email is derived from the DB.
 * Returns { actor, actorEmail } or throws ApiError. (Mirrors csi_get_actor_or_fail,
 * but token-bound instead of body-trusted.)
 */
async function resolveActorFromToken(conn, req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    throw new ApiError(401, "Invalid token user");
  }

  const [rows] = dieticianId
    ? await conn.execute(
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
    : await conn.execute(
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

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

/**
 * Set of trainer/partner codes this actor may act on.
 *   trainer     → own effective code only
 *   admin       → own + child trainers' partner_codes
 *   super_admin → own + child admins' + child trainers' partner_codes
 * Mirrors csi_allowed_codes() (codes upper-cased + de-duped).
 */
async function getAllowedCodesForActor(conn, actor, actorEmail) {
  const codes = new Set();
  const role = String(actor.role);

  const own = getEffectiveCode(actor);
  if (own && normalizeCode(own) !== "") codes.add(normalizeCode(own));

  if (role === "trainer") {
    return [...codes];
  }

  if (role === "admin") {
    const [rows] = await conn.execute(
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
      if (normalizeCode(row.partner_code) !== "") codes.add(normalizeCode(row.partner_code));
    }
    return [...codes];
  }

  if (role === "super_admin") {
    const [rows] = await conn.execute(
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
      if (normalizeCode(row.partner_code) !== "") codes.add(normalizeCode(row.partner_code));
    }
    return [...codes];
  }

  return [...codes];
}

/** csi_can_access_code: is this single code in the actor's allowed set? */
function actorCanUseTrainerCode(allowedCodes, code) {
  const wanted = normalizeCode(code);
  if (wanted === "") return false;
  return allowedCodes.some((c) => normalizeCode(c) === wanted);
}

/** A subscription/invite is reachable if EITHER its trainer_code or trainer_id is allowed. */
function actorCanAccessRow(allowedCodes, row) {
  return (
    actorCanUseTrainerCode(allowedCodes, row.trainer_code) ||
    actorCanUseTrainerCode(allowedCodes, row.trainer_id)
  );
}

// ─── Trainer lookup (for trainer_name hydration) ──────────────────────────────

async function getTrainerByCode(conn, trainerCode) {
  const code = cleanValue(trainerCode);
  if (code === "") return null;

  const [rows] = await conn.execute(
    `SELECT
       td.id,
       td.dietician_id,
       td.name,
       td.email,
       td.phone_no,
       td.location,
       aur.user_id,
       aur.role,
       aur.partner_code,
       aur.parent_user_id,
       aur.status AS role_status
     FROM table_dietician td
     LEFT JOIN app_user_roles aur
       ON LOWER(aur.user_id) = LOWER(td.email)
     WHERE UPPER(td.dietician_id) = UPPER(?)
        OR UPPER(aur.partner_code) = UPPER(?)
     ORDER BY
       CASE WHEN aur.status = 'active' THEN 0 ELSE 1 END,
       td.id DESC
     LIMIT 1`,
    [code, code]
  );
  return rows[0] || null;
}

/** csi_hydrate_trainer_name: attach trainer_name to the subscription for the email. */
async function hydrateTrainerName(conn, sub) {
  const trainer = await getTrainerByCode(conn, sub.trainer_code || sub.trainer_id);
  const name = trainer ? cleanValue(trainer.name) : "";
  sub.trainer_name = name !== "" ? name : "Your trainer";
  return sub;
}

// ─── Redeem code generation ───────────────────────────────────────────────────

function randomRedeemCodeString() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let code = "RSP";
  for (let i = 0; i < 7; i++) {
    code += alphabet[crypto.randomInt(0, alphabet.length)];
  }
  return code;
}

/** csi_unique_redeem_code: a RSP###### code not present in the subscriptions table. */
async function generateUniqueRedeemCode(conn) {
  for (let i = 0; i < 20; i++) {
    const code = randomRedeemCodeString();
    const [rows] = await conn.execute(
      `SELECT id
         FROM trainer_client_plan_subscriptions
        WHERE redeem_code = ?
        LIMIT 1`,
      [code]
    );
    if (!rows[0]) return code;
  }
  throw new ApiError(500, "Could not generate unique redeem code");
}

// ─── Target lookups (row-locked inside the transaction) ───────────────────────

/** csi_get_subscription_for_update: by subscription_id first, else redeem_code. */
async function getSubscriptionForUpdate(conn, { subscriptionId, redeemCode }) {
  if (subscriptionId) {
    const [rows] = await conn.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE id = ?
        LIMIT 1
        FOR UPDATE`,
      [subscriptionId]
    );
    if (rows[0]) return rows[0];
  }

  if (redeemCode) {
    const [rows] = await conn.execute(
      `SELECT *
         FROM trainer_client_plan_subscriptions
        WHERE redeem_code = ?
        LIMIT 1
        FOR UPDATE`,
      [redeemCode]
    );
    if (rows[0]) return rows[0];
  }

  return null;
}

/** csi_get_legacy_invite_for_update: trainer_client_invites by id. */
async function getLegacyInviteForUpdate(conn, inviteId) {
  if (!inviteId) return null;
  const [rows] = await conn.execute(
    `SELECT *
       FROM trainer_client_invites
      WHERE id = ?
      LIMIT 1
      FOR UPDATE`,
    [inviteId]
  );
  return rows[0] || null;
}

/** csi_subscription_is_accepted: redeemed/accepted subscriptions are terminal. */
function subscriptionIsAccepted(sub) {
  const subStatus = String(sub.subscription_status || "").toLowerCase();
  if (subStatus === "accepted" || subStatus === "redeemed") return true;
  if (sub.accepted_profile_id !== null && sub.accepted_profile_id !== undefined &&
      cleanValue(sub.accepted_profile_id) !== "") return true;
  if (sub.accepted_at !== null && sub.accepted_at !== undefined &&
      cleanValue(sub.accepted_at) !== "") return true;
  return false;
}

/** csi_legacy_invite_is_accepted: accepted legacy invites cannot spawn a resend. */
function legacyInviteIsAccepted(invite) {
  const status = String(invite.status || "").toLowerCase();
  if (status === "accepted") return true;
  if (invite.accepted_profile_id !== null && invite.accepted_profile_id !== undefined &&
      cleanValue(invite.accepted_profile_id) !== "") return true;
  return false;
}

/**
 * csi_create_subscription_from_legacy_invite: spawn a fresh subscription row from
 * a legacy trainer_client_invites row. The redeem code / expiry written here are
 * immediately re-generated by the common resend path (parity with the PHP), so a
 * short-lived placeholder is fine. Returns a sub-shaped object for downstream use.
 */
async function createSubscriptionFromLegacyInvite(conn, invite, createdByUserId) {
  const placeholderCode = await generateUniqueRedeemCode(conn);
  const expiresAt = toIstMysqlDateTime(
    new Date(Date.now() + CLIENT_REDEEM_CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
  );

  const trainerId        = cleanValue(invite.trainer_id);
  const trainerCode      = cleanValue(invite.trainer_code) !== "" ? cleanValue(invite.trainer_code) : trainerId;
  const clientName       = cleanValue(invite.client_name);
  const clientMobile     = cleanValue(invite.client_mobile);
  const clientEmail      = normalizeEmail(invite.client_email);
  const planCode         = cleanValue(invite.plan_code);
  const planName         = cleanValue(invite.plan_name);
  const planPriceLabel   = cleanValue(invite.plan_price_label);
  const paymentStatus    = planCode === "free_trial" ? "not_required" : "pending";

  const [result] = await conn.execute(
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
       'failed', 'pending', ?, 'failed', NULL, NULL, NULL,
       'Email resend started', ?, NOW(), NOW()
     )`,
    [
      Number(invite.id),
      trainerId,
      trainerCode,
      clientName,
      clientMobile !== "" ? clientMobile : null,
      clientEmail,
      planCode,
      planName,
      planPriceLabel,
      placeholderCode,
      expiresAt,
      paymentStatus,
      createdByUserId,
    ]
  );

  return {
    id: Number(result.insertId),
    source_invite_id: Number(invite.id),
    trainer_id: trainerId,
    trainer_code: trainerCode,
    client_name: clientName,
    client_mobile: clientMobile,
    client_email: clientEmail,
    plan_code: planCode,
    plan_name: planName,
    plan_price_label: planPriceLabel,
    redeem_code: placeholderCode,
    code_expires_at: expiresAt,
    status: "failed",
    subscription_status: "pending",
    email_status: "failed",
    accepted_profile_id: null,
    accepted_at: null,
  };
}

// ─── Result writes (after the email send, outside the transaction) ────────────

async function updateSubscriptionResult(conn, subscriptionId, status, emailStatus, resendEmailId, errorMessage) {
  await conn.execute(
    `UPDATE trainer_client_plan_subscriptions
        SET status = ?,
            email_status = ?,
            resend_email_id = ?,
            error_message = ?,
            updated_at = NOW()
      WHERE id = ?
      LIMIT 1`,
    [status, emailStatus, resendEmailId, errorMessage, subscriptionId]
  );
}

/**
 * csi_update_source_invite: push the resend result onto the source invite row,
 * guarded against an already-accepted invite (never clobber an acceptance).
 */
async function updateSourceInviteIfNotAccepted(
  conn,
  sourceInviteId,
  status,
  emailStatus,
  resendEmailId,
  errorMessage,
  subscriptionId
) {
  if (!sourceInviteId) return;

  await conn.execute(
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

// ─── Email via Resend ─────────────────────────────────────────────────────────

async function sendResendClientSubscriptionEmail(sub) {
  if (RESEND_API_KEY === "") {
    return { success: false, resend_email_id: null, error: "RESEND_API_KEY is not configured" };
  }

  const safe = {
    CLIENT_NAME: escapeHtml(sub.client_name),
    TRAINER_NAME: escapeHtml(sub.trainer_name),
    TRAINER_CODE: escapeHtml(sub.trainer_code),
    REDEEM_CODE: escapeHtml(sub.redeem_code),
    CODE_EXPIRES_AT: escapeHtml(sub.code_expires_at),
    PLAN_NAME: escapeHtml(sub.plan_name),
    PLAN_PRICE_LABEL: escapeHtml(sub.plan_price_label),
  };

  const html = `<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; color:#222; line-height:1.5;">
    <p>Hi ${safe.CLIENT_NAME},</p>
    <p><strong>${safe.TRAINER_NAME}</strong> has invited you to Respyr on the
       <strong>${safe.PLAN_NAME}</strong> plan (${safe.PLAN_PRICE_LABEL}).</p>
    <p>Your redeem code: <strong style="font-size:18px;letter-spacing:1px;">${safe.REDEEM_CODE}</strong></p>
    <p>Trainer code: <strong>${safe.TRAINER_CODE}</strong></p>
    <p style="color:#666;">This code expires on ${safe.CODE_EXPIRES_AT}.</p>
    <p style="font-size:12px;color:#666;">If you did not expect this email, you can ignore it.</p>
  </body>
</html>`;

  const payload = {
    from: RESEND_FROM_EMAIL,
    to: [sub.client_email],
    subject: "You’ve been invited to Respyr",
    html,
    tags: [
      { name: "kind", value: "client_invite_resend" },
      { name: "plan_code", value: String(sub.plan_code || "") },
      { name: "template_id", value: String(RESEND_TEMPLATE_ID || "inline") },
    ],
  };

  if (RESEND_REPLY_TO) {
    payload.reply_to = RESEND_REPLY_TO;
  }

  try {
    const response = await axios.post("https://api.resend.com/emails", payload, {
      timeout: 30_000,
      headers: {
        Authorization: `Bearer ${RESEND_API_KEY}`,
        "Content-Type": "application/json",
        "User-Agent": "respyr-node-api/1.0",
      },
      validateStatus: () => true,
    });

    if (response.status >= 200 && response.status < 300 && response.data && response.data.id) {
      return { success: true, resend_email_id: response.data.id, error: null };
    }

    return {
      success: false,
      resend_email_id: null,
      error: `Resend API error: HTTP ${response.status}`,
    };
  } catch (err) {
    return {
      success: false,
      resend_email_id: null,
      error: `Resend request error: ${err?.code || err?.message || "unknown"}`,
    };
  }
}

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/resend-client-subscription-invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body (one identifier required):
 *   { "actor_user_id": "", "subscription_id": 12 }
 *   { "actor_user_id": "", "redeem_code": "RSP8K2M9Q" }
 *   { "actor_user_id": "", "invite_id": 5 }          // legacy
 */
const resendClientSubscriptionInvite = async (req, res) => {
  // HIPAA: never let intermediaries cache invite responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP REQUEST_METHOD check).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};

  let conn = null;
  let inTransaction = false;
  let actorEmail = null;
  let actorRole = null;

  try {
    if (!RESEND_API_KEY) {
      throw new ApiError(500, "RESEND_API_KEY is not configured");
    }

    // ── 1. Parse + validate identifiers ──────────────────────────────────────
    const actorUserId  = normalizeEmail(body.actor_user_id ?? "");
    const subscriptionId = toPositiveInt(body.subscription_id);
    const redeemCode     = sanitizeRedeemCode(body.redeem_code);
    const inviteId       = toPositiveInt(body.invite_id);

    if (!subscriptionId && redeemCode === "" && !inviteId) {
      throw new ApiError(400, "subscription_id, redeem_code or invite_id is required");
    }

    // ── 2. DB connection (IST session time zone, parity with PHP) ────────────
    conn = await pool.getConnection();
    await conn.query("SET time_zone = '+05:30'");

    // ── 3. Token-bound authorization (closes the PHP IDOR hole) ──────────────
    const resolved = await resolveActorFromToken(conn, req);
    const actor = resolved.actor;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);

    // Optional actor_user_id is cross-checked, never trusted to select a user.
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: null,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      throw new ApiError(403, "actor_user_id does not match the authenticated user");
    }

    const allowedCodes = await getAllowedCodesForActor(conn, actor, actorEmail);

    // ── 4. Locate the target (transaction + row lock) ────────────────────────
    await conn.beginTransaction();
    inTransaction = true;

    let sub = await getSubscriptionForUpdate(conn, { subscriptionId, redeemCode });

    if (!sub) {
      // Legacy path: resolve an invite_id and spawn a subscription from it.
      const legacyInvite = await getLegacyInviteForUpdate(conn, inviteId);

      if (!legacyInvite) {
        throw new ApiError(404, "Client invite/subscription not found");
      }

      if (!actorCanAccessRow(allowedCodes, legacyInvite)) {
        await writeAuthLogSafe(req, {
          eventType: "client_subscription_invite_resend_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: getEffectiveCode(actor),
          identifier: normalizeEmail(legacyInvite.client_email),
          success: false,
          failureReason: "actor not allowed to resend this client invite",
        });
        throw new ApiError(403, "You are not allowed to resend this client invite");
      }

      if (legacyInviteIsAccepted(legacyInvite)) {
        throw new ApiError(409, "Accepted client invite cannot be resent");
      }

      sub = await createSubscriptionFromLegacyInvite(conn, legacyInvite, actorEmail);
    }

    // ── 5. Authorize + state guards on the subscription ──────────────────────
    if (!actorCanAccessRow(allowedCodes, sub)) {
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: normalizeEmail(sub.client_email),
        success: false,
        failureReason: "actor not allowed to resend this subscription",
      });
      throw new ApiError(403, "You are not allowed to resend this client subscription invite");
    }

    if (subscriptionIsAccepted(sub)) {
      throw new ApiError(409, "Accepted/redeemed subscription cannot be resent");
    }

    if (String(sub.status) === "cancelled" || String(sub.subscription_status) === "cancelled") {
      throw new ApiError(409, "Cancelled subscription cannot be resent. Create a new invite.");
    }

    // ── 6. Regenerate the redeem code + expiry, flip state to pending ────────
    const newRedeemCode = await generateUniqueRedeemCode(conn);
    const newExpiresAt = toIstMysqlDateTime(
      new Date(Date.now() + CLIENT_REDEEM_CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
    );

    await conn.execute(
      `UPDATE trainer_client_plan_subscriptions
          SET redeem_code = ?,
              code_expires_at = ?,
              status = 'failed',
              email_status = 'failed',
              subscription_status = 'pending',
              error_message = 'Email resend started',
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [newRedeemCode, newExpiresAt, Number(sub.id)]
    );

    sub.redeem_code = newRedeemCode;
    sub.code_expires_at = newExpiresAt;

    await conn.commit();
    inTransaction = false;

    // ── 7. Send the email (outside the transaction) ──────────────────────────
    await hydrateTrainerName(conn, sub);

    const emailResult = await sendResendClientSubscriptionEmail(sub);

    const newStatus      = emailResult.success ? "sent" : "failed";
    const newEmailStatus = emailResult.success ? "sent" : "failed";
    const newError       = emailResult.error;
    const resendEmailId  = emailResult.resend_email_id;

    // ── 8. Persist the email result on the subscription + source invite ──────
    await updateSubscriptionResult(
      conn,
      Number(sub.id),
      newStatus,
      newEmailStatus,
      resendEmailId,
      newError
    );

    const sourceInviteId =
      sub.source_invite_id !== null && sub.source_invite_id !== undefined
        ? Number(sub.source_invite_id)
        : null;

    await updateSourceInviteIfNotAccepted(
      conn,
      sourceInviteId,
      newStatus,
      newEmailStatus,
      resendEmailId,
      newError,
      Number(sub.id)
    );

    // ── 9. Audit ─────────────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: emailResult.success
        ? "client_subscription_invite_resent"
        : "client_subscription_invite_resend_failed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: getEffectiveCode(actor),
      identifier: normalizeEmail(sub.client_email),
      success: emailResult.success,
      failureReason: emailResult.success
        ? "Client subscription invite resent"
        : "Client subscription invite resend failed",
    });

    // ── 10. Respond (matches the PHP JSON shape exactly) ─────────────────────
    return res.status(emailResult.success ? 200 : 502).json({
      status: emailResult.success,
      ok: emailResult.success,
      message: emailResult.success
        ? "Client subscription invite resent successfully"
        : "Client subscription invite saved but email resend failed",
      data: {
        subscription_id: Number(sub.id),
        source_invite_id: sourceInviteId,
        redeem_code: newRedeemCode,
        code_expires_at: newExpiresAt,
        client_name: sub.client_name,
        client_email: normalizeEmail(sub.client_email),
        trainer_code: sub.trainer_code,
        plan_code: sub.plan_code,
        plan_name: sub.plan_name,
        plan_price_label: sub.plan_price_label,
        invite_status: newStatus,
        email_status: newEmailStatus,
        resend_email_id: resendEmailId,
        // VAPT: provider error is suppressed from clients in production.
        error_message: APP_DEBUG ? newError : (emailResult.success ? null : "Email resend failed"),
      },
    });
  } catch (err) {
    if (inTransaction && conn) {
      try {
        await conn.rollback();
      } catch (_) {
        /* ignore */
      }
    }

    if (err instanceof ApiError) {
      return res.status(err.status).json(err.payload);
    }

    console.error("RESEND_CLIENT_SUBSCRIPTION_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "client_subscription_invite_resend_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: null,
      identifier: null,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (_) {
        /* ignore */
      }
    }
  }
};

module.exports = { resendClientSubscriptionInvite };
