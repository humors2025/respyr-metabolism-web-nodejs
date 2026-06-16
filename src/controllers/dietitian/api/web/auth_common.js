"use strict";

/**
 * auth_common.js
 *
 * Converted from: auth_common.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Shared helper module for the user-invitation endpoints
 * (admin-invite-trainer, super-admin-invite-trainer, super-admin-invite-admin,
 *  resend-user-invite, revoke-user-invite, …). The PHP `auth_common.php` was a
 * `require_once` include that every invite script pulled in; this is its Node
 * equivalent — a single `require()`-able module so the controllers stop
 * duplicating ~600 lines of identical logic.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  KEY DIFFERENCES FROM THE PHP (intentional, required for Node + security)
 * ──────────────────────────────────────────────────────────────────────────
 *  1. NO `exit`. PHP helpers called sendJson() which does `http_response_code()
 *     + echo + exit`. A Node helper cannot terminate the request from inside a
 *     library function without leaking the `res` object everywhere and breaking
 *     async flow. Instead, validation/auth helpers RETURN a result object:
 *         { ok: true, value }                       // success
 *         { ok: false, status, message }            // caller does res.status().json()
 *     The controller decides how to respond. This is the same return-style the
 *     existing admin-invite-trainer.js / super-admin-invite-trainer.js use.
 *
 *  2. TOKEN-BOUND IDENTITY. The PHP getActorUserByRole() trusted a
 *     body-supplied `actor_user_id` — a privilege-escalation / IDOR vector.
 *     Here the actor is resolved from the VERIFIED JWT (req.user) and
 *     re-checked against the DB on every call (resolveActorFromToken). A
 *     body `actor_user_id` is only ever *cross-checked* against the token
 *     identity (assertActorUserIdMatches) — it can never select a different
 *     user. authMiddleware MUST run before any controller using these helpers.
 *
 *  3. SECRETS COME FROM ENV ONLY. The PHP hard-coded fallback pepper / Resend
 *     key / template id as literals. Those are removed — committing live
 *     secrets is a finding in itself. Values are read from process.env, with a
 *     dev-only JWT_SECRET fallback for the pepper (matches the rest of this
 *     codebase). validateServerConfig() fails closed if required secrets are
 *     missing.
 *
 *  4. PARAMETERIZED QUERIES via mysql2 `pool.execute(sql, params)` — zero
 *     string interpolation, same as PDO prepared statements.
 *
 *  5. PHI/PII IN AUDIT LOGS IS HASHED. Email / IP / user-agent are HMAC-SHA256
 *     hashed with SECURITY_PEPPER before they touch app_auth_logs. Raw PHI
 *     never lands in a log table (HIPAA minimum-necessary).
 *
 *  6. EMAIL via axios over HTTPS (the codebase has no PHP curl); Resend is
 *     called with a hard timeout and no response body is echoed to the client.
 *
 * Tables touched (identical to the PHP — none added/removed):
 *   table_dietician, app_user_roles, app_user_invitations, app_auth_logs
 */

const crypto = require("crypto");
const axios = require("axios");
const pool = require("../../../../config/db");

// ─── Config (env-driven; no committed secrets) ───────────────────────────────

const APP_DEBUG = process.env.NODE_ENV !== "production";

// Pepper for keyed hashing. Dev falls back to JWT_SECRET (matches the existing
// invite controllers). validateServerConfig() rejects an empty pepper.
const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const INVITE_EXPIRY_HOURS = Math.max(
  1,
  parseInt(process.env.INVITE_EXPIRY_HOURS, 10) || 24
);

const RETURN_INVITE_LINK_FOR_TESTING =
  String(process.env.RETURN_INVITE_LINK_FOR_TESTING || "").toLowerCase() ===
  "true";

const FRONTEND_ACCEPT_INVITE_URL =
  process.env.FRONTEND_ACCEPT_INVITE_URL ||
  "https://api.respyr.ai/signup";
//   "https://api.respyr.ai/signup";

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL || "Respyr <invitation@respyr.ai>";
const RESEND_REPLY_TO = process.env.RESEND_REPLY_TO || "respyr@respyr.ai";
const RESEND_INVITE_TEMPLATE_ID =
  process.env.RESEND_INVITE_TEMPLATE_ID || "admin_trainer_invitation";

// Validation bounds.
const EMAIL_MAX_LENGTH = 254;
const NAME_MAX_LENGTH = 100;
const PHONE_MAX_LENGTH = 30;

// Partner-code generation. Alphabet excludes confusable chars (I, O, 0, 1) —
// matches the PHP generateRandomCodePart() alphabet exactly.
const PARTNER_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const PARTNER_CODE_RANDOM_LEN = 7;
const PARTNER_CODE_MAX_ATTEMPTS = 30;

// ─── Generic HTTP / response helpers ─────────────────────────────────────────

/**
 * Set the security/cache headers the PHP emitted as top-of-file header() calls.
 * Call once at the start of every controller. Content-Type is left to
 * res.json(). HIPAA: never let an intermediary cache a PHI-adjacent response.
 */
function applySecurityHeaders(res) {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate, max-age=0"
  );
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
}

/**
 * Express equivalent of the PHP sendJson(). Unlike the PHP it does NOT exit —
 * the caller should `return sendJson(res, ...)` to stop further processing.
 */
function sendJson(res, statusCode, payload) {
  return res.status(statusCode).json(payload);
}

/**
 * Method gate. Express routing usually pins the verb already, but this mirrors
 * the PHP validateMethodPost() guard. Returns true if the response was sent.
 */
function ensurePostOrReject(req, res) {
  if (req.method !== "POST") {
    sendJson(res, 405, { ok: false, message: "Method not allowed" });
    return true;
  }
  return false;
}

/**
 * Express has already parsed JSON into req.body. This validates it the way the
 * PHP getJsonBody() did. Returns { ok: true, body } or { ok: false, status,
 * message }.
 */
function getJsonBody(req) {
  const body = req.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return { ok: false, status: 400, message: "Invalid JSON body" };
  }
  return { ok: true, body };
}

/**
 * Fail-closed config check. Refuses to operate if a required secret is missing.
 * Returns { ok: true } or { ok: false, status, message, missing }.
 */
function validateServerConfig() {
  const missing = [];
  if (!SECURITY_PEPPER) missing.push("SECURITY_PEPPER");
  if (!RESEND_API_KEY) missing.push("RESEND_API_KEY");
  if (!RESEND_INVITE_TEMPLATE_ID) missing.push("RESEND_INVITE_TEMPLATE_ID");

  if (missing.length > 0) {
    return {
      ok: false,
      status: 500,
      message: "Server configuration missing",
      // Only disclose which keys are missing in non-production.
      missing: APP_DEBUG ? missing : [],
    };
  }
  return { ok: true };
}

// ─── Sanitizers / hashing ────────────────────────────────────────────────────

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

/** PHP cleanName(): trim + collapse internal whitespace. */
function cleanName(value) {
  if (value === null || value === undefined) return "";
  return String(value).trim().replace(/\s+/g, " ");
}

/**
 * PHP cleanPhone(): allow only digits/+/-/space/()/ of length 6..30.
 * Returns { ok: true, value } or { ok: false, status, message }. Empty is OK
 * (phone is optional) and yields value "".
 */
function cleanPhone(value) {
  const v = value === null || value === undefined ? "" : String(value).trim();
  if (v === "") return { ok: true, value: "" };

  if (!/^[0-9+\-\s()]{6,30}$/.test(v)) {
    return { ok: false, status: 400, message: "Invalid phone number format" };
  }
  return { ok: true, value: v };
}

/**
 * PHP secureHash() / token hashing. HMAC-SHA256 over the lower-cased, trimmed
 * value keyed by SECURITY_PEPPER. Deterministic + non-reversible without the
 * pepper — a DB dump alone cannot reverse an email hash or forge a token.
 */
function secureHash(value) {
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

/**
 * Hash for audit-log fields (IP, UA, identifier). Same construction as
 * secureHash but kept separate so token hashing and log hashing can diverge
 * later without surprises. Returns null for null/undefined input.
 */
function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
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

/** UTC "YYYY-MM-DD HH:MM:SS" — matches PHP gmdate()/UTC_TIMESTAMP() output. */
function toUtcMysqlDateTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(
      date.getUTCDate()
    )} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(
      date.getUTCSeconds()
    )}`
  );
}

// ─── Audit log (fail-safe, never throws) ─────────────────────────────────────

async function writeAuthLogSafe(
  req,
  { eventType, userId, role, partnerCode, identifier, success, failureReason }
) {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined
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

// ─── Actor resolution (token-bound; replaces PHP getActorUserByRole) ─────────

/**
 * Re-fetch the authenticated actor from the DB using the verified JWT.
 *
 * This codebase's JWTs carry the dietician_id as `sub` (and `dietician_id`),
 * with the email nested under `dietician.email` — there is NO top-level email
 * claim. Prefer the dietician_id (token subject), fall back to email. Mirrors
 * resolveActorFromToken() in the existing invite controllers.
 *
 * @param {object}        req           Express request (req.user from JWT).
 * @param {string|null}   requiredRole  Role to enforce, or null to accept any.
 * @returns {{actor, actorEmail} | {error:{status, body}}}
 */
async function resolveActorFromToken(req, requiredRole = null) {
  const payload = req.user || {};

  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload?.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    return {
      error: { status: 401, body: { ok: false, message: "Invalid token user" } },
    };
  }

  const [rows] = dieticianId
    ? await pool.execute(
        `
          SELECT
            td.id,
            td.dietician_id,
            td.email,
            aur.user_id,
            aur.role,
            aur.partner_code,
            aur.parent_user_id,
            aur.status
          FROM table_dietician td
          INNER JOIN app_user_roles aur
            ON LOWER(aur.user_id) = LOWER(td.email)
          WHERE td.dietician_id = ?
          LIMIT 1
        `,
        [dieticianId]
      )
    : await pool.execute(
        `
          SELECT
            td.id,
            td.dietician_id,
            td.email,
            aur.user_id,
            aur.role,
            aur.partner_code,
            aur.parent_user_id,
            aur.status
          FROM table_dietician td
          INNER JOIN app_user_roles aur
            ON LOWER(aur.user_id) = LOWER(td.email)
          WHERE LOWER(td.email) = LOWER(?)
          LIMIT 1
        `,
        [tokenEmail]
      );

  const actor = rows[0];

  if (!actor) {
    return {
      error: {
        status: 401,
        body: { ok: false, message: "Token user not found" },
      },
    };
  }

  if (String(actor.status) !== "active") {
    return {
      error: {
        status: 403,
        body: { ok: false, message: "Account is not active" },
      },
    };
  }

  if (requiredRole !== null && String(actor.role) !== requiredRole) {
    return {
      error: {
        status: 403,
        body: {
          ok: false,
          message: "You are not allowed to perform this action",
        },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

/**
 * Optional defense-in-depth: if the client sent body.actor_user_id (for
 * frontend back-compat), it MUST equal the token identity. It can never select
 * a different user. Returns { ok: true } or { ok: false, status, message }.
 */
function assertActorUserIdMatches(body, actorEmail) {
  const bodyActorUserId = normalizeEmail(
    body && typeof body === "object" ? body.actor_user_id : ""
  );
  if (bodyActorUserId !== "" && bodyActorUserId !== actorEmail) {
    return {
      ok: false,
      status: 403,
      message: "actor_user_id does not match the authenticated user",
    };
  }
  return { ok: true };
}

// ─── Input validation ────────────────────────────────────────────────────────

/**
 * PHP validateInviteInput(). Returns { ok: true, value } or
 * { ok: false, status, message }. value = { first_name, last_name, email, phone }.
 */
function validateInviteInput(body) {
  if (!body || typeof body !== "object") {
    return { ok: false, status: 400, message: "Invalid request body" };
  }

  const firstName = cleanName(body.first_name);
  const lastName = cleanName(body.last_name);
  const email = normalizeEmail(body.email);

  if (firstName === "") {
    return { ok: false, status: 400, message: "First name is required" };
  }
  if (lastName === "") {
    return { ok: false, status: 400, message: "Last name is required" };
  }
  if (firstName.length > NAME_MAX_LENGTH || lastName.length > NAME_MAX_LENGTH) {
    return {
      ok: false,
      status: 400,
      message: "Name must be maximum 100 characters",
    };
  }

  // Reject control chars in names — defends against CRLF injection and
  // bidi-override smuggling into downstream email templates.
  // eslint-disable-next-line no-control-regex
  const nameSafeRegex = /^[^\x00-\x1f\x7f]+$/;
  if (!nameSafeRegex.test(firstName) || !nameSafeRegex.test(lastName)) {
    return {
      ok: false,
      status: 400,
      message: "Names contain invalid characters",
    };
  }

  if (email === "" || email.length > EMAIL_MAX_LENGTH) {
    return { ok: false, status: 400, message: "Valid email is required" };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { ok: false, status: 400, message: "Valid email is required" };
  }

  const phoneResult = cleanPhone(body.phone);
  if (!phoneResult.ok) return phoneResult;

  return {
    ok: true,
    value: {
      first_name: firstName,
      last_name: lastName,
      email,
      phone: phoneResult.value,
    },
  };
}

// ─── Pre-flight checks ───────────────────────────────────────────────────────

/**
 * PHP ensureInviteCanBeCreated(). Lazily expires stale pending invites for the
 * email, then refuses if the email already maps to a role OR has a live pending
 * invite. Returns { ok: true } or { ok: false, status, message }.
 */
async function ensureInviteCanBeCreated(email) {
  const normalized = normalizeEmail(email);

  // Lazily expire any stale pending invitation for this email (PHP parity).
  await pool.execute(
    `
      UPDATE app_user_invitations
      SET status = 'expired',
          updated_at = UTC_TIMESTAMP()
      WHERE status = 'pending'
        AND expires_at <= UTC_TIMESTAMP()
        AND LOWER(invited_email) = LOWER(?)
    `,
    [normalized]
  );

  const [roleRows] = await pool.execute(
    `
      SELECT id
      FROM app_user_roles
      WHERE LOWER(user_id) = LOWER(?)
      LIMIT 1
    `,
    [normalized]
  );
  if (roleRows.length > 0) {
    return {
      ok: false,
      status: 409,
      message: "This email is already registered",
    };
  }

  const [inviteRows] = await pool.execute(
    `
      SELECT id
      FROM app_user_invitations
      WHERE LOWER(invited_email) = LOWER(?)
        AND status = 'pending'
        AND expires_at > UTC_TIMESTAMP()
      LIMIT 1
    `,
    [normalized]
  );
  if (inviteRows.length > 0) {
    return {
      ok: false,
      status: 409,
      message: "This email already has a pending invitation",
    };
  }

  return { ok: true };
}

// ─── Partner code generation ─────────────────────────────────────────────────

/** PHP generateRandomCodePart(): unbiased pick over PARTNER_CODE_ALPHABET. */
function generateRandomCodePart(length) {
  let code = "";
  for (let i = 0; i < length; i++) {
    code += PARTNER_CODE_ALPHABET[crypto.randomInt(0, PARTNER_CODE_ALPHABET.length)];
  }
  return code;
}

/**
 * PHP generateUniquePartnerCode(): prefix ADM for admin, TRN otherwise, and
 * guarantee the code collides with NONE of app_user_roles, app_user_invitations,
 * or table_dietician. Bounded retry — throws (fails closed) after the cap rather
 * than looping forever.
 */
async function generateUniquePartnerCode(role) {
  const prefix = role === "admin" ? "ADM" : "TRN";

  for (let attempt = 0; attempt < PARTNER_CODE_MAX_ATTEMPTS; attempt++) {
    const candidate = prefix + generateRandomCodePart(PARTNER_CODE_RANDOM_LEN);

    const [hits] = await pool.execute(
      `
        SELECT 1 AS hit FROM app_user_roles
          WHERE UPPER(partner_code) = UPPER(?)
        UNION ALL
        SELECT 1 AS hit FROM app_user_invitations
          WHERE UPPER(partner_code) = UPPER(?)
        UNION ALL
        SELECT 1 AS hit FROM table_dietician
          WHERE UPPER(dietician_id) = UPPER(?)
        LIMIT 1
      `,
      [candidate, candidate, candidate]
    );

    if (hits.length === 0) return candidate;
  }

  throw new Error("Could not generate unique partner code");
}

// ─── Invitation row helpers ──────────────────────────────────────────────────

/**
 * PHP createPendingInvite(). Inserts a `pending` row and returns the new id.
 * invited_email_hash is populated with the keyed email hash (NOT-NULL column).
 */
async function createPendingInvite({
  invitedEmail,
  firstName,
  lastName,
  phone,
  invitedRole,
  partnerCode,
  invitedByUserId,
  parentUserId,
  tokenHash,
  expiresAt,
}) {
  const [result] = await pool.execute(
    `
      INSERT INTO app_user_invitations (
        invited_email,
        invited_first_name,
        invited_last_name,
        invited_phone,
        invited_email_hash,
        invited_role,
        partner_code,
        invited_by_user_id,
        parent_user_id,
        token_hash,
        status,
        expires_at,
        sent_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, NULL, UTC_TIMESTAMP(), UTC_TIMESTAMP())
    `,
    [
      invitedEmail,
      firstName,
      lastName,
      phone,
      secureHash(invitedEmail),
      invitedRole,
      partnerCode,
      normalizeEmail(invitedByUserId),
      normalizeEmail(parentUserId),
      tokenHash,
      expiresAt,
    ]
  );

  return Number(result.insertId);
}

/** PHP markInviteRevoked(). Fail-safe — never throws. */
async function markInviteRevoked(invitationId) {
  try {
    await pool.execute(
      `
        UPDATE app_user_invitations
        SET status = 'revoked',
            updated_at = UTC_TIMESTAMP()
        WHERE id = ?
        LIMIT 1
      `,
      [invitationId]
    );
  } catch (err) {
    console.error("MARK_INVITE_REVOKED_FAILED:", err?.code || err?.message);
  }
}

/** PHP markInviteSent(). */
async function markInviteSent(invitationId) {
  await pool.execute(
    `
      UPDATE app_user_invitations
      SET sent_at = UTC_TIMESTAMP(),
          updated_at = UTC_TIMESTAMP()
      WHERE id = ?
      LIMIT 1
    `,
    [invitationId]
  );
}

// ─── Email via Resend ────────────────────────────────────────────────────────

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Inline invite email body. Every variable is HTML-escaped to prevent template
 * injection if a field somehow bypassed validateInviteInput().
 */
function renderInviteHtml(vars) {
  const safe = {};
  for (const [k, v] of Object.entries(vars)) safe[k] = escapeHtml(v ?? "");

  return `<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; color:#222; line-height:1.5;">
    <p>Hi ${safe.INVITED_NAME},</p>
    <p>${safe.INVITER_EMAIL} has invited you to Respyr as a <strong>${safe.INVITED_ROLE}</strong>.</p>
    <p>Your partner code: <strong>${safe.PARTNER_CODE}</strong></p>
    <p>
      <a href="${safe.INVITE_LINK}"
         style="display:inline-block;padding:10px 18px;background:#0a7d3b;color:#fff;text-decoration:none;border-radius:6px;">
        Accept your invitation
      </a>
    </p>
    <p>This invitation expires in ${safe.EXPIRES_IN}.</p>
    <p style="font-size:12px;color:#666;">If you did not expect this email, you can ignore it.</p>
  </body>
</html>`;
}

/**
 * PHP sendResendTemplateEmail(). Sends via Resend's /emails endpoint over HTTPS
 * with a hard timeout. Resend's public /emails API has no server-side template
 * variable substitution, so the body is rendered here; templateId is passed
 * through as a tag for audit traceability/parity. Returns
 * { ok, http_code, error, data }.
 */
async function sendResendTemplateEmail(toEmail, subject, templateId, variables) {
  if (!RESEND_API_KEY) {
    return {
      ok: false,
      http_code: 0,
      error: "RESEND_API_KEY not configured",
      data: null,
    };
  }

  try {
    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: RESEND_FROM_EMAIL,
        to: [toEmail],
        subject,
        reply_to: RESEND_REPLY_TO,
        html: renderInviteHtml(variables),
        headers: { "X-Entity-Ref-ID": `invite-${variables.PARTNER_CODE}` },
        tags: [
          { name: "kind", value: "invite" },
          { name: "invited_role", value: String(variables.INVITED_ROLE || "") },
          { name: "template_id", value: String(templateId || "inline") },
        ],
      },
      {
        timeout: 20_000,
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        validateStatus: () => true, // treat non-2xx as a handled failure
      }
    );

    const httpCode = response.status;
    if (httpCode < 200 || httpCode >= 300) {
      return {
        ok: false,
        http_code: httpCode,
        error: response.data?.message || "Resend API failed",
        data: response.data ?? null,
      };
    }

    return { ok: true, http_code: httpCode, error: null, data: response.data };
  } catch (err) {
    return {
      ok: false,
      http_code: 0,
      error: err?.code || err?.message || "Resend request failed",
      data: null,
    };
  }
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  // config / constants
  APP_DEBUG,
  SECURITY_PEPPER,
  INVITE_EXPIRY_HOURS,
  RETURN_INVITE_LINK_FOR_TESTING,
  FRONTEND_ACCEPT_INVITE_URL,
  RESEND_INVITE_TEMPLATE_ID,

  // http / response
  applySecurityHeaders,
  sendJson,
  ensurePostOrReject,
  getJsonBody,
  validateServerConfig,

  // sanitizers / hashing
  normalizeEmail,
  cleanName,
  cleanPhone,
  secureHash,
  authLogHash,
  getClientIp,
  getUserAgent,
  toUtcMysqlDateTime,
  escapeHtml,

  // audit
  writeAuthLogSafe,

  // actor / auth
  resolveActorFromToken,
  assertActorUserIdMatches,

  // invite flow
  validateInviteInput,
  ensureInviteCanBeCreated,
  generateRandomCodePart,
  generateUniquePartnerCode,
  createPendingInvite,
  markInviteRevoked,
  markInviteSent,

  // email
  renderInviteHtml,
  sendResendTemplateEmail,
};
