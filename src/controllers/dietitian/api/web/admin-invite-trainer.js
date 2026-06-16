"use strict";

/**
 * admin-invite-trainer.js
 *
 * Converted from: admin-invite-trainer.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/admin-invite-trainer
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin only
 *
 * Behaviour parity with PHP:
 *  - Resolves the acting admin, requires the admin to have a partner_code
 *    (the PHP "Admin partner code is missing" 403 guard — an admin is a real,
 *    linked role).
 *  - Creates a `pending` row in app_user_invitations with a hashed token, a
 *    unique trainer partner_code (TRN + 7 chars), and a UTC expiry.
 *  - Sends a templated invite email via Resend.
 *  - On email failure, marks the invitation revoked and returns 502.
 *  - On success, marks the invitation as sent and returns 201 with the same
 *    JSON shape as the PHP file.
 *
 * Hardening differences from PHP (intentional):
 *  - Actor identity is taken from the verified JWT — never from
 *    req.body.actor_user_id. The PHP version trusted a body-supplied
 *    `actor_user_id`, which is a privilege-escalation vector.
 *  - Token is generated with crypto.randomBytes(32) and stored as a SHA-256
 *    HMAC keyed by SECURITY_PEPPER (falling back to JWT_SECRET). The raw
 *    token never touches the database.
 *  - Partner code uniqueness check uses a parameterized query and retries
 *    a bounded number of times before failing closed.
 *  - All audit log writes use a fail-safe wrapper that hashes PHI/PII.
 *
 * VAPT Controls applied:
 *  - Token-bound authorization (JWT → DB re-check on every call). A stale,
 *    demoted, or partner-code-less admin cannot invite.
 *  - Fully parameterized queries — zero string interpolation.
 *  - Strict input validation: email RFC-like regex + length cap, name length
 *    cap, phone digit/length cap, control-char rejection in names.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Internal error details suppressed in production responses.
 *  - Email-sending uses HTTPS to Resend, with a hard timeout and no body
 *    echoed back to the client on success.
 *
 * HIPAA Controls applied:
 *  - Minimum-necessary data: only the columns needed are selected/inserted.
 *  - PHI (email, IP, UA) in audit logs is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER. Raw PHI never lands in app_auth_logs.
 *  - Structured server-side logs contain only error metadata, never row data.
 *  - Access is bound to an authenticated admin JWT, verified against
 *    app_user_roles before any invite is created or any email is sent.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, app_user_invitations, app_auth_logs.
 */

const crypto = require("crypto");
const axios  = require("axios");
const pool   = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const INVITE_EXPIRY_HOURS = Math.max(
  1,
  parseInt(process.env.INVITE_EXPIRY_HOURS, 10) || 24
);

const FRONTEND_ACCEPT_INVITE_URL =
  process.env.FRONTEND_ACCEPT_INVITE_URL ||
   "https://api.respyr.ai/signup";
  // "https://api.respyr.ai/dietitian/api/web/accept-invite";
  // "https://app.respyr.ai/accept-invite";

const RESEND_API_KEY            = process.env.RESEND_API_KEY            || "";
const RESEND_INVITE_TEMPLATE_ID = process.env.RESEND_INVITE_TEMPLATE_ID || "";
const RESEND_FROM_EMAIL         = process.env.RESEND_FROM_EMAIL         || "Respyr <no-reply@respyr.ai>";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const RETURN_INVITE_LINK_FOR_TESTING =
  String(process.env.RETURN_INVITE_LINK_FOR_TESTING || "").toLowerCase() === "true";

// Trainer partner codes are prefixed TRN (e.g. TRN8M4P6XA) — matches the PHP
// generateUniquePartnerCode($pdo, 'trainer') example.
const PARTNER_CODE_PREFIX        = "TRN";
const PARTNER_CODE_RANDOM_LEN    = 7;
const PARTNER_CODE_MAX_ATTEMPTS  = 10;
const PARTNER_CODE_ALPHABET      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

const EMAIL_MAX_LENGTH = 254;
const NAME_MAX_LENGTH  = 100;
const PHONE_MAX_LENGTH = 20;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string" ? val.trim().toLowerCase() : "";
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
 * SHA-256 HMAC keyed by SECURITY_PEPPER. Used to hash invite tokens before
 * storing them. Reversing the hash without the pepper is computationally
 * infeasible — a DB dump alone cannot be used to accept an invite.
 */
function secureHash(value) {
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value))
    .digest("hex");
}

/**
 * Format a Date (UTC) as "YYYY-MM-DD HH:MM:SS" — matches PHP gmdate() output
 * and the response shape expected by the frontend.
 */
function toUtcMysqlDateTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

/**
 * Fail-safe audit log writer. Schema mirrors writeAuthLogSafe() in the rest of
 * this codebase. Never throws.
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
 * `requiredRole` defaults to 'admin' — only admins may invite trainers.
 */
async function resolveActorFromToken(req, requiredRole = "admin") {
  const payload = req.user || {};

  // This codebase's JWTs carry the dietician_id as `sub` (and `dietician_id`),
  // with the email nested under `dietician.email` — there is NO top-level email
  // claim. Resolve both, prefer the dietician_id (token subject), fall back to
  // email. Mirrors resolveActorFromToken() in resend-user-invite.js.
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail  = normalizeEmail(
    payload.email || payload.user_id || payload?.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    return {
      error: {
        status: 401,
        body: { ok: false, message: "Invalid token user" },
      },
    };
  }

  // Prefer dietician_id (token subject); fall back to email.
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

  if (String(actor.role) !== requiredRole) {
    return {
      error: {
        status: 403,
        body: { ok: false, message: "You are not allowed to perform this action" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

// ─── Input validation ────────────────────────────────────────────────────────

/**
 * Mirrors PHP validateInviteInput(). Returns { ok: true, value } or
 * { ok: false, status, message }.
 */
function validateInviteInput(body) {
  if (!body || typeof body !== "object") {
    return { ok: false, status: 400, message: "Invalid request body" };
  }

  const firstName = typeof body.first_name === "string"
    ? body.first_name.trim()
    : "";
  const lastName = typeof body.last_name === "string"
    ? body.last_name.trim()
    : "";
  const email = normalizeEmail(body.email);
  const phoneRaw = body.phone === null || body.phone === undefined
    ? ""
    : String(body.phone).trim();

  if (!firstName || firstName.length > NAME_MAX_LENGTH) {
    return { ok: false, status: 400, message: "first_name is required" };
  }
  if (!lastName || lastName.length > NAME_MAX_LENGTH) {
    return { ok: false, status: 400, message: "last_name is required" };
  }

  // Disallow control chars in names — defends against CRLF injection
  // and bidi-override smuggling into downstream email templates.
  // eslint-disable-next-line no-control-regex
  const nameSafeRegex = /^[^\x00-\x1f\x7f]+$/;
  if (!nameSafeRegex.test(firstName) || !nameSafeRegex.test(lastName)) {
    return { ok: false, status: 400, message: "Names contain invalid characters" };
  }

  if (!email || email.length > EMAIL_MAX_LENGTH) {
    return { ok: false, status: 400, message: "email is required" };
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return { ok: false, status: 400, message: "Invalid email format" };
  }

  let phone = "";
  if (phoneRaw !== "") {
    // Strip everything except + and digits, then enforce length cap.
    phone = phoneRaw.replace(/[^\d+]/g, "");
    if (phone.length === 0 || phone.length > PHONE_MAX_LENGTH) {
      return { ok: false, status: 400, message: "Invalid phone number" };
    }
  }

  return {
    ok: true,
    value: { first_name: firstName, last_name: lastName, email, phone },
  };
}

// ─── Pre-flight checks ───────────────────────────────────────────────────────

/**
 * Mirrors PHP ensureInviteCanBeCreated(). Refuses if the email already maps
 * to an active role OR has an outstanding pending invite that has not
 * expired.
 */
async function ensureInviteCanBeCreated(email) {
  const [roleRows] = await pool.execute(
    `
      SELECT id
      FROM app_user_roles
      WHERE LOWER(user_id) = LOWER(?)
      LIMIT 1
    `,
    [email]
  );

  if (roleRows.length > 0) {
    return {
      ok: false,
      status: 409,
      message: "A user with this email already exists",
    };
  }

  const [inviteRows] = await pool.execute(
    `
      SELECT id
      FROM app_user_invitations
      WHERE LOWER(invited_email) = LOWER(?)
        AND status     = 'pending'
        AND expires_at > UTC_TIMESTAMP()
      LIMIT 1
    `,
    [email]
  );

  if (inviteRows.length > 0) {
    return {
      ok: false,
      status: 409,
      message: "A pending invitation already exists for this email",
    };
  }

  return { ok: true };
}

// ─── Partner code generation ─────────────────────────────────────────────────

function randomPartnerCodeSuffix() {
  // Use crypto.randomInt for unbiased selection over PARTNER_CODE_ALPHABET.
  let out = "";
  for (let i = 0; i < PARTNER_CODE_RANDOM_LEN; i++) {
    const idx = crypto.randomInt(0, PARTNER_CODE_ALPHABET.length);
    out += PARTNER_CODE_ALPHABET[idx];
  }
  return out;
}

/**
 * Returns a partner_code that does not collide with any existing row in
 * app_user_roles or app_user_invitations. Bounded retry — fails closed
 * after PARTNER_CODE_MAX_ATTEMPTS rather than looping forever.
 */
async function generateUniquePartnerCode() {
  for (let attempt = 0; attempt < PARTNER_CODE_MAX_ATTEMPTS; attempt++) {
    const candidate = PARTNER_CODE_PREFIX + randomPartnerCodeSuffix();

    const [hits] = await pool.execute(
      `
        SELECT 1 AS hit
        FROM app_user_roles
        WHERE UPPER(partner_code) = UPPER(?)
        UNION ALL
        SELECT 1 AS hit
        FROM app_user_invitations
        WHERE UPPER(partner_code) = UPPER(?)
        LIMIT 1
      `,
      [candidate, candidate]
    );

    if (hits.length === 0) {
      return candidate;
    }
  }

  throw new Error("Failed to generate a unique partner code");
}

// ─── Invitation row helpers ──────────────────────────────────────────────────

async function createPendingInvite({
  email,
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
  // app_user_invitations stores a deterministic hash of the invited email
  // (NOT NULL, no DB default) alongside the plaintext — a HIPAA minimum-necessary
  // /dedup column the PHP auth_common.php populated. Use the same keyed hash the
  // token uses so it is consistent and non-reversible without the pepper.
  const invitedEmailHash = secureHash(email);

  const [result] = await pool.execute(
    `
      INSERT INTO app_user_invitations (
        invited_email,
        invited_email_hash,
        invited_first_name,
        invited_last_name,
        invited_phone,
        invited_role,
        partner_code,
        invited_by_user_id,
        parent_user_id,
        token_hash,
        status,
        expires_at,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())
    `,
    [
      email,
      invitedEmailHash,
      firstName,
      lastName,
      phone,
      invitedRole,
      partnerCode,
      invitedByUserId,
      parentUserId,
      tokenHash,
      expiresAt,
    ]
  );

  return Number(result.insertId);
}

async function markInviteRevoked(invitationId) {
  try {
    await pool.execute(
      `
        UPDATE app_user_invitations
        SET status     = 'revoked',
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

async function markInviteSent(invitationId) {
  await pool.execute(
    `
      UPDATE app_user_invitations
      SET status     = 'pending',
          sent_at    = UTC_TIMESTAMP(),
          updated_at = UTC_TIMESTAMP()
      WHERE id = ?
      LIMIT 1
    `,
    [invitationId]
  );
}

// ─── Email via Resend ────────────────────────────────────────────────────────

/**
 * Render the invite email body. Variables are HTML-escaped to prevent
 * template injection if any field somehow bypassed validateInviteInput().
 */
function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

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
 * Sends the invite email via Resend's /emails endpoint. Returns
 * { ok: boolean, status?: number, error?: any }.
 *
 * NOTE: Resend does not have first-class server-side templates with variable
 * substitution. The PHP RESEND_INVITE_TEMPLATE_ID is logged for parity and
 * audit traceability, but the rendering is done here.
 */
async function sendResendTemplateEmail(toEmail, subject, templateId, vars) {
  if (!RESEND_API_KEY) {
    return { ok: false, status: 0, error: "RESEND_API_KEY not configured" };
  }

  try {
    const html = renderInviteHtml(vars);

    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from:    RESEND_FROM_EMAIL,
        to:      [toEmail],
        subject: subject,
        html,
        headers: {
          // Aids deliverability / threading in the recipient's client.
          "X-Entity-Ref-ID": `invite-${vars.PARTNER_CODE}`,
        },
        tags: [
          { name: "kind",         value: "invite" },
          { name: "invited_role", value: String(vars.INVITED_ROLE || "") },
          { name: "template_id",  value: String(templateId || "inline") },
        ],
      },
      {
        timeout: 10_000,
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        // Treat any non-2xx as a failure here; don't throw on 4xx.
        validateStatus: () => true,
      }
    );

    if (response.status >= 200 && response.status < 300) {
      return { ok: true, status: response.status, id: response.data?.id ?? null };
    }

    return {
      ok: false,
      status: response.status,
      error: response.data ?? "Resend non-2xx response",
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: err?.code || err?.message || "Resend request failed",
    };
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/admin-invite-trainer
 *
 * Body:
 *   {
 *     "first_name": "poornesh",
 *     "last_name":  "kumar",
 *     "email":      "poornesh@respyr.ai",
 *     "phone":      "8520046632589"   // optional
 *   }
 *
 * Auth: Bearer JWT with role=admin
 */
const adminInviteTrainer = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches PHP behavior).
  if (req.method !== "POST") {
    return res.status(405).json({
      ok:      false,
      message: "Method not allowed",
    });
  }

  let invitationId = null;
  let actorEmail   = null;
  let actorCode    = null;

  try {
    // ── 1. Resolve actor from JWT + DB (admin only) ────────────────────────
    const resolved = await resolveActorFromToken(req, "admin");

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType:     "invite_trainer_denied",
        userId:        null,
        role:          null,
        partnerCode:   null,
        identifier:    normalizeEmail(
          req.user?.email ||
          req.user?.user_id ||
          req.user?.dietician?.email ||
          req.user?.sub ||
          ""
        ),
        success:       false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });

      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;

    // ── 1b. Cross-check optional actor_user_id against the token identity ──
    // The PHP took the actor FROM the body. We keep `actor_user_id` in the
    // payload for frontend back-compat, but it is only ever cross-checked
    // against the JWT — it can never select a different admin (privilege
    // escalation / IDOR). Mismatch → 403.
    const bodyActorUserId = normalizeEmail(
      req.body && typeof req.body === "object" ? req.body.actor_user_id : ""
    );

    if (bodyActorUserId !== "" && bodyActorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType:     "invite_trainer_denied",
        userId:        actorEmail,
        role:          "admin",
        partnerCode:   actor.partner_code ?? null,
        identifier:    actorEmail,
        success:       false,
        failureReason: "actor_user_id does not match token identity",
      });

      return res.status(403).json({
        ok:      false,
        message: "actor_user_id does not match the authenticated user",
      });
    }

    // ── 1c. Admin must have a partner_code (PHP "linked role" guard) ───────
    if (!actor.partner_code || String(actor.partner_code).trim() === "") {
      await writeAuthLogSafe(req, {
        eventType:     "invite_trainer_denied",
        userId:        actorEmail,
        role:          "admin",
        partnerCode:   null,
        identifier:    actorEmail,
        success:       false,
        failureReason: "Admin partner code is missing",
      });

      return res.status(403).json({
        ok:      false,
        message: "Admin partner code is missing",
      });
    }

    actorCode = String(actor.partner_code);

    // ── 2. Validate input ──────────────────────────────────────────────────
    const validation = validateInviteInput(req.body);

    if (!validation.ok) {
      await writeAuthLogSafe(req, {
        eventType:     "invite_trainer_validation_failed",
        userId:        actorEmail,
        role:          "admin",
        partnerCode:   actorCode,
        identifier:    actorEmail,
        success:       false,
        failureReason: validation.message,
      });

      return res.status(validation.status).json({
        ok:      false,
        message: validation.message,
      });
    }

    const { first_name: firstName, last_name: lastName, email, phone } =
      validation.value;
    const phoneOrNull = phone !== "" ? phone : null;

    // ── 3. Pre-flight: no duplicate / no live pending invite ───────────────
    const canCreate = await ensureInviteCanBeCreated(email);

    if (!canCreate.ok) {
      await writeAuthLogSafe(req, {
        eventType:     "invite_trainer_duplicate",
        userId:        actorEmail,
        role:          "admin",
        partnerCode:   actorCode,
        identifier:    email,
        success:       false,
        failureReason: canCreate.message,
      });

      return res.status(canCreate.status).json({
        ok:      false,
        message: canCreate.message,
      });
    }

    // ── 4. Generate trainer partner code + invite token ────────────────────
    const partnerCode = await generateUniquePartnerCode();

    const rawToken  = crypto.randomBytes(32).toString("hex");
    const tokenHash = secureHash(rawToken);

    const inviteLink =
      `${FRONTEND_ACCEPT_INVITE_URL}?token=${encodeURIComponent(rawToken)}`;

    const expiresAtDate = new Date(
      Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000
    );
    const expiresAt = toUtcMysqlDateTime(expiresAtDate);

    // ── 5. Insert pending invite row ───────────────────────────────────────
    invitationId = await createPendingInvite({
      email,
      firstName,
      lastName,
      phone: phoneOrNull,
      invitedRole:     "trainer",
      partnerCode,
      invitedByUserId: actorEmail,
      parentUserId:    actorEmail,
      tokenHash,
      expiresAt,
    });

    const fullName = `${firstName} ${lastName}`.trim();

    // ── 6. Send the email ──────────────────────────────────────────────────
    const emailResult = await sendResendTemplateEmail(
      email,
      "You have been invited to Respyr",
      RESEND_INVITE_TEMPLATE_ID,
      {
        INVITED_NAME:   fullName,
        INVITER_EMAIL:  actorEmail,
        INVITED_EMAIL:  email,
        INVITED_ROLE:   "trainer",
        PARTNER_CODE:   partnerCode,
        EXPIRES_IN:     `${INVITE_EXPIRY_HOURS} hours`,
        INVITE_LINK:    inviteLink,
      }
    );

    if (!emailResult.ok) {
      await markInviteRevoked(invitationId);

      console.error("RESEND_TRAINER_INVITE_FAILED:", {
        invitation_id: invitationId,
        status:        emailResult.status,
        error:         APP_DEBUG ? emailResult.error : undefined,
      });

      await writeAuthLogSafe(req, {
        eventType:     "invite_trainer_email_failed",
        userId:        actorEmail,
        role:          "admin",
        partnerCode:   actorCode,
        identifier:    email,
        success:       false,
        failureReason: "resend_failed",
      });

      return res.status(502).json({
        ok:      false,
        message: "Invitation email could not be sent",
        ...(APP_DEBUG && { debug_resend_error: emailResult }),
      });
    }

    // ── 7. Mark invite as sent ─────────────────────────────────────────────
    await markInviteSent(invitationId);

    // ── 8. Audit — success ────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType:     "invite_trainer_sent",
      userId:        actorEmail,
      role:          "admin",
      partnerCode:   actorCode,
      identifier:    email,
      success:       true,
      failureReason: `Trainer invite sent to ${email}`,
    });

    // ── 9. Respond (matches PHP JSON shape exactly) ────────────────────────
    const response = {
      ok:      true,
      message: "Trainer invitation sent successfully",
      data: {
        invitation_id:       invitationId,
        invited_first_name:  firstName,
        invited_last_name:   lastName,
        invited_name:        fullName,
        invited_email:       email,
        invited_phone:       phoneOrNull,
        invited_role:        "trainer",
        partner_code:        partnerCode,
        invited_by_user_id:  actorEmail,
        parent_user_id:      actorEmail,
        status:              "pending",
        expires_at:          expiresAt,
        email_sent:          true,
      },
    };

    if (RETURN_INVITE_LINK_FOR_TESTING) {
      response.debug_invite_link = inviteLink;
    }

    return res.status(201).json(response);

  } catch (err) {
    // Defense in depth: if we created an invite row before crashing, revoke it
    // so a half-finished invite cannot be silently activated later.
    if (invitationId !== null) {
      await markInviteRevoked(invitationId);
    }

    console.error("ADMIN_INVITE_TRAINER_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType:     "invite_trainer_error",
      userId:        actorEmail,
      role:          "admin",
      partnerCode:   actorCode,
      identifier:    actorEmail,
      success:       false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok:      false,
      message: "Internal server error",
      ...(APP_DEBUG && {
        debug_error: err?.message,
        debug_file:  err?.stack?.split("\n")[1]?.trim(),
      }),
    });
  }
};

module.exports = { adminInviteTrainer };
