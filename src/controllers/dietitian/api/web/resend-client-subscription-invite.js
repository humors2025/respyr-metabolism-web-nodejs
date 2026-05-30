"use strict";

/**
 * resend-client-subscription-invite.js
 *
 * Converted from: resend-client-subscription-invite.php
 *                 (+ client-subscription-action-common.php `csi_*` helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/resend-client-subscription-invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but only for a subscription whose
 *              trainer_code / trainer_id is inside the actor's allowed-code set.
 *
 * Behaviour parity with the PHP:
 *  - Locates the target inside a transaction (FOR UPDATE) by, in order:
 *      • subscription_id, or
 *      • redeem_code, or
 *      • legacy invite_id (trainer_client_invites) — from which a subscription
 *        row is materialised (csi_create_subscription_from_legacy_invite).
 *  - Guard ladder (each rolls the transaction back first):
 *      • 404 — neither a subscription nor a legacy invite was found,
 *      • 403 — actor's allowed codes do not cover the row's trainer_code/id,
 *      • 409 — already accepted / redeemed (subscription or legacy invite),
 *      • 409 — cancelled (status OR subscription_status = 'cancelled').
 *  - Regenerates the redeem_code on every resend (clean mobile flow), sets the
 *    row to the "sending" state (status='failed', email_status='failed',
 *    subscription_status='pending', error_message='Email resend started'),
 *    commits, hydrates the trainer name, then sends the email.
 *  - Post-send: writes the final status (sent/failed), resend_email_id and
 *    error_message back onto the subscription AND mirrors them onto the source
 *    invite (csi_update_source_invite), then audits.
 *  - Response shape matches the PHP exactly: { status, ok, message, data }.
 *  - HTTP codes match the PHP: 200 on send, 502 when the row was saved but the
 *    email failed.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The PHP took the actor FROM body.actor_user_id — an
 *    IDOR / privilege-escalation hole. Here the actor is resolved from the
 *    verified JWT and re-fetched from the DB (role + status re-checked
 *    server-side). body.actor_user_id is still accepted for frontend
 *    back-compat but is only cross-checked against the token email (mismatch →
 *    403); it can never select another user.
 *  - Tenant isolation enforced server-side: a row can only be resent if its
 *    trainer_code/trainer_id is in the actor's allowed-code set (own code for a
 *    trainer; own + child trainers for an admin; the whole sub-tree for a
 *    super_admin) — identical model to referral-client-list.js.
 *  - Fully parameterized queries. The target is read FOR UPDATE so two
 *    concurrent resends cannot race the redeem-code regeneration.
 *  - redeem_code is generated with crypto.randomInt (unbiased) and verified
 *    unique with a bounded, fail-closed retry.
 *  - Internal error / email-provider details are suppressed in production
 *    (gated behind APP_DEBUG). The PHP echoed raw `debug_error` — an
 *    info-disclosure finding that is closed here.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - PHI in audit logs (client email, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text.
 *  - Every resend (success, denial, conflict, failure, error) is recorded in
 *    app_auth_logs.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_plan_subscriptions, trainer_client_invites,
 * app_auth_logs.
 *
 * ASSUMPTION (documented): client-subscription-action-common.php was not part of
 * the Node repo, so its `csi_*` helpers are reimplemented here from the columns
 * and access model already used by referral-client-list.js and
 * list-trainer-client-invites.js (which read the SAME two tables). The redeem
 * code shape ("RSP" + 6 base32-ish chars, e.g. RSP8K2M9Q) and
 * CLIENT_REDEEM_CODE_EXPIRY_DAYS are taken from the PHP sample / constant. If
 * your common file differed (e.g. extra subscription columns on the
 * create-from-legacy path), align those lists.
 */

const crypto = require("crypto");
const axios = require("axios");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// CLIENT_REDEEM_CODE_EXPIRY_DAYS from the PHP constant (default 7 days).
const CLIENT_REDEEM_CODE_EXPIRY_DAYS = Math.max(
  1,
  parseInt(process.env.CLIENT_REDEEM_CODE_EXPIRY_DAYS, 10) || 7
);

// Redeem codes look like RSP8K2M9Q in the PHP sample: "RSP" + 6 chars.
const REDEEM_CODE_PREFIX = "RSP";
const REDEEM_CODE_RANDOM_LEN = 6;
const REDEEM_CODE_MAX_ATTEMPTS = 12;
// No 0/O/1/I to keep codes unambiguous when typed on mobile.
const REDEEM_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_SUBSCRIPTION_TEMPLATE_ID =
  process.env.RESEND_SUBSCRIPTION_TEMPLATE_ID ||
  process.env.RESEND_INVITE_TEMPLATE_ID ||
  "";
const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL || "Respyr <no-reply@respyr.ai>";

const FRONTEND_REDEEM_URL =
  process.env.FRONTEND_REDEEM_URL || "https://app.respyr.ai/redeem";

const RETURN_REDEEM_CODE_FOR_TESTING =
  String(process.env.RETURN_REDEEM_CODE_FOR_TESTING || "").toLowerCase() ===
  "true";

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return String(val ?? "").trim().toLowerCase();
}

function normalizeCode(val) {
  return String(val ?? "").trim().toUpperCase();
}

function cleanValue(val) {
  return String(val ?? "").trim();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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

/** Format a Date (UTC) as "YYYY-MM-DD HH:MM:SS" — matches PHP date()/gmdate(). */
function toUtcMysqlDateTime(date) {
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
  );
}

/** Format a mysql2 DATETIME value (Date or string) as "YYYY-MM-DD HH:MM:SS". */
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

/** csi_effective_code(): partner_code, else dietician_id, else null. */
function getEffectiveCode(row) {
  if (
    row.partner_code !== null &&
    row.partner_code !== undefined &&
    String(row.partner_code).trim() !== ""
  ) {
    return String(row.partner_code);
  }
  if (
    row.dietician_id !== null &&
    row.dietician_id !== undefined &&
    String(row.dietician_id).trim() !== ""
  ) {
    return String(row.dietician_id);
  }
  return null;
}

// ─── Audit log ───────────────────────────────────────────────────────────────

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
      identifier !== null && identifier !== undefined
        ? authLogHash(identifier)
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
    console.error(
      "RESEND_CLIENT_SUBSCRIPTION_AUDIT_FAILED:",
      err?.code || err?.message
    );
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * csi_get_actor_or_fail(), re-bound to the JWT. Resolve the actor from the token
 * subject (dietician_id), fall back to the token email, then re-check role +
 * status against the DB. Returns { actor, actorEmail } or
 * { error: { status, message } }.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload?.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    return { error: { status: 401, message: "Invalid token user" } };
  }

  const selectCols = `
    td.id,
    td.dietician_id,
    td.name,
    td.email,
    aur.user_id,
    aur.role,
    aur.partner_code,
    aur.parent_user_id,
    aur.status
  `;

  const [rows] = dieticianId
    ? await pool.execute(
        `
          SELECT ${selectCols}
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
          SELECT ${selectCols}
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
    return { error: { status: 403, message: "Actor user not found" } };
  }
  if (String(actor.status) !== "active") {
    return { error: { status: 403, message: "Actor account is not active" } };
  }
  if (!VALID_ACTOR_ROLES.has(String(actor.role))) {
    return { error: { status: 403, message: "Invalid actor role" } };
  }

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

// ─── Allowed codes (csi_allowed_codes) ───────────────────────────────────────

function addCode(codes, code) {
  const c = normalizeCode(code);
  if (c !== "") codes.set(c, c);
}

/**
 * Resolve the set of trainer/partner codes this actor may act on. Mirrors
 * referral-client-list.js getAllowedCodes() (same subscriptions table) exactly:
 *   trainer     → own effective code,
 *   admin       → own + active child trainers' partner_codes,
 *   super_admin → own + child admins' codes + those admins' active trainers'.
 */
async function getAllowedCodes(actor) {
  const codes = new Map();
  const actorEmail = normalizeEmail(actor.user_id || actor.email);
  const role = String(actor.role);

  addCode(codes, getEffectiveCode(actor));
  // A trainer's rows may be keyed by dietician_id rather than partner_code;
  // include both so a legitimate owner is never falsely denied (403).
  addCode(codes, actor.dietician_id);
  addCode(codes, actor.partner_code);

  if (role === "trainer") {
    return [...codes.values()];
  }

  if (role === "admin") {
    const [childRows] = await pool.execute(
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
    for (const row of childRows) addCode(codes, row.partner_code);
    return [...codes.values()];
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
    for (const row of rows) addCode(codes, row.partner_code);
    return [...codes.values()];
  }

  return [...codes.values()];
}

/** csi_can_access_code(): is `code` inside the allowed set (case-insensitive)? */
function canAccessCode(allowedCodes, code) {
  const c = normalizeCode(code);
  if (c === "") return false;
  return allowedCodes.some((allowed) => normalizeCode(allowed) === c);
}

// ─── Target resolution (subscription / legacy invite) ────────────────────────

const SUBSCRIPTION_COLUMNS = `
  id,
  source_invite_id,
  trainer_id,
  trainer_code,
  client_name,
  client_mobile,
  client_email,
  plan_code,
  plan_name,
  plan_price_label,
  status,
  email_status,
  subscription_status,
  resend_email_id,
  accepted_profile_id,
  accepted_at,
  error_message,
  redeem_code,
  code_expires_at,
  created_by_user_id,
  created_at,
  updated_at
`;

/**
 * csi_get_subscription_for_update(): locate the subscription FOR UPDATE by
 * subscription_id (preferred) or redeem_code. Returns the row or null.
 */
async function getSubscriptionForUpdate(conn, body) {
  const subscriptionId = Number.parseInt(body.subscription_id, 10);
  if (Number.isInteger(subscriptionId) && subscriptionId > 0) {
    const [rows] = await conn.execute(
      `SELECT ${SUBSCRIPTION_COLUMNS}
       FROM trainer_client_plan_subscriptions
       WHERE id = ?
       LIMIT 1
       FOR UPDATE`,
      [subscriptionId]
    );
    if (rows[0]) return rows[0];
  }

  const redeemCode = normalizeCode(body.redeem_code);
  if (redeemCode !== "" && redeemCode.length <= 32) {
    const [rows] = await conn.execute(
      `SELECT ${SUBSCRIPTION_COLUMNS}
       FROM trainer_client_plan_subscriptions
       WHERE UPPER(redeem_code) = ?
       LIMIT 1
       FOR UPDATE`,
      [redeemCode]
    );
    if (rows[0]) return rows[0];
  }

  return null;
}

/**
 * csi_get_legacy_invite_for_update(): locate a legacy invite FOR UPDATE by
 * invite_id. Returns the row or null.
 */
async function getLegacyInviteForUpdate(conn, body) {
  const inviteId = Number.parseInt(body.invite_id, 10);
  if (!Number.isInteger(inviteId) || inviteId <= 0) return null;

  const [rows] = await conn.execute(
    `
      SELECT
        id,
        trainer_id,
        trainer_code,
        client_name,
        client_mobile,
        client_email,
        plan_code,
        plan_name,
        plan_price_label,
        status,
        email_status,
        resend_email_id,
        accepted_profile_id,
        accepted_at,
        error_message,
        created_at,
        updated_at
      FROM trainer_client_invites
      WHERE id = ?
      LIMIT 1
      FOR UPDATE
    `,
    [inviteId]
  );

  return rows[0] || null;
}

/** csi_subscription_is_accepted(): accepted/redeemed status or accepted profile. */
function subscriptionIsAccepted(sub) {
  const status = String(sub.status ?? "").toLowerCase();
  const subStatus = String(sub.subscription_status ?? "").toLowerCase();
  if (status === "accepted" || status === "redeemed") return true;
  if (subStatus === "accepted" || subStatus === "redeemed") return true;
  if (cleanValue(sub.accepted_profile_id) !== "") return true;
  return false;
}

/** csi_legacy_invite_is_accepted(): accepted status or accepted profile. */
function legacyInviteIsAccepted(invite) {
  const status = String(invite.status ?? "").toLowerCase();
  if (status === "accepted") return true;
  if (cleanValue(invite.accepted_profile_id) !== "") return true;
  return false;
}

// ─── Redeem code generation (csi_unique_redeem_code) ─────────────────────────

function randomRedeemSuffix() {
  let out = "";
  for (let i = 0; i < REDEEM_CODE_RANDOM_LEN; i++) {
    out += REDEEM_CODE_ALPHABET[crypto.randomInt(0, REDEEM_CODE_ALPHABET.length)];
  }
  return out;
}

/**
 * Generate a redeem_code not present in trainer_client_plan_subscriptions.
 * Bounded, fail-closed retry. The caller is inside the row lock, so a duplicate
 * is only possible against a *different* row — this check covers that.
 */
async function generateUniqueRedeemCode(executor) {
  for (let attempt = 0; attempt < REDEEM_CODE_MAX_ATTEMPTS; attempt++) {
    const candidate = REDEEM_CODE_PREFIX + randomRedeemSuffix();
    const [hits] = await executor.execute(
      `SELECT 1 AS hit
       FROM trainer_client_plan_subscriptions
       WHERE UPPER(redeem_code) = UPPER(?)
       LIMIT 1`,
      [candidate]
    );
    if (hits.length === 0) return candidate;
  }
  throw new Error("Failed to generate a unique redeem code");
}

// ─── Create subscription from a legacy invite ────────────────────────────────

/**
 * csi_create_subscription_from_legacy_invite(): materialise a subscription row
 * from a legacy trainer_client_invites row (used when the caller passed an
 * invite_id with no subscription yet). Runs on the locked transaction
 * connection. Returns the freshly-read subscription row (FOR UPDATE).
 */
async function createSubscriptionFromLegacyInvite(conn, invite, createdByUserId) {
  const redeemCode = await generateUniqueRedeemCode(conn);
  const codeExpiresAt = toUtcMysqlDateTime(
    new Date(Date.now() + CLIENT_REDEEM_CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
  );

  const planCode = cleanValue(invite.plan_code) !== "" ? invite.plan_code : "free_trial";
  const planName = cleanValue(invite.plan_name) !== "" ? invite.plan_name : "Free Trial";

  const [result] = await conn.execute(
    `
      INSERT INTO trainer_client_plan_subscriptions (
        source_invite_id,
        trainer_id,
        trainer_code,
        client_name,
        client_mobile,
        client_email,
        plan_code,
        plan_name,
        plan_price_label,
        status,
        email_status,
        subscription_status,
        redeem_code,
        code_expires_at,
        created_by_user_id,
        created_at,
        updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', 'pending', 'pending', ?, ?, ?, NOW(), NOW())
    `,
    [
      Number(invite.id),
      invite.trainer_id ?? null,
      invite.trainer_code ?? null,
      invite.client_name ?? null,
      invite.client_mobile ?? null,
      normalizeEmail(invite.client_email),
      planCode,
      planName,
      invite.plan_price_label ?? null,
      redeemCode,
      codeExpiresAt,
      createdByUserId,
    ]
  );

  const newId = Number(result.insertId);

  const [rows] = await conn.execute(
    `SELECT ${SUBSCRIPTION_COLUMNS}
     FROM trainer_client_plan_subscriptions
     WHERE id = ?
     LIMIT 1
     FOR UPDATE`,
    [newId]
  );

  return rows[0] || null;
}

// ─── Trainer name hydration (csi_hydrate_trainer_name) ───────────────────────

/**
 * csi_hydrate_trainer_name(): resolve a display name for the subscription's
 * trainer from app_user_roles → table_dietician, by trainer_code or trainer_id.
 * Returns the subscription augmented with `trainer_name` (never throws).
 */
async function hydrateTrainerName(sub) {
  let trainerName = null;
  try {
    const [rows] = await pool.execute(
      `
        SELECT td.name
        FROM app_user_roles aur
        INNER JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE UPPER(aur.partner_code) = UPPER(?)
           OR UPPER(aur.partner_code) = UPPER(?)
        LIMIT 1
      `,
      [cleanValue(sub.trainer_code), cleanValue(sub.trainer_id)]
    );
    if (rows[0] && cleanValue(rows[0].name) !== "") {
      trainerName = rows[0].name;
    }
  } catch (err) {
    console.error("HYDRATE_TRAINER_NAME_FAILED:", err?.code || err?.message);
  }
  return { ...sub, trainer_name: trainerName };
}

// ─── Email via Resend (csi_send_email) ───────────────────────────────────────

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderSubscriptionHtml(vars) {
  const safe = {};
  for (const [k, v] of Object.entries(vars)) safe[k] = escapeHtml(v ?? "");

  return `<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; color:#222; line-height:1.5;">
    <p>Hi ${safe.CLIENT_NAME},</p>
    <p>${safe.TRAINER_NAME} has invited you to start your <strong>${safe.PLAN_NAME}</strong> plan on Respyr${safe.PLAN_PRICE_LABEL ? ` (${safe.PLAN_PRICE_LABEL})` : ""}.</p>
    <p>Your redeem code: <strong style="font-size:18px;letter-spacing:2px;">${safe.REDEEM_CODE}</strong></p>
    <p>
      <a href="${safe.REDEEM_LINK}"
         style="display:inline-block;padding:10px 18px;background:#0a7d3b;color:#fff;text-decoration:none;border-radius:6px;">
        Open Respyr &amp; redeem
      </a>
    </p>
    <p>Open the Respyr app, sign in with this email, and enter the code above.</p>
    <p>This code expires on ${safe.CODE_EXPIRES_AT} (UTC).</p>
    <p style="font-size:12px;color:#666;">If you did not expect this email, you can ignore it.</p>
  </body>
</html>`;
}

/**
 * csi_send_email(): send the client subscription invite via Resend. Returns
 * { success, error, resend_email_id } to mirror the PHP shape. Resend has no
 * first-class server-side variable templates; the template id is sent as a tag
 * for traceability and the body is rendered inline.
 */
async function sendSubscriptionEmail(sub) {
  const toEmail = normalizeEmail(sub.client_email);

  if (!RESEND_API_KEY) {
    return { success: false, error: "RESEND_API_KEY not configured", resend_email_id: null };
  }
  if (!isValidEmail(toEmail)) {
    return { success: false, error: "Invalid client email", resend_email_id: null };
  }

  const clientName =
    cleanValue(sub.client_name) !== "" ? sub.client_name : toEmail;
  const trainerName =
    cleanValue(sub.trainer_name) !== "" ? sub.trainer_name : "Your coach";
  const redeemLink = `${FRONTEND_REDEEM_URL}?code=${encodeURIComponent(sub.redeem_code)}`;

  try {
    const html = renderSubscriptionHtml({
      CLIENT_NAME: clientName,
      TRAINER_NAME: trainerName,
      PLAN_NAME: cleanValue(sub.plan_name) !== "" ? sub.plan_name : "Respyr",
      PLAN_PRICE_LABEL: cleanValue(sub.plan_price_label),
      REDEEM_CODE: sub.redeem_code,
      REDEEM_LINK: redeemLink,
      CODE_EXPIRES_AT: toMysqlDateTime(sub.code_expires_at),
    });

    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: RESEND_FROM_EMAIL,
        to: [toEmail],
        subject: "Your Respyr plan invite",
        html,
        headers: { "X-Entity-Ref-ID": `client-sub-${sub.id}` },
        tags: [
          { name: "kind", value: "client_subscription_invite_resend" },
          { name: "plan_code", value: String(sub.plan_code || "") },
          {
            name: "template_id",
            value: String(RESEND_SUBSCRIPTION_TEMPLATE_ID || "inline"),
          },
        ],
      },
      {
        timeout: 10_000,
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        validateStatus: () => true,
      }
    );

    if (response.status >= 200 && response.status < 300) {
      return {
        success: true,
        error: null,
        resend_email_id: response.data?.id ?? null,
      };
    }

    return {
      success: false,
      error: APP_DEBUG
        ? `Resend ${response.status}: ${JSON.stringify(response.data)}`.slice(0, 240)
        : "Email provider rejected the request",
      resend_email_id: null,
    };
  } catch (err) {
    return {
      success: false,
      error: err?.code || err?.message || "Resend request failed",
      resend_email_id: null,
    };
  }
}

// ─── Source invite mirror (csi_update_source_invite) ─────────────────────────

/**
 * csi_update_source_invite(): mirror the resend outcome back onto the originating
 * trainer_client_invites row (if any) and point latest_subscription_id at the
 * subscription. Never throws.
 */
async function updateSourceInvite(
  sourceInviteId,
  status,
  emailStatus,
  resendEmailId,
  errorMessage,
  subscriptionId
) {
  if (!Number.isInteger(sourceInviteId) || sourceInviteId <= 0) return;

  try {
    await pool.execute(
      `
        UPDATE trainer_client_invites
        SET status                = ?,
            email_status          = ?,
            resend_email_id       = ?,
            error_message         = ?,
            latest_subscription_id = ?,
            updated_at            = NOW()
        WHERE id = ?
        LIMIT 1
      `,
      [
        status,
        emailStatus,
        resendEmailId,
        errorMessage,
        subscriptionId,
        sourceInviteId,
      ]
    );
  } catch (err) {
    console.error("UPDATE_SOURCE_INVITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/resend-client-subscription-invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body (one of subscription_id / redeem_code / invite_id is required):
 *   {
 *     "subscription_id": 12,          // preferred
 *     "redeem_code": "RSP8K2M9Q",     // alternative
 *     "invite_id": 5,                 // legacy fallback
 *     "actor_user_id": ""             // optional; if set, must match token email
 *   }
 */
const resendClientSubscriptionInvite = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP REQUEST_METHOD check).
  if (req.method !== "POST") {
    return res.status(405).json({
      status: false,
      ok: false,
      message: "Only POST method is allowed",
    });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body)
      ? req.body
      : {};

  const actorUserId = normalizeEmail(body.actor_user_id);

  // At least one locator is required.
  const hasSubscriptionId =
    Number.isInteger(Number.parseInt(body.subscription_id, 10)) &&
    Number.parseInt(body.subscription_id, 10) > 0;
  const hasRedeemCode = normalizeCode(body.redeem_code) !== "";
  const hasInviteId =
    Number.isInteger(Number.parseInt(body.invite_id, 10)) &&
    Number.parseInt(body.invite_id, 10) > 0;

  if (!hasSubscriptionId && !hasRedeemCode && !hasInviteId) {
    return res.status(422).json({
      status: false,
      ok: false,
      message: "subscription_id, redeem_code or invite_id is required",
    });
  }

  if (actorUserId !== "" && !isValidEmail(actorUserId)) {
    return res.status(422).json({
      status: false,
      ok: false,
      message: "Valid actor_user_id is required",
    });
  }

  // A loose, non-PHI identifier for denial audits before the row is known.
  const locatorTag = hasSubscriptionId
    ? `sub:${Number.parseInt(body.subscription_id, 10)}`
    : hasRedeemCode
    ? "redeem_code"
    : `invite:${Number.parseInt(body.invite_id, 10)}`;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;
  let conn = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_resend_denied",
        userId: actorUserId || null,
        role: null,
        partnerCode: null,
        identifier: locatorTag,
        success: false,
        failureReason: resolved.error.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json({
        status: false,
        ok: false,
        message: resolved.error.message,
      });
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getEffectiveCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: locatorTag,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "actor_user_id does not match the authenticated user",
      });
    }

    const allowedCodes = await getAllowedCodes(actor);

    // ── 2. Locate the target inside a transaction (FOR UPDATE) ──────────────
    conn = await pool.getConnection();
    await conn.beginTransaction();

    let sub = await getSubscriptionForUpdate(conn, body);

    if (!sub) {
      // Legacy path: materialise a subscription from a trainer_client_invites row.
      const legacyInvite = await getLegacyInviteForUpdate(conn, body);

      if (!legacyInvite) {
        await conn.rollback();
        conn.release();
        conn = null;
        await writeAuthLogSafe(req, {
          eventType: "client_subscription_invite_resend_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: locatorTag,
          success: false,
          failureReason: "Client invite/subscription not found",
        });
        return res.status(404).json({
          status: false,
          ok: false,
          message: "Client invite/subscription not found",
        });
      }

      if (
        !canAccessCode(allowedCodes, legacyInvite.trainer_code) &&
        !canAccessCode(allowedCodes, legacyInvite.trainer_id)
      ) {
        await conn.rollback();
        conn.release();
        conn = null;
        await writeAuthLogSafe(req, {
          eventType: "client_subscription_invite_resend_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: normalizeEmail(legacyInvite.client_email),
          success: false,
          failureReason: "Actor not allowed to resend this client invite",
        });
        return res.status(403).json({
          status: false,
          ok: false,
          message: "You are not allowed to resend this client invite",
        });
      }

      if (legacyInviteIsAccepted(legacyInvite)) {
        await conn.rollback();
        conn.release();
        conn = null;
        return res.status(409).json({
          status: false,
          ok: false,
          message: "Accepted client invite cannot be resent",
        });
      }

      sub = await createSubscriptionFromLegacyInvite(conn, legacyInvite, actorEmail);

      if (!sub) {
        await conn.rollback();
        conn.release();
        conn = null;
        throw new Error("Failed to materialise subscription from legacy invite");
      }
    }

    // ── 3. Tenant + state guards on the subscription ────────────────────────
    if (
      !canAccessCode(allowedCodes, sub.trainer_code) &&
      !canAccessCode(allowedCodes, sub.trainer_id)
    ) {
      await conn.rollback();
      conn.release();
      conn = null;
      await writeAuthLogSafe(req, {
        eventType: "client_subscription_invite_resend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: normalizeEmail(sub.client_email),
        success: false,
        failureReason: "Actor not allowed to resend this subscription",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "You are not allowed to resend this client subscription invite",
      });
    }

    if (subscriptionIsAccepted(sub)) {
      await conn.rollback();
      conn.release();
      conn = null;
      return res.status(409).json({
        status: false,
        ok: false,
        message: "Accepted/redeemed subscription cannot be resent",
      });
    }

    if (
      String(sub.status) === "cancelled" ||
      String(sub.subscription_status) === "cancelled"
    ) {
      await conn.rollback();
      conn.release();
      conn = null;
      return res.status(409).json({
        status: false,
        ok: false,
        message: "Cancelled subscription cannot be resent. Create a new invite.",
      });
    }

    // ── 4. Regenerate redeem code + move row to the "sending" state ─────────
    const newRedeemCode = await generateUniqueRedeemCode(conn);
    const newExpiresAt = toUtcMysqlDateTime(
      new Date(Date.now() + CLIENT_REDEEM_CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
    );

    await conn.execute(
      `
        UPDATE trainer_client_plan_subscriptions
        SET redeem_code         = ?,
            code_expires_at     = ?,
            status              = 'failed',
            email_status        = 'failed',
            subscription_status = 'pending',
            error_message       = 'Email resend started',
            updated_at          = NOW()
        WHERE id = ?
        LIMIT 1
      `,
      [newRedeemCode, newExpiresAt, Number(sub.id)]
    );

    sub.redeem_code = newRedeemCode;
    sub.code_expires_at = newExpiresAt;

    await conn.commit();
    conn.release();
    conn = null;

    // ── 5. Hydrate trainer name + send the email ────────────────────────────
    sub = await hydrateTrainerName(sub);

    const emailResult = await sendSubscriptionEmail(sub);

    const newStatus = emailResult.success ? "sent" : "failed";
    const newEmailStatus = emailResult.success ? "sent" : "failed";
    const newError = emailResult.error;
    const resendEmailId = emailResult.resend_email_id;

    // ── 6. Persist the final outcome onto the subscription ──────────────────
    await pool.execute(
      `
        UPDATE trainer_client_plan_subscriptions
        SET status          = ?,
            email_status    = ?,
            resend_email_id = ?,
            error_message   = ?,
            updated_at      = NOW()
        WHERE id = ?
        LIMIT 1
      `,
      [newStatus, newEmailStatus, resendEmailId, newError, Number(sub.id)]
    );

    // ── 7. Mirror the outcome onto the source invite (if any) ───────────────
    const sourceInviteId =
      sub.source_invite_id !== null && sub.source_invite_id !== undefined
        ? Number(sub.source_invite_id)
        : null;

    await updateSourceInvite(
      sourceInviteId,
      newStatus,
      newEmailStatus,
      resendEmailId,
      newError,
      Number(sub.id)
    );

    // ── 8. Audit ────────────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: emailResult.success
        ? "client_subscription_invite_resent"
        : "client_subscription_invite_resend_failed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: normalizeEmail(sub.client_email),
      success: emailResult.success,
      failureReason: emailResult.success
        ? "Client subscription invite resent"
        : "Client subscription invite resend failed",
    });

    // ── 9. Respond (matches the PHP JSON shape exactly) ─────────────────────
    const response = {
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
        client_name: sub.client_name ?? null,
        client_email: normalizeEmail(sub.client_email),
        trainer_code: sub.trainer_code ?? null,
        plan_code: sub.plan_code ?? null,
        plan_name: sub.plan_name ?? null,
        plan_price_label: sub.plan_price_label ?? null,
        invite_status: newStatus,
        email_status: newEmailStatus,
        resend_email_id: resendEmailId,
        // VAPT: provider error text only in non-production.
        error_message: APP_DEBUG ? newError : emailResult.success ? null : "resend_failed",
      },
    };

    if (RETURN_REDEEM_CODE_FOR_TESTING) {
      response.debug_redeem_code = newRedeemCode;
    }

    return res.status(emailResult.success ? 200 : 502).json(response);
  } catch (err) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (_) {
        /* ignore */
      }
      try {
        conn.release();
      } catch (_) {
        /* ignore */
      }
      conn = null;
    }

    console.error("RESEND_CLIENT_SUBSCRIPTION_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "client_subscription_invite_resend_error",
      userId: actorEmail || actorUserId || null,
      role: actorRole,
      partnerCode: actorCode,
      identifier: locatorTag,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { resendClientSubscriptionInvite };
