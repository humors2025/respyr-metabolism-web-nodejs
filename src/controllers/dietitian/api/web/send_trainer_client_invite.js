"use strict";

/**
 * send_trainer_client_invite.js
 *
 * Converted from: send_trainer_client_invite.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/send_trainer_client_invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but ONLY for a trainer code the
 *              actor is allowed to use (own code, or a child trainer's code).
 *
 * Behaviour parity with the PHP:
 *  - Resolves the trusted plan (referral_plans table if present, else the
 *    hard-coded backend plan map) — invalid plan_code → 400.
 *  - Prevents a duplicate pending invite for the same (trainer_code, client_email,
 *    plan_code) → 409.
 *  - Creates a trainer_client_plan_subscriptions row (with a unique RSP######
 *    redeem code + expiry), then upserts the latest trainer_client_invites row
 *    WITHOUT clobbering an already-accepted invite.
 *  - Sends the invite email via Resend (template id + variables, same payload as
 *    the PHP), then writes the email result back to both rows (the invite row
 *    update is guarded against the accepted state).
 *  - Response shape matches the PHP exactly: { status, ok, message, data{...} }
 *    with the same keys/ordering.
 *
 * VAPT hardening (beyond the PHP — this is the whole point of the sprint):
 *  - Token-bound identity. The PHP only checked authorization when the caller
 *    chose to send body.actor_user_id; with no actor_user_id ANY caller could
 *    invite clients under ANY trainer_id (a textbook IDOR / privilege-escalation
 *    hole). Here the actor is ALWAYS resolved from the verified JWT and
 *    re-checked (role + status) against the DB, and the actor must ALWAYS be
 *    allowed to use the requested trainer code — there is no unauthenticated /
 *    unauthorized path. body.actor_user_id is still accepted for frontend
 *    back-compat but is only cross-checked against the token identity
 *    (mismatch → 403); it can never select another user.
 *  - Every query is fully parameterized (no string interpolation).
 *  - Redeem codes use crypto.randomInt (CSPRNG), not a biased PRNG.
 *  - Internal error / email-provider details are suppressed in production
 *    (gated behind APP_DEBUG). The PHP forced API_DEBUG=true and echoed file/
 *    line/message — an info-disclosure finding closed here.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (client email, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *  - Every invite (success / failure / denial) is recorded in app_auth_logs.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, referral_plans (optional), trainer_client_invites,
 * trainer_client_plan_subscriptions, app_auth_logs.
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

// Resend config (was resend_config.php constants).
const RESEND_API_KEY     = process.env.RESEND_API_KEY     || "";
const RESEND_FROM_EMAIL  = process.env.RESEND_FROM_EMAIL  || "";
const RESEND_REPLY_TO    = process.env.RESEND_REPLY_TO    || "";
const RESEND_TEMPLATE_ID = process.env.RESEND_TEMPLATE_ID || "";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// IST (Asia/Kolkata, UTC+05:30) — the PHP ran date_default_timezone_set('Asia/Kolkata')
// and SET time_zone = '+05:30', so all stored timestamps are IST wall-clock.
const IST_OFFSET_MS = (5 * 60 + 30) * 60 * 1000;

// Hard-coded trusted backend plan map (fallback when referral_plans is absent).
const FALLBACK_PLANS = {
  free_trial: {
    plan_code: "free_trial",
    plan_name: "Free Trial",
    plan_price_label: "Free",
    amount: "0.00",
    currency: "USD",
    billing_cycle: "trial",
  },
  monthly: {
    plan_code: "monthly",
    plan_name: "Monthly Plan",
    plan_price_label: "$50/mo",
    amount: "50.00",
    currency: "USD",
    billing_cycle: "monthly",
  },
  lease_quarterly: {
    plan_code: "lease_quarterly",
    plan_name: "Lease (Quarterly)",
    plan_price_label: "$150",
    amount: "150.00",
    currency: "USD",
    billing_cycle: "quarterly",
  },
  yearly: {
    plan_code: "yearly",
    plan_name: "Yearly Plan",
    plan_price_label: "$300/yr",
    amount: "300.00",
    currency: "USD",
    billing_cycle: "yearly",
  },
};

// ─── Error type for early-exit validation (mirrors PHP jsonResponse(...)) ──────

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

function normalizeMobile(mobile) {
  return cleanValue(mobile).replace(/\s+/g, "");
}

function normalizeCode(code) {
  return String(code === null || code === undefined ? "" : code).trim().toUpperCase();
}

function isValidEmail(email) {
  // Conservative single-address check (parity with FILTER_VALIDATE_EMAIL intent).
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
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

/** Format a mysql2 DATETIME value as a string (parity with PHP row passthrough). */
function formatDbDateTime(val) {
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
    console.error("CLIENT_INVITE_AUDIT_LOG_FAILED:", err?.code || err?.message);
  }
}

// ─── Schema / plan helpers ────────────────────────────────────────────────────

async function tableExists(conn, tableName) {
  const [rows] = await conn.execute(
    `SELECT COUNT(*) AS total
       FROM INFORMATION_SCHEMA.TABLES
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?`,
    [tableName]
  );
  return rows.length > 0 && Number(rows[0].total) > 0;
}

/**
 * Resolve the trusted plan. Future-ready: prefer referral_plans (if present),
 * else fall back to the hard-coded backend plan map. Invalid → ApiError 400.
 */
async function getTrustedPlanByCode(conn, planCodeInput) {
  let planCode = String(planCodeInput === null || planCodeInput === undefined ? "" : planCodeInput)
    .trim()
    .toLowerCase();

  if (planCode === "") planCode = "free_trial";

  if (await tableExists(conn, "referral_plans")) {
    const [rows] = await conn.execute(
      `SELECT
         plan_code,
         plan_name,
         plan_price_label,
         amount,
         currency,
         billing_cycle
       FROM referral_plans
       WHERE plan_code = ?
         AND status = 'active'
       LIMIT 1`,
      [planCode]
    );

    if (rows[0]) {
      const r = rows[0];
      return {
        plan_code: r.plan_code,
        plan_name: r.plan_name,
        plan_price_label: r.plan_price_label,
        amount: r.amount ?? null,
        currency: r.currency ?? null,
        billing_cycle: r.billing_cycle ?? null,
      };
    }
  }

  if (!Object.prototype.hasOwnProperty.call(FALLBACK_PLANS, planCode)) {
    throw new ApiError(400, "Invalid plan_code");
  }

  return FALLBACK_PLANS[planCode];
}

// ─── Actor resolution (token-bound) + allowed codes ───────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. The token carries dietician_id in `sub`; email is derived from the DB.
 * Returns { actor, actorEmail } or throws ApiError.
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
 * Set of trainer/partner codes this actor may invite clients under.
 *   trainer     → own effective code only
 *   admin       → own + child trainers' partner_codes
 *   super_admin → own + child admins' + child trainers' partner_codes
 * Mirrors getAllowedCodesForActor() in the PHP (codes upper-cased + de-duped).
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

function actorCanUseTrainerCode(allowedCodes, trainerCode) {
  const wanted = normalizeCode(trainerCode);
  return allowedCodes.some((code) => normalizeCode(code) === wanted);
}

// ─── Trainer + invite lookups ─────────────────────────────────────────────────

async function getTrainerByCode(conn, trainerCode) {
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
    [trainerCode, trainerCode]
  );
  return rows[0] || null;
}

async function findExistingLatestInvite(conn, trainerId, clientEmail) {
  const [rows] = await conn.execute(
    `SELECT *
       FROM trainer_client_invites
      WHERE UPPER(trainer_id) = UPPER(?)
        AND LOWER(client_email) = LOWER(?)
      ORDER BY id DESC
      LIMIT 1`,
    [trainerId, clientEmail]
  );
  return rows[0] || null;
}

async function hasPendingSamePlan(conn, trainerCode, clientEmail, planCode) {
  const [rows] = await conn.execute(
    `SELECT id, redeem_code, created_at
       FROM trainer_client_plan_subscriptions
      WHERE UPPER(trainer_code) = UPPER(?)
        AND LOWER(client_email) = LOWER(?)
        AND plan_code = ?
        AND status = 'sent'
        AND subscription_status = 'pending'
      ORDER BY id DESC
      LIMIT 1`,
    [trainerCode, clientEmail, planCode]
  );
  return rows[0] || null;
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

// ─── Subscription + invite writes ─────────────────────────────────────────────

async function createPlanSubscription(
  conn,
  sourceInviteId,
  trainerId,
  trainerCode,
  clientName,
  clientMobile,
  clientEmail,
  selectedPlan,
  createdByUserId
) {
  const redeemCode = await generateUniqueRedeemCode(conn);
  const expiresAt = toIstMysqlDateTime(
    new Date(Date.now() + CLIENT_REDEEM_CODE_EXPIRY_DAYS * 24 * 60 * 60 * 1000)
  );
  const paymentStatus = selectedPlan.plan_code === "free_trial" ? "not_required" : "pending";

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
       'Email sending started', ?, NOW(), NOW()
     )`,
    [
      sourceInviteId,
      trainerId,
      trainerCode,
      clientName,
      clientMobile !== "" ? clientMobile : null,
      clientEmail,
      selectedPlan.plan_code,
      selectedPlan.plan_name,
      selectedPlan.plan_price_label,
      redeemCode,
      expiresAt,
      paymentStatus,
      createdByUserId,
    ]
  );

  return {
    subscription_id: Number(result.insertId),
    redeem_code: redeemCode,
    code_expires_at: expiresAt,
    payment_status: paymentStatus,
  };
}

/**
 * Upsert the latest trainer_client_invites row WITHOUT clobbering an already
 * accepted invite. Returns the invite id.
 */
async function insertOrUpdateLatestInviteIfSafe(
  conn,
  existingInvite,
  subscriptionId,
  trainerId,
  trainerCode,
  clientName,
  clientMobile,
  clientEmail,
  selectedPlan
) {
  if (existingInvite) {
    const oldStatus = String(existingInvite.status || "").toLowerCase();
    const acceptedProfileId = cleanValue(existingInvite.accepted_profile_id ?? "");

    if (oldStatus === "accepted" || acceptedProfileId !== "") {
      return Number(existingInvite.id);
    }

    await conn.execute(
      `UPDATE trainer_client_invites
          SET trainer_code = ?,
              client_name = ?,
              client_mobile = ?,
              plan_code = ?,
              plan_name = ?,
              plan_price_label = ?,
              latest_subscription_id = ?,
              status = 'failed',
              email_status = 'failed',
              resend_email_id = NULL,
              error_message = 'Email sending started',
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [
        trainerCode,
        clientName,
        clientMobile !== "" ? clientMobile : null,
        selectedPlan.plan_code,
        selectedPlan.plan_name,
        selectedPlan.plan_price_label,
        subscriptionId,
        Number(existingInvite.id),
      ]
    );

    return Number(existingInvite.id);
  }

  const [result] = await conn.execute(
    `INSERT INTO trainer_client_invites (
       trainer_id,
       trainer_code,
       client_name,
       client_mobile,
       client_email,
       plan_code,
       plan_name,
       plan_price_label,
       latest_subscription_id,
       status,
       email_status,
       resend_email_id,
       error_message,
       created_at,
       updated_at
     )
     VALUES (
       ?, ?, ?, ?, ?, ?, ?, ?, ?,
       'failed', 'failed', NULL, 'Email sending started', NOW(), NOW()
     )`,
    [
      trainerId,
      trainerCode,
      clientName,
      clientMobile !== "" ? clientMobile : null,
      clientEmail,
      selectedPlan.plan_code,
      selectedPlan.plan_name,
      selectedPlan.plan_price_label,
      subscriptionId,
    ]
  );

  return Number(result.insertId);
}

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

async function updateLatestInviteResultIfNotAccepted(
  conn,
  sourceInviteId,
  subscriptionId,
  status,
  emailStatus,
  resendEmailId,
  errorMessage
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

async function sendResendTrainerInviteEmail(
  clientEmail,
  clientName,
  trainerName,
  trainerCode,
  selectedPlan,
  redeemCode,
  codeExpiresAt
) {
  if (RESEND_API_KEY === "") {
    return { success: false, resend_email_id: null, error: "RESEND_API_KEY is not configured" };
  }

  const payload = {
    from: RESEND_FROM_EMAIL,
    to: [clientEmail],
    subject: "You’ve been invited to Respyr",
    reply_to: RESEND_REPLY_TO,
    template: {
      id: RESEND_TEMPLATE_ID,
      variables: {
        CLIENT_NAME: clientName,
        TRAINER_NAME: trainerName,
        TRAINER_CODE: trainerCode,

        REDEEM_CODE: redeemCode,
        CODE_EXPIRES_AT: codeExpiresAt,

        PLAN_CODE: selectedPlan.plan_code,
        PLAN_NAME: selectedPlan.plan_name,
        PLAN_PRICE_LABEL: selectedPlan.plan_price_label,
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
 * POST /dietitian/api/web/send_trainer_client_invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "trainer_id": "RespyrD03",      // required — trainer/partner code
 *     "client_name": "Jane Doe",      // required
 *     "client_mobile": "+15551234567",// optional
 *     "client_email": "jane@x.com",   // required, valid email
 *     "plan_code": "monthly",         // optional, defaults free_trial
 *     "actor_user_id": ""             // optional; if set, must match token email
 *   }
 */
const sendTrainerClientInvite = async (req, res) => {
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
  let actorEmail = null;
  let actorRole = null;
  let trainerCode = null;

  try {
    // ── 0. Required Resend config (was resend_config.php constants) ──────────
    const requiredEnv = {
      RESEND_API_KEY,
      RESEND_FROM_EMAIL,
      RESEND_REPLY_TO,
      RESEND_TEMPLATE_ID,
    };
    for (const [name, value] of Object.entries(requiredEnv)) {
      if (!value) {
        throw new ApiError(500, `${name} is not configured`);
      }
    }

    // ── 1. Parse + validate the payload ──────────────────────────────────────
    const actorUserId    = normalizeEmail(body.actor_user_id ?? "");
    const trainerIdInput = normalizeCode(body.trainer_id ?? "");
    const clientName     = cleanValue(body.client_name ?? "");
    const clientMobile   = normalizeMobile(cleanValue(body.client_mobile ?? ""));
    const clientEmail    = normalizeEmail(body.client_email ?? "");
    const planCode       = cleanValue(body.plan_code ?? "free_trial");

    if (trainerIdInput === "") {
      throw new ApiError(400, "trainer_id is required");
    }
    if (clientName === "") {
      throw new ApiError(400, "client_name is required");
    }
    if (clientEmail === "" || !isValidEmail(clientEmail)) {
      throw new ApiError(400, "Valid client_email is required");
    }
    if (clientMobile !== "" && !/^\+?[0-9]{10,15}$/.test(clientMobile)) {
      throw new ApiError(400, "Invalid client_mobile");
    }

    // ── 2. DB connection (IST session time zone, parity with PHP) ───────────
    conn = await pool.getConnection();
    await conn.query("SET time_zone = '+05:30'");

    const selectedPlan = await getTrustedPlanByCode(conn, planCode);

    // ── 3. Token-bound authorization (closes the PHP IDOR hole) ─────────────
    const resolved = await resolveActorFromToken(conn, req);
    const actor = resolved.actor;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);

    // Optional actor_user_id is cross-checked, never trusted to select a user.
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "client_plan_invite_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: clientEmail,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      throw new ApiError(403, "actor_user_id does not match the authenticated user");
    }

    const allowedCodes = await getAllowedCodesForActor(conn, actor, actorEmail);

    if (!actorCanUseTrainerCode(allowedCodes, trainerIdInput)) {
      await writeAuthLogSafe(req, {
        eventType: "client_plan_invite_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: clientEmail,
        success: false,
        failureReason: "actor not allowed to use this trainer code",
      });
      throw new ApiError(403, "You are not allowed to invite clients using this trainer code");
    }

    // ── 4. Resolve the trainer the invite is sent under ─────────────────────
    const trainer = await getTrainerByCode(conn, trainerIdInput);

    if (!trainer) {
      throw new ApiError(404, "Trainer/admin code not found");
    }
    if (trainer.role_status !== null && trainer.role_status !== undefined &&
        String(trainer.role_status) !== "active") {
      throw new ApiError(403, "Trainer/admin account is not active");
    }

    const trainerId = cleanValue(trainer.dietician_id);
    trainerCode = getEffectiveCode(trainer);
    if (trainerCode === null || String(trainerCode).trim() === "") {
      trainerCode = trainerId;
    }

    let trainerName = cleanValue(trainer.name ?? "");
    if (trainerName === "") trainerName = "Your trainer";

    const trainerRole =
      trainer.role !== null && trainer.role !== undefined ? trainer.role : "trainer";

    const createdByUserId = actorEmail;

    // ── 5. Reject a duplicate pending invite for the same plan ──────────────
    const pendingSamePlan = await hasPendingSamePlan(
      conn,
      trainerCode,
      clientEmail,
      selectedPlan.plan_code
    );

    if (pendingSamePlan) {
      throw new ApiError(409, "This client already has a pending invite for this plan", {
        data: {
          subscription_id: Number(pendingSamePlan.id),
          redeem_code: pendingSamePlan.redeem_code,
          created_at: formatDbDateTime(pendingSamePlan.created_at),
          plan_code: selectedPlan.plan_code,
        },
      });
    }

    // ── 6. Create the subscription/history row first ────────────────────────
    const existingInvite = await findExistingLatestInvite(conn, trainerId, clientEmail);
    let sourceInviteId = existingInvite ? Number(existingInvite.id) : null;

    const subscriptionMeta = await createPlanSubscription(
      conn,
      sourceInviteId,
      trainerId,
      trainerCode,
      clientName,
      clientMobile,
      clientEmail,
      selectedPlan,
      createdByUserId
    );

    const subscriptionId = subscriptionMeta.subscription_id;
    const redeemCode = subscriptionMeta.redeem_code;
    const codeExpiresAt = subscriptionMeta.code_expires_at;
    const paymentStatus = subscriptionMeta.payment_status;

    // ── 7. Upsert the latest invite row (never clobbers an accepted one) ─────
    sourceInviteId = await insertOrUpdateLatestInviteIfSafe(
      conn,
      existingInvite,
      subscriptionId,
      trainerId,
      trainerCode,
      clientName,
      clientMobile,
      clientEmail,
      selectedPlan
    );

    if (sourceInviteId !== null) {
      await conn.execute(
        `UPDATE trainer_client_plan_subscriptions
            SET source_invite_id = ?,
                updated_at = NOW()
          WHERE id = ?
          LIMIT 1`,
        [sourceInviteId, subscriptionId]
      );
    }

    // ── 8. Send the invite email (redeem code + plan details) ───────────────
    const emailResult = await sendResendTrainerInviteEmail(
      clientEmail,
      clientName,
      trainerName,
      trainerCode,
      selectedPlan,
      redeemCode,
      codeExpiresAt
    );

    const inviteStatus = emailResult.success ? "sent" : "failed";
    const emailStatus = emailResult.success ? "sent" : "failed";
    const resendEmailId = emailResult.resend_email_id;
    const errorMessage = emailResult.error;

    await updateSubscriptionResult(
      conn,
      subscriptionId,
      inviteStatus,
      emailStatus,
      resendEmailId,
      errorMessage
    );

    await updateLatestInviteResultIfNotAccepted(
      conn,
      sourceInviteId,
      subscriptionId,
      inviteStatus,
      emailStatus,
      resendEmailId,
      errorMessage
    );

    // ── 9. Audit ─────────────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType: emailResult.success ? "client_plan_invite_sent" : "client_plan_invite_failed",
      userId: createdByUserId,
      role: trainerRole,
      partnerCode: trainerCode,
      identifier: clientEmail,
      success: emailResult.success,
      failureReason: emailResult.success ? "Client plan invite sent" : "Client plan invite failed",
    });

    // ── 10. Respond (matches the PHP JSON shape exactly) ────────────────────
    return res.status(emailResult.success ? 200 : 500).json({
      status: emailResult.success,
      ok: emailResult.success,
      message: emailResult.success
        ? "Invite email sent successfully"
        : "Invite saved but email sending failed",
      data: {
        subscription_id: subscriptionId,
        source_invite_id: sourceInviteId,

        redeem_code: redeemCode,
        code_expires_at: codeExpiresAt,

        trainer_id: trainerId,
        trainer_name: trainerName,
        trainer_code: trainerCode,
        partner_code: trainerCode,

        client_name: clientName,
        client_mobile: clientMobile,
        client_email: clientEmail,

        plan_code: selectedPlan.plan_code,
        plan_name: selectedPlan.plan_name,
        plan_price_label: selectedPlan.plan_price_label,

        subscription_status: "pending",
        payment_status: paymentStatus,

        invite_status: inviteStatus,
        email_status: emailStatus,
        resend_email_id: resendEmailId,
        // VAPT: provider error is suppressed from clients in production.
        error_message: APP_DEBUG ? errorMessage : (emailResult.success ? null : "Email sending failed"),
      },
    });
  } catch (err) {
    if (err instanceof ApiError) {
      return res.status(err.status).json(err.payload);
    }

    console.error("SEND_TRAINER_CLIENT_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "client_plan_invite_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: trainerCode,
      identifier: normalizeEmail(body.client_email ?? ""),
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

module.exports = { sendTrainerClientInvite };
