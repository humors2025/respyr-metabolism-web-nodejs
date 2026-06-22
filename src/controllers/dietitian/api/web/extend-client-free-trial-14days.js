"use strict";

/**
 * extend-client-free-trial-14days.js
 *
 * Converted from: extend-client-free-trial-14days.php
 *                 (+ cors.php / db_connection_pdo.php helpers)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/extend-client-free-trial-14days
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but ONLY for a subscription whose
 *              dietician_id the actor is allowed to use (own code, or a child
 *              trainer's / child admin's code).
 *
 * Behaviour parity with the PHP:
 *  - Target by `client_subscription_id` OR `profile_id`.
 *  - When `client_subscription_id` is supplied we first resolve its profile_id,
 *    then ALWAYS lock + evaluate the LATEST client_subscriptions row for that
 *    profile_id (ORDER BY id DESC ... FOR UPDATE). If the supplied id is not the
 *    latest row → 409 (old-row extension is blocked).
 *  - Latest row must be plan_code = FREE_TRIAL (409 otherwise).
 *  - Cancelled subscriptions cannot be extended (409).
 *  - Existing trial duration must be <= 7 days; it may already be expired (409 if
 *    duration is already > 7 days — i.e. already extended).
 *  - New end date = subscription_start_date + 14 days; current_period_end is set
 *    to match, cancel_at_period_end reset to 0; status becomes 'active' if the new
 *    end is in the future, else 'expired'.
 *  - The reason is stored in app_auth_logs.failure_reason (NOT in the
 *    subscription row), exactly like the PHP.
 *  - Response shape matches the PHP exactly: { status, ok, message, data{...} }.
 *
 * VAPT hardening (beyond the PHP — this is the whole point of the sprint):
 *  - Token-bound identity. The PHP trusted body.actor_user_id to resolve the
 *    actor (a textbook IDOR — anyone could pass another admin's email). Here the
 *    actor is ALWAYS resolved from the verified JWT and re-checked (role + status)
 *    against the DB. body.actor_user_id is still accepted for frontend back-compat
 *    but is only CROSS-CHECKED against the token identity (mismatch → 403); it can
 *    never select another user.
 *  - The target is authorized on the subscription's dietician_id against the
 *    actor's allowed-code set, so a caller can never extend a trial that belongs
 *    to a code they don't own.
 *  - Row lock (SELECT ... FOR UPDATE) inside a transaction prevents an
 *    extend-vs-cancel / double-extend race.
 *  - Every query is fully parameterized (no string interpolation).
 *  - Internal error details are suppressed in production (gated behind APP_DEBUG);
 *    the PHP echoed the exception message/file/line unconditionally (API_DEBUG).
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Every extend / denial / failure is recorded in app_auth_logs.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI/PII in audit logs (the profile_id|dietician_id
 *    identifier, IP, UA) is HMAC-SHA256 hashed with SECURITY_PEPPER — never stored
 *    in clear text.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, client_subscriptions, app_auth_logs.
 */

const crypto = require("crypto");
const pool   = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const DEFAULT_REASON = "Free trial extended to 14 days";
const MAX_REASON_LEN = 1000;     // stored capped; audit column caps again at 255
const MAX_TRIAL_DAYS = 7;        // existing trial must be <= this to qualify
const TARGET_TRIAL_DAYS = 14;    // new total trial length

// IST (Asia/Kolkata, UTC+05:30). The PHP ran date_default_timezone_set('Asia/Kolkata')
// and SET time_zone = '+05:30', so every stored datetime is IST wall-clock.
const IST_OFFSET_MS = (5 * 60 + 30) * 60 * 1000;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// ─── Error type for early-exit validation (mirrors PHP jsonResponse(...); exit) ─

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

/** filter_var(..., FILTER_VALIDATE_EMAIL) intent — conservative single-address check. */
function isValidEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/** Parse a positive integer id, or return null. (PHP (int) cast for our id inputs.) */
function toPositiveInt(value) {
  const n = parseInt(cleanValue(value), 10);
  return Number.isInteger(n) && n > 0 ? n : null;
}

/** @phpparity getEffectiveCode — partner_code, else dietician_id, else null. */
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

// ─── IST wall-clock date helpers (parity with PHP strtotime/date in Asia/Kolkata) ─

/**
 * Parse a stored IST wall-clock datetime ("YYYY-MM-DD HH:MM:SS", "YYYY-MM-DDTHH:MM:SS"
 * or "YYYY-MM-DD") into a "pseudo-UTC" epoch (ms) that holds the same wall-clock
 * fields under the UTC getters. Returns null when unparseable (PHP strtotime===false).
 *
 * Because India observes no DST, day arithmetic on this value is exact and the
 * +05:30 offset cancels out in any wall-clock-to-wall-clock difference.
 */
function parseWallClockMs(value) {
  const str = cleanValue(value);
  if (str === "") return null;

  const dt = str.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/);
  if (dt) {
    return Date.UTC(+dt[1], +dt[2] - 1, +dt[3], +dt[4], +dt[5], +dt[6]);
  }

  const d = str.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (d) {
    return Date.UTC(+d[1], +d[2] - 1, +d[3], 0, 0, 0);
  }

  return null;
}

/** Format a pseudo-UTC epoch (ms) back to "YYYY-MM-DD HH:MM:SS" (MySQL DATETIME). */
function formatWallClock(ms) {
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, "0");
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`
  );
}

/** Current IST wall-clock as a pseudo-UTC epoch (ms) — the frame parseWallClockMs uses. */
function nowWallClockMs() {
  return Date.now() + IST_OFFSET_MS;
}

/**
 * @phpparity daysBetween — ceil((end - start) / 1 day) in whole days, or null when
 * either date is unparseable or end <= start.
 */
function daysBetween(startValue, endValue) {
  const startMs = parseWallClockMs(startValue);
  const endMs = parseWallClockMs(endValue);

  if (startMs === null || endMs === null || endMs <= startMs) {
    return null;
  }

  return Math.ceil((endMs - startMs) / MS_PER_DAY);
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

/**
 * @phpparity writeAuditLog — fail-safe insert into app_auth_logs with hashed
 * identifier/IP/UA. PHP read $_SERVER for IP/UA; here we take them from `req`.
 * Writes are best-effort: a logging failure must never break the request.
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
    console.error("EXTEND_FREE_TRIAL_AUDIT_LOG_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) + allowed codes ───────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. The token carries dietician_id in `sub`; email is derived from the DB.
 * Returns { actor, actorEmail } or throws ApiError. (Mirrors getActorByEmail, but
 * token-bound instead of body-trusted — this is the IDOR the sprint closes.)
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
           td.id, td.dietician_id, td.name, td.phone_no, td.email,
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
           td.id, td.dietician_id, td.name, td.phone_no, td.email,
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
    throw new ApiError(403, "You are not allowed to extend free trial");
  }

  return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
}

/**
 * Set of trainer/partner codes this actor may act on.
 *   trainer     → own effective code only
 *   admin       → own + child trainers' codes
 *   super_admin → own + child admins' + child trainers' codes
 *
 * @phpparity getAllowedCodes — the child-code SELECTs use
 *   COALESCE(NULLIF(aur.partner_code,''), NULLIF(td.dietician_id,''))
 * so a trainer with an empty partner_code is still scoped by their dietician_id
 * (which is exactly how client_subscriptions rows are tagged). Codes are
 * upper-cased + de-duped.
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
      `SELECT COALESCE(NULLIF(aur.partner_code, ''), NULLIF(td.dietician_id, '')) AS code
         FROM app_user_roles aur
         LEFT JOIN table_dietician td
           ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)`,
      [actorEmail]
    );
    for (const row of rows) {
      if (normalizeCode(row.code) !== "") codes.add(normalizeCode(row.code));
    }
    return [...codes];
  }

  if (role === "super_admin") {
    const [rows] = await conn.execute(
      `SELECT COALESCE(NULLIF(aur.partner_code, ''), NULLIF(td.dietician_id, '')) AS code
         FROM app_user_roles aur
         LEFT JOIN table_dietician td
           ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.status = 'active'
          AND (
                (
                    aur.role = 'admin'
                    AND LOWER(aur.parent_user_id) = LOWER(?)
                )
                OR
                (
                    aur.role = 'trainer'
                    AND (
                        LOWER(aur.parent_user_id) = LOWER(?)
                        OR LOWER(aur.parent_user_id) IN (
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
      if (normalizeCode(row.code) !== "") codes.add(normalizeCode(row.code));
    }
    return [...codes];
  }

  return [...codes];
}

/** @phpparity codeAllowed — is this single code in the actor's allowed set? */
function codeAllowed(allowedCodes, code) {
  const wanted = normalizeCode(code);
  if (wanted === "") return false;
  return allowedCodes.some((c) => normalizeCode(c) === wanted);
}

// ─── Target lookups ────────────────────────────────────────────────────────────

/** @phpparity getSubscriptionById — single client_subscriptions row by id. */
async function getSubscriptionById(conn, clientSubscriptionId) {
  const [rows] = await conn.execute(
    `SELECT *
       FROM client_subscriptions
      WHERE id = ?
      LIMIT 1`,
    [clientSubscriptionId]
  );
  return rows[0] || null;
}

/**
 * @phpparity getLatestSubscriptionForUpdateByProfile — the newest
 * client_subscriptions row for a profile_id, row-locked inside the transaction.
 */
async function getLatestSubscriptionForUpdateByProfile(conn, profileId) {
  const [rows] = await conn.execute(
    `SELECT *
       FROM client_subscriptions
      WHERE profile_id = ?
      ORDER BY id DESC
      LIMIT 1
      FOR UPDATE`,
    [profileId]
  );
  return rows[0] || null;
}

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/extend-client-free-trial-14days
 *
 * Headers: Authorization: Bearer <JWT>
 * Body (one target required):
 *   { "actor_user_id": "sagar@respyr.in", "client_subscription_id": 13, "reason": "..." }
 *   { "actor_user_id": "sagar@respyr.in", "profile_id": "profile308", "reason": "..." }
 */
const extendClientFreeTrial14Days = async (req, res) => {
  // HIPAA: never let intermediaries cache subscription responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP REQUEST_METHOD check).
  if (req.method !== "POST") {
    return res
      .status(405)
      .json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};

  let conn = null;
  let inTransaction = false;
  let actorEmail = null;
  let actorRole = null;

  try {
    // ── 1. Parse + validate inputs ───────────────────────────────────────────
    const actorUserId          = normalizeEmail(body.actor_user_id ?? "");
    const clientSubscriptionId = toPositiveInt(body.client_subscription_id);
    let   profileId            = cleanValue(body.profile_id).slice(0, 191);

    const reason = (
      cleanValue(body.reason) !== "" ? cleanValue(body.reason) : DEFAULT_REASON
    ).slice(0, MAX_REASON_LEN);

    // PHP rejected a malformed actor_user_id (422). We keep that validation when a
    // value is supplied, but the value is only ever cross-checked against the
    // token (below) — it can never SELECT the actor.
    if (actorUserId !== "" && !isValidEmail(actorUserId)) {
      throw new ApiError(422, "Valid actor_user_id is required");
    }

    if (!clientSubscriptionId && profileId === "") {
      throw new ApiError(422, "client_subscription_id or profile_id is required");
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
        eventType: "free_trial_extend_denied",
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

    // ── 4. Resolve profile_id from client_subscription_id if needed ──────────
    // (Done before the transaction; mirrors the PHP, which looks up the supplied
    //  row only to learn its profile_id, then locks the latest row for it.)
    if (clientSubscriptionId) {
      const requestedSub = await getSubscriptionById(conn, clientSubscriptionId);
      if (!requestedSub) {
        throw new ApiError(404, "client_subscription_id not found");
      }
      profileId = cleanValue(requestedSub.profile_id);
    }

    // ── 5. Lock + evaluate the LATEST subscription row for this profile ──────
    await conn.beginTransaction();
    inTransaction = true;

    const subscription = await getLatestSubscriptionForUpdateByProfile(conn, profileId);

    if (!subscription) {
      throw new ApiError(404, "Latest subscription not found for this profile_id");
    }

    // If the frontend sent an old subscription id, block old-row extension.
    if (clientSubscriptionId && Number(subscription.id) !== clientSubscriptionId) {
      throw new ApiError(409, "This is not the latest client_subscriptions row for this profile_id", {
        data: {
          requested_client_subscription_id: clientSubscriptionId,
          latest_client_subscription_id: Number(subscription.id),
          latest_plan_code: subscription.plan_code,
          latest_status: subscription.status,
        },
      });
    }

    const subDieticianId = cleanValue(subscription.dietician_id);
    const auditIdentifier = `${cleanValue(subscription.profile_id)}|${subDieticianId}`;

    // ── 6. Scope check — actor must own this subscription's dietician_id ──────
    if (!codeAllowed(allowedCodes, subDieticianId)) {
      await conn.rollback();
      inTransaction = false;
      await writeAuthLogSafe(req, {
        eventType: "free_trial_extend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: auditIdentifier,
        success: false,
        failureReason: `Subscription outside actor scope | ${reason}`,
      });
      throw new ApiError(403, "You are not allowed to extend this client subscription");
    }

    // ── 7. Latest row must be an un-extended, non-cancelled FREE_TRIAL ───────
    if (normalizeCode(subscription.plan_code) !== "FREE_TRIAL") {
      await conn.rollback();
      inTransaction = false;
      await writeAuthLogSafe(req, {
        eventType: "free_trial_extend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: auditIdentifier,
        success: false,
        failureReason: `Latest subscription is not FREE_TRIAL | ${reason}`,
      });
      throw new ApiError(409, "Latest subscription is not FREE_TRIAL", {
        data: {
          latest_client_subscription_id: Number(subscription.id),
          latest_plan_code: subscription.plan_code,
          latest_status: subscription.status,
        },
      });
    }

    const subStatus = cleanValue(subscription.status).toLowerCase();
    if (subStatus === "cancelled" || subStatus === "canceled") {
      await conn.rollback();
      inTransaction = false;
      await writeAuthLogSafe(req, {
        eventType: "free_trial_extend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: auditIdentifier,
        success: false,
        failureReason: `Cancelled subscription cannot be extended | ${reason}`,
      });
      throw new ApiError(409, "Cancelled subscription cannot be extended");
    }

    // ── 8. Date math (IST wall-clock, parity with PHP strtotime/date) ────────
    const startDate = cleanValue(subscription.subscription_start_date);
    if (startDate === "") {
      throw new ApiError(409, "subscription_start_date is missing");
    }

    const startMs = parseWallClockMs(startDate);
    if (startMs === null) {
      throw new ApiError(409, "subscription_start_date is invalid");
    }

    let oldEndDate = cleanValue(subscription.subscription_end_date);
    if (oldEndDate === "") {
      oldEndDate = formatWallClock(startMs + MAX_TRIAL_DAYS * MS_PER_DAY);
    }

    let currentTotalDays = daysBetween(startDate, oldEndDate);
    if (currentTotalDays === null) {
      currentTotalDays = MAX_TRIAL_DAYS;
    }

    // Extend only if the latest FREE_TRIAL is still a <= 7-day trial (may be expired).
    if (currentTotalDays > MAX_TRIAL_DAYS) {
      await conn.rollback();
      inTransaction = false;
      await writeAuthLogSafe(req, {
        eventType: "free_trial_extend_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: getEffectiveCode(actor),
        identifier: auditIdentifier,
        success: false,
        failureReason: `Trial duration already more than 7 days | ${reason}`,
      });
      throw new ApiError(409, "This FREE_TRIAL is already extended or duration is more than 7 days", {
        data: {
          client_subscription_id: Number(subscription.id),
          current_total_days: currentTotalDays,
          max_total_days: TARGET_TRIAL_DAYS,
        },
      });
    }

    const newEndMs = startMs + TARGET_TRIAL_DAYS * MS_PER_DAY;
    const newEndDate = formatWallClock(newEndMs);
    const addedDays = TARGET_TRIAL_DAYS - currentTotalDays;

    // Active if the new end is still in the future (compared in the IST frame), else expired.
    const nowMs = nowWallClockMs();
    const newStatus = newEndMs >= nowMs ? "active" : "expired";

    // ── 9. Apply the extension ───────────────────────────────────────────────
    await conn.execute(
      `UPDATE client_subscriptions
          SET subscription_end_date = ?,
              current_period_end = ?,
              status = ?,
              cancel_at_period_end = 0,
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [newEndDate, newEndDate, newStatus, Number(subscription.id)]
    );

    await conn.commit();
    inTransaction = false;

    // ── 10. Audit (reason is stored ONLY here — app_auth_logs.failure_reason) ─
    const auditReason =
      `Reason: ${reason}` +
      ` | sub_id=${Number(subscription.id)}` +
      ` | profile=${cleanValue(subscription.profile_id)}` +
      ` | old_end=${oldEndDate}` +
      ` | new_end=${newEndDate}` +
      ` | old_days=${currentTotalDays}` +
      ` | new_days=${TARGET_TRIAL_DAYS}`;

    await writeAuthLogSafe(req, {
      eventType: "free_trial_extended_to_14_days",
      userId: actorEmail,
      role: actorRole,
      partnerCode: getEffectiveCode(actor),
      identifier: auditIdentifier,
      success: true,
      failureReason: auditReason,
    });

    const daysRemaining = Math.max(0, Math.ceil((newEndMs - nowMs) / MS_PER_DAY));

    // ── 11. Respond (matches the PHP JSON shape exactly) ─────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "FREE_TRIAL extended to total 14 days successfully",
      data: {
        client_subscription_id: Number(subscription.id),
        profile_id: subscription.profile_id,
        dietitian_id: subscription.dietician_id,
        plan_code: subscription.plan_code,

        old_status: subscription.status,
        new_status: newStatus,

        subscription_start_date: startDate,
        old_subscription_end_date: oldEndDate,
        new_subscription_end_date: newEndDate,

        old_total_days: currentTotalDays,
        new_total_days: TARGET_TRIAL_DAYS,
        added_days: addedDays,
        days_remaining: daysRemaining,

        extended_by_user_id: actorEmail,
        extended_by_role: actorRole,
        reason_saved_in: "app_auth_logs.failure_reason",
        reason: reason,
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

    console.error("EXTEND_FREE_TRIAL_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "free_trial_extend_error",
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

module.exports = { extendClientFreeTrial14Days };
