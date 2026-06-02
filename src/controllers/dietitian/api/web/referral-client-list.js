"use strict";

/**
 * referral-client-list.js
 *
 * Converted from: referral-client-list.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/referral-client-list
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer
 *
 * Behaviour parity with the PHP:
 *  - Resolves the actor's set of allowed trainer/partner codes:
 *      • trainer     → own effective code only,
 *      • admin       → own code + active child trainers' partner_codes,
 *      • super_admin → own code + child admins' codes + those admins' active
 *                       trainers' partner_codes.
 *  - Optional partner_code filter: must be one of the allowed codes (else 403).
 *  - Merges three sources into one list, in this precedence:
 *      1. trainer_client_plan_subscriptions (new plan history),
 *      2. trainer_client_invites not already represented by a subscription
 *         (matched by source_invite_id OR trainer_code|email|plan_code key),
 *      3. legacy table_clients rows with NO matching invite/subscription
 *         (treated as old accepted free clients).
 *  - Sorts the merged list by sent_on_date DESC, computes status counts, then
 *    paginates in memory (page/limit, limit clamped to 1..50, default 10).
 *  - Response shape matches the PHP exactly: { status, ok, message, mode,
 *    actor, filters, summary, pagination, columns, data }.
 *  - Legacy table_clients columns are auto-detected via INFORMATION_SCHEMA
 *    exactly as the PHP did (profile_id/name/phone/email/date fallbacks).
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (dietician_id in `sub`, email fallback) and re-fetched from the DB, with
 *    status + role re-checked server-side. The PHP trusted body.actor_user_id —
 *    an IDOR / cross-tenant read hole. body.actor_user_id is still accepted for
 *    frontend/back-compat but is only cross-checked against the token email
 *    (mismatch → 403); it can never select another user's data.
 *  - Every query is fully parameterized. The dynamic `IN (...)` code lists are
 *    built as `?` placeholders + params, never string-interpolated. The only
 *    identifiers interpolated into SQL are legacy column/order names chosen from
 *    a hardcoded candidate whitelist (never raw user input).
 *  - Internal error details are suppressed in production (gated behind
 *    APP_DEBUG). The PHP shipped with API_DEBUG=true leaking file/line/message.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - PHI in audit logs (identifier, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text.
 *  - Every list view (success, denial, error) is recorded in app_auth_logs.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_plan_subscriptions, trainer_client_invites,
 * table_clients, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 50;

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
  // Mirrors PHP filter_var(FILTER_VALIDATE_EMAIL) closely enough for gating.
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

/**
 * Format a mysql2 DATETIME value as "YYYY-MM-DD HH:MM:SS" (matches the sibling
 * list controllers and the PHP response shape). Accepts Date objects (mysql2
 * default) and strings.
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

/** Numeric sort key from a DATETIME value (Date or string), 0 when missing. */
function toSortTs(val) {
  if (val === null || val === undefined || val === "") return 0;
  if (val instanceof Date) {
    const t = val.getTime();
    return Number.isNaN(t) ? 0 : t;
  }
  const t = Date.parse(String(val).replace(" ", "T"));
  return Number.isNaN(t) ? 0 : t;
}

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
    console.error("REFERRAL_CLIENT_LIST_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT and re-check role/status against
 * the DB. Returns { actor, actorEmail } or { error: { status, message } }.
 *
 * JWT shape: dietician_id in sub/dietician_id; email may be nested under
 * dietician.email. Resolve by dietician_id first, fall back to email, derive
 * actorEmail from the DB row.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
  const tokenEmail = normalizeEmail(
    payload.email || payload.user_id || payload.dietician?.email || ""
  );

  if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
    return { error: { status: 401, message: "Invalid token user" } };
  }

  const selectCols = `
    td.id,
    td.dietician_id,
    td.name,
    td.phone_no,
    td.email,
    td.location,
    td.is_reset_password,
    aur.role,
    aur.partner_code,
    aur.parent_user_id,
    aur.status,
    aur.email_verified_at
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

// ─── Allowed codes ───────────────────────────────────────────────────────────

function addCode(codes, code) {
  const c = normalizeCode(code);
  if (c !== "") codes.set(c, c);
}

/**
 * Resolve the set of trainer/partner codes this actor may view. Mirrors the
 * PHP getAllowedCodes() role branches exactly.
 */
async function getAllowedCodes(actor) {
  const codes = new Map();
  const actorEmail = normalizeEmail(actor.email);
  const role = String(actor.role);

  addCode(codes, getEffectiveCode(actor));

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

/**
 * Restrict the view to a single selected code if requested. Returns
 * { codes } on success, or { forbidden: true } if the selected code is not
 * allowed (caller maps to 403, matching the PHP jsonResponse(403)).
 */
function filterSelectedCode(allowedCodes, selectedCode) {
  const sel = normalizeCode(selectedCode);
  if (sel === "") return { codes: allowedCodes };

  for (const code of allowedCodes) {
    if (normalizeCode(code) === sel) return { codes: [sel] };
  }
  return { forbidden: true };
}

// ─── Source fetches ──────────────────────────────────────────────────────────

/** Build "?,?,?" placeholders and push uppercased codes into params. */
function buildInPlaceholders(codes, params) {
  const placeholders = [];
  for (const code of codes) {
    placeholders.push("?");
    params.push(normalizeCode(code));
  }
  return placeholders.join(",");
}

async function fetchSubscriptionRows(codes) {
  if (codes.length === 0) return [];

  const params = [];
  const inList = buildInPlaceholders(codes, params);

  const [rows] = await pool.execute(
    `
      SELECT
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
        resend_email_id,
        accepted_profile_id,
        accepted_at,
        error_message,
        created_by_user_id,
        created_at,
        updated_at
      FROM trainer_client_plan_subscriptions
      WHERE UPPER(trainer_code) IN (${inList})
         OR UPPER(trainer_id) IN (${inList})
      ORDER BY created_at DESC, id DESC
    `,
    [...params, ...params]
  );

  return rows;
}

async function fetchInviteRows(codes) {
  if (codes.length === 0) return [];

  const params = [];
  const inList = buildInPlaceholders(codes, params);

  const [rows] = await pool.execute(
    `
      SELECT
        id,
        trainer_id,
        trainer_code,
        client_name,
        client_mobile,
        client_email,

        COALESCE(plan_code, 'free_trial') AS plan_code,
        COALESCE(plan_name, 'Free Trial') AS plan_name,
        plan_price_label,
        latest_subscription_id,

        status,
        email_status,
        resend_email_id,
        accepted_profile_id,
        accepted_at,
        error_message,
        created_at,
        updated_at
      FROM trainer_client_invites
      WHERE UPPER(trainer_code) IN (${inList})
         OR UPPER(trainer_id) IN (${inList})
      ORDER BY created_at DESC, id DESC
    `,
    [...params, ...params]
  );

  return rows;
}

// ─── Legacy table_clients (dynamic-column) ───────────────────────────────────

async function tableColumns(tableName) {
  const [rows] = await pool.execute(
    `
      SELECT COLUMN_NAME
      FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?
    `,
    [tableName]
  );
  const cols = {};
  for (const row of rows) cols[row.COLUMN_NAME] = true;
  return cols;
}

/** Return the first candidate that exists as a column, else null. */
function pickColumn(columns, candidates) {
  for (const col of candidates) {
    if (columns[col]) return col;
  }
  return null;
}

/**
 * Fetch legacy table_clients rows that have NO matching invite/subscription —
 * treated as old accepted free clients. Column names are chosen from a
 * hardcoded candidate whitelist (pickColumn), so the identifiers interpolated
 * into the SQL are never raw user input. The code IN-list stays parameterized.
 */
async function fetchLegacyClientRows(codes, knownInviteKeys) {
  if (codes.length === 0) return [];

  const columns = await tableColumns("table_clients");
  if (!columns.dietician_id) return [];

  const profileIdCol = pickColumn(columns, ["profile_id", "id"]);
  const nameCol = pickColumn(columns, ["profile_name", "client_name", "name", "full_name"]);
  const phoneCol = pickColumn(columns, ["phone_no", "mobile", "client_mobile", "phone"]);
  const emailCol = pickColumn(columns, ["email", "client_email"]);
  const dateCol = pickColumn(columns, ["created_at", "date_time", "dttm", "updated_at"]);

  const selectParts = [
    profileIdCol ? `\`${profileIdCol}\` AS profile_id` : "NULL AS profile_id",
    nameCol ? `\`${nameCol}\` AS client_name` : "NULL AS client_name",
    phoneCol ? `\`${phoneCol}\` AS client_mobile` : "NULL AS client_mobile",
    emailCol ? `\`${emailCol}\` AS client_email` : "NULL AS client_email",
    dateCol ? `\`${dateCol}\` AS created_on` : "NULL AS created_on",
    "`dietician_id` AS dietician_id",
  ];

  const orderBy = dateCol ? `\`${dateCol}\` DESC` : "`dietician_id` ASC";

  const params = [];
  const inList = buildInPlaceholders(codes, params);

  const [dbRows] = await pool.execute(
    `
      SELECT ${selectParts.join(", ")}
      FROM table_clients
      WHERE UPPER(dietician_id) IN (${inList})
      ORDER BY ${orderBy}
    `,
    params
  );

  const rows = [];

  for (const row of dbRows) {
    const profileId = cleanValue(row.profile_id);
    const email = normalizeEmail(row.client_email);
    const mobile = cleanValue(row.client_mobile);

    // Core rule: if an invite/subscription already exists for this client,
    // skip it here (it is represented by the other sources).
    let hasInvite = false;
    if (profileId !== "" && knownInviteKeys.has("profile:" + normalizeCode(profileId))) {
      hasInvite = true;
    }
    if (email !== "" && knownInviteKeys.has("email:" + email)) {
      hasInvite = true;
    }
    if (mobile !== "" && knownInviteKeys.has("mobile:" + mobile)) {
      hasInvite = true;
    }
    if (hasInvite) continue;

    rows.push({
      source: "table_clients_legacy",
      subscription_id: null,
      invite_id: null,

      name: row.client_name,
      phone: row.client_mobile,
      email,

      plan: {
        plan_code: "free_trial",
        plan_name: "Free Version",
        plan_price_label: "Free",
      },

      status: "accepted",
      raw_status: "legacy_accepted",

      sent_on_date: toMysqlDateTime(row.created_on),
      accepted_profile_id: profileId !== "" ? profileId : null,
      accepted_at: toMysqlDateTime(row.created_on),

      trainer_id: row.dietician_id,
      trainer_code: row.dietician_id,

      email_status: null,
      resend_email_id: null,
      error_message: null,

      actions: {
        can_resend: false,
        can_revoke: false,
        resend_api: null,
        revoke_api: null,
      },

      created_at: toMysqlDateTime(row.created_on),
      updated_at: null,

      __sortTs: toSortTs(row.created_on),
    });
  }

  return rows;
}

// ─── Row formatting ──────────────────────────────────────────────────────────

function rowStatus(rawStatus, acceptedProfileId) {
  const status = String(rawStatus ?? "").toLowerCase();
  const accepted = cleanValue(acceptedProfileId);

  if (status === "accepted" || accepted !== "") return "accepted";
  if (status === "sent") return "pending";
  if (status === "failed") return "failed";
  if (status === "cancelled") return "cancelled";
  return status !== "" ? status : "pending";
}

function actionForStatus(status) {
  const can = status === "pending" || status === "failed";
  return {
    can_resend: can,
    can_revoke: can,
    resend_api: can ? "resend-client-invite.php" : null,
    revoke_api: can ? "revoke-client-invite.php" : null,
  };
}

function formatSubscriptionRow(row) {
  const status = rowStatus(row.status, row.accepted_profile_id);
  return {
    source: "trainer_client_plan_subscriptions",
    subscription_id: Number(row.id),
    invite_id:
      row.source_invite_id !== null && row.source_invite_id !== undefined
        ? Number(row.source_invite_id)
        : null,

    name: row.client_name,
    phone: row.client_mobile,
    email: normalizeEmail(row.client_email),

    plan: {
      plan_code: row.plan_code,
      plan_name: row.plan_name,
      plan_price_label: row.plan_price_label,
    },

    status,
    raw_status: row.status,

    sent_on_date: toMysqlDateTime(row.created_at),
    accepted_profile_id: row.accepted_profile_id,
    accepted_at: toMysqlDateTime(row.accepted_at),

    trainer_id: row.trainer_id,
    trainer_code: row.trainer_code,

    email_status: row.email_status,
    resend_email_id: row.resend_email_id,
    error_message: row.error_message,

    actions: actionForStatus(status),

    created_at: toMysqlDateTime(row.created_at),
    updated_at: toMysqlDateTime(row.updated_at),

    __sortTs: toSortTs(row.created_at),
  };
}

function formatInviteRow(row) {
  const status = rowStatus(row.status, row.accepted_profile_id);
  return {
    source: "trainer_client_invites",
    subscription_id:
      row.latest_subscription_id !== null && row.latest_subscription_id !== undefined
        ? Number(row.latest_subscription_id)
        : null,
    invite_id: Number(row.id),

    name: row.client_name,
    phone: row.client_mobile,
    email: normalizeEmail(row.client_email),

    plan: {
      plan_code: row.plan_code,
      plan_name: row.plan_name,
      plan_price_label: row.plan_price_label,
    },

    status,
    raw_status: row.status,

    sent_on_date: toMysqlDateTime(row.created_at),
    accepted_profile_id: row.accepted_profile_id,
    accepted_at: toMysqlDateTime(row.accepted_at),

    trainer_id: row.trainer_id,
    trainer_code: row.trainer_code,

    email_status: row.email_status,
    resend_email_id: row.resend_email_id,
    error_message: row.error_message,

    actions: actionForStatus(status),

    created_at: toMysqlDateTime(row.created_at),
    updated_at: toMysqlDateTime(row.updated_at),

    __sortTs: toSortTs(row.created_at),
  };
}

/** Known dedup keys (email / mobile / accepted profile) across both sources. */
function buildKnownKeysFromInvites(inviteRows, subscriptionRows) {
  const keys = new Set();

  const add = (row) => {
    const email = normalizeEmail(row.client_email);
    const mobile = cleanValue(row.client_mobile);
    if (email !== "") keys.add("email:" + email);
    if (mobile !== "") keys.add("mobile:" + mobile);
    if (row.accepted_profile_id) {
      keys.add("profile:" + normalizeCode(row.accepted_profile_id));
    }
  };

  for (const row of inviteRows) add(row);
  for (const row of subscriptionRows) add(row);

  return keys;
}

function statusCounts(rows) {
  const counts = { accepted: 0, pending: 0, failed: 0, cancelled: 0, total: rows.length };
  for (const row of rows) {
    if (
      row.status === "accepted" ||
      row.status === "pending" ||
      row.status === "failed" ||
      row.status === "cancelled"
    ) {
      counts[row.status]++;
    }
  }
  return counts;
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/referral-client-list
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "partner_code": "RESPYRD03",   // optional; must be an allowed code
 *     "page": 1,                     // optional, default 1
 *     "limit": 10,                   // optional, default 10, clamped to 1..50
 *     "actor_user_id": ""            // optional; if set, must match token email
 *   }
 */
const referralClientList = async (req, res) => {
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
  const selectedCode = normalizeCode(body.partner_code);

  let page = Number.parseInt(body.page, 10);
  let limit = Number.parseInt(body.limit, 10);
  if (!Number.isInteger(page) || page <= 0) page = 1;
  if (!Number.isInteger(limit) || limit <= 0 || limit > MAX_LIMIT) limit = DEFAULT_LIMIT;

  // If a frontend sends actor_user_id, it must look like an email (parity with
  // the PHP 422). Identity itself still comes from the token, not this field.
  if (actorUserId !== "" && !isValidEmail(actorUserId)) {
    return res.status(422).json({
      status: false,
      ok: false,
      message: "Valid actor_user_id is required",
    });
  }

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "referral_client_list_denied",
        userId: actorUserId || null,
        role: null,
        partnerCode: null,
        identifier: actorUserId || String(req.user?.sub || ""),
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
        eventType: "referral_client_list_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorUserId,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "actor_user_id does not match the authenticated user",
      });
    }

    // ── 2. Resolve allowed codes + apply optional partner_code filter ───────
    const allowedCodes = await getAllowedCodes(actor);
    const filtered = filterSelectedCode(allowedCodes, selectedCode);

    if (filtered.forbidden) {
      await writeAuthLogSafe(req, {
        eventType: "referral_client_list_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorEmail,
        success: false,
        failureReason: "partner_code not allowed for actor",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "You are not allowed to view this partner code",
      });
    }

    const viewCodes = filtered.codes;

    // ── 3. Fetch the three sources ──────────────────────────────────────────
    const subscriptionRowsRaw = await fetchSubscriptionRows(viewCodes);
    const inviteRowsRaw = await fetchInviteRows(viewCodes);

    const formattedRows = [];

    // 3a. New plan history rows.
    for (const row of subscriptionRowsRaw) {
      formattedRows.push(formatSubscriptionRow(row));
    }

    // 3b. Invite rows not already represented by a subscription.
    const subscriptionInviteIds = new Set();
    const subscriptionKeys = new Set();

    for (const sub of subscriptionRowsRaw) {
      if (sub.source_invite_id) {
        subscriptionInviteIds.add(Number(sub.source_invite_id));
      }
      const key =
        normalizeCode(sub.trainer_code) +
        "|" +
        normalizeEmail(sub.client_email) +
        "|" +
        sub.plan_code;
      subscriptionKeys.add(key);
    }

    for (const row of inviteRowsRaw) {
      const inviteId = Number(row.id);
      const key =
        normalizeCode(row.trainer_code) +
        "|" +
        normalizeEmail(row.client_email) +
        "|" +
        row.plan_code;

      if (subscriptionInviteIds.has(inviteId) || subscriptionKeys.has(key)) {
        continue;
      }
      formattedRows.push(formatInviteRow(row));
    }

    // 3c. Legacy accepted free clients (only when no invite/subscription).
    const knownInviteKeys = buildKnownKeysFromInvites(inviteRowsRaw, subscriptionRowsRaw);
    const legacyRows = await fetchLegacyClientRows(viewCodes, knownInviteKeys);
    for (const legacyRow of legacyRows) {
      formattedRows.push(legacyRow);
    }

    // ── 4. Sort by sent_on_date DESC ────────────────────────────────────────
    formattedRows.sort((a, b) => b.__sortTs - a.__sortTs);

    // ── 5. Counts + pagination ──────────────────────────────────────────────
    const counts = statusCounts(formattedRows);
    const offset = (page - 1) * limit;
    const pagedRows = formattedRows
      .slice(offset, offset + limit)
      .map(({ __sortTs, ...rest }) => rest); // strip internal sort key

    // ── 6. Audit success ────────────────────────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "referral_client_list_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: true,
      failureReason: "Viewed referral client list",
    });

    // ── 7. Respond (matches the PHP JSON shape exactly) ─────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Referral clients fetched successfully",
      mode: "referral_clients",
      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
        parent_user_id: actor.parent_user_id ?? null,
        name: actor.name,
      },
      filters: {
        selected_partner_code: selectedCode !== "" ? selectedCode : null,
        view_codes: viewCodes,
      },
      summary: {
        accepted_count: counts.accepted,
        pending_count: counts.pending,
        failed_count: counts.failed,
        cancelled_count: counts.cancelled,
        total_count: counts.total,
      },
      pagination: {
        page,
        limit,
        offset,
        has_more: offset + limit < counts.total,
      },
      columns: ["name", "phone", "email", "plan", "status", "sent_on_date", "actions"],
      data: pagedRows,
    });
  } catch (err) {
    console.error("REFERRAL_CLIENT_LIST_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "referral_client_list_error",
      userId: actorEmail || actorUserId || null,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail || actorUserId || null,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug: { error: err?.message } }),
    });
  }
};

module.exports = { referralClientList };
