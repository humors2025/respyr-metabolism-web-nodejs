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
 *  - Resolves the actor's set of allowed trainer/partner codes (each code is
 *    COALESCE(NULLIF(partner_code,''), NULLIF(dietician_id,''))):
 *      • trainer     → own effective code only,
 *      • admin       → own code + active child trainers' codes,
 *      • super_admin → own code + child admins' codes + trainers whose parent is
 *                       the super_admin directly OR one of those child admins.
 *  - Optional partner_code filter: must be one of the allowed codes (else 403).
 *  - Merges three sources into one list, in this precedence:
 *      1. trainer_client_plan_subscriptions (new plan history),
 *      2. trainer_client_invites not already represented by a subscription
 *         (matched by source_invite_id OR trainer_code|email|plan_code key),
 *      3. legacy table_clients rows with NO matching invite/subscription
 *         (treated as old accepted free clients).
 *  - redeem_code / referral_code comes ONLY from trainer_client_plan_subscriptions.
 *  - Free-trial extension (extend14days) availability is decided by the LATEST
 *    client_subscriptions row per profile_id: latest plan FREE_TRIAL, not
 *    cancelled, total duration <= 7 days → extension to 14 days available.
 *  - Strict HIPAA scope filter: an accepted row is hidden unless the accepted
 *    client's table_clients.dietician_id is inside the actor's view codes AND
 *    matches the invite/subscription trainer.
 *  - Search (optional): empty allowed; if present requires >= 3 chars (else 422);
 *    matches name / phone / invite email / accepted email / redeem code /
 *    referral code. Applied after merge + sort, before pagination.
 *  - Sorts the merged list by sent_on_date DESC, computes status counts (incl.
 *    extend14days_available_count), then paginates in memory (page/limit, limit
 *    clamped to 1..50, default 10).
 *  - Response shape matches the PHP: { status, ok, message, mode, actor, filters,
 *    summary, pagination, columns, data }.
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
 *  - Production safe: backend API route/filenames are NOT exposed in `actions`.
 *    The frontend maps the boolean flags to internal service calls.
 *  - Internal error details are suppressed in production (gated behind
 *    APP_DEBUG). The PHP shipped with API_DEBUG=true leaking file/line/message.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - PHI in audit logs (identifier, IP, UA) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text.
 *  - Every list view (success, denial, error) is recorded in app_auth_logs.
 *  - Strict scope filter prevents cross-dietician PHI leakage.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_plan_subscriptions, trainer_client_invites,
 * table_clients, client_subscriptions, app_auth_logs.
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
const SEARCH_MIN_LENGTH = 3;
const MS_PER_DAY = 86400000;

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return String(val ?? "").trim().toLowerCase();
}

function normalizeCode(val) {
  return String(val ?? "").trim().toUpperCase();
}

function normalizeSearch(val) {
  return String(val ?? "").trim();
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

/** Parse a DATETIME value (Date or string) into epoch ms, or null when absent/invalid. */
function parseMs(val) {
  if (val === null || val === undefined || val === "") return null;
  if (val instanceof Date) {
    const t = val.getTime();
    return Number.isNaN(t) ? null : t;
  }
  const t = Date.parse(String(val).replace(" ", "T"));
  return Number.isNaN(t) ? null : t;
}

/** Numeric sort key from a DATETIME value (Date or string), 0 when missing. */
function toSortTs(val) {
  const ms = parseMs(val);
  return ms === null ? 0 : ms;
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
 * PHP getAllowedCodes() role branches exactly, including the
 * COALESCE(NULLIF(partner_code,''), NULLIF(td.dietician_id,'')) fallback so a
 * trainer with no partner_code still resolves to their dietician_id.
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
        SELECT COALESCE(NULLIF(aur.partner_code, ''), NULLIF(td.dietician_id, '')) AS code
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
      `,
      [actorEmail]
    );
    for (const row of childRows) addCode(codes, row.code);
    return [...codes.values()];
  }

  if (role === "super_admin") {
    const [rows] = await pool.execute(
      `
        SELECT COALESCE(NULLIF(aur.partner_code, ''), NULLIF(td.dietician_id, '')) AS code
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
          )
      `,
      [actorEmail, actorEmail, actorEmail]
    );
    for (const row of rows) addCode(codes, row.code);
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

// The latest client_subscriptions row per profile_id decides extension
// availability. It is NOT filtered by plan_code — the latest row wins.
const CLIENT_SUBSCRIPTION_SELECT = `
  cs.id                   AS client_subscription_id,
  cs.dietician_id         AS client_subscription_dietician_id,
  cs.profile_id           AS client_subscription_profile_id,
  cs.plan_code            AS client_subscription_plan_code,
  cs.plan_name            AS client_subscription_plan_name,
  cs.status               AS client_subscription_status,
  cs.subscription_start_date   AS client_subscription_start_date,
  cs.subscription_end_date     AS client_subscription_end_date,
  cs.current_period_end        AS client_subscription_current_period_end,
  cs.created_at           AS client_subscription_created_at,
  cs.updated_at           AS client_subscription_updated_at
`;

async function fetchSubscriptionRows(codes) {
  if (codes.length === 0) return [];

  // Safe if the redeem_code column does not exist yet (parity with the PHP,
  // which probed INFORMATION_SCHEMA before selecting it).
  const subscriptionCols = await tableColumns("trainer_client_plan_subscriptions");
  const redeemCodeSelect = subscriptionCols.redeem_code
    ? "s.redeem_code"
    : "NULL AS redeem_code";

  const params = [];
  const inList = buildInPlaceholders(codes, params);

  const [rows] = await pool.execute(
    `
      SELECT
        s.id,
        s.source_invite_id,
        s.trainer_id,
        s.trainer_code,
        ${redeemCodeSelect},
        s.client_name,
        s.client_mobile,
        s.client_email,
        s.plan_code,
        s.plan_name,
        s.plan_price_label,
        s.status,
        s.email_status,
        s.resend_email_id,
        s.accepted_profile_id,
        s.accepted_at,
        s.error_message,
        s.created_by_user_id,
        s.created_at,
        s.updated_at,

        tc.profile_id   AS mapped_accepted_profile_id,
        tc.profile_name AS accepted_client_name,
        tc.phone_no     AS accepted_client_phone,
        tc.email        AS accepted_client_email,
        tc.dietician_id AS accepted_client_dietician_id,
        tc.dttm         AS accepted_client_joined_at,

        ${CLIENT_SUBSCRIPTION_SELECT}
      FROM trainer_client_plan_subscriptions s

      LEFT JOIN table_clients tc
        ON tc.profile_id = s.accepted_profile_id
       AND (
            UPPER(tc.dietician_id) = UPPER(s.trainer_code)
         OR UPPER(tc.dietician_id) = UPPER(s.trainer_id)
       )

      LEFT JOIN client_subscriptions cs
        ON cs.id = (
            SELECT cs1.id
            FROM client_subscriptions cs1
            WHERE cs1.profile_id = s.accepted_profile_id
            ORDER BY cs1.id DESC
            LIMIT 1
        )

      WHERE UPPER(s.trainer_code) IN (${inList})
         OR UPPER(s.trainer_id) IN (${inList})
      ORDER BY s.created_at DESC, s.id DESC
    `,
    [...params, ...params]
  );

  return rows;
}

async function fetchInviteRows(codes) {
  if (codes.length === 0) return [];

  // redeem_code for invite rows can only come from the linked subscription
  // (direct latest_subscription_id, else the most recent source_invite_id row).
  // Return NULL if the subscription table has no redeem_code column yet.
  const subscriptionCols = await tableColumns("trainer_client_plan_subscriptions");
  const subscriptionRedeemSelect = subscriptionCols.redeem_code
    ? "COALESCE(ps_direct.redeem_code, ps_latest.redeem_code) AS subscription_redeem_code"
    : "NULL AS subscription_redeem_code";

  const params = [];
  const inList = buildInPlaceholders(codes, params);

  const [rows] = await pool.execute(
    `
      SELECT
        i.id,
        i.trainer_id,
        i.trainer_code,
        i.client_name,
        i.client_mobile,
        i.client_email,

        COALESCE(i.plan_code, 'free_trial') AS plan_code,
        COALESCE(i.plan_name, 'Free Trial') AS plan_name,
        i.plan_price_label,
        i.latest_subscription_id,

        i.status,
        i.email_status,
        i.resend_email_id,
        i.accepted_profile_id,
        i.accepted_at,
        i.error_message,
        i.created_at,
        i.updated_at,

        ${subscriptionRedeemSelect},

        tc.profile_id   AS mapped_accepted_profile_id,
        tc.profile_name AS accepted_client_name,
        tc.phone_no     AS accepted_client_phone,
        tc.email        AS accepted_client_email,
        tc.dietician_id AS accepted_client_dietician_id,
        tc.dttm         AS accepted_client_joined_at,

        ${CLIENT_SUBSCRIPTION_SELECT}
      FROM trainer_client_invites i

      LEFT JOIN trainer_client_plan_subscriptions ps_direct
        ON ps_direct.id = i.latest_subscription_id

      LEFT JOIN (
        SELECT source_invite_id, MAX(id) AS latest_id
        FROM trainer_client_plan_subscriptions
        WHERE source_invite_id IS NOT NULL
        GROUP BY source_invite_id
      ) latest_sub
        ON latest_sub.source_invite_id = i.id

      LEFT JOIN trainer_client_plan_subscriptions ps_latest
        ON ps_latest.id = latest_sub.latest_id

      LEFT JOIN table_clients tc
        ON tc.profile_id = i.accepted_profile_id
       AND (
            UPPER(tc.dietician_id) = UPPER(i.trainer_code)
         OR UPPER(tc.dietician_id) = UPPER(i.trainer_id)
       )

      LEFT JOIN client_subscriptions cs
        ON cs.id = (
            SELECT cs1.id
            FROM client_subscriptions cs1
            WHERE cs1.profile_id = i.accepted_profile_id
            ORDER BY cs1.id DESC
            LIMIT 1
        )

      WHERE UPPER(i.trainer_code) IN (${inList})
         OR UPPER(i.trainer_id) IN (${inList})
      ORDER BY i.created_at DESC, i.id DESC
    `,
    [...params, ...params]
  );

  return rows;
}

/** Latest client_subscriptions row for a profile_id, aliased like the joins above. */
async function getLatestClientSubscriptionByProfile(profileId) {
  const pid = cleanValue(profileId);
  if (pid === "") return {};

  const [rows] = await pool.execute(
    `
      SELECT
        id                     AS client_subscription_id,
        dietician_id           AS client_subscription_dietician_id,
        profile_id             AS client_subscription_profile_id,
        plan_code              AS client_subscription_plan_code,
        plan_name              AS client_subscription_plan_name,
        status                 AS client_subscription_status,
        subscription_start_date AS client_subscription_start_date,
        subscription_end_date   AS client_subscription_end_date,
        current_period_end      AS client_subscription_current_period_end,
        created_at             AS client_subscription_created_at,
        updated_at             AS client_subscription_updated_at
      FROM client_subscriptions
      WHERE profile_id = ?
      ORDER BY id DESC
      LIMIT 1
    `,
    [pid]
  );

  return rows[0] || {};
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

    // Latest client_subscriptions row decides extension availability.
    const subscriptionRow = await getLatestClientSubscriptionByProfile(profileId);
    const freeTrialInfo = freeTrialSubscriptionInfo(subscriptionRow);
    const statusMeta = statusLabelFromRow("accepted", freeTrialInfo);

    rows.push({
      source: "table_clients_legacy",
      subscription_id: null,
      invite_id: null,

      name: row.client_name,
      phone: row.client_mobile,
      email,

      // Legacy rows have no subscription, hence no redeem code.
      redeem_code: null,
      referral_code: null,

      plan: {
        plan_code: "free_trial",
        plan_name: "Free Trial",
        plan_price_label: "Free",
      },

      status: "accepted",
      raw_status: "legacy_accepted",
      status_code: statusMeta.status_code,
      status_label: statusMeta.status_label,

      sent_on_date: toMysqlDateTime(row.created_on),
      accepted_profile_id: profileId !== "" ? profileId : null,
      accepted_at: toMysqlDateTime(row.created_on),

      accepted_email: email,
      accepted_client: {
        profile_id: profileId !== "" ? profileId : null,
        name: row.client_name,
        phone: row.client_mobile,
        email,
        dietician_id: row.dietician_id,
        joined_at: toMysqlDateTime(row.created_on),
        matched_by: "table_clients_legacy",
      },

      trainer_id: row.dietician_id,
      trainer_code: row.dietician_id,

      extend14days_available: freeTrialInfo.extend14days_available,
      free_trial_subscription: freeTrialInfo,

      email_status: null,
      resend_email_id: null,
      error_message: null,

      actions: {
        can_resend: false,
        can_revoke: false,
        can_extend_14_days: freeTrialInfo.extend14days_available,
      },

      created_at: toMysqlDateTime(row.created_on),
      updated_at: null,

      __sortTs: toSortTs(row.created_on),
    });
  }

  return rows;
}

// ─── Row formatting ──────────────────────────────────────────────────────────

function rowStatus(rawStatus, acceptedProfileId, mappedAcceptedProfileId = null) {
  const status = String(rawStatus ?? "").toLowerCase();
  const accepted = cleanValue(acceptedProfileId);
  const mapped = cleanValue(mappedAcceptedProfileId);

  if (status === "accepted" || accepted !== "" || mapped !== "") return "accepted";
  if (status === "sent") return "pending";
  if (status === "failed") return "failed";
  if (status === "cancelled" || status === "canceled") return "cancelled";
  return status !== "" ? status : "pending";
}

/**
 * Production safe: do NOT expose backend API filenames/routes in the response.
 * The frontend maps these boolean flags to internal service calls.
 */
function actionForStatus(status) {
  const can = status === "pending" || status === "failed";
  return {
    can_resend: can,
    can_revoke: can,
  };
}

/**
 * Strict rule (parity with the PHP getRedeemCodeFromRow): redeem_code may only
 * come from trainer_client_plan_subscriptions. Subscription rows expose it as
 * `redeem_code`; invite rows as `subscription_redeem_code` (from the linked
 * subscription). Never trainer_code. Legacy rows have none.
 */
function getRedeemCodeFromRow(row) {
  if (row.redeem_code !== undefined && cleanValue(row.redeem_code) !== "") {
    return cleanValue(row.redeem_code);
  }
  if (
    row.subscription_redeem_code !== undefined &&
    cleanValue(row.subscription_redeem_code) !== ""
  ) {
    return cleanValue(row.subscription_redeem_code);
  }
  return null;
}

/**
 * Build the accepted-client object from the table_clients LEFT JOIN, mapping
 * accepted_profile_id -> table_clients.profile_id (parity with the PHP).
 * Returns null when neither the raw nor the mapped profile id is present.
 */
function acceptedClientFromRow(row) {
  const acceptedProfileId =
    row.accepted_profile_id !== undefined ? cleanValue(row.accepted_profile_id) : "";
  const mappedProfileId =
    row.mapped_accepted_profile_id !== undefined
      ? cleanValue(row.mapped_accepted_profile_id)
      : "";

  if (acceptedProfileId === "" && mappedProfileId === "") return null;

  return {
    profile_id: mappedProfileId !== "" ? mappedProfileId : acceptedProfileId,
    name: row.accepted_client_name ?? null,
    phone: row.accepted_client_phone ?? null,
    email:
      row.accepted_client_email !== undefined && row.accepted_client_email !== null
        ? normalizeEmail(row.accepted_client_email)
        : null,
    dietician_id: row.accepted_client_dietician_id ?? null,
    joined_at: toMysqlDateTime(row.accepted_client_joined_at),
    matched_by: "accepted_profile_id",
  };
}

/** Whole-day difference between two DATETIME values (ceil), or null. */
function daysBetween(startVal, endVal) {
  const startTs = parseMs(startVal);
  const endTs = parseMs(endVal);
  if (startTs === null || endTs === null || endTs <= startTs) return null;
  return Math.ceil((endTs - startTs) / MS_PER_DAY);
}

/**
 * Free-trial extension availability from the LATEST client_subscriptions row.
 * Rule: latest plan FREE_TRIAL, not cancelled, total duration <= 7 days →
 * extension to 14 days is available (even if the 7 days already expired).
 * Parity with the PHP freeTrialSubscriptionInfo().
 */
function freeTrialSubscriptionInfo(row) {
  const subscriptionId =
    row.client_subscription_id !== null && row.client_subscription_id !== undefined
      ? Number(row.client_subscription_id)
      : null;

  if (!subscriptionId) {
    return {
      exists: false,
      subscription_id: null,
      latest_plan_code: null,
      latest_status: null,
      latest_subscription_start_date: null,
      latest_subscription_end_date: null,
      current_period_end: null,
      trial_total_days: null,
      days_remaining: null,
      extend14days_available: false,
      extend_to_total_days: 14,
      message: "No latest client_subscriptions row found",
    };
  }

  const planCode = normalizeCode(row.client_subscription_plan_code); // trim + upper
  const status = String(cleanValue(row.client_subscription_status)).toLowerCase();

  const startRaw = row.client_subscription_start_date ?? null;
  const endRaw = row.client_subscription_end_date ?? null;
  const cpeRaw = row.client_subscription_current_period_end ?? null;

  const startMs = parseMs(startRaw);
  const endMs = parseMs(endRaw);

  const trialTotalDays =
    startMs !== null && endMs !== null ? daysBetween(startRaw, endRaw) : null;

  const daysRemaining =
    endMs !== null ? Math.max(0, Math.ceil((endMs - Date.now()) / MS_PER_DAY)) : null;

  const isFreeTrial = planCode === "FREE_TRIAL";
  const notCancelled = status !== "cancelled" && status !== "canceled";

  const extendAvailable =
    isFreeTrial && notCancelled && trialTotalDays !== null && trialTotalDays <= 7;

  let message;
  if (extendAvailable) {
    message = "extend14days available";
  } else if (!isFreeTrial) {
    message = "Latest subscription is not FREE_TRIAL";
  } else if (!notCancelled) {
    message = "Cancelled subscription cannot be extended";
  } else if (trialTotalDays !== null && trialTotalDays > 7) {
    message = "Already extended or trial duration is more than 7 days";
  } else {
    message = "extend14days not available";
  }

  return {
    exists: true,
    subscription_id: subscriptionId,
    latest_plan_code: planCode,
    latest_status: status,
    latest_subscription_start_date: startMs !== null ? toMysqlDateTime(startRaw) : null,
    latest_subscription_end_date: endMs !== null ? toMysqlDateTime(endRaw) : null,
    current_period_end: parseMs(cpeRaw) !== null ? toMysqlDateTime(cpeRaw) : null,
    trial_total_days: trialTotalDays,
    days_remaining: daysRemaining,
    extend14days_available: extendAvailable,
    extend_to_total_days: 14,
    message,
  };
}

/** Status code + human label, factoring in the trial state. Parity with PHP. */
function statusLabelFromRow(status, freeTrialInfo) {
  if (status === "cancelled") {
    return { status_code: "cancelled", status_label: "Cancelled" };
  }
  if (status === "failed") {
    return { status_code: "failed", status_label: "Failed" };
  }

  if (freeTrialInfo.exists && freeTrialInfo.latest_plan_code === "FREE_TRIAL") {
    const daysRemaining = freeTrialInfo.days_remaining;
    if (daysRemaining !== null && daysRemaining > 0) {
      return {
        status_code: "trial_active",
        status_label:
          daysRemaining === 1 ? "1 day remaining" : `${daysRemaining} days remaining`,
      };
    }
    return { status_code: "trial_expired", status_label: "Expired" };
  }

  if (status === "accepted") {
    return { status_code: "accepted", status_label: "Accepted" };
  }
  if (status === "pending") {
    return { status_code: "pending", status_label: "Pending" };
  }

  const label = status ? status.charAt(0).toUpperCase() + status.slice(1) : "";
  return { status_code: status, status_label: label };
}

function formatSubscriptionRow(row) {
  const acceptedClient = acceptedClientFromRow(row);
  const status = rowStatus(
    row.status,
    row.accepted_profile_id,
    row.mapped_accepted_profile_id
  );

  const freeTrialInfo = freeTrialSubscriptionInfo(row);
  const statusMeta = statusLabelFromRow(status, freeTrialInfo);
  const referralCode = getRedeemCodeFromRow(row);

  const actions = actionForStatus(status);
  actions.can_extend_14_days = freeTrialInfo.extend14days_available;

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

    // New fields; intentionally NOT added to `columns` to avoid a UI break.
    redeem_code: referralCode,
    referral_code: referralCode,

    plan: {
      plan_code: row.plan_code,
      plan_name: row.plan_name,
      plan_price_label: row.plan_price_label,
    },

    status,
    raw_status: row.status,
    status_code: statusMeta.status_code,
    status_label: statusMeta.status_label,

    sent_on_date: toMysqlDateTime(row.created_at),
    accepted_profile_id: row.accepted_profile_id,
    accepted_at: toMysqlDateTime(row.accepted_at),

    // New mapped fields (from the table_clients join); not in `columns`.
    accepted_email: acceptedClient ? acceptedClient.email : null,
    accepted_client: acceptedClient,

    trainer_id: row.trainer_id,
    trainer_code: row.trainer_code,

    extend14days_available: freeTrialInfo.extend14days_available,
    free_trial_subscription: freeTrialInfo,

    email_status: row.email_status,
    resend_email_id: row.resend_email_id,
    error_message: row.error_message,

    actions,

    created_at: toMysqlDateTime(row.created_at),
    updated_at: toMysqlDateTime(row.updated_at),

    __sortTs: toSortTs(row.created_at),
  };
}

function formatInviteRow(row) {
  const acceptedClient = acceptedClientFromRow(row);
  const status = rowStatus(
    row.status,
    row.accepted_profile_id,
    row.mapped_accepted_profile_id
  );

  const freeTrialInfo = freeTrialSubscriptionInfo(row);
  const statusMeta = statusLabelFromRow(status, freeTrialInfo);
  const referralCode = getRedeemCodeFromRow(row);

  const actions = actionForStatus(status);
  actions.can_extend_14_days = freeTrialInfo.extend14days_available;

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

    // Null unless the linked subscription has a redeem_code. Never trainer_code.
    redeem_code: referralCode,
    referral_code: referralCode,

    plan: {
      plan_code: row.plan_code,
      plan_name: row.plan_name,
      plan_price_label: row.plan_price_label,
    },

    status,
    raw_status: row.status,
    status_code: statusMeta.status_code,
    status_label: statusMeta.status_label,

    sent_on_date: toMysqlDateTime(row.created_at),
    accepted_profile_id: row.accepted_profile_id,
    accepted_at: toMysqlDateTime(row.accepted_at),

    // New mapped fields (from the table_clients join); not in `columns`.
    accepted_email: acceptedClient ? acceptedClient.email : null,
    accepted_client: acceptedClient,

    trainer_id: row.trainer_id,
    trainer_code: row.trainer_code,

    extend14days_available: freeTrialInfo.extend14days_available,
    free_trial_subscription: freeTrialInfo,

    email_status: row.email_status,
    resend_email_id: row.resend_email_id,
    error_message: row.error_message,

    actions,

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
    if (row.mapped_accepted_profile_id) {
      keys.add("profile:" + normalizeCode(row.mapped_accepted_profile_id));
    }
  };

  for (const row of inviteRows) add(row);
  for (const row of subscriptionRows) add(row);

  return keys;
}

// ─── Strict HIPAA scope filter ───────────────────────────────────────────────

/** True if `value` (normalized) is one of the allowed codes. */
function codeInList(codes, value) {
  const v = normalizeCode(value);
  if (v === "") return false;
  for (const code of codes) {
    if (normalizeCode(code) === v) return true;
  }
  return false;
}

/**
 * A row is visible only if it belongs to the actor's view codes AND, when
 * accepted, the accepted client's table_clients.dietician_id is also inside the
 * view codes and matches this invite/subscription trainer. Prevents showing an
 * accepted profile that actually belongs to another dietician (HIPAA).
 * Parity with the PHP rowPassesStrictScope().
 */
function rowPassesStrictScope(row, viewCodes) {
  const trainerId = row.trainer_id ?? "";
  const trainerCode = row.trainer_code ?? "";

  // Row must belong to actor allowed codes.
  if (!codeInList(viewCodes, trainerId) && !codeInList(viewCodes, trainerCode)) {
    return false;
  }

  const acceptedProfileId =
    row.accepted_profile_id !== undefined ? cleanValue(row.accepted_profile_id) : "";

  // Pending/failed invite has no accepted profile yet → allowed (trainer matched).
  if (acceptedProfileId === "") return true;

  // Accepted row must have a matching accepted_client from table_clients.
  if (!row.accepted_client || typeof row.accepted_client !== "object") {
    return false;
  }

  const clientDieticianId = row.accepted_client.dietician_id ?? "";

  // Accepted client's dietician_id must be inside actor view codes...
  if (!codeInList(viewCodes, clientDieticianId)) return false;

  // ...and must match this invite/subscription trainer_id or trainer_code.
  if (!codeInList([trainerId, trainerCode], clientDieticianId)) return false;

  return true;
}

function applyStrictScopeFilter(rows, viewCodes) {
  return rows.filter((row) => rowPassesStrictScope(row, viewCodes));
}

// ─── Search ──────────────────────────────────────────────────────────────────

/**
 * Filter by name / phone / invite email / accepted email / redeem code /
 * referral code. Assumes the search length was already validated (>= 3) by the
 * controller; an empty search returns the rows unchanged.
 */
function applySearchFilter(rows, search) {
  const s = normalizeSearch(search);
  if (s === "") return rows;

  const needle = s.toLowerCase();

  return rows.filter((row) => {
    const haystack = [
      row.name ?? "",
      row.phone ?? "",
      row.email ?? "",
      row.accepted_email ?? "",
      row.redeem_code ?? "",
      row.referral_code ?? "",
    ]
      .join(" ")
      .toLowerCase();

    return haystack.indexOf(needle) !== -1;
  });
}

function statusCounts(rows) {
  const counts = {
    accepted: 0,
    pending: 0,
    failed: 0,
    cancelled: 0,
    total: rows.length,
    extend14days_available_count: 0,
  };
  for (const row of rows) {
    if (
      row.status === "accepted" ||
      row.status === "pending" ||
      row.status === "failed" ||
      row.status === "cancelled"
    ) {
      counts[row.status]++;
    }
    if (row.extend14days_available) {
      counts.extend14days_available_count++;
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
 *     "search": "ank",               // optional; if set, >= 3 chars
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
  const search = normalizeSearch(body.search);

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

  // Validate search before running heavy queries (empty search is fine).
  if (search !== "" && search.length < SEARCH_MIN_LENGTH) {
    return res.status(422).json({
      status: false,
      ok: false,
      message: "Search must be at least 3 characters",
      search_min_length: SEARCH_MIN_LENGTH,
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

    // ── 4. Strict HIPAA/scope filter ────────────────────────────────────────
    let rows = applyStrictScopeFilter(formattedRows, viewCodes);

    // ── 5. Sort by sent_on_date DESC ────────────────────────────────────────
    rows.sort((a, b) => b.__sortTs - a.__sortTs);

    // ── 6. Search (after merge + sort, before pagination) ───────────────────
    rows = applySearchFilter(rows, search);

    // ── 7. Counts + pagination ──────────────────────────────────────────────
    const counts = statusCounts(rows);
    const offset = (page - 1) * limit;
    const pagedRows = rows
      .slice(offset, offset + limit)
      .map(({ __sortTs, ...rest }) => rest); // strip internal sort key

    // ── 8. Audit success ────────────────────────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "referral_client_list_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: true,
      failureReason: "Viewed referral client list",
    });

    // ── 9. Respond (matches the PHP JSON shape) ─────────────────────────────
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
        search,
        search_min_length: SEARCH_MIN_LENGTH,
        view_codes: viewCodes,
      },
      summary: {
        accepted_count: counts.accepted,
        pending_count: counts.pending,
        failed_count: counts.failed,
        cancelled_count: counts.cancelled,
        extend14days_available_count: counts.extend14days_available_count,
        total_count: counts.total,
      },
      pagination: {
        page,
        limit,
        offset,
        total: counts.total,
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
