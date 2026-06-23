"use strict";

/**
 * trainer-sales-analytics.js
 *
 * Converted from: trainer-sales-analytics.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/trainer-sales-analytics
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : trainer | admin | super_admin
 *
 * Behaviour parity with the PHP:
 *  - Latest client_subscriptions row per profile_id within a partner_code is used
 *    (INNER JOIN on MAX(id) per profile_id).
 *  - active / expired / attention_for_renewal / upcoming are derived from
 *    subscription_start_date and subscription_end_date — NOT from cs.status.
 *  - Free-trial plans are excluded.
 *  - Payments are matched by Stripe subscription id (strong) or, when missing,
 *    by plan_code within the subscription window (fallback), then aggregated.
 *  - purchase_filter periods (this_month / last_month / last_3_months / yearly /
 *    custom / all) computed in IST, exactly like the PHP DateTime maths.
 *  - allowed-codes scoping per role:
 *      trainer     → own effective code only
 *      admin       → own + active trainers parented to the actor
 *      super_admin → all active super_admin/admin/trainer codes
 *  - Response keys/shape match the PHP (status, ok, message, mode, actor,
 *    filters, summary, tab_counts, pagination, search_options, data) and the
 *    same per-row structure (client / subscription / payment blocks).
 *  - Same DB tables only: table_dietician, app_user_roles, client_subscriptions,
 *    payments, table_clients (plus app_auth_logs for the audit trail).
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (sub = dietician_id) and re-checked against the DB on every call. The PHP
 *    trusted body.actor_id, which let any caller read another tenant's sales
 *    (IDOR / privilege escalation). body.actor_id is still accepted for
 *    frontend/back-compat, but it is only cross-checked against the token email
 *    (mismatch → 403); it can never select a different user.
 *  - Every reused PHP named param (:now_ts, :search, :partner_code …) becomes an
 *    ordered positional placeholder with a bound value. No string interpolation;
 *    only validated integers (renewal_days, LIMIT, OFFSET) are inlined.
 *  - LIKE wildcards in the search term are escaped before binding.
 *  - Internal error details are suppressed in production (gated behind APP_DEBUG).
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI never logged to server logs.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - IST (Asia/Kolkata) preserved: a dedicated connection runs
 *    SET time_zone = '+05:30' so DATE_ADD / DATEDIFF match the PHP output.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;

const PURCHASE_FILTERS = [
  "this_month",
  "last_month",
  "last_3_months",
  "yearly",
  "custom",
  "all",
];

const PURCHASE_FILTER_ALIASES = {
  current_month: "this_month",
  month: "this_month",
  last_3_month: "last_3_months",
  "3_months": "last_3_months",
  three_months: "last_3_months",
  this_year: "yearly",
  year: "yearly",
};

const USER_STATES = [
  "all",
  "active",
  "expired",
  "attention_for_renewal",
  "upcoming",
];

const USER_STATE_ALIASES = {
  renewal: "attention_for_renewal",
  attention: "attention_for_renewal",
  renewal_attention: "attention_for_renewal",
  expiring: "attention_for_renewal",
  expired_user: "expired",
  active_user: "active",
};

const SEARCHABLE_FIELDS = [
  "profile_id",
  "client_id",
  "client_name",
  "client_email",
  "client_phone",
  "plan_code",
  "plan_name",
  "stripe_subscription_id",
  "stripe_customer_id",
  "stripe_payment_intent_id",
  "session_id",
  "coupon_code",
];

// ─── Generic helpers ─────────────────────────────────────────────────────────

function cleanValue(val) {
  return String(val === null || val === undefined ? "" : val).trim();
}

function normalizeEmail(val) {
  return cleanValue(val).toLowerCase();
}

function normalizeCode(val) {
  return cleanValue(val).toUpperCase();
}

function toIntOrNull(val) {
  if (val === null || val === undefined || val === "") return null;
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : null;
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

function isEmail(val) {
  // Conservative RFC-ish check; mirrors PHP FILTER_VALIDATE_EMAIL intent.
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val);
}

/** PHP minor_to_major(): cents → major units, 2 dp. */
function minorToMajor(minor) {
  return Math.round((toInt(minor) / 100) * 100) / 100;
}

/** Escape LIKE wildcards so user input can't widen the match. */
function escapeLike(value) {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

/** Format a mysql2 DATETIME (Date or string) as "YYYY-MM-DD HH:MM:SS". */
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

/** PHP get_effective_code($row): partner_code, else dietician_id, else null. */
function getEffectiveCode(row) {
  if (row.partner_code !== null && row.partner_code !== undefined &&
      cleanValue(row.partner_code) !== "") {
    return String(row.partner_code);
  }
  if (row.dietician_id !== null && row.dietician_id !== undefined &&
      cleanValue(row.dietician_id) !== "") {
    return String(row.dietician_id);
  }
  return null;
}

// ─── IST date helpers (PHP date_default_timezone_set('Asia/Kolkata')) ──────────

/** A Date whose UTC fields read as IST wall-clock — read with getUTC*(). */
function istNow() {
  return new Date(Date.now() + IST_OFFSET_MS);
}

function fmtIstParts(y, mZeroBased, d, hh = 0, mm = 0, ss = 0) {
  const pad = (n) => String(n).padStart(2, "0");
  // Normalise overflow (e.g. month 12) via Date.UTC.
  const t = new Date(Date.UTC(y, mZeroBased, d, hh, mm, ss));
  return (
    `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())} ` +
    `${pad(t.getUTCHours())}:${pad(t.getUTCMinutes())}:${pad(t.getUTCSeconds())}`
  );
}

function fmtIstDate(y, mZeroBased, d) {
  const pad = (n) => String(n).padStart(2, "0");
  const t = new Date(Date.UTC(y, mZeroBased, d));
  return `${t.getUTCFullYear()}-${pad(t.getUTCMonth() + 1)}-${pad(t.getUTCDate())}`;
}

// ─── Audit log ───────────────────────────────────────────────────────────────

/** Fail-safe audit writer mirroring the sibling controllers. Never throws. */
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
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or { error }.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return {
      error: {
        status: 401,
        body: { status: false, ok: false, message: "Invalid token user" },
      },
    };
  }

  const [rows] = await pool.execute(
    `
      SELECT
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
      FROM table_dietician td
      INNER JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE td.dietician_id = ?
      LIMIT 1
    `,
    [dieticianId]
  );

  const actor = rows[0];

  if (!actor) {
    return {
      error: {
        status: 403,
        body: { status: false, ok: false, message: "Actor user not found" },
      },
    };
  }

  if (String(actor.status) !== "active") {
    return {
      error: {
        status: 403,
        body: { status: false, ok: false, message: "Actor account is not active" },
      },
    };
  }

  if (!VALID_ACTOR_ROLES.has(String(actor.role))) {
    return {
      error: {
        status: 403,
        body: { status: false, ok: false, message: "Invalid actor role" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Allowed codes (PHP get_allowed_codes) ───────────────────────────────────

function addCode(set, code) {
  const c = normalizeCode(code);
  if (c !== "") set.add(c);
}

async function getAllowedCodes(actor, actorEmail) {
  const codes = new Set();
  const role = String(actor.role);

  addCode(codes, getEffectiveCode(actor));

  if (role === "trainer") {
    return [...codes];
  }

  if (role === "admin") {
    const [rows] = await pool.execute(
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
    for (const row of rows) addCode(codes, row.code);
    return [...codes];
  }

  if (role === "super_admin") {
    const [rows] = await pool.execute(
      `
        SELECT COALESCE(NULLIF(aur.partner_code, ''), NULLIF(td.dietician_id, '')) AS code
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.status = 'active'
          AND aur.role IN ('super_admin', 'admin', 'trainer')
      `
    );
    for (const row of rows) addCode(codes, row.code);
    return [...codes];
  }

  return [...codes];
}

function assertPartnerCodeAllowed(allowedCodes, partnerCode) {
  const target = normalizeCode(partnerCode);
  for (const code of allowedCodes) {
    if (normalizeCode(code) === target) return target;
  }
  return null;
}

// ─── Filter normalisation ────────────────────────────────────────────────────

/** Returns { value } or { error: { status, body } }. */
function normalizePurchaseFilter(raw) {
  let value = cleanValue(raw).toLowerCase();
  if (value === "") return { value: "this_month" };

  if (PURCHASE_FILTER_ALIASES[value]) value = PURCHASE_FILTER_ALIASES[value];

  if (!PURCHASE_FILTERS.includes(value)) {
    return {
      error: {
        status: 422,
        body: {
          status: false,
          ok: false,
          message: "Invalid purchase_filter",
          allowed_purchase_filter: PURCHASE_FILTERS,
        },
      },
    };
  }
  return { value };
}

/** Returns { period } or { error }. period = {purchase_filter,period_label,period_start,period_end}. */
function resolvePurchasePeriod(body) {
  const pf = normalizePurchaseFilter(body.purchase_filter ?? "");
  if (pf.error) return { error: pf.error };
  const purchaseFilter = pf.value;

  const now = istNow();
  const y = now.getUTCFullYear();
  const m = now.getUTCMonth(); // 0-based, IST

  if (purchaseFilter === "custom") {
    const dateFrom = cleanValue(body.date_from);
    const dateTo = cleanValue(body.date_to);

    if (dateFrom === "" || dateTo === "") {
      return {
        error: {
          status: 422,
          body: {
            status: false,
            ok: false,
            message: "date_from and date_to are required for custom purchase_filter",
          },
        },
      };
    }

    const dateRe = /^\d{4}-\d{2}-\d{2}$/;
    if (!dateRe.test(dateFrom) || !dateRe.test(dateTo)) {
      return {
        error: {
          status: 422,
          body: {
            status: false,
            ok: false,
            message: "date_from and date_to must be YYYY-MM-DD",
          },
        },
      };
    }

    const [fy, fm, fd] = dateFrom.split("-").map(Number);
    const [ty, tm, td] = dateTo.split("-").map(Number);
    const startMs = Date.UTC(fy, fm - 1, fd);
    const endMs = Date.UTC(ty, tm - 1, td) + 24 * 60 * 60 * 1000; // +1 day exclusive

    if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) {
      return {
        error: {
          status: 422,
          body: { status: false, ok: false, message: "Invalid custom date range" },
        },
      };
    }

    if (endMs <= startMs) {
      return {
        error: {
          status: 422,
          body: {
            status: false,
            ok: false,
            message: "date_to must be greater than or equal to date_from",
          },
        },
      };
    }

    return {
      period: {
        purchase_filter: purchaseFilter,
        period_label: `${dateFrom} to ${dateTo}`,
        period_start: fmtIstParts(fy, fm - 1, fd),
        period_end: fmtIstParts(ty, tm - 1, td + 1),
      },
    };
  }

  if (purchaseFilter === "this_month") {
    return {
      period: {
        purchase_filter: purchaseFilter,
        period_label: fmtIstDate(y, m, 1).slice(0, 7),
        period_start: fmtIstParts(y, m, 1),
        period_end: fmtIstParts(y, m + 1, 1),
      },
    };
  }

  if (purchaseFilter === "last_month") {
    return {
      period: {
        purchase_filter: purchaseFilter,
        period_label: fmtIstDate(y, m - 1, 1).slice(0, 7),
        period_start: fmtIstParts(y, m - 1, 1),
        period_end: fmtIstParts(y, m, 1),
      },
    };
  }

  if (purchaseFilter === "last_3_months") {
    const labelEnd = fmtIstDate(y, m + 1, 0); // last day of current month
    return {
      period: {
        purchase_filter: purchaseFilter,
        period_label: `${fmtIstDate(y, m - 2, 1)} to ${labelEnd}`,
        period_start: fmtIstParts(y, m - 2, 1),
        period_end: fmtIstParts(y, m + 1, 1),
      },
    };
  }

  if (purchaseFilter === "yearly") {
    return {
      period: {
        purchase_filter: purchaseFilter,
        period_label: String(y),
        period_start: fmtIstParts(y, 0, 1),
        period_end: fmtIstParts(y + 1, 0, 1),
      },
    };
  }

  return {
    period: {
      purchase_filter: "all",
      period_label: "all",
      period_start: "1970-01-01 00:00:00",
      period_end: "9999-12-31 23:59:59",
    },
  };
}

/** Returns { value } or { error }. */
function normalizeUserState(raw) {
  let value = cleanValue(raw).toLowerCase();
  if (value === "") return { value: "all" };

  if (USER_STATE_ALIASES[value]) value = USER_STATE_ALIASES[value];

  if (!USER_STATES.includes(value)) {
    return {
      error: {
        status: 422,
        body: {
          status: false,
          ok: false,
          message: "Invalid user_state",
          allowed_user_state: USER_STATES,
        },
      },
    };
  }
  return { value };
}

/** Returns { value } or { error }. */
function normalizeRenewalDays(raw) {
  if (raw === null || raw === undefined || raw === "") return { value: 7 };

  const days = toInt(raw);
  if (days < 1 || days > 90) {
    return {
      error: {
        status: 422,
        body: {
          status: false,
          ok: false,
          message: "renewal_days must be between 1 and 90",
        },
      },
    };
  }
  return { value: days };
}

// ─── SQL builders ────────────────────────────────────────────────────────────

/**
 * Build the grouped base query. Every PHP named param (reused under emulated
 * prepares) is expanded into ordered positional placeholders. renewalDays is a
 * validated integer and is the only inlined value.
 *
 * Returns { sql, params } where params follow the exact `?` order of `sql`.
 */
function buildBaseGroupedSql({
  partnerCode,
  periodStart,
  periodEnd,
  search,
  userState,
  renewalDays,
  nowTs,
}) {
  const code = normalizeCode(partnerCode);
  const rd = toInt(renewalDays); // validated 1..90, safe to inline
  const params = [];

  // SELECT clause references :now_ts eight times (CASE x7 + DATEDIFF x1).
  const selectNow = [];
  for (let i = 0; i < 8; i++) selectNow.push(nowTs);

  // whereExtra (search + user_state), built alongside its bound params.
  let whereExtra = "";
  const whereParams = [];

  if (search !== "") {
    const like = `%${escapeLike(search)}%`;
    whereExtra += `
      AND (
        cs.profile_id LIKE ?
        OR CAST(cs.client_id AS CHAR) LIKE ?
        OR cs.plan_code LIKE ?
        OR cs.plan_name LIKE ?
        OR cs.stripe_subscription_id LIKE ?
        OR cs.stripe_customer_id LIKE ?
        OR tc.profile_name LIKE ?
        OR tc.email LIKE ?
        OR tc.phone_no LIKE ?
        OR p.session_id LIKE ?
        OR p.stripe_payment_intent_id LIKE ?
        OR p.stripe_subscription_id LIKE ?
        OR p.stripe_customer_id LIKE ?
        OR p.coupon_code LIKE ?
      )
    `;
    for (let i = 0; i < 14; i++) whereParams.push(like);
  }

  if (userState === "active") {
    whereExtra += `
      AND cs.subscription_start_date <= ?
      AND cs.subscription_end_date >= ?
    `;
    whereParams.push(nowTs, nowTs);
  } else if (userState === "expired") {
    whereExtra += `
      AND cs.subscription_end_date < ?
    `;
    whereParams.push(nowTs);
  } else if (userState === "attention_for_renewal") {
    whereExtra += `
      AND cs.subscription_start_date <= ?
      AND cs.subscription_end_date >= ?
      AND cs.subscription_end_date <= DATE_ADD(?, INTERVAL ${rd} DAY)
    `;
    whereParams.push(nowTs, nowTs, nowTs);
  } else if (userState === "upcoming") {
    whereExtra += `
      AND cs.subscription_start_date > ?
    `;
    whereParams.push(nowTs);
  }

  const sql = `
    SELECT
      cs.id AS client_subscription_id,
      cs.dietician_id AS partner_code,
      cs.profile_id,
      cs.client_id,

      cs.coupon_code AS subscription_coupon_code,
      cs.plan_code,
      cs.plan_name,
      cs.duration_months,
      cs.currency AS subscription_currency,

      cs.status AS raw_subscription_status,
      cs.subscription_start_date,
      cs.subscription_end_date,
      cs.current_period_end,
      cs.cancel_at_period_end,
      cs.stripe_subscription_id,
      cs.stripe_customer_id,
      cs.activated_at,
      cs.created_at AS subscription_created_at,
      cs.updated_at AS subscription_updated_at,

      CASE
        WHEN cs.subscription_end_date < ? THEN 'expired'
        WHEN cs.subscription_start_date > ? THEN 'upcoming'
        WHEN cs.subscription_start_date <= ?
             AND cs.subscription_end_date >= ?
             AND cs.subscription_end_date <= DATE_ADD(?, INTERVAL ${rd} DAY)
            THEN 'attention_for_renewal'
        WHEN cs.subscription_start_date <= ?
             AND cs.subscription_end_date >= ?
            THEN 'active'
        ELSE 'unknown'
      END AS derived_user_state,

      DATEDIFF(DATE(cs.subscription_end_date), DATE(?)) AS days_left_for_renewal,

      tc.profile_name AS client_name,
      tc.email AS client_email,
      tc.phone_no AS client_phone,
      tc.dietician_id AS client_dietician_id,
      tc.dttm AS client_joined_at,

      MIN(COALESCE(NULLIF(p.currency, ''), NULLIF(cs.currency, ''), 'INR')) AS currency,

      COUNT(p.id) AS payment_count,
      GROUP_CONCAT(p.id ORDER BY COALESCE(p.paid_at, p.created_at) DESC, p.id DESC) AS payment_ids,

      MIN(COALESCE(p.paid_at, p.created_at)) AS first_paid_at,
      MAX(COALESCE(p.paid_at, p.created_at)) AS latest_paid_at,

      SUM(COALESCE(p.base_amount_minor, 0)) AS gross_sales_minor,
      SUM(COALESCE(p.discount_amount_minor, 0)) AS discount_minor,
      SUM(COALESCE(p.final_amount_minor, 0)) AS net_sales_minor,

      MAX(p.id) AS latest_payment_id,

      SUBSTRING_INDEX(
        GROUP_CONCAT(p.session_id ORDER BY COALESCE(p.paid_at, p.created_at) DESC, p.id DESC SEPARATOR '||'),
        '||', 1
      ) AS latest_session_id,

      SUBSTRING_INDEX(
        GROUP_CONCAT(p.stripe_payment_intent_id ORDER BY COALESCE(p.paid_at, p.created_at) DESC, p.id DESC SEPARATOR '||'),
        '||', 1
      ) AS latest_stripe_payment_intent_id,

      SUBSTRING_INDEX(
        GROUP_CONCAT(p.stripe_subscription_id ORDER BY COALESCE(p.paid_at, p.created_at) DESC, p.id DESC SEPARATOR '||'),
        '||', 1
      ) AS latest_payment_stripe_subscription_id,

      SUBSTRING_INDEX(
        GROUP_CONCAT(p.stripe_customer_id ORDER BY COALESCE(p.paid_at, p.created_at) DESC, p.id DESC SEPARATOR '||'),
        '||', 1
      ) AS latest_payment_stripe_customer_id,

      SUBSTRING_INDEX(
        GROUP_CONCAT(COALESCE(p.coupon_code, cs.coupon_code) ORDER BY COALESCE(p.paid_at, p.created_at) DESC, p.id DESC SEPARATOR '||'),
        '||', 1
      ) AS latest_coupon_code

    FROM client_subscriptions cs

    INNER JOIN (
      SELECT
        profile_id,
        MAX(id) AS latest_subscription_id
      FROM client_subscriptions
      WHERE UPPER(dietician_id) = ?
      GROUP BY profile_id
    ) latest_cs
      ON latest_cs.latest_subscription_id = cs.id

    INNER JOIN payments p
      ON p.profile_id = cs.profile_id
     AND p.status = 'succeeded'
     AND COALESCE(p.final_amount_minor, 0) > 0
     AND COALESCE(p.paid_at, p.created_at) >= ?
     AND COALESCE(p.paid_at, p.created_at) < ?
     AND (
          (
            p.stripe_subscription_id IS NOT NULL
            AND p.stripe_subscription_id <> ''
            AND cs.stripe_subscription_id IS NOT NULL
            AND cs.stripe_subscription_id <> ''
            AND p.stripe_subscription_id = cs.stripe_subscription_id
          )
          OR
          (
            (
              p.stripe_subscription_id IS NULL
              OR p.stripe_subscription_id = ''
              OR cs.stripe_subscription_id IS NULL
              OR cs.stripe_subscription_id = ''
            )
            AND UPPER(p.plan_code) = UPPER(cs.plan_code)
            AND COALESCE(p.paid_at, p.created_at) >= DATE_SUB(cs.subscription_start_date, INTERVAL 1 DAY)
            AND COALESCE(p.paid_at, p.created_at) <= DATE_ADD(cs.subscription_end_date, INTERVAL 1 DAY)
          )
     )

    LEFT JOIN table_clients tc
      ON tc.profile_id = cs.profile_id
     AND UPPER(tc.dietician_id) = UPPER(cs.dietician_id)

    WHERE UPPER(cs.dietician_id) = ?

      AND NOT (
            UPPER(REPLACE(cs.plan_code, '-', '_')) IN ('FREE_TRIAL', 'TRIAL', 'FREE')
            OR LOWER(cs.plan_name) LIKE '%free trial%'
      )

      ${whereExtra}

    GROUP BY
      cs.id,
      cs.dietician_id,
      cs.profile_id,
      cs.client_id,
      cs.coupon_code,
      cs.plan_code,
      cs.plan_name,
      cs.duration_months,
      cs.currency,
      cs.status,
      cs.subscription_start_date,
      cs.subscription_end_date,
      cs.current_period_end,
      cs.cancel_at_period_end,
      cs.stripe_subscription_id,
      cs.stripe_customer_id,
      cs.activated_at,
      cs.created_at,
      cs.updated_at,
      tc.profile_name,
      tc.email,
      tc.phone_no,
      tc.dietician_id,
      tc.dttm
  `;

  // Param order MUST follow the `?` order in `sql`:
  //   SELECT now_ts x8 → latest_cs partner_code → payments period_start/end
  //   → main WHERE partner_code → whereExtra (search/user_state).
  params.push(...selectNow); // 8
  params.push(code); // latest_cs
  params.push(periodStart, periodEnd); // payments window
  params.push(code); // main WHERE
  params.push(...whereParams);

  return { sql, params };
}

async function fetchSummary(conn, opts) {
  const { sql: baseSql, params: baseParams } = buildBaseGroupedSql(opts);
  const rd = toInt(opts.renewalDays);
  const now = opts.nowTs;

  // Outer SELECT references now_ts 7 times (active x2, expired x1,
  // attention x3, upcoming x1) BEFORE the base subquery.
  const sql = `
    SELECT
      COUNT(*) AS total_purchased_clients,

      SUM(CASE WHEN x.subscription_start_date <= ?
                AND x.subscription_end_date >= ?
               THEN 1 ELSE 0 END) AS active_users,

      SUM(CASE WHEN x.subscription_end_date < ?
               THEN 1 ELSE 0 END) AS expired_users,

      SUM(CASE WHEN x.subscription_start_date <= ?
                AND x.subscription_end_date >= ?
                AND x.subscription_end_date <= DATE_ADD(?, INTERVAL ${rd} DAY)
               THEN 1 ELSE 0 END) AS attention_for_renewal_users,

      SUM(CASE WHEN x.subscription_start_date > ?
               THEN 1 ELSE 0 END) AS upcoming_users,

      SUM(x.payment_count) AS total_payments,
      SUM(x.gross_sales_minor) AS gross_sales_minor,
      SUM(x.discount_minor) AS discount_minor,
      SUM(x.net_sales_minor) AS net_sales_minor,

      GROUP_CONCAT(DISTINCT x.currency ORDER BY x.currency) AS currencies
    FROM (${baseSql}) x
  `;

  const params = [now, now, now, now, now, now, now, ...baseParams];

  const [rows] = await conn.execute(sql, params);
  return rows[0] || {};
}

async function fetchRows(conn, opts, page, limit) {
  const { sql: baseSql, params: baseParams } = buildBaseGroupedSql(opts);

  // Validated integers — safe to inline (bound LIMIT/OFFSET is rejected on some
  // MySQL builds under prepared statements).
  const safeLimit = Math.max(1, Math.min(100, toInt(limit)));
  const safePage = Math.max(1, toInt(page));
  const offset = (safePage - 1) * safeLimit;

  const sql = `
    SELECT *
    FROM (${baseSql}) x
    ORDER BY x.latest_paid_at DESC, x.client_subscription_id DESC
    LIMIT ${safeLimit} OFFSET ${offset}
  `;

  const [rows] = await conn.execute(sql, baseParams);
  return rows;
}

// ─── Formatters ──────────────────────────────────────────────────────────────

function formatSummary(raw) {
  const grossMinor = toInt(raw.gross_sales_minor);
  const discountMinor = toInt(raw.discount_minor);
  const netMinor = toInt(raw.net_sales_minor);

  let currencies = [];
  if (raw.currencies) {
    currencies = String(raw.currencies)
      .split(",")
      .map((c) => c.trim())
      .filter((c) => c !== "");
  }

  return {
    total_purchased_clients: toInt(raw.total_purchased_clients),
    active_users: toInt(raw.active_users),
    expired_users: toInt(raw.expired_users),
    attention_for_renewal_users: toInt(raw.attention_for_renewal_users),
    upcoming_users: toInt(raw.upcoming_users),

    total_payments: toInt(raw.total_payments),

    currencies,

    gross_sales_minor: grossMinor,
    discount_minor: discountMinor,
    net_sales_minor: netMinor,

    gross_sales: minorToMajor(grossMinor),
    discount: minorToMajor(discountMinor),
    net_sales: minorToMajor(netMinor),
  };
}

function formatAnalyticsRow(row) {
  const grossMinor = toInt(row.gross_sales_minor);
  const discountMinor = toInt(row.discount_minor);
  const netMinor = toInt(row.net_sales_minor);

  const clientName = cleanValue(row.client_name);
  const clientEmail = normalizeEmail(row.client_email);
  const clientPhone = cleanValue(row.client_phone);

  const paymentIdsRaw = cleanValue(row.payment_ids);
  const paymentIds =
    paymentIdsRaw !== ""
      ? paymentIdsRaw.split(",").map((v) => toInt(v))
      : [];

  return {
    profile_id: row.profile_id,
    client_subscription_id: toInt(row.client_subscription_id),
    partner_code: row.partner_code,

    client: {
      client_id: toIntOrNull(row.client_id),
      profile_id: row.profile_id,
      name: clientName !== "" ? clientName : null,
      email: clientEmail !== "" ? clientEmail : null,
      phone: clientPhone !== "" ? clientPhone : null,
      dietician_id: row.client_dietician_id ?? null,
      joined_at: toMysqlDateTime(row.client_joined_at),
    },

    subscription: {
      is_latest_subscription: true,
      latest_rule: "MAX(client_subscriptions.id) per profile_id within partner_code",

      plan_code: row.plan_code,
      plan_name: row.plan_name,
      duration_months: toIntOrNull(row.duration_months),
      currency: row.subscription_currency,

      raw_status: row.raw_subscription_status,
      derived_user_state: row.derived_user_state,
      days_left_for_renewal: toIntOrNull(row.days_left_for_renewal),

      subscription_start_date: toMysqlDateTime(row.subscription_start_date),
      subscription_end_date: toMysqlDateTime(row.subscription_end_date),
      current_period_end: toMysqlDateTime(row.current_period_end),
      cancel_at_period_end: toInt(row.cancel_at_period_end),

      stripe_subscription_id: row.stripe_subscription_id,
      stripe_customer_id: row.stripe_customer_id,

      activated_at: toMysqlDateTime(row.activated_at),
      created_at: toMysqlDateTime(row.subscription_created_at),
      updated_at: toMysqlDateTime(row.subscription_updated_at),
    },

    payment: {
      payment_count: toInt(row.payment_count),
      payment_ids: paymentIds,

      first_paid_at: toMysqlDateTime(row.first_paid_at),
      latest_paid_at: toMysqlDateTime(row.latest_paid_at),

      currency: row.currency,

      gross_sales_minor: grossMinor,
      discount_minor: discountMinor,
      net_sales_minor: netMinor,

      gross_sales: minorToMajor(grossMinor),
      discount: minorToMajor(discountMinor),
      net_sales: minorToMajor(netMinor),

      latest_payment_id: toIntOrNull(row.latest_payment_id),
      latest_session_id: row.latest_session_id,
      latest_stripe_payment_intent_id: row.latest_stripe_payment_intent_id,
      latest_payment_stripe_subscription_id: row.latest_payment_stripe_subscription_id,
      latest_payment_stripe_customer_id: row.latest_payment_stripe_customer_id,
      latest_coupon_code: row.latest_coupon_code,
    },
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/trainer-sales-analytics
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "actor_id": "",            // optional; if set, must match the token email
 *     "partner_code": "TRNY3EQQLM",
 *     "purchase_filter": "this_month",
 *     "user_state": "all",
 *     "renewal_days": 7,
 *     "page": 1,
 *     "limit": 10,
 *     "search": "",
 *     "date_from": "YYYY-MM-DD", // custom only
 *     "date_to":   "YYYY-MM-DD"  // custom only
 *   }
 */
const trainerSalesAnalytics = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({
      status: false,
      ok: false,
      message: "Only POST method is allowed",
    });
  }

  const body = req.body && typeof req.body === "object" ? req.body : {};

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;
  let conn = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_sales_analytics_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: String(req.user?.sub || req.user?.dietician_id || ""),
        success: false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getEffectiveCode(actor);

    // ── 1b. Optional actor_id — present + cross-checked against the token ────
    const bodyActorId = normalizeEmail(body.actor_id);
    if (bodyActorId !== "") {
      if (!isEmail(bodyActorId) || bodyActorId !== actorEmail) {
        await writeAuthLogSafe(req, {
          eventType: "trainer_sales_analytics_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: bodyActorId,
          success: false,
          failureReason: "actor_id does not match token identity",
        });
        return res.status(403).json({
          status: false,
          ok: false,
          message: "actor_id does not match the authenticated user",
        });
      }
    }

    // ── 2. Validate request inputs ──────────────────────────────────────────
    const partnerCode = normalizeCode(body.partner_code);
    if (partnerCode === "") {
      return res.status(422).json({
        status: false,
        ok: false,
        message: "partner_code is required",
      });
    }

    const search = cleanValue(body.search);
    if (search !== "" && search.length < 3) {
      return res.status(422).json({
        status: false,
        ok: false,
        message: "Search must be at least 3 characters",
        search_min_length: 3,
      });
    }

    let page = toInt(body.page);
    let limit = toInt(body.limit);
    if (page <= 0) page = 1;
    if (limit <= 0) limit = 10;
    if (limit > 100) limit = 100;

    const periodRes = resolvePurchasePeriod(body);
    if (periodRes.error) {
      return res.status(periodRes.error.status).json(periodRes.error.body);
    }
    const purchasePeriod = periodRes.period;

    const userStateRes = normalizeUserState(body.user_state ?? "all");
    if (userStateRes.error) {
      return res.status(userStateRes.error.status).json(userStateRes.error.body);
    }
    const userState = userStateRes.value;

    const renewalRes = normalizeRenewalDays(body.renewal_days ?? 7);
    if (renewalRes.error) {
      return res.status(renewalRes.error.status).json(renewalRes.error.body);
    }
    const renewalDays = renewalRes.value;

    // ── 3. Authorize partner_code against allowed-codes scope ───────────────
    const allowedCodes = await getAllowedCodes(actor, actorEmail);
    const viewPartnerCode = assertPartnerCodeAllowed(allowedCodes, partnerCode);

    if (viewPartnerCode === null) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_sales_analytics_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: partnerCode,
        success: false,
        failureReason: "partner_code not in allowed scope",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "You are not allowed to view this partner_code",
      });
    }

    // ── 4. Dedicated IST connection for date maths parity with the PHP ──────
    conn = await pool.getConnection();
    await conn.query("SET time_zone = '+05:30'");

    // Current time as an IST wall-clock string for SQL date maths.
    const istParts = istNow();
    const pad = (n) => String(n).padStart(2, "0");
    const nowTsIst =
      `${istParts.getUTCFullYear()}-${pad(istParts.getUTCMonth() + 1)}-${pad(istParts.getUTCDate())} ` +
      `${pad(istParts.getUTCHours())}:${pad(istParts.getUTCMinutes())}:${pad(istParts.getUTCSeconds())}`;

    const queryOpts = {
      partnerCode: viewPartnerCode,
      periodStart: purchasePeriod.period_start,
      periodEnd: purchasePeriod.period_end,
      search,
      userState,
      renewalDays,
      nowTs: nowTsIst,
    };

    // Summary for the selected user_state.
    const summaryRaw = await fetchSummary(conn, queryOpts);

    // Tab counts: same period + search, no user_state filter.
    const tabSummaryRaw = await fetchSummary(conn, { ...queryOpts, userState: "all" });

    // Page of rows for the selected user_state.
    const rowsRaw = await fetchRows(conn, queryOpts, page, limit);

    const summary = formatSummary(summaryRaw);
    const tabSummary = formatSummary(tabSummaryRaw);
    const data = rowsRaw.map(formatAnalyticsRow);

    const totalRows = summary.total_purchased_clients;
    const offset = (page - 1) * limit;
    const totalPages = limit > 0 ? Math.ceil(totalRows / limit) : 0;

    // ── 5. Audit — success (fire-and-forget) ────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "trainer_sales_analytics_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: viewPartnerCode,
      identifier: viewPartnerCode,
      success: true,
      failureReason: "Trainer sales analytics viewed",
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Trainer sales analytics fetched successfully",
      mode: "trainer_sales_analytics",

      actor: {
        actor_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
        parent_user_id: actor.parent_user_id ?? null,
        name: actor.name ?? null,
      },

      filters: {
        partner_code: viewPartnerCode,

        purchase_filter: purchasePeriod.purchase_filter,
        period_label: purchasePeriod.period_label,
        period_start: purchasePeriod.period_start,
        period_end_exclusive: purchasePeriod.period_end,

        user_state: userState,
        renewal_days: renewalDays,
        now: nowTsIst,

        search,
        search_min_length: 3,

        latest_subscription_rule:
          "Only MAX(client_subscriptions.id) per profile_id within partner_code is used",
        expiry_rule:
          "Active/expired is derived from subscription_start_date and subscription_end_date, not from status",
      },

      summary,

      tab_counts: {
        all: tabSummary.total_purchased_clients,
        active: tabSummary.active_users,
        expired: tabSummary.expired_users,
        attention_for_renewal: tabSummary.attention_for_renewal_users,
        upcoming: tabSummary.upcoming_users,
      },

      pagination: {
        page,
        limit,
        offset,
        total: totalRows,
        total_pages: totalPages,
        has_more: offset + limit < totalRows,
        next_page: offset + limit < totalRows ? page + 1 : null,
        prev_page: page > 1 ? page - 1 : null,
      },

      search_options: {
        searchable_fields: SEARCHABLE_FIELDS,
      },

      data,
    });
  } catch (err) {
    console.error("TRAINER_SALES_ANALYTICS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "trainer_sales_analytics_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: actorEmail,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug: { error: err?.message } }),
    });
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (e) {
        /* no-op */
      }
    }
  }
};

module.exports = { trainerSalesAnalytics };
