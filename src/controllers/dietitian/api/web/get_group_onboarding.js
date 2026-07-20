"use strict";

/**
 * get_group_onboarding.js
 *
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get_group_onboarding
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin who is a member of the requested group
 *
 * Purpose (onboarding roster). Given a group_name and a date window, returns the
 * people who were ONBOARDED into that group's network inside the window — the
 * trainers/admins whose app_user_roles row was created, and the clients whose
 * table_clients row was created — as ONE feed ordered newest-first.
 *
 * Sibling of get_group_details.js: identical actor resolution, identical RBAC,
 * identical group/network derivation, identical masking. Where get_group_details
 * answers "who is in this group right now", this answers "who joined between
 * these two dates".
 *
 * Sources (no new tables):
 *   - providers : app_user_roles.created_at  (admins of the group + their trainers)
 *   - clients   : table_clients.dttm         (clients owned by any network code)
 * Both streams are UNION ALL'd in SQL on (kind, key, onboarded_at) so ONE page of
 * the merged feed is fetched, then each page row is hydrated with detail. Counts
 * are computed over the same filters, so counts.* always describe the full window,
 * not the page.
 *
 * Exclusion rule (deliberate, documented deviation from get_group_details):
 *   A table_clients row whose email matches ANY network provider (admin/trainer)
 *   email is that provider's own self-test profile, not an onboarded client, and
 *   is dropped from the feed and from every count. get_group_details excluded only
 *   the group's ADMIN emails plus the row's own owner; using the full provider set
 *   here is the same intent applied uniformly, and matches the convention already
 *   used by that file's period_overview.
 *
 * VAPT hardening:
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (sub = dietician_id) and re-checked against the DB (role + status) on every
 *    call. body.actor_user_id is accepted for frontend/back-compat but is only
 *    cross-checked against the token email (mismatch -> 403); it can never select
 *    a different user.
 *  - Group membership is enforced before any group data is read: super_admin, or
 *    an admin whose effective code is an active member of group_name.
 *  - Every IN (...) list and every exclusion clause uses placeholders + bound
 *    params. LIMIT/OFFSET are the only inlined values and are hard-coerced to
 *    non-negative integers first (mysql2 prepared statements reject bound
 *    LIMIT/OFFSET on some MySQL builds).
 *  - LIKE wildcards (% _ \) in the search term are escaped so a caller cannot
 *    widen the search beyond what they typed.
 *  - date_from / date_to are strictly validated calendar dates (2026-02-31 is
 *    rejected) before reaching SQL, and the span is capped at MAX_RANGE_DAYS so a
 *    caller cannot force an unbounded scan.
 *  - Internal error details are suppressed in production (gated behind APP_DEBUG).
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The session time zone is never mutated (shared mysql2 pool — a SET time_zone
 *    would leak into concurrent requests). Date bucketing uses the DB clock; the
 *    DEFAULT window is app-computed in IST, the same approach as the siblings.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT * over PHI rows.
 *  - Client name/email and owner email are MASKED in the response.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every onboarding-roster read is recorded in app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["admin", "super_admin"]);

const MAX_LIMIT = 50;
const DEFAULT_LIMIT = 10;

// VAPT: bound the scan window.
const MAX_RANGE_DAYS = 366;

// Default window when the caller sends no dates: the last N days, inclusive of today.
const DEFAULT_WINDOW_DAYS = 30;

const ALLOWED_TYPES = new Set(["all", "trainer", "client"]);

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string"
    ? val.trim().toLowerCase()
    : String(val ?? "").trim().toLowerCase();
}

function normalizeCode(val) {
  return String(val ?? "").trim().toUpperCase();
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

/** null/blank -> default ("NA"), else trimmed string. */
function cleanValue(val, def = "NA") {
  if (val === null || val === undefined) return def;
  const str = String(val).trim();
  return str === "" ? def : str;
}

/** null/blank/non-numeric -> null, else rounded to 2 decimals. */
function scoreValue(val) {
  if (val === null || val === undefined || val === "" || Number.isNaN(Number(val))) {
    return null;
  }
  return Math.round(Number(val) * 100) / 100;
}

/** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS". */
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

/**
 * Strictly validate a YYYY-MM-DD string, returning the normalized date or null.
 * Round-tripping through Date rejects impossible calendar dates (2026-02-31 rolls
 * forward to 2026-03-03, so the round-trip no longer matches).
 */
function validDateYmd(value) {
  if (value === null || value === undefined) return null;

  const str = String(value).trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(str)) return null;

  const d = new Date(`${str}T00:00:00Z`);
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== str) return null;

  return str;
}

/** Today's date in Asia/Kolkata as "YYYY-MM-DD". */
function todayDateIST() {
  const ist = new Date(Date.now() + (5 * 60 + 30) * 60 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${ist.getUTCFullYear()}-${pad(ist.getUTCMonth() + 1)}-${pad(ist.getUTCDate())}`;
}

/** Shift a validated YYYY-MM-DD by whole days. */
function shiftDaysYmd(ymd, days) {
  const d = new Date(`${ymd}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

/** Inclusive whole-day span between two validated YYYY-MM-DD strings. */
function daysBetweenInclusive(fromYmd, toYmd) {
  const from = new Date(`${fromYmd}T00:00:00Z`).getTime();
  const to = new Date(`${toYmd}T00:00:00Z`).getTime();
  return Math.floor((to - from) / 86400000) + 1;
}

/**
 * Whole days elapsed between an onboarding timestamp and today (IST), or null.
 * Both sides are reduced to a calendar day first, so the answer is stable within
 * a day and never negative-by-a-few-hours.
 */
function daysSince(dateTimeVal) {
  const str = toMysqlDateTime(dateTimeVal);
  if (str === null) return null;

  const ymd = validDateYmd(str.slice(0, 10));
  if (ymd === null) return null;

  const diff = daysBetweenInclusive(ymd, todayDateIST()) - 1;
  return diff < 0 ? 0 : diff;
}

/**
 * Keep the first TWO & last letter of each word, star the middle.
 * "Jennifer Lawson" -> "Je*****r La***n". Whitespace runs are preserved.
 */
function maskName(name) {
  const str = String(name ?? "").trim();
  if (str === "") return str;

  const parts = str.split(/(\s+)/);

  return parts
    .map((word) => {
      if (word === "" || /^\s+$/.test(word)) return word;

      const chars = Array.from(word);
      const len = chars.length;

      if (len <= 3) {
        if (len <= 2) return word;
        return chars[0] + "*".repeat(len - 2) + chars[len - 1];
      }

      const start = chars[0] + chars[1];
      return start + "*".repeat(len - 3) + chars[len - 1];
    })
    .join("");
}

/**
 * Star the middle of the local part, keep the first TWO & last char of it and the
 * full domain. "kaleikochambers7@icloud.com" -> "ka*************7@icloud.com".
 */
function maskEmail(email) {
  if (email === null || email === undefined) return null;

  const str = String(email).trim();
  if (str === "" || str.indexOf("@") === -1) return str;

  const atPos = str.lastIndexOf("@");
  const local = str.slice(0, atPos);
  const domain = str.slice(atPos); // includes '@'

  const chars = Array.from(local);
  const len = chars.length;

  let masked;
  if (len <= 3) {
    if (len <= 2) {
      masked = "*".repeat(len);
    } else {
      masked = chars[0] + "*".repeat(len - 2) + chars[len - 1];
    }
  } else {
    masked = chars[0] + chars[1] + "*".repeat(len - 3) + chars[len - 1];
  }

  return masked + domain;
}

/** partner_code, else dietician_id, else null. */
function getActorEffectiveCode(actor) {
  if (actor.partner_code !== null && actor.partner_code !== undefined &&
      String(actor.partner_code).trim() !== "") {
    return String(actor.partner_code);
  }
  if (actor.dietician_id !== null && actor.dietician_id !== undefined &&
      String(actor.dietician_id).trim() !== "") {
    return String(actor.dietician_id);
  }
  return null;
}

/** Escape LIKE wildcards so a caller cannot widen the search beyond their term. */
function escapeLike(term) {
  return String(term).replace(/[\\%_]/g, "\\$&");
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

// ─── Parameterized exclusion clauses ─────────────────────────────────────────

/**
 * TRUE when `col`'s email is NOT one of the excluded (provider) emails — i.e. the
 * row is a real client, not a provider's own self-test profile. `col` is a
 * controller-controlled column name (never user input); `emails` are always bound.
 */
function emailKeepClause(emails, col) {
  if (emails.length === 0) return { sql: "1=1", params: [] };
  const placeholders = emails.map(() => "?").join(",");
  return {
    sql: `(${col} IS NULL OR TRIM(${col}) = '' OR LOWER(TRIM(${col})) NOT IN (${placeholders}))`,
    params: emails.map(normalizeEmail),
  };
}

/**
 * TRUE when the test's profile does NOT belong to a provider self-test profile, so
 * a provider who tested themselves is never counted in their own client totals.
 */
function profileNotProviderClause(emails, testAlias) {
  if (emails.length === 0) return { sql: "1=1", params: [] };
  const placeholders = emails.map(() => "?").join(",");
  return {
    sql: `${testAlias}.profile_id NOT IN (
              SELECT pc.profile_id
              FROM table_clients pc
              WHERE pc.email IS NOT NULL
                AND TRIM(pc.email) <> ''
                AND LOWER(TRIM(pc.email)) IN (${placeholders})
          )`,
    params: emails.map(normalizeEmail),
  };
}

// ─── Audit log ───────────────────────────────────────────────────────────────

/**
 * Fail-safe audit writer mirroring the sibling controllers. Never throws.
 *   app_auth_logs(event_type, user_id, role, partner_code, identifier_hash,
 *                 ip_hash, user_agent_hash, session_id_hash, success, failure_reason)
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
    console.error("GET_GROUP_ONBOARDING_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or
 * { error: { status, body } }.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return { error: { status: 401, body: { status: false, ok: false, message: "Invalid token user" } } };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.dietician_id,
        td.name,
        td.email,
        aur.role,
        aur.partner_code,
        aur.status
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
    return { error: { status: 403, body: { status: false, ok: false, message: "Actor user not found" } } };
  }

  if (String(actor.status) !== "active") {
    return { error: { status: 403, body: { status: false, ok: false, message: "Actor account is not active" } } };
  }

  if (!ALLOWED_ACTOR_ROLES.has(String(actor.role))) {
    return {
      error: {
        status: 403,
        body: { status: false, ok: false, message: "Only an admin can view group onboarding" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Group / network derivation ──────────────────────────────────────────────

/** Active member (admin) codes of the group, UPPER-cased. */
async function getGroupMemberCodes(groupName) {
  const [rows] = await pool.execute(
    `
      SELECT DISTINCT UPPER(dietician_id) AS code
      FROM ta_admin_groups
      WHERE group_name = ?
        AND status = 'active'
      ORDER BY code
    `,
    [groupName]
  );

  const codes = [];
  for (const row of rows) {
    if (row.code !== "" && row.code !== null && row.code !== undefined) {
      codes.push(String(row.code));
    }
  }
  return codes;
}

/**
 * The group's admin members. Lightweight: identity + created_at only, no counts
 * (per-provider counts are computed for the current page only, further down).
 */
async function getGroupAdmins(codes) {
  if (codes.length === 0) return [];

  const inList = codes.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        td.dietician_id,
        td.name,
        td.email,
        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        aur.status,
        aur.created_at
      FROM table_dietician td
      LEFT JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE UPPER(td.dietician_id) IN (${inList})
    `,
    codes.map(normalizeCode)
  );

  return rows.map((row) => {
    let partnerCode = row.partner_code;
    if (partnerCode === null || partnerCode === undefined || String(partnerCode).trim() === "") {
      partnerCode = row.dietician_id; // fallback
    }

    return {
      kind: "provider",
      dietician_id: row.dietician_id,
      partner_code: partnerCode,
      name: cleanValue(row.name),
      email: row.email !== null && row.email !== undefined ? normalizeEmail(row.email) : null,
      role: row.role !== null && row.role !== undefined ? row.role : "admin",
      parent_admin_email: null,
      status: row.status,
      created_at: row.created_at,
    };
  });
}

/** Active trainers whose parent_user_id is one of the group's admin emails. */
async function getGroupTrainers(adminEmails) {
  if (adminEmails.length === 0) return [];

  const inList = adminEmails.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        aur.partner_code,
        aur.user_id AS email,
        aur.role,
        aur.parent_user_id,
        aur.status,
        aur.created_at,
        td.dietician_id,
        td.name
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE aur.role = 'trainer'
        AND aur.status = 'active'
        AND LOWER(aur.parent_user_id) IN (${inList})
      ORDER BY aur.partner_code
    `,
    adminEmails.map(normalizeEmail)
  );

  return rows.map((row) => {
    let code = row.partner_code;
    if (code === null || code === undefined || String(code).trim() === "") {
      code = row.dietician_id; // fallback
    }

    return {
      kind: "provider",
      dietician_id: row.dietician_id,
      partner_code: code,
      name: cleanValue(row.name),
      email: row.email !== null && row.email !== undefined ? normalizeEmail(row.email) : null,
      role: "trainer",
      parent_admin_email:
        row.parent_user_id !== null && row.parent_user_id !== undefined
          ? normalizeEmail(row.parent_user_id)
          : null,
      status: row.status,
      created_at: row.created_at,
    };
  });
}

// ─── Feed building blocks ────────────────────────────────────────────────────

/**
 * The provider half of the feed. Keyed on LOWER(user_id) because partner_code can
 * be NULL in app_user_roles (the admin fallback above), while user_id is the join
 * key the rest of this file already trusts.
 *   { sql, params } producing (kind, key_id, onboarded_at).
 */
function providerFeedPart(providerEmails, escapedSearch, fromDt, toDtExclusive) {
  const inList = providerEmails.map(() => "?").join(",");
  const params = [...providerEmails.map(normalizeEmail), fromDt, toDtExclusive];

  let searchSql = "";
  if (escapedSearch !== "") {
    searchSql = `
      AND (
        LOWER(COALESCE(td.name, '')) LIKE LOWER(?)
        OR LOWER(aur.user_id) LIKE LOWER(?)
        OR LOWER(COALESCE(aur.partner_code, '')) LIKE LOWER(?)
      )
    `;
    const like = `%${escapedSearch}%`;
    params.push(like, like, like);
  }

  return {
    sql: `
      SELECT
        'provider' AS kind,
        LOWER(aur.user_id) AS key_id,
        aur.created_at AS onboarded_at
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE LOWER(aur.user_id) IN (${inList})
        AND aur.created_at IS NOT NULL
        AND aur.created_at >= ?
        AND aur.created_at < ?
        ${searchSql}
    `,
    params,
  };
}

/**
 * The client half of the feed: clients owned by any network code, minus provider
 * self-test profiles.
 *   { sql, params } producing (kind, key_id, onboarded_at).
 */
function clientFeedPart(networkCodes, providerEmails, escapedSearch, fromDt, toDtExclusive) {
  const inList = networkCodes.map(() => "?").join(",");
  const keepClient = emailKeepClause(providerEmails, "tc.email");

  const params = [
    ...networkCodes.map(normalizeCode),
    ...keepClient.params,
    fromDt,
    toDtExclusive,
  ];

  let searchSql = "";
  if (escapedSearch !== "") {
    searchSql = `
      AND (
        LOWER(tc.profile_id) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.profile_name, '')) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.email, '')) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.phone_no, '')) LIKE LOWER(?)
      )
    `;
    const like = `%${escapedSearch}%`;
    params.push(like, like, like, like);
  }

  return {
    sql: `
      SELECT
        'client' AS kind,
        tc.profile_id AS key_id,
        tc.dttm AS onboarded_at
      FROM table_clients tc
      WHERE UPPER(tc.dietician_id) IN (${inList})
        AND ${keepClient.sql}
        AND tc.dttm IS NOT NULL
        AND tc.dttm >= ?
        AND tc.dttm < ?
        ${searchSql}
    `,
    params,
  };
}

/** COUNT(*) over one feed part. */
async function countFeedPart(part) {
  const [rows] = await pool.execute(
    `SELECT COUNT(*) AS total FROM (${part.sql}) AS feed`,
    part.params
  );
  return toInt(rows[0]?.total);
}

/**
 * One page of the merged feed. Parenthesised SELECTs so the trailing ORDER BY
 * applies to the union, not to the last branch.
 *
 * limit/offset are hard-coerced to non-negative ints, so inlining is
 * injection-safe. mysql2 prepared statements reject bound LIMIT/OFFSET on some
 * MySQL builds, hence they are not passed as placeholders.
 */
async function fetchFeedPage(parts, limit, offset) {
  if (parts.length === 0) return [];

  const safeLimit = Math.max(0, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

  const sql =
    parts.map((p) => `(${p.sql})`).join(" UNION ALL ") +
    `
      ORDER BY onboarded_at DESC, kind ASC, key_id ASC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `;

  const params = parts.flatMap((p) => p.params);

  const [rows] = await pool.execute(sql, params);
  return rows;
}

// ─── Page hydration ──────────────────────────────────────────────────────────

/**
 * Clients-owned count per provider code, for the page's providers only.
 * Provider self-test profiles are excluded, so a trainer never counts themselves.
 * Returns Map(UPPER(code) => count).
 */
async function getClientCountsByCode(codes, providerEmails) {
  const map = new Map();
  if (codes.length === 0) return map;

  const inList = codes.map(() => "?").join(",");
  const keepClient = emailKeepClause(providerEmails, "c.email");

  const [rows] = await pool.execute(
    `
      SELECT UPPER(c.dietician_id) AS code, COUNT(*) AS total_clients
      FROM table_clients c
      WHERE UPPER(c.dietician_id) IN (${inList})
        AND ${keepClient.sql}
      GROUP BY UPPER(c.dietician_id)
    `,
    [...codes.map(normalizeCode), ...keepClient.params]
  );

  for (const row of rows) {
    map.set(String(row.code), toInt(row.total_clients));
  }
  return map;
}

/**
 * Test totals per provider code, for the page's providers only. A "test" is
 * 1 per profile per day — the same COUNT(DISTINCT profile_id, DATE(date_time))
 * convention the sibling controllers use. Provider self-tests are excluded.
 * Returns Map(UPPER(code) => { total_tests, total_tested_clients }).
 */
async function getTestCountsByCode(codes, providerEmails) {
  const map = new Map();
  if (codes.length === 0) return map;

  const inCodesA = codes.map(() => "?").join(",");
  const inCodesB = codes.map(() => "?").join(",");
  const keepTest = profileNotProviderClause(providerEmails, "t");

  const normCodes = codes.map(normalizeCode);

  const [rows] = await pool.execute(
    `
      SELECT
        UPPER(t.dietitian_id) AS code,
        COUNT(DISTINCT t.profile_id, DATE(t.date_time)) AS total_tests,
        COUNT(DISTINCT t.profile_id) AS total_tested_clients
      FROM table_test_data t
      WHERE UPPER(t.dietitian_id) IN (${inCodesA})
        AND t.profile_id IN (
              SELECT c.profile_id
              FROM table_clients c
              WHERE UPPER(c.dietician_id) IN (${inCodesB})
        )
        AND ${keepTest.sql}
      GROUP BY UPPER(t.dietitian_id)
    `,
    [...normCodes, ...normCodes, ...keepTest.params]
  );

  for (const row of rows) {
    map.set(String(row.code), {
      total_tests: toInt(row.total_tests),
      total_tested_clients: toInt(row.total_tested_clients),
    });
  }
  return map;
}

/**
 * Each provider's OWN test data (their table_clients row matching their login
 * email), for the page's providers only. Same shape as get_group_details'
 * self_reading. Returns Map(email => { total_tests, latest_date_time, latest_score,
 * profile_id }).
 */
async function getSelfReadingsByEmail(emails) {
  const norm = [
    ...new Set(
      emails
        .filter((e) => e !== null && e !== undefined)
        .map(normalizeEmail)
        .filter((e) => e !== "")
    ),
  ];

  const map = new Map();
  if (norm.length === 0) return map;

  const inList = norm.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        LOWER(TRIM(tc.email)) AS owner_email,
        tc.profile_id,

        (
          SELECT COUNT(DISTINCT DATE(tt.date_time))
          FROM table_test_data tt
          WHERE tt.profile_id = tc.profile_id
            AND UPPER(tt.dietitian_id) = UPPER(tc.dietician_id)
        ) AS total_tests,

        latest.date_time AS latest_date_time,
        latest.fat_loss_metabolism_score AS latest_score

      FROM table_clients tc

      LEFT JOIN table_test_data latest
        ON latest.test_id = (
          SELECT t1.test_id
          FROM table_test_data t1
          WHERE t1.profile_id = tc.profile_id
            AND UPPER(t1.dietitian_id) = UPPER(tc.dietician_id)
          ORDER BY t1.date_time DESC, t1.test_id DESC
          LIMIT 1
        )

      WHERE tc.email IS NOT NULL
        AND TRIM(tc.email) <> ''
        AND LOWER(TRIM(tc.email)) IN (${inList})
    `,
    norm
  );

  for (const row of rows) {
    const email = row.owner_email;
    if (!email) continue;

    if (!map.has(email)) {
      map.set(email, {
        total_tests: 0,
        latest_date_time: null,
        latest_score: null,
        profile_id: null,
      });
    }

    const entry = map.get(email);
    entry.total_tests += toInt(row.total_tests);

    // a provider may have more than one self profile; keep the most recent test.
    if (row.latest_date_time !== null && row.latest_date_time !== undefined) {
      const current = entry.latest_date_time;
      const isNewer =
        current === null ||
        (row.latest_date_time instanceof Date && current instanceof Date
          ? row.latest_date_time.getTime() > current.getTime()
          : String(row.latest_date_time) > String(current));

      if (isNewer) {
        entry.latest_date_time = row.latest_date_time;
        entry.latest_score = row.latest_score;
        entry.profile_id = row.profile_id;
      }
    }
  }

  return map;
}

function buildSelfReading(selfMap, email) {
  const key = email !== null && email !== undefined ? normalizeEmail(email) : "";
  const self = key !== "" ? selfMap.get(key) : undefined;

  if (self) {
    return {
      has_reading: toInt(self.total_tests) > 0,
      profile_id: self.profile_id,
      total_tests: toInt(self.total_tests),
      latest_test: {
        date_time: toMysqlDateTime(self.latest_date_time),
        metabolism_score: scoreValue(self.latest_score),
      },
    };
  }

  return {
    has_reading: false,
    profile_id: null,
    total_tests: 0,
    latest_test: { date_time: null, metabolism_score: null },
  };
}

/** Full client rows for the page's profile_ids. Order is re-applied by the caller. */
async function fetchClientsByProfileIds(profileIds) {
  if (profileIds.length === 0) return [];

  const inList = profileIds.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        tc.profile_id,
        tc.dietician_id,
        tc.profile_name,
        tc.phone_no,
        tc.email,
        tc.age,
        tc.gender,
        tc.height,
        tc.weight,
        tc.region,
        tc.location,
        tc.level_type,
        tc.dttm,

        td.name  AS owner_name,
        td.email AS owner_email,

        IFNULL(uh.goal, '') AS fitness_goal,

        first_test.date_time AS first_test_date_time,

        latest.date_time AS latest_test_date_time,
        latest.fat_loss_metabolism_score AS latest_score,

        (
          SELECT COUNT(DISTINCT DATE(tt.date_time))
          FROM table_test_data tt
          WHERE tt.profile_id = tc.profile_id
            AND UPPER(tt.dietitian_id) = UPPER(tc.dietician_id)
        ) AS total_tests

      FROM table_clients tc

      LEFT JOIN table_dietician td
        ON UPPER(td.dietician_id) = UPPER(tc.dietician_id)

      LEFT JOIN (
        SELECT uh1.profile_id, uh1.goal
        FROM user_habits uh1
        INNER JOIN (
          SELECT profile_id, MAX(id) AS max_id
          FROM user_habits
          GROUP BY profile_id
        ) uh2
          ON uh1.id = uh2.max_id
      ) uh
        ON uh.profile_id = tc.profile_id

      LEFT JOIN table_test_data latest
        ON latest.test_id = (
          SELECT t1.test_id
          FROM table_test_data t1
          WHERE t1.profile_id = tc.profile_id
            AND UPPER(t1.dietitian_id) = UPPER(tc.dietician_id)
          ORDER BY t1.date_time DESC, t1.test_id DESC
          LIMIT 1
        )

      LEFT JOIN table_test_data first_test
        ON first_test.test_id = (
          SELECT t2.test_id
          FROM table_test_data t2
          WHERE t2.profile_id = tc.profile_id
            AND UPPER(t2.dietitian_id) = UPPER(tc.dietician_id)
          ORDER BY t2.date_time ASC, t2.test_id ASC
          LIMIT 1
        )

      WHERE tc.profile_id IN (${inList})
    `,
    profileIds.map((id) => String(id))
  );

  return rows;
}

/** MASKED onboarded-client entry. */
function formatClientEntry(row) {
  const totalTests = toInt(row.total_tests);

  return {
    kind: "client",
    profile_id: row.profile_id,
    dietician_id: row.dietician_id,
    profile_name: maskName(row.profile_name),
    phone_no: row.phone_no,
    email: maskEmail(row.email),
    age: row.age,
    gender: cleanValue(row.gender),
    height: cleanValue(row.height),
    weight: cleanValue(row.weight),
    region: row.region,
    location: row.location,
    level_type: cleanValue(row.level_type),
    fitness_goal: cleanValue(row.fitness_goal),

    onboarded_at: toMysqlDateTime(row.dttm),
    days_since_onboarding: daysSince(row.dttm),

    owner: {
      partner_code: row.dietician_id,
      name: cleanValue(row.owner_name),
      email:
        row.owner_email !== null && row.owner_email !== undefined
          ? maskEmail(normalizeEmail(row.owner_email))
          : null,
    },

    // Activation signal: did this onboarded client ever actually test?
    activated: totalTests > 0,
    first_test_at: toMysqlDateTime(row.first_test_date_time),
    total_tests: totalTests,

    latest_test: {
      date_time: toMysqlDateTime(row.latest_test_date_time),
      metabolism_score: scoreValue(row.latest_score),
    },
  };
}

/** Onboarded provider (admin/trainer) entry. Providers are staff, so not masked. */
function formatProviderEntry(provider, clientCounts, testCounts, selfMap) {
  const code = normalizeCode(provider.partner_code);
  const tests = testCounts.get(code) || { total_tests: 0, total_tested_clients: 0 };

  return {
    kind: "provider",
    partner_code: provider.partner_code,
    dietician_id: provider.dietician_id ?? null,
    name: provider.name,
    email: provider.email,
    role: provider.role,
    parent_admin_email: provider.parent_admin_email,
    status: provider.status,

    onboarded_at: toMysqlDateTime(provider.created_at),
    days_since_onboarding: daysSince(provider.created_at),

    total_clients: toInt(clientCounts.get(code)),
    total_tests: tests.total_tests,
    total_tested_clients: tests.total_tested_clients,

    self_reading: buildSelfReading(selfMap, provider.email ?? null),
  };
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(req) {
  const src = req.body && typeof req.body === "object" ? req.body : {};

  let page = parseInt(src.page, 10);
  if (!Number.isFinite(page) || page <= 0) page = 1;

  let limit = parseInt(src.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > MAX_LIMIT) {
    limit = DEFAULT_LIMIT;
  }

  const search = typeof src.search === "string" ? src.search.trim() : "";
  const groupName = typeof src.group_name === "string" ? src.group_name.trim() : "";

  // Optional. Accepted for frontend/back-compat, never authoritative — see the
  // cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);

  const typeRaw = String(src.type ?? "all").trim().toLowerCase();
  const type = ALLOWED_TYPES.has(typeRaw) ? typeRaw : "all";

  // Optional scope: restrict the feed to ONE network code's subtree.
  const memberCode = normalizeCode(src.member);

  return {
    page,
    limit,
    search,
    groupName,
    actorUserId,
    type,
    memberCode,
    typeRaw,
    dateFromRaw: String(src.date_from ?? "").trim(),
    dateToRaw: String(src.date_to ?? "").trim(),
    offset: (page - 1) * limit,
  };
}

/**
 * Window rules:
 *   date_from and/or date_to sent -> that range (a missing side defaults to the other)
 *   neither                       -> the last DEFAULT_WINDOW_DAYS days, ending today (IST)
 * Returns { from, to } or { error: { status, body } }.
 */
function resolveWindow({ dateFromRaw, dateToRaw }) {
  const fail = (message) => ({
    error: { status: 422, body: { status: false, ok: false, message } },
  });

  let from;
  let to;

  if (dateFromRaw !== "" || dateToRaw !== "") {
    from = dateFromRaw !== "" ? validDateYmd(dateFromRaw) : null;
    to = dateToRaw !== "" ? validDateYmd(dateToRaw) : null;

    if (dateFromRaw !== "" && from === null) {
      return fail("date_from must be a valid YYYY-MM-DD date");
    }
    if (dateToRaw !== "" && to === null) {
      return fail("date_to must be a valid YYYY-MM-DD date");
    }

    if (from === null) from = to;
    if (to === null) to = from;

    if (from > to) return fail("date_from cannot be after date_to");
  } else {
    to = todayDateIST();
    from = shiftDaysYmd(to, -(DEFAULT_WINDOW_DAYS - 1));
  }

  if (daysBetweenInclusive(from, to) > MAX_RANGE_DAYS) {
    return fail(`date range cannot exceed ${MAX_RANGE_DAYS} days`);
  }

  return { from, to };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get_group_onboarding
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "group_name": "USA (Evan & Derek)",   // required
 *     "date_from": "2026-06-20",            // optional; default = last 30 days
 *     "date_to": "2026-07-20",              // optional
 *     "type": "all",                        // optional: all | trainer | client
 *     "member": "RESPYRD06",                // optional; scope to ONE network code's subtree
 *     "page": 1,                            // optional, default 1
 *     "limit": 10,                          // optional, default 10, max 50
 *     "search": "",                         // optional
 *     "actor_user_id": ""                   // optional; if set, must match token
 *   }
 */
const getGroupOnboarding = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate.
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const inputs = parseInputs(req);
  const { page, limit, search, groupName, actorUserId, type, memberCode, offset } = inputs;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "group_onboarding_denied",
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
    actorCode = normalizeCode(getActorEffectiveCode(actor));

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "group_onboarding_denied",
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

    // ── 1c. Required input ──────────────────────────────────────────────────
    if (groupName === "") {
      return res.status(422).json({ status: false, ok: false, message: "group_name is required" });
    }

    // ── 1d. Window (validated before it can reach SQL) ──────────────────────
    const window = resolveWindow(inputs);
    if (window.error) {
      return res.status(window.error.status).json(window.error.body);
    }
    const { from: dateFrom, to: dateTo } = window;

    const fromDt = `${dateFrom} 00:00:00`;
    const toDtExclusive = `${shiftDaysYmd(dateTo, 1)} 00:00:00`;

    // ── 2. Group members ────────────────────────────────────────────────────
    const memberCodes = await getGroupMemberCodes(groupName);

    if (memberCodes.length === 0) {
      await writeAuthLogSafe(req, {
        eventType: "group_onboarding_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: groupName,
        success: false,
        failureReason: "Group not found or has no active members",
      });
      return res.status(404).json({
        status: false,
        ok: false,
        message: "Group not found or has no active members",
      });
    }

    // ── 2b. RBAC: super_admin, OR an admin who is a member of this group ─────
    const isSuperAdmin = actorRole === "super_admin";
    if (!isSuperAdmin && !memberCodes.includes(actorCode)) {
      await writeAuthLogSafe(req, {
        eventType: "group_onboarding_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: groupName,
        success: false,
        failureReason: "Actor is not a member of this group",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "You are not a member of this group",
      });
    }

    // ── 3. Network = the group's admins + their trainers ────────────────────
    const admins = await getGroupAdmins(memberCodes);

    const adminEmails = admins
      .map((a) => a.email)
      .filter((e) => e !== null && e !== undefined && String(e).trim() !== "");

    const trainers = await getGroupTrainers(adminEmails);

    let providers = [...admins, ...trainers];

    // network codes = admin codes ∪ trainer codes (de-duplicated, UPPER)
    const networkCodesMap = new Map();
    for (const c of memberCodes) {
      const code = normalizeCode(c);
      if (code !== "") networkCodesMap.set(code, code);
    }
    for (const p of providers) {
      const code = normalizeCode(p.partner_code);
      if (code !== "") networkCodesMap.set(code, code);
    }
    let networkCodes = [...networkCodesMap.values()];

    // ── 3b. Optional single-member scope ────────────────────────────────────
    // An ADMIN code scopes to that admin + their child trainers; a TRAINER code
    // scopes to that trainer alone. The code must belong to this group's network,
    // otherwise 404 — this is also the authz gate that stops `member` from
    // reading outside the group.
    let scope = { type: "group", partner_code: null, name: null };

    if (memberCode !== "") {
      if (!networkCodes.includes(memberCode)) {
        await writeAuthLogSafe(req, {
          eventType: "group_onboarding_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: memberCode,
          success: false,
          failureReason: "member is not part of this group",
        });
        return res.status(404).json({
          status: false,
          ok: false,
          message: "member is not part of this group",
        });
      }

      const target = providers.find((p) => normalizeCode(p.partner_code) === memberCode);
      const targetEmail = target ? target.email : null;

      if (memberCodes.includes(memberCode)) {
        // admin subtree: the admin + their child trainers
        providers = providers.filter((p) => {
          if (normalizeCode(p.partner_code) === memberCode) return true;
          return (
            p.parent_admin_email !== null &&
            targetEmail !== null &&
            normalizeEmail(p.parent_admin_email) === normalizeEmail(targetEmail)
          );
        });
        scope = { type: "member", partner_code: memberCode, name: target ? target.name : null };
      } else {
        // single trainer
        providers = providers.filter((p) => normalizeCode(p.partner_code) === memberCode);
        scope = { type: "trainer", partner_code: memberCode, name: target ? target.name : null };
      }

      networkCodes = [
        ...new Set(providers.map((p) => normalizeCode(p.partner_code)).filter((c) => c !== "")),
      ];
    }

    // Every provider email in the (possibly scoped) network. Used both as the
    // provider-feed key set and as the self-test exclusion set for clients.
    const providerEmails = [
      ...new Set(
        providers
          .map((p) => p.email)
          .filter((e) => e !== null && e !== undefined && String(e).trim() !== "")
          .map(normalizeEmail)
      ),
    ];

    // ── 4. Build + count the feed ───────────────────────────────────────────
    const escapedSearch = search !== "" ? escapeLike(search) : "";

    const wantProviders = type === "all" || type === "trainer";
    const wantClients = type === "all" || type === "client";

    const parts = [];

    const providerPart =
      wantProviders && providerEmails.length > 0
        ? providerFeedPart(providerEmails, escapedSearch, fromDt, toDtExclusive)
        : null;

    const clientPart =
      wantClients && networkCodes.length > 0
        ? clientFeedPart(networkCodes, providerEmails, escapedSearch, fromDt, toDtExclusive)
        : null;

    if (providerPart) parts.push(providerPart);
    if (clientPart) parts.push(clientPart);

    const newProviders = providerPart ? await countFeedPart(providerPart) : 0;
    const newClients = clientPart ? await countFeedPart(clientPart) : 0;
    const total = newProviders + newClients;

    const feedRows = await fetchFeedPage(parts, limit, offset);

    // ── 5. Hydrate this page only ───────────────────────────────────────────
    const pageProviderEmails = feedRows
      .filter((r) => r.kind === "provider")
      .map((r) => normalizeEmail(r.key_id));

    const pageProviders = pageProviderEmails
      .map((email) => providers.find((p) => normalizeEmail(p.email ?? "") === email))
      .filter(Boolean);

    const pageProviderCodes = [
      ...new Set(pageProviders.map((p) => normalizeCode(p.partner_code)).filter((c) => c !== "")),
    ];

    const pageProfileIds = feedRows
      .filter((r) => r.kind === "client")
      .map((r) => String(r.key_id));

    const [clientCounts, testCounts, selfMap, clientRows] = await Promise.all([
      getClientCountsByCode(pageProviderCodes, providerEmails),
      getTestCountsByCode(pageProviderCodes, providerEmails),
      getSelfReadingsByEmail(pageProviders.map((p) => p.email)),
      fetchClientsByProfileIds(pageProfileIds),
    ]);

    const providerByEmail = new Map(
      pageProviders.map((p) => [normalizeEmail(p.email ?? ""), p])
    );
    const clientByProfileId = new Map(clientRows.map((r) => [String(r.profile_id), r]));

    // Re-apply the feed's ordering — the hydration queries returned unordered sets.
    const items = [];
    for (const row of feedRows) {
      if (row.kind === "provider") {
        const provider = providerByEmail.get(normalizeEmail(row.key_id));
        if (provider) {
          items.push(formatProviderEntry(provider, clientCounts, testCounts, selfMap));
        }
      } else {
        const client = clientByProfileId.get(String(row.key_id));
        if (client) {
          items.push(formatClientEntry(client));
        }
      }
    }

    // ── 6. Audit the read (fire-and-forget) ─────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "group_onboarding_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier:
        "group:" + groupName + "|window:" + dateFrom + ".." + dateTo +
        "|type:" + type + "|page:" + page + "|search:" + search +
        "|scope:" + scope.type + (memberCode !== "" ? ":" + memberCode : "") +
        "|masked:true",
      success: true,
      failureReason: "Group onboarding roster viewed (client identity masked)",
    });

    // ── 7. Respond ──────────────────────────────────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Group onboarding fetched successfully",
      group_name: groupName,

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
      },

      window: {
        date_from: dateFrom,
        date_to: dateTo,
        days: daysBetweenInclusive(dateFrom, dateTo),
        type,
        scope,
      },

      group_member_codes: memberCodes,
      network_codes: networkCodes,

      // onboarded INSIDE the window (not the group's lifetime totals)
      counts: {
        new_trainers: newProviders,
        new_clients: newClients,
        total,
      },

      pagination: {
        page,
        limit,
        offset,
        total,
        has_more: offset + limit < total,
      },

      // merged feed, newest onboarding first
      items,
    });
  } catch (err) {
    console.error("GET_GROUP_ONBOARDING_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "group_onboarding_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: groupName,
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

module.exports = { getGroupOnboarding };
