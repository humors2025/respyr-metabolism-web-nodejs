"use strict";

/**
 * get_group_period_readers.js
 *
 * Platform : Respyr Dietitian API (api.respyr.ai)
 * Security : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get_group_period_readers
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin who is a member of the requested group
 *
 * Purpose. The Period Overview donut on /super-admin/analytics shows COUNTS
 * of trainer vs client readings (from get_group_details -> period_overview).
 * This endpoint answers the follow-up question: WHO are those readers?
 *
 * It returns, for a date window and the same optional member/trainer scope:
 *   - trainer_readers : providers (admins + trainers) who took a SELF reading
 *                       in the window, each with reads (distinct days),
 *                       first/last reading time
 *   - client_readers  : real client profiles (self profiles excluded) that
 *                       took a reading in the window, MASKED, paginated,
 *                       each with reads (distinct days), first/last reading time
 *
 * Reading convention (identical to get_group_details / total_tests):
 *   1 reading = 1 per profile per day  ->  COUNT(DISTINCT profile_id, DATE(date_time))
 * so summing each row's `reads` reproduces the period_overview counts exactly:
 *   sum(trainer_readers[].reads) === period_overview.trainer_readings
 *   sum over ALL client readers    === period_overview.client_readings
 *
 * Window rules (same as get_group_details period_overview):
 *   overview_date sent       -> that single day
 *   else overview_from/_to   -> that range (a missing side defaults to the other)
 *   else                     -> today (Asia/Kolkata)
 * NOTE: unlike the counts flow (which fans out one call per day from the
 * frontend), a week/month here is ONE call with overview_from/overview_to.
 *
 * Scope rules (same as get_group_details):
 *   overview_member omitted  -> whole group network
 *   ADMIN member code        -> that admin + their child trainers + their clients
 *   TRAINER code             -> that trainer + their own clients
 *   code outside the network -> 404 (authz gate)
 *
 * type: "all" (default) | "trainers" | "clients" — which list(s) to compute.
 *
 * VAPT hardening:
 *  - Token-bound identity (JWT sub = dietician_id, re-verified against DB).
 *    body.actor_user_id accepted for back-compat, cross-checked only (403 on
 *    mismatch) — it can never select a different user.
 *  - RBAC: super_admin, or an admin who is a member of the group. overview_member
 *    must be inside the group's network (else 404) so it cannot read outside it.
 *  - Every IN (...) uses placeholders; LIMIT/OFFSET are hard-coerced integers
 *    (mysql2 rejects bound LIMIT/OFFSET on some MySQL builds).
 *  - overview_* dates strictly validated (real calendar dates) and the span is
 *    capped at MAX_OVERVIEW_RANGE_DAYS to prevent unbounded scans.
 *  - LIKE wildcards in the client search term are escaped.
 *  - Errors are generic in production (APP_DEBUG-gated); logs carry metadata only.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - No session time_zone mutation (shared pool). DATE() bucketing uses the DB
 *    clock; the DEFAULT day is app-computed in IST (todayDateIST) — the same
 *    documented approach as get_group_details.js.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT * over PHI rows.
 *  - Client profile_name/email are MASKED (maskName/maskEmail). Provider emails
 *    are MASKED in the response too (the dashboard only needs name + code).
 *  - PHI in audit logs is HMAC-SHA256 hashed with SECURITY_PEPPER.
 *  - Every read is recorded in app_auth_logs.
 *
 * Tables touched (nothing new): table_dietician, app_user_roles, ta_admin_groups,
 * table_clients, table_test_data, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["admin", "super_admin"]);

// client_readers pagination (trainer list is naturally small — never paginated)
const MAX_LIMIT = 100;
const DEFAULT_LIMIT = 50;

// VAPT: bound the scan window (same rationale as get_group_details.js).
const MAX_OVERVIEW_RANGE_DAYS = 366;

// ─── Generic helpers (ported from get_group_details.js) ──────────────────────

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

function cleanValue(val, def = "NA") {
  if (val === null || val === undefined) return def;
  const str = String(val).trim();
  return str === "" ? def : str;
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

/** Strictly validate a YYYY-MM-DD string; impossible calendar dates rejected. */
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

/** The next calendar day of a validated YYYY-MM-DD. */
function nextDayYmd(ymd) {
  const d = new Date(`${ymd}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

/** Inclusive whole-day span between two validated YYYY-MM-DD strings. */
function daysBetweenInclusive(fromYmd, toYmd) {
  const from = new Date(`${fromYmd}T00:00:00Z`).getTime();
  const to = new Date(`${toYmd}T00:00:00Z`).getTime();
  return Math.floor((to - from) / 86400000) + 1;
}

/** maskName(): keep first TWO & last letter of each word, star the middle. */
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

/** maskEmail(): star the middle of the local part, keep the full domain. */
function maskEmail(email) {
  if (email === null || email === undefined) return null;

  const str = String(email).trim();
  if (str === "" || str.indexOf("@") === -1) return str;

  const atPos = str.lastIndexOf("@");
  const local = str.slice(0, atPos);
  const domain = str.slice(atPos);

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

// ─── Audit log ───────────────────────────────────────────────────────────────

/** Fail-safe audit writer. Never throws. */
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
    console.error("GET_GROUP_PERIOD_READERS_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Identical to get_group_details.js.
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
        body: { status: false, ok: false, message: "Only an admin can view period readers" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Group data (lightweight — identity only, no count subqueries) ───────────

/** Active member codes (UPPER) of the group. */
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

/** Member (admin) identity rows for the group's codes — no heavy counts. */
async function getMembersLite(codes) {
  if (codes.length === 0) return [];

  const inList = codes.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        td.dietician_id,
        td.name,
        td.email,
        aur.role,
        aur.partner_code
      FROM table_dietician td
      LEFT JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE UPPER(td.dietician_id) IN (${inList})
    `,
    codes.map(normalizeCode)
  );

  const members = [];
  for (const row of rows) {
    let partnerCode = row.partner_code;
    if (partnerCode === null || partnerCode === undefined || String(partnerCode).trim() === "") {
      partnerCode = row.dietician_id;
    }

    members.push({
      dietician_id: row.dietician_id,
      partner_code: partnerCode,
      name: cleanValue(row.name),
      email: row.email !== null && row.email !== undefined ? normalizeEmail(row.email) : null,
      role: row.role !== null && row.role !== undefined ? row.role : "admin",
      parent_admin_email: null,
    });
  }
  return members;
}

/** Active child trainers under the given admin emails — identity only. */
async function getChildTrainersLite(adminEmails) {
  if (adminEmails.length === 0) return [];

  const inList = adminEmails.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        aur.partner_code,
        aur.user_id AS email,
        aur.parent_user_id,
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

  const trainers = [];
  for (const row of rows) {
    let code = row.partner_code;
    if (code === null || code === undefined || String(code).trim() === "") {
      code = row.dietician_id;
    }

    trainers.push({
      partner_code: code,
      name: cleanValue(row.name),
      email: row.email !== null && row.email !== undefined ? normalizeEmail(row.email) : null,
      role: "trainer",
      parent_admin_email:
        row.parent_user_id !== null && row.parent_user_id !== undefined
          ? normalizeEmail(row.parent_user_id)
          : null,
    });
  }
  return trainers;
}

// ─── Period readers ──────────────────────────────────────────────────────────

/**
 * Providers (admins/trainers) who took a SELF reading in the window.
 *
 * Same self-profile matching as get_group_details.getPeriodOverview() /
 * getSelfReadingsByEmail(): a self profile is a table_clients row whose email is
 * one of the scope's provider emails AND whose dietician_id matches the test's
 * dietitian_id. Grouped per provider email; reads = distinct (profile, day), so
 * the SUM of `reads` across rows === period_overview.trainer_readings.
 */
async function getTrainerReaders(providerEmails, dateFrom, dateTo) {
  const emails = [
    ...new Set(
      providerEmails
        .filter((e) => e !== null && e !== undefined)
        .map(normalizeEmail)
        .filter((e) => e !== "")
    ),
  ];

  if (emails.length === 0) return [];

  const inEmails = emails.map(() => "?").join(",");

  const fromDt = `${dateFrom} 00:00:00`;
  const toDtExclusive = `${nextDayYmd(dateTo)} 00:00:00`;

  const [rows] = await pool.execute(
    `
      SELECT
        LOWER(TRIM(sc.email))                              AS provider_email,
        COUNT(DISTINCT sc.profile_id, DATE(t.date_time))   AS read_count,
        MIN(t.date_time)                                   AS first_reading_at,
        MAX(t.date_time)                                   AS last_reading_at
      FROM table_test_data t
      INNER JOIN table_clients sc
        ON sc.profile_id = t.profile_id
       AND UPPER(sc.dietician_id) = UPPER(t.dietitian_id)
      WHERE sc.email IS NOT NULL
        AND TRIM(sc.email) <> ''
        AND LOWER(TRIM(sc.email)) IN (${inEmails})
        AND t.date_time >= ?
        AND t.date_time < ?
      GROUP BY LOWER(TRIM(sc.email))
      ORDER BY last_reading_at DESC
    `,
    [...emails, fromDt, toDtExclusive]
  );

  return rows.map((row) => ({
    provider_email: row.provider_email,
    reads: toInt(row.read_count),
    first_reading_at: toMysqlDateTime(row.first_reading_at),
    last_reading_at: toMysqlDateTime(row.last_reading_at),
  }));
}

/** Shared WHERE for the client-readers queries. Returns { sql, params }. */
function buildClientReadersWhere(codes, providerEmails, dateFrom, dateTo, escapedSearch) {
  const normCodes = codes.map(normalizeCode);
  const inCodesA = normCodes.map(() => "?").join(",");
  const inCodesB = normCodes.map(() => "?").join(",");

  const fromDt = `${dateFrom} 00:00:00`;
  const toDtExclusive = `${nextDayYmd(dateTo)} 00:00:00`;

  // exclude self (provider) profiles — same clause as getPeriodOverview()
  const emails = [
    ...new Set(
      providerEmails
        .filter((e) => e !== null && e !== undefined)
        .map(normalizeEmail)
        .filter((e) => e !== "")
    ),
  ];

  let selfExcludeSql = "1=1";
  let selfExcludeParams = [];

  if (emails.length > 0) {
    const inSelf = emails.map(() => "?").join(",");
    selfExcludeSql = `t.profile_id NOT IN (
            SELECT sc2.profile_id
            FROM table_clients sc2
            WHERE sc2.email IS NOT NULL
              AND TRIM(sc2.email) <> ''
              AND LOWER(TRIM(sc2.email)) IN (${inSelf})
        )`;
    selfExcludeParams = emails;
  }

  // optional search over the client's identifying columns (server-side, raw
  // values — the response stays masked). Wildcards in the term are escaped.
  let searchSql = "";
  let searchParams = [];
  if (escapedSearch !== "") {
    searchSql = `
      AND t.profile_id IN (
            SELECT cs.profile_id
            FROM table_clients cs
            WHERE UPPER(cs.dietician_id) IN (${inCodesB})
              AND (
                LOWER(cs.profile_id) LIKE LOWER(?)
                OR LOWER(COALESCE(cs.profile_name, '')) LIKE LOWER(?)
                OR LOWER(COALESCE(cs.email, '')) LIKE LOWER(?)
              )
      )`;
    const like = `%${escapedSearch}%`;
    searchParams = [...normCodes, like, like, like];
  }

  const sql = `
      UPPER(t.dietitian_id) IN (${inCodesA})
      AND t.date_time >= ?
      AND t.date_time < ?
      AND t.profile_id IN (
            SELECT c.profile_id
            FROM table_clients c
            WHERE UPPER(c.dietician_id) IN (${inCodesB})
      )
      AND ${selfExcludeSql}
      ${searchSql}
  `;

  const params = [
    ...normCodes,
    fromDt,
    toDtExclusive,
    ...normCodes,
    ...selfExcludeParams,
    ...searchParams,
  ];

  return { sql, params };
}

/** Distinct client profiles with >= 1 reading in the window (for pagination). */
async function countClientReaders(codes, providerEmails, dateFrom, dateTo, escapedSearch) {
  if (codes.length === 0) return 0;

  const where = buildClientReadersWhere(codes, providerEmails, dateFrom, dateTo, escapedSearch);

  const [rows] = await pool.execute(
    `SELECT COUNT(DISTINCT t.profile_id) AS cnt
     FROM table_test_data t
     WHERE ${where.sql}`,
    where.params
  );

  return toInt(rows[0]?.cnt);
}

/**
 * One row per client profile that took a reading in the window, newest first.
 * reads = distinct days in the window, so summing `reads` over ALL pages
 * reproduces period_overview.client_readings exactly.
 */
async function fetchClientReaders(codes, providerEmails, dateFrom, dateTo, escapedSearch, limit, offset) {
  if (codes.length === 0) return [];

  const where = buildClientReadersWhere(codes, providerEmails, dateFrom, dateTo, escapedSearch);

  // LIMIT/OFFSET inlined after hard integer coercion (mysql2 prepared statements
  // reject bound LIMIT/OFFSET on some MySQL builds) — same as sibling controllers.
  const safeLimit = Math.max(1, Math.min(MAX_LIMIT, toInt(limit) || DEFAULT_LIMIT));
  const safeOffset = Math.max(0, toInt(offset));

  const [rows] = await pool.execute(
    `
      SELECT
        t.profile_id,
        UPPER(t.dietitian_id)                 AS dietitian_id,
        COUNT(DISTINCT DATE(t.date_time))     AS read_count,
        MIN(t.date_time)                      AS first_reading_at,
        MAX(t.date_time)                      AS last_reading_at
      FROM table_test_data t
      WHERE ${where.sql}
      GROUP BY t.profile_id, UPPER(t.dietitian_id)
      ORDER BY last_reading_at DESC
      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    where.params
  );

  return rows.map((row) => ({
    profile_id: row.profile_id,
    dietitian_id: row.dietitian_id,
    reads: toInt(row.read_count),
    first_reading_at: toMysqlDateTime(row.first_reading_at),
    last_reading_at: toMysqlDateTime(row.last_reading_at),
  }));
}

/** MASKED identity (name/email) for a page of client profile_ids. */
async function getClientIdentities(profileIds) {
  if (profileIds.length === 0) return new Map();

  const inList = profileIds.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT
        tc.profile_id,
        tc.profile_name,
        tc.email,
        UPPER(tc.dietician_id) AS dietician_id
      FROM table_clients tc
      WHERE tc.profile_id IN (${inList})
    `,
    profileIds
  );

  const map = new Map();
  for (const row of rows) {
    // a profile_id can appear under more than one code; first row wins, matching
    // the fetch above which groups per (profile, code).
    const key = `${row.profile_id}|${row.dietician_id}`;
    if (!map.has(key)) {
      map.set(key, {
        profile_name: maskName(cleanValue(row.profile_name, "")),
        email: maskEmail(row.email),
      });
    }
    // also index by bare profile_id as a fallback
    if (!map.has(row.profile_id)) {
      map.set(row.profile_id, {
        profile_name: maskName(cleanValue(row.profile_name, "")),
        email: maskEmail(row.email),
      });
    }
  }
  return map;
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

  // Optional. Back-compat only — cross-checked against the token, never authoritative.
  const actorUserId = normalizeEmail(src.actor_user_id);

  const overviewMember = normalizeCode(src.overview_member);
  const overviewDateRaw = String(src.overview_date ?? "").trim();
  const overviewFromRaw = String(src.overview_from ?? "").trim();
  const overviewToRaw = String(src.overview_to ?? "").trim();

  let type = String(src.type ?? "all").trim().toLowerCase();
  if (!["all", "trainers", "clients"].includes(type)) type = "all";

  return {
    page,
    limit,
    search,
    groupName,
    actorUserId,
    overviewMember,
    overviewDateRaw,
    overviewFromRaw,
    overviewToRaw,
    type,
    offset: (page - 1) * limit,
  };
}

/** Same window rules as get_group_details.resolveOverviewRange(). */
function resolveOverviewRange({ overviewDateRaw, overviewFromRaw, overviewToRaw }) {
  const fail = (message) => ({
    error: { status: 422, body: { status: false, ok: false, message } },
  });

  let from;
  let to;

  if (overviewDateRaw !== "") {
    from = validDateYmd(overviewDateRaw);
    if (from === null) return fail("overview_date must be a valid YYYY-MM-DD date");
    to = from;
  } else if (overviewFromRaw !== "" || overviewToRaw !== "") {
    from = overviewFromRaw !== "" ? validDateYmd(overviewFromRaw) : null;
    to = overviewToRaw !== "" ? validDateYmd(overviewToRaw) : null;

    if (overviewFromRaw !== "" && from === null) {
      return fail("overview_from must be a valid YYYY-MM-DD date");
    }
    if (overviewToRaw !== "" && to === null) {
      return fail("overview_to must be a valid YYYY-MM-DD date");
    }

    if (from === null) from = to;
    if (to === null) to = from;

    if (from > to) return fail("overview_from cannot be after overview_to");
  } else {
    from = todayDateIST();
    to = from;
  }

  if (daysBetweenInclusive(from, to) > MAX_OVERVIEW_RANGE_DAYS) {
    return fail(`overview range cannot exceed ${MAX_OVERVIEW_RANGE_DAYS} days`);
  }

  return { from, to };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get_group_period_readers
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "group_name": "USA (Evan & Derek)",   // required
 *     "overview_date": "2026-07-27",         // optional; ONE day
 *     "overview_from": "2026-07-01",         // optional; range start
 *     "overview_to": "2026-07-27",           // optional; range end
 *     "overview_member": "RESPYRD06",        // optional; member/trainer scope
 *     "type": "all",                          // optional; all|trainers|clients
 *     "page": 1,                              // optional; client_readers page
 *     "limit": 50,                            // optional; default 50, max 100
 *     "search": "",                           // optional; filters client readers
 *     "actor_user_id": ""                     // optional; if set, must match token
 *   }
 */
const getGroupPeriodReaders = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const inputs = parseInputs(req);
  const {
    page, limit, search, groupName, actorUserId, overviewMember, type, offset,
  } = inputs;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "period_readers_denied",
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
        eventType: "period_readers_denied",
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
    const range = resolveOverviewRange(inputs);
    if (range.error) {
      return res.status(range.error.status).json(range.error.body);
    }
    const { from: dateFrom, to: dateTo } = range;

    // ── 2. Group members ────────────────────────────────────────────────────
    const memberCodes = await getGroupMemberCodes(groupName);

    if (memberCodes.length === 0) {
      await writeAuthLogSafe(req, {
        eventType: "period_readers_denied",
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
        eventType: "period_readers_denied",
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

    // ── 3. Network (members + child trainers, identity only) ────────────────
    const members = await getMembersLite(memberCodes);
    const memberEmails = members
      .map((m) => m.email)
      .filter((e) => e !== null && e !== "");

    const childTrainers = await getChildTrainersLite(memberEmails);

    // Providers = the group's admins + their child trainers (admins appear as
    // provider entries too — same as get_group_details' trainers list).
    const providers = [...members, ...childTrainers];

    const networkCodesMap = new Map();
    for (const c of memberCodes) {
      const code = normalizeCode(c);
      if (code !== "") networkCodesMap.set(code, code);
    }
    for (const p of providers) {
      const code = normalizeCode(p.partner_code);
      if (code !== "") networkCodesMap.set(code, code);
    }
    const networkCodes = [...networkCodesMap.values()];

    // ── 4. Optional member/trainer scope (same rules + 404 gate as details) ──
    let scopeCodes = networkCodes;
    let scopeEmails = providers
      .map((p) => p.email)
      .filter((e) => e !== null && e !== undefined && String(e).trim() !== "");
    let scope = { type: "group", partner_code: null, name: null };

    if (overviewMember !== "") {
      if (!networkCodes.includes(overviewMember)) {
        await writeAuthLogSafe(req, {
          eventType: "period_readers_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: overviewMember,
          success: false,
          failureReason: "overview_member is not part of this group",
        });
        return res.status(404).json({
          status: false,
          ok: false,
          message: "overview_member is not part of this group",
        });
      }

      if (memberCodes.includes(overviewMember)) {
        // ---- admin member: self + child trainers ----
        const member = members.find(
          (m) =>
            normalizeCode(m.partner_code) === overviewMember ||
            normalizeCode(m.dietician_id) === overviewMember
        );

        const memberEmail = member ? member.email : null;
        const memberName = member ? member.name : null;

        const sCodes = new Map([[overviewMember, overviewMember]]);
        const sEmails = new Map();

        if (memberEmail !== null && memberEmail !== "") {
          sEmails.set(memberEmail, memberEmail);
        }

        for (const t of childTrainers) {
          const parent = t.parent_admin_email ?? null;
          if (
            parent !== null &&
            memberEmail !== null &&
            normalizeEmail(parent) === normalizeEmail(memberEmail)
          ) {
            const tc = normalizeCode(t.partner_code);
            if (tc !== "") sCodes.set(tc, tc);

            if (t.email !== null && t.email !== undefined && String(t.email).trim() !== "") {
              const te = normalizeEmail(t.email);
              sEmails.set(te, te);
            }
          }
        }

        scopeCodes = [...sCodes.values()];
        scopeEmails = [...sEmails.values()];
        scope = { type: "member", partner_code: overviewMember, name: memberName };
      } else {
        // ---- single trainer scope ----
        const trainer = providers.find(
          (t) => normalizeCode(t.partner_code) === overviewMember
        );

        const trainerEmail = trainer ? trainer.email ?? null : null;
        const trainerName = trainer ? trainer.name ?? null : null;

        scopeCodes = [overviewMember];
        scopeEmails =
          trainerEmail !== null && String(trainerEmail).trim() !== ""
            ? [normalizeEmail(trainerEmail)]
            : [];
        scope = { type: "trainer", partner_code: overviewMember, name: trainerName };
      }
    }

    // ── 5. Trainer readers (providers with a self reading in the window) ─────
    let trainerReaders = [];
    let trainerReadings = 0;

    if (type === "all" || type === "trainers") {
      const rawTrainerReaders = await getTrainerReaders(scopeEmails, dateFrom, dateTo);

      // attach provider identity (name / code / role) by email; emails masked out.
      const byEmail = new Map();
      for (const p of providers) {
        if (p.email !== null && p.email !== "" && !byEmail.has(p.email)) {
          byEmail.set(p.email, p);
        }
      }

      trainerReaders = rawTrainerReaders.map((r) => {
        const p = byEmail.get(r.provider_email) || null;
        return {
          partner_code: p ? p.partner_code : null,
          name: p ? p.name : "NA",
          email: maskEmail(r.provider_email),
          role: p ? p.role : "trainer",
          reads: r.reads,
          first_reading_at: r.first_reading_at,
          last_reading_at: r.last_reading_at,
        };
      });

      trainerReadings = trainerReaders.reduce((s, r) => s + r.reads, 0);
    }

    // ── 6. Client readers (masked, paginated) ────────────────────────────────
    let clientReaders = [];
    let totalClientReaders = 0;
    let clientReadings = 0;
    const escapedSearch = search !== "" ? escapeLike(search) : "";

    if (type === "all" || type === "clients") {
      totalClientReaders = await countClientReaders(
        scopeCodes, scopeEmails, dateFrom, dateTo, escapedSearch
      );

      const rows = await fetchClientReaders(
        scopeCodes, scopeEmails, dateFrom, dateTo, escapedSearch, limit, offset
      );

      const identities = await getClientIdentities(rows.map((r) => r.profile_id));

      clientReaders = rows.map((r) => {
        const idn =
          identities.get(`${r.profile_id}|${r.dietitian_id}`) ||
          identities.get(r.profile_id) ||
          { profile_name: "NA", email: null };

        return {
          profile_id: r.profile_id,
          profile_name: idn.profile_name === "" ? "NA" : idn.profile_name,
          email: idn.email,
          dietitian_id: r.dietitian_id,
          reads: r.reads,
          first_reading_at: r.first_reading_at,
          last_reading_at: r.last_reading_at,
        };
      });

      // period total across ALL client readers (not just this page) — matches
      // period_overview.client_readings by construction.
      const sumWhere = buildClientReadersWhere(
        scopeCodes, scopeEmails, dateFrom, dateTo, escapedSearch
      );
      const [sumRows] = await pool.execute(
        `SELECT COUNT(DISTINCT t.profile_id, DATE(t.date_time)) AS cnt
         FROM table_test_data t
         WHERE ${sumWhere.sql}`,
        sumWhere.params
      );
      clientReadings = toInt(sumRows[0]?.cnt);
    }

    // ── 7. Audit the read (fire-and-forget) ─────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "period_readers_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier:
        "group:" + groupName + "|window:" + dateFrom + ".." + dateTo +
        "|scope:" + scope.type + (overviewMember !== "" ? ":" + overviewMember : "") +
        "|type:" + type + "|page:" + page + "|masked:true",
      success: true,
      failureReason: "Period readers viewed (client identity masked)",
    });

    // ── 8. Respond ──────────────────────────────────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Period readers fetched successfully",
      group_name: groupName,

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
      },

      period: { date_from: dateFrom, date_to: dateTo },
      scope,

      totals: {
        trainer_readings: trainerReadings,
        client_readings: clientReadings,
        total_readings: trainerReadings + clientReadings,
        trainer_readers: trainerReaders.length,
        client_readers: totalClientReaders,
      },

      // providers (admins + trainers) who self-tested in the window
      trainer_readers: trainerReaders,

      // real client profiles that tested in the window (masked, paginated)
      client_readers_pagination: {
        page,
        limit,
        offset,
        total: totalClientReaders,
        has_more: offset + limit < totalClientReaders,
      },
      client_readers: clientReaders,
    });
  } catch (err) {
    console.error("GET_GROUP_PERIOD_READERS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "period_readers_error",
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

module.exports = { getGroupPeriodReaders };