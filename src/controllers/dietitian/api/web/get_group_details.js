"use strict";

/**
 * get_group_details.js
 *
 * Converted from: get_group_details.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get-group-details
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin who is a member of the requested group
 *
 * Purpose (group-centric admin view). Given a group_name, returns EVERYTHING
 * under that group from the single-table ta_admin_groups design:
 *   - group_members : the admin codes that belong to the group (ta_admin_groups)
 *   - trainers      : the trainers under each of those admins
 *                     (app_user_roles.role = 'trainer', parent_user_id = admin email)
 *                     PLUS the group's own admins as entries
 *   - clients       : all clients owned by (members + their trainers), paginated,
 *                     with name/email MASKED
 *
 * Behaviour parity with the PHP:
 *  - Member codes come from ta_admin_groups (status = 'active').
 *  - memberEmails is the exclusion set: any client/test carrying a group admin's
 *    email is an admin-acting-as-client and is dropped from every list and count
 *    (emailKeepClause / profileNotAdminClause ported verbatim).
 *  - Per-member / per-trainer total_clients, total_tests, total_tested_clients
 *    computed with the exact same correlated subqueries.
 *  - Network codes = member codes ∪ trainer codes; clients are listed for those.
 *  - Client rows carry MASKED profile_name and email, masked owner email, latest
 *    test date + metabolism score, and a per-client distinct-day test count.
 *  - Response keys/shape match the PHP (status, message, group_name, actor,
 *    group_member_codes, network_codes, counts, group_members, trainers,
 *    clients_pagination, clients). `ok` is mirrored alongside `status` like the
 *    sibling Node controllers.
 *  - Same DB tables only: table_dietician, app_user_roles, ta_admin_groups,
 *    table_clients, table_test_data, user_habits, app_auth_logs. Nothing added.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (sub = dietician_id) and re-checked against the DB on every call. The PHP
 *    trusted body.actor_user_id, which let any caller read another group's whole
 *    roster + client PHI (IDOR / privilege escalation). body.actor_user_id is
 *    still accepted for frontend/back-compat, but it is only cross-checked
 *    against the token email (mismatch → 403); it can never select a different
 *    user. role + status are re-verified server-side.
 *  - Every IN (...) filter and every masking-exclusion clause uses placeholders +
 *    bound params, never string interpolation. LIMIT/OFFSET are the only inlined
 *    values and are hard-coerced to non-negative integers first (mysql2 prepared
 *    statements reject bound LIMIT/OFFSET on some MySQL builds).
 *  - LIKE search wildcards (% _ \) in the user term are escaped so a caller
 *    cannot widen the search beyond what they typed.
 *  - Internal error details are suppressed in production responses (gated behind
 *    APP_DEBUG). Server logs carry only error metadata (code/errno/sqlState).
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The PHP ran `SET time_zone = '+05:30'`. That is NOT done here: this app uses
 *    a shared mysql2 pool and mutating the session TZ would leak into other
 *    concurrent requests. Date bucketing (DATE(date_time)) uses the DB server
 *    clock, matching the documented decision in trainer-admin-clients-list-dir.js.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT * over PHI rows.
 *  - Client name/email are MASKED in the response (maskName / maskEmail).
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every group-detail read is recorded in app_auth_logs.
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

/** Faithful port of PHP cleanValue(): null/blank → default ("NA"), else trimmed string. */
function cleanValue(val, def = "NA") {
  if (val === null || val === undefined) return def;
  const str = String(val).trim();
  return str === "" ? def : str;
}

/** PHP scoreValue(): null/blank/non-numeric → null, else rounded to 2 decimals. */
function scoreValue(val) {
  if (val === null || val === undefined || val === "" || Number.isNaN(Number(val))) {
    return null;
  }
  return Math.round(Number(val) * 100) / 100;
}

/** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS" (matches PHP string output). */
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
 * Port of PHP maskName(): keep the first TWO & last letter of each word, star the
 * middle. "Jennifer Lawson" -> "Je*****r La***n". Whitespace runs are preserved.
 * Array.from() iterates by code point so multi-byte characters count like mb_*.
 */
function maskName(name) {
  const str = String(name ?? "").trim();
  if (str === "") return str;

  // Split on whitespace runs while keeping the delimiters (like PHP DELIM_CAPTURE).
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
 * Port of PHP maskEmail(): star the middle of the local part, keep the first TWO
 * & last char of it and the full domain.
 * "kaleikochambers7@icloud.com" -> "ka*************7@icloud.com".
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

/** PHP get_actor_effective_code(): partner_code, else dietician_id, else null. */
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

// ─── Parameterized masking-exclusion clauses ─────────────────────────────────

/**
 * Port of PHP emailKeepClause(): TRUE when $col's email is NOT one of the excluded
 * (admin) emails. Used to drop clients who are actually group admins that
 * registered / tested as a client. `col` is a controller-controlled column name
 * (never user input); `emails` are always bound. Returns { sql, params }.
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
 * Port of PHP profileNotAdminClause(): TRUE when the test's profile does NOT belong
 * to a client whose email is one of the excluded (admin) emails — so an admin who
 * tested as a client is never counted in any provider's test totals.
 * Returns { sql, params }.
 */
function profileNotAdminClause(emails, testAlias) {
  if (emails.length === 0) return { sql: "1=1", params: [] };
  const placeholders = emails.map(() => "?").join(",");
  return {
    sql: `${testAlias}.profile_id NOT IN (
              SELECT ac.profile_id
              FROM table_clients ac
              WHERE ac.email IS NOT NULL
                AND TRIM(ac.email) <> ''
                AND LOWER(TRIM(ac.email)) IN (${placeholders})
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
    console.error("GET_GROUP_DETAILS_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or
 * { error: { status, body } }. Mirrors PHP getActorForApi(), but keyed off the
 * verified token rather than a body-supplied email.
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
        body: { status: false, ok: false, message: "Only an admin can view group details" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Group data ──────────────────────────────────────────────────────────────

/** Port of PHP getGroupMemberCodes(): active member codes (UPPER) of the group. */
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
 * Port of PHP getMemberEmails(): emails of the group's admin (member) codes. Used
 * as the exclusion set — any client carrying one of these is a group admin acting
 * as a client and must not be counted.
 */
async function getMemberEmails(codes) {
  if (codes.length === 0) return [];

  const inList = codes.map(() => "?").join(",");

  const [rows] = await pool.execute(
    `
      SELECT DISTINCT LOWER(TRIM(td.email)) AS email
      FROM table_dietician td
      WHERE UPPER(td.dietician_id) IN (${inList})
        AND td.email IS NOT NULL
        AND TRIM(td.email) <> ''
    `,
    codes.map(normalizeCode)
  );

  const emails = [];
  for (const row of rows) {
    if (row.email) emails.push(row.email);
  }
  return emails;
}

/** Port of PHP getMembersInfo(): member (admin) info + per-member counts. */
async function getMembersInfo(codes, excludeEmails) {
  if (codes.length === 0) return [];

  const inList = codes.map(() => "?").join(",");

  const keepClient = emailKeepClause(excludeEmails, "c.email");
  const keepTest1 = profileNotAdminClause(excludeEmails, "t");
  const keepTest2 = profileNotAdminClause(excludeEmails, "t");

  const sql = `
    SELECT
      td.dietician_id,
      td.name,
      td.email,
      aur.role,
      aur.partner_code,
      aur.parent_user_id,
      aur.status,
      aur.created_at,

      (
        SELECT COUNT(*)
        FROM table_clients c
        WHERE UPPER(c.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND NOT (
                c.email IS NOT NULL
                AND TRIM(c.email) <> ''
                AND td.email IS NOT NULL
                AND LOWER(TRIM(c.email)) = LOWER(TRIM(td.email))
          )
          AND ${keepClient.sql}
      ) AS total_clients,

      (
        SELECT COUNT(DISTINCT t.profile_id, DATE(t.date_time))
        FROM table_test_data t
        WHERE UPPER(t.dietitian_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND t.profile_id NOT IN (
                SELECT c2.profile_id
                FROM table_clients c2
                WHERE UPPER(c2.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
                  AND c2.email IS NOT NULL
                  AND TRIM(c2.email) <> ''
                  AND td.email IS NOT NULL
                  AND LOWER(TRIM(c2.email)) = LOWER(TRIM(td.email))
          )
          AND t.profile_id IN (
                SELECT c3.profile_id
                FROM table_clients c3
                WHERE UPPER(c3.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          )
          AND ${keepTest1.sql}
      ) AS total_tests,

      /* Distinct clients who have taken at least one test (1 count per such client) */
      (
        SELECT COUNT(DISTINCT t.profile_id)
        FROM table_test_data t
        WHERE UPPER(t.dietitian_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND t.profile_id NOT IN (
                SELECT c2.profile_id
                FROM table_clients c2
                WHERE UPPER(c2.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
                  AND c2.email IS NOT NULL
                  AND TRIM(c2.email) <> ''
                  AND td.email IS NOT NULL
                  AND LOWER(TRIM(c2.email)) = LOWER(TRIM(td.email))
          )
          AND t.profile_id IN (
                SELECT c3.profile_id
                FROM table_clients c3
                WHERE UPPER(c3.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          )
          AND ${keepTest2.sql}
      ) AS total_tested_clients,

      /* The admin's OWN readings: tests on a profile that belongs to a client
         whose email is the admin's own email — i.e. the admin testing
         themselves. Exact inverse of the exclusion applied above. Counted by
         distinct profile+day, matching total_tests. */
      (
        SELECT COUNT(DISTINCT t.profile_id, DATE(t.date_time))
        FROM table_test_data t
        WHERE UPPER(t.dietitian_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND td.email IS NOT NULL
          AND TRIM(td.email) <> ''
          AND t.profile_id IN (
                SELECT c4.profile_id
                FROM table_clients c4
                WHERE UPPER(c4.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
                  AND c4.email IS NOT NULL
                  AND TRIM(c4.email) <> ''
                  AND LOWER(TRIM(c4.email)) = LOWER(TRIM(td.email))
          )
      ) AS self_readings

    FROM table_dietician td
    LEFT JOIN app_user_roles aur
      ON LOWER(aur.user_id) = LOWER(td.email)
    WHERE UPPER(td.dietician_id) IN (${inList})
  `;

  const params = [
    ...keepClient.params,
    ...keepTest1.params,
    ...keepTest2.params,
    ...codes.map(normalizeCode),
  ];

  const [rows] = await pool.execute(sql, params);

  const members = [];
  for (const row of rows) {
    let partnerCode = row.partner_code;
    if (partnerCode === null || partnerCode === undefined || String(partnerCode).trim() === "") {
      partnerCode = row.dietician_id; // fallback
    }

    members.push({
      dietician_id: row.dietician_id,
      partner_code: partnerCode,
      name: cleanValue(row.name),
      email: row.email !== null && row.email !== undefined ? normalizeEmail(row.email) : null,
      role: row.role !== null && row.role !== undefined ? row.role : "admin",
      status: row.status,
      created_at: toMysqlDateTime(row.created_at),
      total_clients: toInt(row.total_clients),
      total_tests: toInt(row.total_tests),
      total_tested_clients: toInt(row.total_tested_clients),
      self_readings: toInt(row.self_readings),
    });
  }

  return members;
}

/** Port of PHP getChildTrainers(): child trainers under the given admin emails. */
async function getChildTrainers(adminEmails, excludeEmails) {
  if (adminEmails.length === 0) return [];

  const inList = adminEmails.map(() => "?").join(",");

  const keepClient = emailKeepClause(excludeEmails, "c.email");
  const keepTest1 = profileNotAdminClause(excludeEmails, "t");
  const keepTest2 = profileNotAdminClause(excludeEmails, "t");

  const sql = `
    SELECT
      aur.partner_code,
      aur.user_id AS email,
      aur.role,
      aur.parent_user_id,
      aur.status,
      aur.created_at,
      td.dietician_id,
      td.name,

      (
        SELECT COUNT(*)
        FROM table_clients c
        WHERE UPPER(c.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND NOT (
                c.email IS NOT NULL
                AND TRIM(c.email) <> ''
                AND td.email IS NOT NULL
                AND LOWER(TRIM(c.email)) = LOWER(TRIM(td.email))
          )
          AND ${keepClient.sql}
      ) AS total_clients,

      (
        SELECT COUNT(DISTINCT t.profile_id, DATE(t.date_time))
        FROM table_test_data t
        WHERE UPPER(t.dietitian_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND t.profile_id NOT IN (
                SELECT c2.profile_id
                FROM table_clients c2
                WHERE UPPER(c2.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
                  AND c2.email IS NOT NULL
                  AND TRIM(c2.email) <> ''
                  AND td.email IS NOT NULL
                  AND LOWER(TRIM(c2.email)) = LOWER(TRIM(td.email))
          )
          AND t.profile_id IN (
                SELECT c3.profile_id
                FROM table_clients c3
                WHERE UPPER(c3.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          )
          AND ${keepTest1.sql}
      ) AS total_tests,

      /* Distinct clients who have taken at least one test (1 count per such client) */
      (
        SELECT COUNT(DISTINCT t.profile_id)
        FROM table_test_data t
        WHERE UPPER(t.dietitian_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND t.profile_id NOT IN (
                SELECT c2.profile_id
                FROM table_clients c2
                WHERE UPPER(c2.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
                  AND c2.email IS NOT NULL
                  AND TRIM(c2.email) <> ''
                  AND td.email IS NOT NULL
                  AND LOWER(TRIM(c2.email)) = LOWER(TRIM(td.email))
          )
          AND t.profile_id IN (
                SELECT c3.profile_id
                FROM table_clients c3
                WHERE UPPER(c3.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          )
          AND ${keepTest2.sql}
      ) AS total_tested_clients,

      /* The trainer's OWN readings: tests on a profile that belongs to a client
         whose email is the trainer's own email — i.e. the trainer testing
         themselves. This is the exact inverse of the exclusion applied above, so
         a reading is counted either as a client's test OR as a self reading,
         never both. Counted by distinct profile+day, matching total_tests. */
      (
        SELECT COUNT(DISTINCT t.profile_id, DATE(t.date_time))
        FROM table_test_data t
        WHERE UPPER(t.dietitian_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
          AND td.email IS NOT NULL
          AND TRIM(td.email) <> ''
          AND t.profile_id IN (
                SELECT c4.profile_id
                FROM table_clients c4
                WHERE UPPER(c4.dietician_id) = UPPER(COALESCE(aur.partner_code, td.dietician_id))
                  AND c4.email IS NOT NULL
                  AND TRIM(c4.email) <> ''
                  AND LOWER(TRIM(c4.email)) = LOWER(TRIM(td.email))
          )
      ) AS self_readings

    FROM app_user_roles aur
    LEFT JOIN table_dietician td
      ON LOWER(td.email) = LOWER(aur.user_id)
    WHERE aur.role = 'trainer'
      AND aur.status = 'active'
      AND LOWER(aur.parent_user_id) IN (${inList})
    ORDER BY aur.partner_code
  `;

  const params = [
    ...keepClient.params,
    ...keepTest1.params,
    ...keepTest2.params,
    ...adminEmails.map(normalizeEmail),
  ];

  const [rows] = await pool.execute(sql, params);

  const trainers = [];
  for (const row of rows) {
    let code = row.partner_code;
    if (code === null || code === undefined || String(code).trim() === "") {
      code = row.dietician_id; // fallback
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
      created_at: toMysqlDateTime(row.created_at),
      total_clients: toInt(row.total_clients),
      total_tests: toInt(row.total_tests),
      total_tested_clients: toInt(row.total_tested_clients),
      self_readings: toInt(row.self_readings),
    });
  }

  return trainers;
}

// ─── Clients ─────────────────────────────────────────────────────────────────

/** Port of PHP countClientsForCodes(). */
async function countClientsForCodes(codes, escapedSearch, excludeEmails) {
  if (codes.length === 0) return 0;

  const inList = codes.map(() => "?").join(",");
  const keepClient = emailKeepClause(excludeEmails, "tc.email");

  const params = [...codes.map(normalizeCode), ...keepClient.params];

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

  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS total
      FROM table_clients tc
      LEFT JOIN table_dietician td
        ON UPPER(td.dietician_id) = UPPER(tc.dietician_id)
      WHERE UPPER(tc.dietician_id) IN (${inList})
        AND NOT (
              tc.email IS NOT NULL
              AND TRIM(tc.email) <> ''
              AND td.email IS NOT NULL
              AND LOWER(TRIM(tc.email)) = LOWER(TRIM(td.email))
        )
        AND ${keepClient.sql}
      ${searchSql}
    `,
    params
  );

  return toInt(rows[0]?.total);
}

/** Port of PHP fetchClientsForCodes(). */
async function fetchClientsForCodes(codes, escapedSearch, limit, offset, excludeEmails) {
  if (codes.length === 0) return [];

  const inList = codes.map(() => "?").join(",");
  const keepClient = emailKeepClause(excludeEmails, "tc.email");

  const params = [...codes.map(normalizeCode), ...keepClient.params];

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

  // limit/offset are hard-coerced to non-negative ints, so inlining is
  // injection-safe. mysql2 prepared statements reject bound LIMIT/OFFSET on some
  // MySQL builds, hence they are not passed as placeholders.
  const safeLimit = Math.max(0, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

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

      WHERE UPPER(tc.dietician_id) IN (${inList})
        AND NOT (
              tc.email IS NOT NULL
              AND TRIM(tc.email) <> ''
              AND td.email IS NOT NULL
              AND LOWER(TRIM(tc.email)) = LOWER(TRIM(td.email))
        )
        AND ${keepClient.sql}
      ${searchSql}

      ORDER BY
        CASE WHEN latest.date_time IS NULL THEN 1 ELSE 0 END ASC,
        latest.date_time DESC,
        tc.dttm DESC

      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    params
  );

  return rows;
}

/** Port of PHP formatClientRows(): MASKED client rows. */
function formatClientRows(rows) {
  return rows.map((row) => {
    const score = scoreValue(row.latest_score);

    return {
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
      joined_dttm: cleanValue(toMysqlDateTime(row.dttm)),
      created_at: cleanValue(toMysqlDateTime(row.dttm)),

      owner: {
        partner_code: row.dietician_id,
        name: cleanValue(row.owner_name),
        email:
          row.owner_email !== null && row.owner_email !== undefined
            ? maskEmail(normalizeEmail(row.owner_email))
            : null,
      },

      total_tests: toInt(row.total_tests),

      latest_test: {
        date_time: toMysqlDateTime(row.latest_test_date_time),
        metabolism_score: score,
      },
    };
  });
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

  return { page, limit, search, groupName, actorUserId, offset: (page - 1) * limit };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get-group-details
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "group_name": "USA (Evan & Derek)",   // required
 *     "page": 1,                             // optional, default 1
 *     "limit": 10,                           // optional, default 10, max 50
 *     "search": "",                          // optional, filters clients
 *     "actor_user_id": ""                    // optional; if set, must match token
 *   }
 */
const getGroupDetails = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const { page, limit, search, groupName, actorUserId, offset } = parseInputs(req);

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "group_details_denied",
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
        eventType: "group_details_denied",
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

    // ── 1c. Required input: group_name ──────────────────────────────────────
    if (groupName === "") {
      return res.status(422).json({ status: false, ok: false, message: "group_name is required" });
    }

    // ── 2. Group members ────────────────────────────────────────────────────
    const memberCodes = await getGroupMemberCodes(groupName);

    if (memberCodes.length === 0) {
      await writeAuthLogSafe(req, {
        eventType: "group_details_denied",
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
        eventType: "group_details_denied",
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

    // ── 3. Members + trainers ───────────────────────────────────────────────
    // admin emails of this group; a client carrying one of these is an admin
    // acting as a client and is excluded from every client list and every count.
    const memberEmails = await getMemberEmails(memberCodes);

    const members = await getMembersInfo(memberCodes, memberEmails);
    const childTrainers = await getChildTrainers(memberEmails, memberEmails);

    // include the group's admins (group_members) as entries in the trainers list.
    const adminEntries = members.map((m) => ({
      partner_code: m.partner_code,
      name: m.name,
      email: m.email,
      role: m.role,
      parent_admin_email: null,
      created_at: m.created_at,
      total_clients: m.total_clients,
      total_tests: m.total_tests,
      total_tested_clients: m.total_tested_clients,
      self_readings: m.self_readings,
    }));

    const trainers = [...adminEntries, ...childTrainers];

    // ── 4. Network codes = members + trainers (de-duplicated, UPPER) ─────────
    const networkCodesMap = new Map();
    for (const c of memberCodes) {
      const code = normalizeCode(c);
      if (code !== "") networkCodesMap.set(code, code);
    }
    for (const t of trainers) {
      const code = normalizeCode(t.partner_code);
      if (code !== "") networkCodesMap.set(code, code);
    }
    const networkCodes = [...networkCodesMap.values()];

    // ── 5. Clients (masked, paginated) ──────────────────────────────────────
    const escapedSearch = search !== "" ? escapeLike(search) : "";

    const totalClients = await countClientsForCodes(networkCodes, escapedSearch, memberEmails);
    const clientRows = await fetchClientsForCodes(
      networkCodes,
      escapedSearch,
      limit,
      offset,
      memberEmails
    );

    // ── 6. Audit the read (fire-and-forget) ─────────────────────────────────
    writeAuthLogSafe(req, {
      eventType: "group_details_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier:
        "group:" + groupName + "|page:" + page + "|search:" + search + "|masked:true",
      success: true,
      failureReason: "Group details viewed (client identity masked)",
    });

    // ── 7. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Group details fetched successfully",
      group_name: groupName,

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorCode,
      },

      group_member_codes: memberCodes,
      network_codes: networkCodes,

      counts: {
        members: members.length,
        trainers: trainers.length,
        clients: totalClients,
      },

      // the admins in the group
      group_members: members,

      // trainers under those admins (admins included as entries too)
      trainers,

      // clients of members + trainers (paginated)
      clients_pagination: {
        page,
        limit,
        offset,
        total: totalClients,
        has_more: offset + limit < totalClients,
      },

      clients: formatClientRows(clientRows),
    });
  } catch (err) {
    console.error("GET_GROUP_DETAILS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "group_details_error",
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

module.exports = { getGroupDetails };
