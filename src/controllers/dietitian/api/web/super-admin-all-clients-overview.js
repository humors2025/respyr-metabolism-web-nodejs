"use strict";

/**
 * super-admin-all-clients-overview.js
 *
 * Converted from: super-admin-all-clients-overview.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/super-admin-all-clients-overview
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin only
 *
 * Behaviour parity with the PHP:
 *  - Returns a paginated, MASKED list of every client in the super admin's
 *    network, plus a summary block, for a selected date.
 *  - Network scope matches super-admin-overview.php: own effective code + active
 *    admins parented to the super admin + active trainers parented to it or to
 *    one of those admins (one level — no extra recursion introduced). A client
 *    counts only when table_clients.dietician_id is inside that network.
 *  - `date` drives only the selected-date tested/missed calculation.
 *  - never_tested_clients = network clients who never tested even once.
 *  - type filter: all | tested | missed | never_tested (invalid → all).
 *  - Per-row diet_plan.generated_at is resolved from
 *    weekly_food_json_suggestions when that table (and the expected columns)
 *    exist — the column names are auto-detected exactly as the PHP did.
 *  - Client identity is masked (name / email / phone / age-band). dob, age,
 *    region, location, profile_image are never returned.
 *  - Response keys/shape match the PHP (status, ok, message, mode, actor,
 *    filters, summary, pagination, privacy, columns, clients).
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT
 *    (sub = dietician_id) and re-fetched from the DB on every call — NOT from
 *    body.actor_user_id as the PHP did. Trusting a client-supplied actor id is an
 *    IDOR / privilege-escalation hole; deriving identity from the token closes it.
 *    role + status are re-checked server-side so a stale/demoted token cannot read
 *    data. body.actor_user_id is still accepted for frontend/back-compat, but it
 *    is only cross-checked against the token email (mismatch → 403); it can never
 *    be used to act as a different user.
 *  - Fully parameterized queries (? placeholders). Network/diet-plan IN-lists are
 *    bound with placeholders, never string-interpolated. The only inlined values
 *    are LIMIT/OFFSET (hard-coerced to non-negative ints — mysql2 prepared
 *    statements reject bound LIMIT/OFFSET on some MySQL builds) and the
 *    diet-plan column identifiers, which are whitelisted from INFORMATION_SCHEMA
 *    and backtick-escaped before use.
 *  - LIKE search wildcards (% _ \) in the user term are escaped so a caller
 *    cannot widen the search beyond what they typed.
 *  - Internal error details are suppressed in production responses (gated behind
 *    APP_DEBUG); server logs carry only error metadata, never row data or PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The PHP ran `SET time_zone = '+05:30'` on the connection. That is NOT done
 *    here: this app uses a shared mysql2 pool and mutating the session TZ would
 *    leak into other concurrent requests. The selected-date defaults to an
 *    app-computed IST date, preserving the PHP's Asia/Kolkata semantics. The
 *    3-month window uses the DB server clock via NOW().
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; client identity masked before it leaves the server.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every masked read (and every denial) is recorded in app_auth_logs.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, table_clients, table_test_data, user_habits,
 * weekly_food_json_suggestions, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_TYPES = new Set(["all", "tested", "missed", "never_tested"]);

const MAX_LIMIT = 50;
const DEFAULT_LIMIT = 10;

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return String(val ?? "").trim().toLowerCase();
}

function normalizeCode(val) {
  return String(val ?? "").trim().toUpperCase();
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

/** PHP sac_clean_value(): null/blank → default ("NA"), else trimmed string. */
function cleanValue(val, def = "NA") {
  if (val === null || val === undefined) return def;
  const str = String(val).trim();
  return str === "" ? def : str;
}

/** PHP sac_score_value(): null/blank/non-numeric → null, else rounded to 2 decimals. */
function scoreValue(val) {
  if (val === null || val === undefined || val === "" || Number.isNaN(Number(val))) {
    return null;
  }
  return Math.round(Number(val) * 100) / 100;
}

/** PHP sac_get_metabolism_zone(). */
function getMetabolismZone(score) {
  if (score === null || score === undefined || score === "") return null;
  const s = Number(score);
  if (Number.isNaN(s)) return null;
  if (s >= 80) return "Optimal";
  if (s >= 70) return "Moderate";
  return "Focus";
}

/** Real YYYY-MM-DD check (not just regex). */
function isValidDate(str) {
  if (typeof str !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
  const d = new Date(`${str}T00:00:00Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === str;
}

/** Today's date in Asia/Kolkata as "YYYY-MM-DD" (PHP used IST default TZ). */
function todayDateIST() {
  const now = new Date();
  const ist = new Date(now.getTime() + (5 * 60 + 30) * 60 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${ist.getUTCFullYear()}-${pad(ist.getUTCMonth() + 1)}-${pad(ist.getUTCDate())}`;
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

/** Escape LIKE wildcards so a caller cannot widen the search beyond their term. */
function escapeLike(term) {
  return String(term).replace(/[\\%_]/g, "\\$&");
}

/** PHP sac_get_actor_code(): partner_code if non-blank, else dietician_id, else null. */
function getActorCode(actor) {
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

// ─── Masking (faithful port of the PHP sac_mask_* helpers) ───────────────────

function maskToken(part) {
  const len = part.length;
  if (len <= 1) return "x";
  if (len <= 2) return part.slice(0, 1) + "x";
  if (len <= 4) return part.slice(0, 2) + "x".repeat(len - 2);
  return part.slice(0, 2) + "x".repeat(Math.max(3, len - 3)) + part.slice(-1);
}

function maskName(name) {
  const trimmed = String(name ?? "").trim();
  if (trimmed === "" || trimmed.toUpperCase() === "NA") return "Client";
  return trimmed.split(/\s+/).map(maskToken).join(" ");
}

function maskEmail(email) {
  const normalized = normalizeEmail(email);
  if (normalized === "" || !normalized.includes("@")) return "NA";
  const atIdx = normalized.indexOf("@");
  const local = normalized.slice(0, atIdx);
  const domain = normalized.slice(atIdx + 1);
  return maskToken(local) + "@" + domain;
}

function maskPhone(phone) {
  const trimmed = String(phone ?? "").trim();
  if (trimmed === "") return "NA";
  const digits = trimmed.replace(/\D+/g, "");
  if (digits === "") return "NA";
  const len = digits.length;
  if (len <= 4) return "x".repeat(len);
  return "x".repeat(Math.max(0, len - 4)) + digits.slice(-4);
}

function ageGroup(age) {
  if (age === null || age === undefined || age === "" || Number.isNaN(Number(age))) {
    return "NA";
  }
  const a = toInt(age);
  if (a <= 0) return "NA";
  if (a < 18) return "<18";
  if (a <= 24) return "18-24";
  if (a <= 34) return "25-34";
  if (a <= 44) return "35-44";
  if (a <= 54) return "45-54";
  if (a <= 64) return "55-64";
  return "65+";
}

// ─── Audit log ───────────────────────────────────────────────────────────────

/**
 * Fail-safe audit writer mirroring the sibling controllers. Never throws — audit
 * failures must not surface to the client.
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
    console.error("SUPER_ADMIN_ALL_CLIENTS_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and require
 * an active super_admin. Returns { actor, actorEmail } or
 * { error: { status, body } }.
 *
 * NOTE: this intentionally diverges from the PHP, which trusted
 * body.actor_user_id. See the file header (VAPT hardening).
 */
async function resolveSuperAdminFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return { error: { status: 401, body: { status: false, ok: false, message: "Invalid token user" } } };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.id,
        td.dietician_id,
        td.name,
        td.email,
        td.phone_no,

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
  );

  const actor = rows[0];

  if (!actor) {
    return { error: { status: 403, body: { status: false, ok: false, message: "Actor user not found" } } };
  }

  if (String(actor.status) !== "active") {
    return { error: { status: 403, body: { status: false, ok: false, message: "Actor account is not active" } } };
  }

  if (String(actor.role) !== "super_admin") {
    return {
      error: {
        status: 403,
        body: { status: false, ok: false, message: "Only super admin can access this API" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Network codes (PHP sac_get_super_admin_network_codes) ───────────────────

/**
 * Build the upper-cased, de-duplicated set of partner codes in this super
 * admin's network: own effective code + admins parented to it + trainers
 * parented to it or to one of those admins (one level, exactly as the PHP).
 * Uses COALESCE(partner_code, dietician_id) so trainers without a partner_code
 * still contribute their dietician_id, matching the PHP.
 */
async function getSuperAdminNetworkCodes(actor, actorEmail) {
  const codes = new Map();

  const addCode = (code) => {
    const c = normalizeCode(code);
    if (c !== "") codes.set(c, c);
  };

  addCode(getActorCode(actor));

  const [rows] = await pool.execute(
    `
      SELECT
        COALESCE(NULLIF(aur.partner_code, ''), NULLIF(td.dietician_id, '')) AS code
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

  for (const row of rows) addCode(row.code);

  return [...codes.values()];
}

// ─── Diet-plan dynamic column detection (PHP sac_build_diet_plan_sql) ────────

/**
 * weekly_food_json_suggestions has drifted across deployments, so the PHP picked
 * the diet / profile / created columns by name at runtime. We reproduce that:
 * the candidate names are matched against INFORMATION_SCHEMA (a fixed allow-list),
 * and the chosen identifiers are backtick-escaped before being inlined — they are
 * never user input. Returns { selectSql, joinSql, params } where params feed the
 * (currently zero) placeholders in joinSql.
 */
async function buildDietPlanSql() {
  const fallback = { selectSql: "NULL AS diet_plan_generated_at", joinSql: "" };

  let cols;
  try {
    const [rows] = await pool.execute(
      `
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'weekly_food_json_suggestions'
      `
    );
    cols = new Set(rows.map((r) => r.COLUMN_NAME));
  } catch (err) {
    console.error("DIET_PLAN_COLUMN_LOOKUP_FAILED:", err?.code || err?.message);
    return fallback;
  }

  if (cols.size === 0) return fallback;

  const pick = (candidates) => candidates.find((c) => cols.has(c)) || null;

  const dietCol = pick(["dietitian_id", "dietician_id", "trainer_id", "trainer_code"]);
  const profileCol = pick(["profile_id"]);
  const createdCol = pick(["created_at", "dttm", "date_time", "updated_at"]);

  if (dietCol === null || profileCol === null || createdCol === null) {
    return fallback;
  }

  // Whitelisted identifiers (from INFORMATION_SCHEMA) — backtick-escaped.
  const q = (name) => "`" + String(name).replace(/`/g, "") + "`";
  const dietColSql = q(dietCol);
  const profileColSql = q(profileCol);
  const createdColSql = q(createdCol);

  return {
    selectSql: "dp.generated_at AS diet_plan_generated_at",
    joinSql: `
      LEFT JOIN (
        SELECT
          UPPER(${dietColSql}) AS diet_key,
          ${profileColSql} AS profile_id,
          MAX(${createdColSql}) AS generated_at
        FROM weekly_food_json_suggestions
        GROUP BY UPPER(${dietColSql}), ${profileColSql}
      ) dp
        ON dp.diet_key = UPPER(tc.dietician_id)
       AND dp.profile_id = tc.profile_id
    `,
  };
}

// ─── SQL fragment builders ───────────────────────────────────────────────────

/**
 * WHERE filters shared by the summary, count, and fetch queries. Returns
 * { sql, params } with params already in textual placeholder order. When the
 * network is empty the filter forces an empty result set (matches PHP `1=0`).
 */
function buildClientFilters(networkCodes, dietitianId, escapedSearch) {
  let sql = " WHERE 1=1 ";
  const params = [];

  if (!Array.isArray(networkCodes) || networkCodes.length === 0) {
    sql += " AND 1=0 ";
    return { sql, params };
  }

  const placeholders = networkCodes.map(() => "?").join(",");
  sql += ` AND UPPER(tc.dietician_id) IN (${placeholders}) `;
  for (const c of networkCodes) params.push(normalizeCode(c));

  if (dietitianId !== "") {
    sql += " AND UPPER(tc.dietician_id) = UPPER(?) ";
    params.push(dietitianId);
  }

  if (escapedSearch !== "") {
    sql += `
      AND (
        LOWER(tc.profile_id) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.profile_name, '')) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.email, '')) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.phone_no, '')) LIKE LOWER(?)
        OR LOWER(COALESCE(tc.dietician_id, '')) LIKE LOWER(?)
      )
    `;
    const like = `%${escapedSearch}%`;
    params.push(like, like, like, like, like);
  }

  return { sql, params };
}

/** PHP sac_selected_day_join_sql() — one `?` for the selected date. */
function selectedDayJoinSql() {
  return `
    LEFT JOIN (
      SELECT
        UPPER(dietitian_id) AS diet_key,
        profile_id,
        MAX(date_time) AS selected_date_time
      FROM table_test_data
      WHERE DATE(date_time) = ?
      GROUP BY UPPER(dietitian_id), profile_id
    ) sdt
      ON sdt.diet_key = UPPER(tc.dietician_id)
     AND sdt.profile_id = tc.profile_id
  `;
}

/** PHP sac_anytime_test_join_sql() — no placeholders. */
function anytimeTestJoinSql() {
  return `
    LEFT JOIN (
      SELECT
        UPPER(dietitian_id) AS diet_key,
        profile_id,
        MAX(date_time) AS any_last_test_date_time,
        COUNT(*) AS lifetime_test_count
      FROM table_test_data
      GROUP BY UPPER(dietitian_id), profile_id
    ) anyt
      ON anyt.diet_key = UPPER(tc.dietician_id)
     AND anyt.profile_id = tc.profile_id
  `;
}

/** PHP sac_type_filter_sql() — `type` is allow-listed, so these are constants. */
function typeFilterSql(type) {
  if (type === "tested") return " AND sdt.selected_date_time IS NOT NULL ";
  if (type === "missed") return " AND sdt.selected_date_time IS NULL ";
  if (type === "never_tested") return " AND anyt.profile_id IS NULL ";
  return "";
}

// ─── Queries ─────────────────────────────────────────────────────────────────

async function getSummaryCounts(selectedDate, escapedSearch, dietitianId, networkCodes) {
  const filters = buildClientFilters(networkCodes, dietitianId, escapedSearch);
  const params = [selectedDate, ...filters.params];

  const [rows] = await pool.execute(
    `
      SELECT
        COUNT(DISTINCT tc.profile_id) AS total_clients,

        COUNT(DISTINCT CASE
          WHEN sdt.selected_date_time IS NOT NULL
          THEN tc.profile_id
        END) AS tested_clients,

        COUNT(DISTINCT tc.profile_id)
        -
        COUNT(DISTINCT CASE
          WHEN sdt.selected_date_time IS NOT NULL
          THEN tc.profile_id
        END) AS missed_clients,

        COUNT(DISTINCT CASE
          WHEN anyt.profile_id IS NULL
          THEN tc.profile_id
        END) AS never_tested_clients,

        COUNT(DISTINCT CASE
          WHEN anyt.profile_id IS NOT NULL
          THEN tc.profile_id
        END) AS tested_anytime_clients,

        COUNT(DISTINCT CASE
          WHEN sdt.selected_date_time IS NULL
           AND anyt.profile_id IS NOT NULL
          THEN tc.profile_id
        END) AS missed_but_tested_before

      FROM table_clients tc
      ${selectedDayJoinSql()}
      ${anytimeTestJoinSql()}
      ${filters.sql}
    `,
    params
  );

  const row = rows[0] || {};
  return {
    total_clients: toInt(row.total_clients),
    tested_clients: toInt(row.tested_clients),
    missed_clients: toInt(row.missed_clients),
    never_tested_clients: toInt(row.never_tested_clients),
    tested_anytime_clients: toInt(row.tested_anytime_clients),
    missed_but_tested_before: toInt(row.missed_but_tested_before),
  };
}

async function countFilteredClients(selectedDate, escapedSearch, dietitianId, type, networkCodes) {
  const filters = buildClientFilters(networkCodes, dietitianId, escapedSearch);
  const params = [selectedDate, ...filters.params];

  const [rows] = await pool.execute(
    `
      SELECT COUNT(DISTINCT tc.profile_id) AS total
      FROM table_clients tc
      ${selectedDayJoinSql()}
      ${anytimeTestJoinSql()}
      ${filters.sql}
      ${typeFilterSql(type)}
    `,
    params
  );

  return toInt(rows[0]?.total);
}

async function fetchClients(selectedDate, escapedSearch, dietitianId, type, limit, offset, networkCodes) {
  const dietPlan = await buildDietPlanSql();
  const filters = buildClientFilters(networkCodes, dietitianId, escapedSearch);

  // Placeholder order follows the textual order of `?` in the SQL below:
  //   selectedDayJoinSql (selected_date)
  //   selected_test sub-select (selected_date again)
  //   filters.params (network codes, optional dietitian, optional search)
  const params = [selectedDate, selectedDate, ...filters.params];

  // limit/offset are hard-coerced to non-negative ints, so inlining them is
  // injection-safe. mysql2 prepared statements reject bound LIMIT/OFFSET on some
  // MySQL builds, hence they are not passed as placeholders.
  const safeLimit = Math.max(1, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

  const [rows] = await pool.execute(
    `
      SELECT
        tc.profile_id,
        tc.dietician_id,
        tc.profile_name,
        tc.phone_no,
        tc.email,
        tc.dob,
        tc.age,
        tc.gender,
        tc.height,
        tc.weight,
        tc.region,
        tc.location,
        tc.level_type,
        tc.dttm,

        td.name AS dietitian_name,
        td.email AS dietitian_email,
        td.phone_no AS dietitian_phone,
        aur.role AS dietitian_role,
        aur.partner_code AS dietitian_partner_code,

        IFNULL(uh.goal, '') AS fitness_goal,
        IFNULL(uh.activity, '') AS activity,
        IFNULL(uh.food_type, '') AS food_type,

        sdt.selected_date_time,

        anyt.any_last_test_date_time,
        anyt.lifetime_test_count,

        selected_test.test_id AS selected_test_id,
        selected_test.date_time AS selected_test_date_time,
        selected_test.fat_loss_metabolism_score AS selected_fat_loss_metabolism_score,
        selected_test.acetone_ppm AS selected_acetone_ppm,
        selected_test.ethanol_ppm AS selected_ethanol_ppm,
        selected_test.h2_ppm AS selected_h2_ppm,

        latest.test_id AS latest_test_id,
        latest.date_time AS latest_test_date_time,
        latest.fat_loss_metabolism_score,
        latest.acetone_ppm,
        latest.ethanol_ppm,
        latest.h2_ppm,

        IFNULL(test_count.tests_count_3_months, 0) AS tests_count_3_months,

        ${dietPlan.selectSql}

      FROM table_clients tc

      LEFT JOIN table_dietician td
        ON UPPER(td.dietician_id) = UPPER(tc.dietician_id)

      LEFT JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)

      LEFT JOIN (
        SELECT uh1.*
        FROM user_habits uh1
        INNER JOIN (
          SELECT profile_id, MAX(id) AS max_id
          FROM user_habits
          GROUP BY profile_id
        ) uh2
          ON uh1.id = uh2.max_id
      ) uh
        ON uh.profile_id = tc.profile_id

      ${selectedDayJoinSql()}
      ${anytimeTestJoinSql()}

      LEFT JOIN table_test_data selected_test
        ON selected_test.test_id = (
          SELECT t0.test_id
          FROM table_test_data t0
          WHERE t0.profile_id = tc.profile_id
            AND UPPER(t0.dietitian_id) = UPPER(tc.dietician_id)
            AND DATE(t0.date_time) = ?
          ORDER BY t0.date_time DESC, t0.test_id DESC
          LIMIT 1
        )

      LEFT JOIN table_test_data latest
        ON latest.test_id = (
          SELECT t1.test_id
          FROM table_test_data t1
          WHERE t1.profile_id = tc.profile_id
            AND UPPER(t1.dietitian_id) = UPPER(tc.dietician_id)
          ORDER BY t1.date_time DESC, t1.test_id DESC
          LIMIT 1
        )

      LEFT JOIN (
        SELECT
          UPPER(dietitian_id) AS diet_key,
          profile_id,
          COUNT(DISTINCT DATE(date_time)) AS tests_count_3_months
        FROM table_test_data
        WHERE date_time >= DATE_SUB(NOW(), INTERVAL 3 MONTH)
        GROUP BY UPPER(dietitian_id), profile_id
      ) test_count
        ON test_count.diet_key = UPPER(tc.dietician_id)
       AND test_count.profile_id = tc.profile_id

      ${dietPlan.joinSql}

      ${filters.sql}
      ${typeFilterSql(type)}

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

// ─── Row formatting (masked — PHP sac_format_client_rows) ────────────────────

function formatClientRows(rows, selectedDate) {
  return rows.map((row) => {
    const partnerCode =
      row.dietitian_partner_code !== null &&
      row.dietitian_partner_code !== undefined &&
      String(row.dietitian_partner_code).trim() !== ""
        ? row.dietitian_partner_code
        : row.dietician_id;

    const isTestedOnSelectedDate = !!row.selected_date_time;
    const hasEverTested = !!row.any_last_test_date_time;

    const selectedScore = scoreValue(row.selected_fat_loss_metabolism_score);
    const latestScore = scoreValue(row.fat_loss_metabolism_score);

    const dietPlanCreatedAt =
      row.diet_plan_generated_at !== undefined ? row.diet_plan_generated_at : null;
    const dietPlanGenerated = !!dietPlanCreatedAt;

    const maskedName = maskName(row.profile_name);
    const maskedEmail = maskEmail(row.email);
    const maskedPhone = maskPhone(row.phone_no);

    return {
      name: maskedName,
      email: maskedEmail,
      phone_no: maskedPhone,

      profile_id: row.profile_id,
      dietitian_id: row.dietician_id,
      dietician_id: row.dietician_id,
      partner_code: partnerCode,
      trainer_code: partnerCode,

      level_type: cleanValue(row.level_type),

      fitness_goal: cleanValue(row.fitness_goal),
      activity: cleanValue(row.activity),
      food_type: cleanValue(row.food_type),

      selected_date_status: {
        date: selectedDate,
        status: isTestedOnSelectedDate ? "tested" : "missed",
        tested: isTestedOnSelectedDate,
        test_time: toMysqlDateTime(row.selected_date_time),
      },

      selected_date_test: {
        test_id: row.selected_test_id !== null && row.selected_test_id !== undefined
          ? toInt(row.selected_test_id)
          : null,
        date_time: toMysqlDateTime(row.selected_test_date_time),
        metabolism_score: selectedScore,
        zone: getMetabolismZone(selectedScore),
        acetone_ppm: scoreValue(row.selected_acetone_ppm),
        ethanol_ppm: scoreValue(row.selected_ethanol_ppm),
        h2_ppm: scoreValue(row.selected_h2_ppm),
      },

      test_history: {
        has_ever_tested: hasEverTested,
        never_tested: !hasEverTested,
        lifetime_test_count: toInt(row.lifetime_test_count),
        last_test_date_time: toMysqlDateTime(row.any_last_test_date_time),
      },

      latest_test: {
        test_id: row.latest_test_id !== null && row.latest_test_id !== undefined
          ? toInt(row.latest_test_id)
          : null,
        date_time: toMysqlDateTime(row.latest_test_date_time),
        metabolism_score: latestScore,
        zone: getMetabolismZone(latestScore),
        acetone_ppm: scoreValue(row.acetone_ppm),
        ethanol_ppm: scoreValue(row.ethanol_ppm),
        h2_ppm: scoreValue(row.h2_ppm),
      },

      metabolism_score: selectedScore !== null ? selectedScore : latestScore,
      zone: selectedScore !== null
        ? getMetabolismZone(selectedScore)
        : getMetabolismZone(latestScore),
      acetone_ppm: isTestedOnSelectedDate
        ? scoreValue(row.selected_acetone_ppm)
        : scoreValue(row.acetone_ppm),
      ethanol_ppm: isTestedOnSelectedDate
        ? scoreValue(row.selected_ethanol_ppm)
        : scoreValue(row.ethanol_ppm),
      h2_ppm: isTestedOnSelectedDate
        ? scoreValue(row.selected_h2_ppm)
        : scoreValue(row.h2_ppm),
      last_active: toMysqlDateTime(row.latest_test_date_time),

      tests_count_3_months: toInt(row.tests_count_3_months),

      diet_plan: {
        generated: dietPlanGenerated,
        created_at: dietPlanGenerated ? toMysqlDateTime(dietPlanCreatedAt) : "NA",
      },

      associated_dietitian: {
        dietitian_id: row.dietician_id,
        dietician_id: row.dietician_id,
        name: cleanValue(row.dietitian_name),
        email: cleanValue(row.dietitian_email),
        role: cleanValue(row.dietitian_role),
        partner_code: partnerCode,
      },

      client: {
        profile_id: row.profile_id,
        name: maskedName,
        email: maskedEmail,
        phone_no: maskedPhone,
        dob: "hidden",
        age: "hidden",
        age_group: ageGroup(row.age),
        gender: cleanValue(row.gender),
        height: cleanValue(row.height),
        weight: cleanValue(row.weight),
        region: "hidden",
        location: "hidden",
        joined_dttm: cleanValue(toMysqlDateTime(row.dttm)),
        profile_image: null,
      },
    };
  });
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(req) {
  const src = req.body && typeof req.body === "object" ? req.body : {};

  // Optional. Accepted for frontend/back-compat, but never authoritative — see
  // the cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);

  let page = Number.parseInt(src.page, 10);
  if (!Number.isFinite(page) || page <= 0) page = 1;

  let limit = Number.parseInt(src.limit, 10);
  if (!Number.isFinite(limit) || limit <= 0 || limit > MAX_LIMIT) {
    limit = DEFAULT_LIMIT;
  }

  const search = typeof src.search === "string" ? src.search.trim() : "";

  let type = typeof src.type === "string" ? src.type.trim().toLowerCase() : "all";
  if (!ALLOWED_TYPES.has(type)) type = "all";

  const dietitianId = typeof src.dietitian_id === "string" ? src.dietitian_id.trim() : "";

  const dateRaw = typeof src.date === "string" ? src.date.trim() : "";
  const dateProvided = dateRaw !== "";
  const selectedDate = isValidDate(dateRaw) ? dateRaw : todayDateIST();

  return {
    actorUserId,
    page,
    limit,
    search,
    type,
    dietitianId,
    dateRaw,
    dateProvided,
    selectedDate,
    offset: (page - 1) * limit,
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/super-admin-all-clients-overview
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "page": 1,
 *     "limit": 10,
 *     "search": "",
 *     "date": "2026-06-02",          // optional; defaults to today (IST)
 *     "type": "all",                 // all | tested | missed | never_tested
 *     "dietitian_id": "",            // optional network-code filter
 *     "actor_user_id": ""            // optional; if set, must match the token email
 *   }
 */
const superAdminAllClientsOverview = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const {
    actorUserId, page, limit, search, type, dietitianId,
    dateRaw, dateProvided, selectedDate, offset,
  } = parseInputs(req);

  // If a date was supplied but malformed, reject it (PHP returned 422). A blank
  // date is allowed and defaults to today (IST).
  if (dateProvided && !isValidDate(dateRaw)) {
    return res.status(422).json({
      status: false,
      ok: false,
      message: "date must be in YYYY-MM-DD format",
    });
  }

  const auditIdentifier =
    `date:${selectedDate}|type:${type}|search:${search}|dietitian:${dietitianId}|page:${page}`;

  let actorEmail = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT (super_admin only) ────────────
    const resolved = await resolveSuperAdminFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "super_admin_all_clients_access_denied",
        userId: actorUserId || null,
        role: null,
        partnerCode: null,
        identifier: auditIdentifier,
        success: false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorCode = getActorCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "super_admin_all_clients_access_denied",
        userId: actorEmail,
        role: "super_admin",
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "actor_user_id does not match the authenticated user",
      });
    }

    // ── 2. Network scope ────────────────────────────────────────────────────
    const networkCodes = await getSuperAdminNetworkCodes(actor, actorEmail);

    // ── 3. Summary + total + page rows ──────────────────────────────────────
    const escapedSearch = search !== "" ? escapeLike(search) : "";

    const summary = await getSummaryCounts(selectedDate, escapedSearch, dietitianId, networkCodes);
    const total = await countFilteredClients(selectedDate, escapedSearch, dietitianId, type, networkCodes);
    const rows = await fetchClients(
      selectedDate, escapedSearch, dietitianId, type, limit, offset, networkCodes
    );

    // ── 4. Audit the masked read (fire-and-forget) ─────────────────────────
    writeAuthLogSafe(req, {
      eventType: "super_admin_all_clients_viewed",
      userId: actorEmail,
      role: "super_admin",
      partnerCode: actorCode,
      identifier: auditIdentifier,
      success: true,
      failureReason: "Super admin viewed masked all clients overview",
    });

    // ── 5. Respond (matches the PHP JSON shape) ────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Super admin clients fetched successfully",
      mode: "super_admin_all_clients_overview",

      actor: {
        user_id: actorEmail,
        role: "super_admin",
        partner_code: actorCode,
        name: actor.name ?? null,
      },

      filters: {
        date: selectedDate,
        type,
        search,
        dietitian_id: dietitianId !== "" ? dietitianId : null,
        network_codes: networkCodes,
      },

      summary: {
        total_clients: summary.total_clients,

        selected_date: selectedDate,
        tested_clients: summary.tested_clients,
        missed_clients: summary.missed_clients,

        never_tested_clients: summary.never_tested_clients,
        tested_anytime_clients: summary.tested_anytime_clients,
        missed_but_tested_before: summary.missed_but_tested_before,
      },

      pagination: {
        page,
        limit,
        offset,
        total,
        has_more: offset + limit < total,
      },

      privacy: {
        client_identity_masked: true,
        raw_name_returned: false,
        raw_email_returned: false,
        raw_phone_returned: false,
        dob_returned: false,
        location_returned: false,
        profile_image_returned: false,
        audit_logged: true,
      },

      columns: [
        "name",
        "email",
        "profile_id",
        "dietitian_id",
        "partner_code",
        "level_type",
        "fitness_goal",
        "metabolism_score",
        "acetone_ppm",
        "ethanol_ppm",
        "h2_ppm",
        "diet_plan",
        "last_active",
      ],

      clients: formatClientRows(rows, selectedDate),
    });
  } catch (err) {
    console.error("SUPER_ADMIN_ALL_CLIENTS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "super_admin_all_clients_error",
      userId: actorEmail || actorUserId || null,
      role: actorEmail ? "super_admin" : null,
      partnerCode: actorCode,
      identifier: auditIdentifier,
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

module.exports = { superAdminAllClientsOverview };
