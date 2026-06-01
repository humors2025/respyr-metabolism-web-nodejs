"use strict";

/**
 * trainer-clients-overview-for-super-admin.js
 *
 * Converted from: trainer-clients-overview-for-super-admin.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/trainer-clients-overview-for-super-admin
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer (each scoped to its own network)
 *
 * Behaviour parity with the PHP:
 *  - Resolves a single TARGET trainer from trainer_id (which may be a
 *    dietician_id OR a partner_code; dietician_id matched case-insensitively).
 *  - The actor may only view the target if the target's effective code (or its
 *    dietician_id) belongs to the actor's network:
 *      trainer    → own effective code only
 *      admin      → own code + active trainers directly parented to the admin
 *      super_admin→ own code + active admins parented to it + active trainers
 *                   parented to it OR to one of those admins (one level, exactly
 *                   as the PHP — no extra recursion introduced).
 *  - Client identity is MASKED (name + email). Zone is never returned. Raw
 *    name/email are never returned.
 *  - metabolism_score = latest test fat_loss_metabolism_score only.
 *  - Per-row tests_count_3_months = distinct test DATES in the last 3 months.
 *  - Summary tested_clients / missed_clients are computed for TODAY only.
 *  - Response keys/shape match the PHP (status, ok, message, mode, actor,
 *    trainer, summary, pagination, columns, privacy, data).
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT
 *    (sub = dietician_id) and re-fetched from the DB on every call — NOT from
 *    body.actor_user_id as the PHP did. Trusting a client-supplied actor id is
 *    an IDOR / privilege-escalation hole; deriving identity from the token closes
 *    it. role + status are re-checked server-side so a stale/demoted token cannot
 *    read data. body.actor_user_id is still accepted for frontend/back-compat,
 *    but it is only cross-checked against the token email (mismatch → 403); it
 *    can never be used to act as a different user.
 *  - Fully parameterized queries. Network IN-lists are bound with placeholders,
 *    never string-interpolated. LIMIT/OFFSET are the only inlined values and are
 *    hard-coerced to non-negative integers first (mysql2 prepared statements
 *    reject bound LIMIT/OFFSET on some MySQL builds).
 *  - LIKE search wildcards (% _ \) in the user term are escaped so a caller
 *    cannot widen the search beyond what they typed.
 *  - Internal error details are suppressed in production responses; server logs
 *    carry only error metadata (code/errno/sqlState), never row data or PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The PHP ran `SET time_zone = '+05:30'` on the connection. That is NOT done
 *    here: this app uses a shared mysql2 pool and mutating the session TZ would
 *    leak into other concurrent requests. The 3-month window uses the DB server
 *    clock via NOW(); the TODAY tested/missed window uses an app-computed IST
 *    date passed as a bound parameter (see todayDateIST), preserving the PHP's
 *    Asia/Kolkata semantics without mutating the session.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns selected; no SELECT *.
 *  - Client identity is masked before it leaves the server.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every masked-overview read is recorded in app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const { resolveActorFromToken: sharedResolveActorFromToken } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

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

/** Today's date in Asia/Kolkata as "YYYY-MM-DD" (PHP set date_default_timezone IST). */
function todayDateIST() {
  // Shift UTC by +05:30 then read the UTC parts of the shifted instant.
  const now = new Date();
  const ist = new Date(now.getTime() + (5 * 60 + 30) * 60 * 1000);
  const pad = (n) => String(n).padStart(2, "0");
  return `${ist.getUTCFullYear()}-${pad(ist.getUTCMonth() + 1)}-${pad(ist.getUTCDate())}`;
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

/** PHP getEffectiveCode(): partner_code if non-blank, else dietician_id, else null. */
function getEffectiveCode(row) {
  if (row.partner_code !== null && row.partner_code !== undefined &&
      String(row.partner_code).trim() !== "") {
    return String(row.partner_code);
  }
  if (row.dietician_id !== null && row.dietician_id !== undefined &&
      String(row.dietician_id).trim() !== "") {
    return String(row.dietician_id);
  }
  return null;
}

// ─── Masking (faithful port of PHP maskName / maskEmail) ─────────────────────

function maskToken(part) {
  const len = part.length;
  if (len <= 2) {
    return part.slice(0, 1) + "x";
  }
  if (len <= 4) {
    return part.slice(0, 2) + "x".repeat(len - 2);
  }
  return part.slice(0, 2) + "x".repeat(Math.max(3, len - 3)) + part.slice(-1);
}

function maskName(name) {
  const trimmed = String(name ?? "").trim();
  if (trimmed === "") return "Client";

  return trimmed
    .split(/\s+/)
    .map(maskToken)
    .join(" ");
}

function maskEmail(email) {
  const normalized = normalizeEmail(email);
  if (normalized === "" || !normalized.includes("@")) return null;

  const atIdx = normalized.indexOf("@");
  const local = normalized.slice(0, atIdx);
  const domain = normalized.slice(atIdx + 1);

  return maskToken(local) + "@" + domain;
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
    console.error("TRAINER_CLIENTS_OVERVIEW_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or
 * { error: { status, body } }.
 *
 * NOTE: this intentionally diverges from the PHP, which trusted
 * body.actor_user_id. See the file header (VAPT hardening).
 */
async function resolveActorFromToken(req) {
  // Identity + status/role check delegated to the shared access-control module;
  // the neutral result is mapped back into this controller's error shape.
  const resolved = await sharedResolveActorFromToken(req, ALLOWED_ACTOR_ROLES);

  if (resolved.ok) {
    return { actor: resolved.actor, actorEmail: resolved.actorEmail };
  }

  const REASON_BODY = {
    invalid_token:    { status: 401, message: "Invalid token user" },
    not_found:        { status: 403, message: "Actor user not found" },
    inactive:         { status: 403, message: "Actor account is not active" },
    role_not_allowed: { status: 403, message: "Invalid actor role" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, body: { status: false, ok: false, message: m.message } } };
}

// ─── Network resolution (PHP getAllowedCodesForActor) ────────────────────────

/**
 * Build the actor's allowed network of UPPER-cased codes. One level of nesting,
 * exactly as the PHP — no extra recursion is introduced.
 */
async function getAllowedCodesForActor(actor, actorEmail) {
  const codes = new Map();

  const addCode = (code) => {
    const c = normalizeCode(code);
    if (c !== "") codes.set(c, c);
  };

  addCode(getEffectiveCode(actor));

  const role = String(actor.role);

  if (role === "trainer") {
    return [...codes.values()];
  }

  if (role === "admin") {
    const [rows] = await pool.execute(
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
    for (const row of rows) addCode(row.partner_code);
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
          )
      `,
      [actorEmail, actorEmail, actorEmail]
    );
    for (const row of rows) addCode(row.partner_code);
    return [...codes.values()];
  }

  return [...codes.values()];
}

function canAccessTrainerCode(allowedCodes, targetCode) {
  const t = normalizeCode(targetCode);
  if (t === "") return false;
  return allowedCodes.some((c) => normalizeCode(c) === t);
}

// ─── Target trainer resolution (PHP getTrainerByCodeOrFail) ──────────────────

/**
 * Resolve a single trainer/admin by code. trainerCode may match
 * table_dietician.dietician_id OR app_user_roles.partner_code (both
 * case-insensitive). Prefers an active role row, then the highest td.id.
 * Returns { trainer } or { error: { status, body } }.
 */
async function getTrainerByCodeOrFail(trainerCode) {
  const code = normalizeCode(trainerCode);

  if (code === "") {
    return { error: { status: 422, body: { status: false, ok: false, message: "trainer_id is required" } } };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.id,
        td.dietician_id,
        td.name,
        td.email,
        td.phone_no,

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
      LIMIT 1
    `,
    [code, code]
  );

  const trainer = rows[0];

  if (!trainer) {
    return { error: { status: 404, body: { status: false, ok: false, message: "Trainer/admin code not found" } } };
  }

  if (trainer.role_status !== null && trainer.role_status !== undefined &&
      String(trainer.role_status) !== "active") {
    return { error: { status: 403, body: { status: false, ok: false, message: "Trainer/admin account is not active" } } };
  }

  return { trainer };
}

// ─── Count + fetch (single target code) ──────────────────────────────────────

function buildSearchSql() {
  return `
    AND (
      LOWER(base.profile_id) LIKE LOWER(?)
      OR LOWER(COALESCE(base.client_name, '')) LIKE LOWER(?)
      OR LOWER(COALESCE(base.client_email, '')) LIKE LOWER(?)
    )
  `;
}

// Minimum-necessary client projection. table_clients carries no goal column in
// this schema, so the per-row goal is taken from the latest test's goal_type
// (PHP did the same when no client goal column existed).
const CLIENT_SELECT = `
  tc.profile_id,
  tc.dietician_id,
  tc.profile_name AS client_name,
  tc.email AS client_email,
  tc.phone_no AS client_mobile,
  tc.dttm AS client_created_at
`;

async function countClientsForTrainer(targetCode, escapedSearch) {
  const params = [normalizeCode(targetCode)];

  let searchSql = "";
  if (escapedSearch !== "") {
    searchSql = buildSearchSql();
    const like = `%${escapedSearch}%`;
    params.push(like, like, like);
  }

  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS total
      FROM (
        SELECT
          ${CLIENT_SELECT}
        FROM table_clients tc
        WHERE UPPER(tc.dietician_id) = UPPER(?)
      ) base
      WHERE 1=1
      ${searchSql}
    `,
    params
  );

  return toInt(rows[0]?.total);
}

async function countClientsTestedOnDate(targetCode, escapedSearch, targetDate) {
  const params = [normalizeCode(targetCode)];

  let searchSql = "";
  if (escapedSearch !== "") {
    searchSql = buildSearchSql();
    const like = `%${escapedSearch}%`;
    params.push(like, like, like);
  }

  // target_date is bound LAST to match the placeholder order in the SQL below.
  params.push(targetDate);

  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS total
      FROM (
        SELECT
          ${CLIENT_SELECT}
        FROM table_clients tc
        WHERE UPPER(tc.dietician_id) = UPPER(?)
      ) base
      WHERE 1=1
      ${searchSql}
        AND EXISTS (
          SELECT 1
          FROM table_test_data t
          WHERE UPPER(t.dietitian_id) = UPPER(base.dietician_id)
            AND t.profile_id = base.profile_id
            AND DATE(t.date_time) = ?
          LIMIT 1
        )
    `,
    params
  );

  return toInt(rows[0]?.total);
}

async function fetchClientsForTrainer(targetCode, escapedSearch, limit, offset) {
  const params = [normalizeCode(targetCode)];

  let searchSql = "";
  if (escapedSearch !== "") {
    searchSql = buildSearchSql();
    const like = `%${escapedSearch}%`;
    params.push(like, like, like);
  }

  // limit/offset are hard-coerced to non-negative ints, so inlining them is
  // injection-safe. mysql2 prepared statements reject bound LIMIT/OFFSET on some
  // MySQL builds, hence they are not passed as placeholders.
  const safeLimit = Math.max(0, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

  const [rows] = await pool.execute(
    `
      SELECT
        base.profile_id,
        base.dietician_id,
        base.client_name,
        base.client_email,
        base.client_mobile,
        base.client_created_at,

        latest.test_id AS latest_test_id,
        latest.date_time AS latest_test_date_time,
        latest.goal_type AS latest_goal_type,
        latest.level_type AS latest_level_type,

        latest.fat_loss_metabolism_score,

        latest.acetone_ppm,
        latest.h2_ppm,
        latest.ethanol_ppm,

        tests.tests_count_3_months
      FROM (
        SELECT
          ${CLIENT_SELECT}
        FROM table_clients tc
        WHERE UPPER(tc.dietician_id) = UPPER(?)
      ) base

      LEFT JOIN table_test_data latest
        ON latest.test_id = (
          SELECT t2.test_id
          FROM table_test_data t2
          WHERE UPPER(t2.dietitian_id) = UPPER(base.dietician_id)
            AND t2.profile_id = base.profile_id
            AND t2.date_time >= DATE_SUB(NOW(), INTERVAL 3 MONTH)
          ORDER BY t2.date_time DESC, t2.test_id DESC
          LIMIT 1
        )

      LEFT JOIN (
        SELECT
          UPPER(t3.dietitian_id) AS dietitian_id_key,
          t3.profile_id,
          COUNT(DISTINCT DATE(t3.date_time)) AS tests_count_3_months
        FROM table_test_data t3
        WHERE t3.date_time >= DATE_SUB(NOW(), INTERVAL 3 MONTH)
        GROUP BY UPPER(t3.dietitian_id), t3.profile_id
      ) tests
        ON tests.dietitian_id_key = UPPER(base.dietician_id)
       AND tests.profile_id = base.profile_id

      WHERE 1=1
      ${searchSql}

      ORDER BY
        CASE WHEN latest.date_time IS NULL THEN 1 ELSE 0 END ASC,
        latest.date_time DESC,
        base.profile_id DESC

      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    params
  );

  return rows;
}

// ─── Row formatting (masked) ─────────────────────────────────────────────────

function formatClientRow(row) {
  const latestTestDate = toMysqlDateTime(row.latest_test_date_time);
  const testsCount = toInt(row.tests_count_3_months);

  let goal = null;
  if (row.latest_goal_type !== null && row.latest_goal_type !== undefined &&
      String(row.latest_goal_type).trim() !== "") {
    goal = row.latest_goal_type;
  }

  const metabolismScore = scoreValue(row.fat_loss_metabolism_score);

  return {
    profile_id: row.profile_id,

    // Masked identity only.
    name: maskName(row.client_name),
    email: maskEmail(row.client_email),

    // Raw values deliberately not returned.
    client_name_raw: null,
    client_email_raw: null,

    fitness_goal: goal,

    // Metabolism score comes only from latest fat_loss_metabolism_score.
    metabolism_score: metabolismScore,

    // Zone intentionally not returned.
    zone: null,

    // Count only 1 test per day for last 3 months.
    tests_count_3_months: testsCount,

    // Old UI compatibility alias.
    tests: testsCount,

    last_active: latestTestDate,

    // Latest biomarker data from latest test in last 3 months.
    latest_test: {
      test_id:
        row.latest_test_id !== null && row.latest_test_id !== undefined
          ? toInt(row.latest_test_id)
          : null,
      date_time: latestTestDate,
      acetone_ppm: scoreValue(row.acetone_ppm),
      ethanol_ppm: scoreValue(row.ethanol_ppm),
      h2_ppm: scoreValue(row.h2_ppm),
    },

    biomarkers: {
      acetone_ppm: scoreValue(row.acetone_ppm),
      ethanol_ppm: scoreValue(row.ethanol_ppm),
      h2_ppm: scoreValue(row.h2_ppm),
    },
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
  const trainerInput =
    src.trainer_id !== undefined && src.trainer_id !== null
      ? normalizeCode(src.trainer_id)
      : "";

  // Optional. Accepted for frontend/back-compat, but never authoritative — see
  // the cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);

  return { page, limit, search, trainerInput, actorUserId, offset: (page - 1) * limit };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/trainer-clients-overview-for-super-admin
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "trainer_id": "RespyrD03",   // dietician_id OR partner_code (required)
 *     "page": 1,
 *     "limit": 10,
 *     "search": "",
 *     "actor_user_id": ""          // optional; if set, must match the token email
 *   }
 */
const trainerClientsOverviewForSuperAdmin = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const { page, limit, search, trainerInput, actorUserId, offset } = parseInputs(req);

  let actorEmail = null;
  let actorRole = null;
  let actorEffectiveCode = null;
  let targetCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_clients_overview_access_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: null,
        success: false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorEffectiveCode = getEffectiveCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_clients_overview_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorEffectiveCode,
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

    // ── 2. Resolve the target trainer by code ───────────────────────────────
    const trainerResult = await getTrainerByCodeOrFail(trainerInput);

    if (trainerResult.error) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_clients_overview_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorEffectiveCode,
        identifier: trainerInput,
        success: false,
        failureReason: trainerResult.error.body?.message || "trainer resolution failed",
      });
      return res.status(trainerResult.error.status).json(trainerResult.error.body);
    }

    const { trainer } = trainerResult;

    targetCode = getEffectiveCode(trainer);
    if (targetCode === null || String(targetCode).trim() === "") {
      targetCode = trainer.dietician_id;
    }

    // ── 3. RBAC gate: target must be inside the actor's network ─────────────
    const allowedCodes = await getAllowedCodesForActor(actor, actorEmail);

    if (!canAccessTrainerCode(allowedCodes, targetCode) &&
        !canAccessTrainerCode(allowedCodes, trainer.dietician_id)) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_clients_overview_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorEffectiveCode,
        identifier: targetCode,
        success: false,
        failureReason: "Actor not allowed to view target trainer clients",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "You are not allowed to view this trainer clients",
      });
    }

    // ── 4. Count → today summary → fetch ────────────────────────────────────
    const escapedSearch = search !== "" ? escapeLike(search) : "";

    const totalClients = await countClientsForTrainer(targetCode, escapedSearch);

    // Summary tested/missed is TODAY only (Asia/Kolkata).
    const todayDate = todayDateIST();
    const summaryTested = await countClientsTestedOnDate(targetCode, escapedSearch, todayDate);
    const summaryMissed = Math.max(0, totalClients - summaryTested);

    // Row data uses latest test in last 3 months + distinct test-day count.
    const rows = await fetchClientsForTrainer(targetCode, escapedSearch, limit, offset);
    const formattedRows = rows.map(formatClientRow);

    // ── 5. Audit the masked read (fire-and-forget) ─────────────────────────
    writeAuthLogSafe(req, {
      eventType: "trainer_clients_overview_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorEffectiveCode,
      identifier: targetCode,
      success: true,
      failureReason: "Viewed masked trainer clients overview",
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Trainer clients overview fetched successfully",
      mode: "trainer_clients_overview",

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorEffectiveCode,
      },

      trainer: {
        name: trainer.name,
        email: normalizeEmail(trainer.email),
        dietician_id: trainer.dietician_id,
        partner_code: targetCode,
        actual_role:
          trainer.role !== null && trainer.role !== undefined ? trainer.role : "trainer",
        display_role: "trainer",
      },

      summary: {
        total_clients: totalClients,

        // Dashboard cards: today only.
        tested_clients: summaryTested,
        missed_clients: summaryMissed,
        tested_missed_date: todayDate,
        tested_missed_rule: "tested_clients means at least one test on tested_missed_date",

        // Per-row tests column: last 3 months.
        tests_window: "last_3_months",
        test_count_rule: "max_1_test_per_day_per_profile",
      },

      pagination: {
        page,
        limit,
        offset,
        total: totalClients,
        has_more: offset + limit < totalClients,
      },

      columns: [
        "name",
        "email",
        "profile_id",
        "fitness_goal",
        "metabolism_score",
        "acetone_ppm",
        "ethanol_ppm",
        "h2_ppm",
        "tests_count_3_months",
        "last_active",
      ],

      privacy: {
        client_identity_masked: true,
        zone_returned: false,
        raw_name_returned: false,
        raw_email_returned: false,
        audit_logged: true,
      },

      data: formattedRows,
    });
  } catch (err) {
    console.error("TRAINER_CLIENTS_OVERVIEW_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "trainer_clients_overview_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorEffectiveCode,
      identifier: targetCode,
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

module.exports = { trainerClientsOverviewForSuperAdmin };
