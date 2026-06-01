"use strict";

/**
 * get-clients-data-total-missed-test-masked.js
 *
 * Converted from: get-clients-data-total-missed-test-masked.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get-clients-data-total-missed-test-masked
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer (each scoped to its own network)
 *
 * Behaviour parity with the PHP:
 *  - Resolves a TARGET dietician_id and returns its clients' tested/missed status
 *    for a selected date, with a tested/missed/all summary for that date.
 *  - RBAC (ctd_actor_can_access_code):
 *      trainer     → own code only
 *      admin       → own code + active trainers directly parented to the admin
 *      super_admin → own code + self/children + active trainers parented to it or
 *                    to one of its active admins (one level — no extra recursion).
 *  - Client identity is MASKED (name / email / phone / age-band). dob, region,
 *    location, profile_image are never returned.
 *  - metabolism_score / zone / last test come from the LATEST test ON the
 *    selected date; test_taken_count = distinct test DATES in the last 3 months.
 *  - type filter: all | tested | missed (invalid → all).
 *  - Response keys/shape match the PHP (status, message, dietician_id,
 *    selected_date, type, pagination, summary, privacy, clients). `ok` is
 *    mirrored alongside `status` to match the sibling Node controllers.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT
 *    (sub = dietician_id) and re-fetched from the DB on every call — NOT from
 *    body.actor_user_id as the PHP did. Trusting a client-supplied actor id is an
 *    IDOR / privilege-escalation hole; deriving identity from the token closes it.
 *    role + status are re-checked server-side. body.actor_user_id is still
 *    accepted for frontend/back-compat, but it is only cross-checked against the
 *    token email (mismatch → 403); it can never select a different user.
 *  - Fully parameterized queries (? placeholders). LIMIT/OFFSET are the only
 *    inlined values and are hard-coerced to non-negative integers first (mysql2
 *    prepared statements reject bound LIMIT/OFFSET on some MySQL builds).
 *  - Strict input validation: dietician_id required, date must be a real
 *    YYYY-MM-DD, type allow-listed.
 *  - Internal error details are suppressed in production responses (gated behind
 *    APP_DEBUG); server logs carry only error metadata, never row data or PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The PHP ran `SET time_zone = '+05:30'` on the connection. That is NOT done
 *    here: this app uses a shared mysql2 pool and mutating the session TZ would
 *    leak into other concurrent requests. The "today" comparison uses an
 *    app-computed IST date, preserving the PHP's Asia/Kolkata semantics. The
 *    3-month window uses the DB server clock via CURDATE() (approximate count).
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; client identity masked before it leaves the server.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every masked read (and every denial) is recorded in app_auth_logs.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, table_clients, table_test_data, user_habits, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  resolveActorFromToken: sharedResolveActorFromToken,
  actorCanAccessCode: sharedActorCanAccessCode,
} = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);
const ALLOWED_TYPES = new Set(["all", "tested", "missed"]);

const PAGE_LIMIT = 10;
const MAX_PAGE = 10000;

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

/** PHP ctd_clean_value(): null/blank → default ("NA"), else trimmed string. */
function cleanValue(val, def = "NA") {
  const str = String(val ?? "").trim();
  return str === "" ? def : str;
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

/** "YYYY-MM-DD" from a DATETIME value (Date or string). */
function toDateOnly(val) {
  if (!val) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())}`;
  }
  const s = String(val);
  const m = s.match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : null;
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

/** PHP ctd_get_actor_code(): partner_code if non-blank, else dietician_id, else null. */
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

// ─── Masking (faithful port of the PHP ctd_mask_* helpers) ───────────────────

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
  if (normalized === "" || normalized.toUpperCase() === "NA" ||
      !normalized.includes("@")) {
    return "NA";
  }
  const atIdx = normalized.indexOf("@");
  const local = normalized.slice(0, atIdx);
  const domain = normalized.slice(atIdx + 1);
  return maskToken(local) + "@" + domain;
}

function maskPhone(phone) {
  const trimmed = String(phone ?? "").trim();
  if (trimmed === "" || trimmed.toUpperCase() === "NA") return "NA";

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

// ─── Business helpers ────────────────────────────────────────────────────────

function getMetabolismZone(score) {
  if (score === null || score === undefined || score === "") return null;
  const s = Number(score);
  if (Number.isNaN(s)) return null;
  if (s >= 80) return "Optimal";
  if (s >= 70) return "Moderate";
  return "Focus";
}

function formatFitnessGoal(raw) {
  let goal = String(raw ?? "").trim();
  if (goal === "") goal = "fat_loss";
  return goal
    .toLowerCase()
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function getLastLoggedText(lastDateTime, selectedDate) {
  if (!lastDateTime) return "No test yet";
  const lastDateOnly = toDateOnly(lastDateTime);
  if (!lastDateOnly) return "No test yet";
  const today = todayDateIST();
  if (selectedDate === today && lastDateOnly === selectedDate) return "Today";
  return lastDateOnly;
}

function formatClientRows(rows, selectedDate) {
  return rows.map((row) => {
    const rawScore = row.metabolism_score;
    const score =
      rawScore !== null && rawScore !== undefined && rawScore !== ""
        ? Number(rawScore)
        : null;
    const safeScore = Number.isNaN(score) ? null : score;

    const fitnessGoalRaw = row.fitness_goal ?? "";
    const fitnessGoalValue =
      String(fitnessGoalRaw).trim() !== "" ? fitnessGoalRaw : "weight_loss";

    return {
      dietician_id: normalizeCode(row.dietician_id),
      profile_id: row.profile_id,

      // Masked identity fields.
      client_name: maskName(row.client_name),
      phone_no: maskPhone(row.phone_no),
      email: maskEmail(row.email),
      dob: "hidden",
      age: ageGroup(row.age),

      // Non-direct context fields.
      gender: cleanValue(row.gender),
      height: cleanValue(row.height),
      weight: cleanValue(row.weight),

      // Location/region/image are hidden — they can identify a client.
      region: "hidden",
      location: "hidden",

      fitness_goal: fitnessGoalValue,
      fitness_goal_display: formatFitnessGoal(fitnessGoalRaw),
      metabolism_score: safeScore,
      zone: getMetabolismZone(safeScore),
      test_taken_count: toInt(row.test_taken_count),
      last_logged_date: toMysqlDateTime(row.last_logged_date),
      last_logged: getLastLoggedText(row.last_logged_date, selectedDate),
      p_created: toMysqlDateTime(row.dttm),

      // Image can identify a client — never returned.
      p_image: null,

      level_type: cleanValue(row.level_type),
    };
  });
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
    console.error("CLIENT_TOTAL_MISSED_AUDIT_FAILED:", err?.code || err?.message);
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
  // Delegates identity + status/role checks to the shared access-control module
  // (single audited choke point), then maps the neutral, reason-coded result
  // back into THIS controller's historical error shape so behavior is unchanged.
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

// ─── RBAC: can the actor view this dietician's clients? ───────────────────────

/**
 * Port of PHP ctd_actor_can_access_code(). One level of nesting, exactly as the
 * PHP — no extra recursion is introduced.
 */
async function actorCanAccessCode(actor, actorEmail, targetCode) {
  // One-level hierarchy RBAC now lives in the shared access-control module so it
  // is defined and audited in exactly one place.
  return sharedActorCanAccessCode(actor, actorEmail, targetCode);
}

// ─── Queries ─────────────────────────────────────────────────────────────────

async function fetchSummary(dieticianId, selectedDate) {
  const [rows] = await pool.execute(
    `
      SELECT
        COUNT(DISTINCT tc.profile_id) AS all_total,

        COUNT(DISTINCT CASE
          WHEN DATE(tt.date_time) = ?
          THEN tc.profile_id
        END) AS tested_total,

        COUNT(DISTINCT tc.profile_id)
        - COUNT(DISTINCT CASE
          WHEN DATE(tt.date_time) = ?
          THEN tc.profile_id
        END) AS missed_total

      FROM table_clients tc

      LEFT JOIN table_test_data tt
        ON tt.profile_id = tc.profile_id
        AND UPPER(TRIM(tt.dietitian_id)) = ?
        AND DATE(tt.date_time) = ?

      WHERE UPPER(TRIM(tc.dietician_id)) = ?
    `,
    [selectedDate, selectedDate, dieticianId, selectedDate, dieticianId]
  );
  return rows[0] || {};
}

async function fetchClients(dieticianId, selectedDate, type, limit, offset) {
  // type is allow-listed before this call, so these fragments are constants —
  // no user input is interpolated into SQL.
  let filterCondition = "";
  if (type === "tested") {
    filterCondition = "AND ttd.test_id IS NOT NULL";
  } else if (type === "missed") {
    filterCondition = "AND ttd.test_id IS NULL";
  }

  // limit/offset are hard-coerced to non-negative ints, so inlining them is
  // injection-safe. mysql2 prepared statements reject bound LIMIT/OFFSET on some
  // MySQL builds, hence they are not passed as placeholders.
  const safeLimit = Math.max(1, toInt(limit));
  const safeOffset = Math.max(0, toInt(offset));

  const [rows] = await pool.execute(
    `
      SELECT
        tc.dietician_id,
        tc.profile_id,
        tc.profile_name AS client_name,
        tc.phone_no,
        tc.email,
        tc.dob,
        tc.age,
        tc.gender,
        tc.height,
        tc.weight,
        tc.region,
        tc.location,
        tc.dttm,
        tc.profile_image,
        tc.level_type,

        IFNULL(uh.goal, '') AS fitness_goal,

        CASE
          WHEN ttd.test_id IS NOT NULL THEN 'tested'
          ELSE 'missed'
        END AS test_status,

        ttd.fat_loss_metabolism_score AS metabolism_score,
        ttd.date_time AS last_logged_date,
        IFNULL(ttc.test_taken_count, 0) AS test_taken_count

      FROM table_clients tc

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

      LEFT JOIN table_test_data ttd
        ON ttd.test_id = (
          SELECT t1.test_id
          FROM table_test_data t1
          WHERE t1.profile_id = tc.profile_id
            AND UPPER(TRIM(t1.dietitian_id)) = ?
            AND DATE(t1.date_time) = ?
          ORDER BY t1.date_time DESC, t1.test_id DESC
          LIMIT 1
        )

      LEFT JOIN (
        SELECT
          profile_id,
          COUNT(DISTINCT DATE(date_time)) AS test_taken_count
        FROM table_test_data
        WHERE UPPER(TRIM(dietitian_id)) = ?
          AND date_time >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
        GROUP BY profile_id
      ) ttc
        ON ttc.profile_id = tc.profile_id

      WHERE UPPER(TRIM(tc.dietician_id)) = ?
      ${filterCondition}

      ORDER BY
        CASE WHEN ttd.date_time IS NULL THEN 1 ELSE 0 END ASC,
        ttd.date_time DESC,
        tc.dttm DESC

      LIMIT ${safeLimit} OFFSET ${safeOffset}
    `,
    [dieticianId, selectedDate, dieticianId, dieticianId]
  );

  return rows;
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(req) {
  const src = req.body && typeof req.body === "object" ? req.body : {};

  // Optional. Accepted for frontend/back-compat, but never authoritative — see
  // the cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);

  // Canonical key is `dietitian_id` (with a "t"); `dietician_id` (with a "c")
  // is still accepted for back-compat with the original PHP payload.
  const dieticianId = normalizeCode(src.dietitian_id ?? src.dietician_id);

  let type = typeof src.type === "string" ? src.type.trim().toLowerCase() : "all";
  if (!ALLOWED_TYPES.has(type)) type = "all";

  const pageNum = Number.parseInt(src.page, 10);
  const page =
    Number.isInteger(pageNum) && pageNum >= 1 && pageNum <= MAX_PAGE ? pageNum : 1;

  const dateRaw = typeof src.date === "string" ? src.date.trim() : "";
  const dateProvided = dateRaw !== "";
  const selectedDate = isValidDate(dateRaw) ? dateRaw : todayDateIST();

  const limit = PAGE_LIMIT;
  const offset = (page - 1) * limit;

  return {
    actorUserId,
    dieticianId,
    type,
    page,
    dateRaw,
    dateProvided,
    selectedDate,
    limit,
    offset,
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get-clients-data-total-missed-test-masked
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "dietician_id": "RespyrD03",   // target (required)
 *     "type": "all",                 // all | tested | missed
 *     "page": 1,
 *     "date": "2026-05-27",          // optional; defaults to today (IST)
 *     "actor_user_id": ""            // optional; if set, must match the token email
 *   }
 */
const getClientsDataTotalMissedTestMasked = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "method is not allowed" });
  }

  const { actorUserId, dieticianId, type, page, dateRaw, dateProvided, selectedDate, limit, offset } =
    parseInputs(req);

  // Mirror the PHP's explicit input validation.
  if (dieticianId === "") {
    return res.status(400).json({ status: false, ok: false, message: "dietitian_id is required" });
  }

  // If a date was supplied but malformed, reject it (PHP returned 400). A blank
  // date is allowed and defaults to today.
  if (dateProvided && !isValidDate(dateRaw)) {
    return res.status(400).json({
      status: false,
      ok: false,
      message: "date must be in YYYY-MM-DD format",
    });
  }

  const auditIdentifier = `${dieticianId}|${type}|${selectedDate}|page:${page}`;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "client_test_dashboard_access_denied",
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
    actorRole = String(actor.role);
    actorCode = getActorCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "client_test_dashboard_access_denied",
        userId: actorEmail,
        role: actorRole,
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

    // ── 2. RBAC: actor must be allowed to view this dietician's clients ─────
    const canAccess = await actorCanAccessCode(actor, actorEmail, dieticianId);

    if (!canAccess) {
      await writeAuthLogSafe(req, {
        eventType: "client_test_dashboard_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "Actor not allowed for dietician_id",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "You are not allowed to view this client data",
      });
    }

    // ── 3. Summary (selected date) + masked client list ────────────────────
    const summary = await fetchSummary(dieticianId, selectedDate);
    const rows = await fetchClients(dieticianId, selectedDate, type, limit, offset);

    // ── 4. Audit the masked read (fire-and-forget) ─────────────────────────
    writeAuthLogSafe(req, {
      eventType: "client_test_dashboard_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: auditIdentifier,
      success: true,
      failureReason: "Viewed masked client tested/missed dashboard",
    });

    // ── 5. Respond (matches the PHP JSON shape) ────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Dashboard data fetched successfully",
      dietician_id: dieticianId,
      selected_date: selectedDate,
      type,
      pagination: {
        page,
        limit,
      },
      summary: {
        all_total: toInt(summary.all_total),
        tested_total: toInt(summary.tested_total),
        missed_total: toInt(summary.missed_total),
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
      clients: formatClientRows(rows, selectedDate),
    });
  } catch (err) {
    console.error("CLIENT_TOTAL_MISSED_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "client_test_dashboard_error",
      userId: actorEmail || actorUserId || null,
      role: actorRole,
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

module.exports = { getClientsDataTotalMissedTestMasked };
