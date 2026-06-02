"use strict";

/**
 * get-data-points-score-all-ranges-coach-masking.js
 *
 * Converted from: get-data-points-score-all-ranges-coach-masking.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get-data-points-score-all-ranges-coach-masking
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer (each scoped to its own network)
 *
 * Behaviour parity with the PHP:
 *  - Returns a test's full data-points payload for a (profile_id, dietitian_id)
 *    pair. `date` (YYYY-MM-DD) is OPTIONAL: when supplied, the latest test ON
 *    that date is used; when omitted, the latest test overall is used — the exact
 *    PHP behaviour (ORDER BY date_time DESC, test_id DESC LIMIT 1).
 *  - RBAC (actorCanAccessDietitianCode):
 *      trainer     → own code only
 *      admin       → own code + active trainers directly parented to the admin
 *      super_admin → own code + self/children + active trainers parented to it or
 *                    to one of its active admins (one level — no extra recursion).
 *  - Client identity is MASKED: profile_name / phone_no / email masked; dob, age,
 *    region, location → "hidden"; age_group derived from age; profile_image never
 *    returned. raw_json is returned but recursively scrubbed of direct
 *    identifiers (sanitizeRawJsonForCoach).
 *  - Same response keys/shape as the unmasked sibling (total_test_taken,
 *    profile_details, user_habits, selected_test, fat_use_pattern_trend,
 *    trend_breakdown, trainer_note_section, energy, breath_markers,
 *    metabolism_score_summary, ai_status, raw_json). Envelope is
 *    { status, message, data } to match the PHP sendResponse().
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT
 *    (sub = dietician_id) and re-fetched from the DB on every call — NOT from
 *    body.actor_user_id as the PHP did. Trusting a client-supplied actor id is an
 *    IDOR / privilege-escalation hole; deriving identity from the token closes it.
 *    role + status are re-checked server-side. body.actor_user_id is still
 *    accepted for frontend/back-compat, but it is only cross-checked against the
 *    token email (mismatch → 403); it can never select a different user.
 *  - Fully parameterized queries (? placeholders). No string interpolation.
 *  - Internal error details are suppressed in production responses (gated behind
 *    APP_DEBUG); server logs carry only error metadata, never row data or PHI.
 *    (The PHP echoed the raw DB/exception message — an info-disclosure finding.)
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The PHP ran `SET time_zone = '+05:30'` on the connection. That is NOT done
 *    here: this app uses a shared mysql2 pool and mutating the session TZ would
 *    leak into other concurrent requests. Datetimes are formatted in JS instead.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; client identity masked before it leaves the server.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every masked read (and every denial) is recorded in app_auth_logs.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, table_clients, user_habits, table_test_data, app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// Direct-identifier keys scrubbed out of raw_json (PHP $blockedKeys).
const BLOCKED_JSON_KEYS = new Set([
  "name",
  "full_name",
  "profile_name",
  "client_name",
  "email",
  "client_email",
  "phone",
  "phone_no",
  "mobile",
  "client_mobile",
  "dob",
  "date_of_birth",
  "profile_image",
  "image",
  "location",
  "address",
  "region",
]);

// ─── Response envelope ───────────────────────────────────────────────────────

function sendResponse(res, httpCode, status, message, data = null) {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  const response = { status, message };
  if (status === true && data !== null) {
    response.data = data;
  }
  return res.status(httpCode).json(response);
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return String(val ?? "").trim().toLowerCase();
}

function normalizeCode(val) {
  return String(val ?? "").trim().toUpperCase();
}

function getValue(object, keys, defaultValue = null) {
  let temp = object;
  for (const key of keys) {
    if (
      temp === null ||
      temp === undefined ||
      typeof temp !== "object" ||
      Array.isArray(temp) ||
      !Object.prototype.hasOwnProperty.call(temp, key)
    ) {
      return defaultValue;
    }
    temp = temp[key];
  }
  return temp;
}

function cleanFloat(value, defaultValue = 0) {
  if (value === null || value === undefined || value === "") return defaultValue;
  const n = Number(value);
  return Number.isFinite(n) ? n : defaultValue;
}

function cleanString(value, defaultValue = "NA") {
  if (value === null || value === undefined || value === "") return defaultValue;
  return String(value);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeObject(value) {
  return isPlainObject(value) ? value : {};
}

function safeArray(value) {
  return Array.isArray(value) ? value : [];
}

function isValidDateOnly(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(value.trim())) {
    return false;
  }
  const trimmed = value.trim();
  const d = new Date(`${trimmed}T00:00:00.000Z`);
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === trimmed;
}

/** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS" (matches the unmasked sibling). */
function formatDateTime(value) {
  if (!value) return "NA";
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return "NA";
    const pad = (n) => String(n).padStart(2, "0");
    return (
      `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} ` +
      `${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`
    );
  }
  return String(value);
}

/** "YYYY-MM-DD" from a DATETIME value (Date or string). */
function toDateOnly(value) {
  if (!value) return null;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  }
  const m = String(value).match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : null;
}

/** "DD Mon, YYYY" from a YYYY-MM-DD string (PHP date('d M, Y')). */
function formatDisplayDate(dateString) {
  if (!isValidDateOnly(dateString)) return "NA";
  const [year, month, day] = dateString.split("-").map(Number);
  const shortMonths = [
    "", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
  ];
  return `${String(day).padStart(2, "0")} ${shortMonths[month]}, ${year}`;
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

/** PHP getActorEffectiveCode(): partner_code if non-blank, else dietician_id, else null. */
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

// ─── Masking (faithful port of the PHP mask* helpers) ────────────────────────

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

function makeAgeGroup(age) {
  if (age === null || age === undefined || age === "" || Number.isNaN(Number(age))) {
    return "NA";
  }
  const a = Math.trunc(Number(age));
  if (a <= 0) return "NA";
  if (a < 18) return "<18";
  if (a <= 24) return "18-24";
  if (a <= 34) return "25-34";
  if (a <= 44) return "35-44";
  if (a <= 54) return "45-54";
  if (a <= 64) return "55-64";
  return "65+";
}

// ─── raw_json scrubbing (PHP sanitizeRawJsonForCoach) ────────────────────────

function sanitizeRawJsonForCoach(value) {
  if (Array.isArray(value)) {
    return value.map((item) =>
      item !== null && typeof item === "object" ? sanitizeRawJsonForCoach(item) : item
    );
  }
  if (isPlainObject(value)) {
    const clean = {};
    for (const [key, item] of Object.entries(value)) {
      if (BLOCKED_JSON_KEYS.has(String(key).toLowerCase())) {
        clean[key] = "hidden";
        continue;
      }
      clean[key] =
        item !== null && typeof item === "object" ? sanitizeRawJsonForCoach(item) : item;
    }
    return clean;
  }
  return value;
}

function removeDirectIdentifiersFromJson(decodedJson) {
  if (decodedJson === null || typeof decodedJson !== "object") return null;
  return sanitizeRawJsonForCoach(decodedJson);
}

// ─── food_type parsing (PHP parseFoodType) ───────────────────────────────────

function parseFoodType(foodTypeRaw) {
  if (!foodTypeRaw) {
    return { raw: "NA", diet_type: "NA", primary_cuisine: "NA", secondary_cuisine: "NA" };
  }

  const raw = Buffer.isBuffer(foodTypeRaw)
    ? foodTypeRaw.toString("utf8").trim()
    : String(foodTypeRaw).trim();

  const result = { raw, diet_type: "NA", primary_cuisine: "NA", secondary_cuisine: "NA" };

  try {
    const decoded = JSON.parse(raw);
    if (decoded && typeof decoded === "object" && !Array.isArray(decoded)) {
      result.diet_type =
        decoded.diet_type !== undefined && decoded.diet_type !== ""
          ? String(decoded.diet_type) : "NA";
      result.primary_cuisine =
        decoded.primary_cuisine !== undefined && decoded.primary_cuisine !== ""
          ? String(decoded.primary_cuisine) : "NA";
      result.secondary_cuisine =
        decoded.secondary_cuisine !== undefined && decoded.secondary_cuisine !== ""
          ? String(decoded.secondary_cuisine) : "NA";
      return result;
    }
  } catch (_) {
    // Fall through to legacy key:value parsing.
  }

  const trimmed = raw.replace(/^\{/, "").replace(/\}$/, "").trim();
  for (const pair of trimmed.split(",")) {
    const parts = pair.split(":");
    if (parts.length < 2) continue;
    const key = parts[0].trim();
    const value = parts.slice(1).join(":").trim();
    if (key === "diet_type") result.diet_type = value !== "" ? value : "NA";
    else if (key === "primary_cuisine") result.primary_cuisine = value !== "" ? value : "NA";
    else if (key === "secondary_cuisine") result.secondary_cuisine = value !== "" ? value : "NA";
  }

  return result;
}

// ─── test_json column parsing ────────────────────────────────────────────────

function parseJsonColumn(columnValue) {
  if (columnValue === null || columnValue === undefined) {
    return { ok: false, empty: true, data: null };
  }

  let jsonText = "";

  if (Buffer.isBuffer(columnValue)) {
    jsonText = columnValue.toString("utf8");
  } else if (typeof columnValue === "string") {
    jsonText = columnValue;
  } else if (columnValue && columnValue.type === "Buffer" && Array.isArray(columnValue.data)) {
    jsonText = Buffer.from(columnValue.data).toString("utf8");
  } else if (isPlainObject(columnValue)) {
    return { ok: true, empty: false, data: columnValue };
  } else {
    return { ok: false, empty: false, data: null };
  }

  jsonText = jsonText.trim();
  if (!jsonText) return { ok: false, empty: true, data: null };

  try {
    const parsed = JSON.parse(jsonText);
    if (!isPlainObject(parsed)) return { ok: false, empty: false, data: null };
    return { ok: true, empty: false, data: parsed };
  } catch (_) {
    return { ok: false, empty: false, data: null };
  }
}

function buildTrendItem(decodedJson, key, title) {
  return {
    title,
    score: cleanFloat(getValue(decodedJson, ["Metabolism_Score_Analysis", key, "score"], 0)),
    zone: cleanString(getValue(decodedJson, ["Metabolism_Score_Analysis", key, "zone"], "NA")),
    short_text: cleanString(getValue(decodedJson, ["Metabolism_Score_Analysis", key, "client_state"], "NA")),
    interpretation: cleanString(getValue(decodedJson, ["Metabolism_Score_Analysis", key, "interpretation"], "NA")),
    intervention: cleanString(getValue(decodedJson, ["Metabolism_Score_Analysis", key, "intervention"], "NA")),
    what_is_this_score: cleanString(getValue(decodedJson, ["Metabolism_Score_Analysis", key, "what_is_this_score"], "NA")),
  };
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
    console.error("COACH_DATA_POINTS_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or
 * { error: { status, message } }.
 *
 * NOTE: this intentionally diverges from the PHP, which trusted
 * body.actor_user_id. See the file header (VAPT hardening).
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return { error: { status: 401, message: "Invalid token user" } };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.dietician_id,
        td.name,
        td.email,

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
    return { error: { status: 403, message: "Actor user not found" } };
  }
  if (String(actor.status) !== "active") {
    return { error: { status: 403, message: "Actor account is not active" } };
  }
  if (!ALLOWED_ACTOR_ROLES.has(String(actor.role))) {
    return { error: { status: 403, message: "Invalid actor role" } };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── RBAC: can the actor view this dietitian's data? ─────────────────────────

/**
 * Port of PHP actorCanAccessDietitianCode(). One level of nesting, exactly as the
 * PHP — no extra recursion is introduced.
 */
async function actorCanAccessDietitianCode(actor, actorEmail, targetCode) {
  const target = normalizeCode(targetCode);
  if (target === "") return false;

  const ownCode = getActorEffectiveCode(actor);
  if (ownCode !== null && normalizeCode(ownCode) === target) {
    return true;
  }

  const role = String(actor.role);

  if (role === "trainer") {
    return false;
  }

  if (role === "admin") {
    const [rows] = await pool.execute(
      `
        SELECT aur.id
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
          AND (
                UPPER(aur.partner_code) = UPPER(?)
             OR UPPER(td.dietician_id) = UPPER(?)
          )
        LIMIT 1
      `,
      [actorEmail, target, target]
    );
    return rows.length > 0;
  }

  if (role === "super_admin") {
    const [rows] = await pool.execute(
      `
        SELECT aur.id
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.status = 'active'
          AND (
                UPPER(aur.partner_code) = UPPER(?)
             OR UPPER(td.dietician_id) = UPPER(?)
          )
          AND (
                LOWER(aur.user_id) = LOWER(?)
             OR LOWER(aur.parent_user_id) = LOWER(?)
             OR LOWER(aur.parent_user_id) IN (
                    SELECT LOWER(user_id)
                    FROM app_user_roles
                    WHERE role = 'admin'
                      AND status = 'active'
                      AND LOWER(parent_user_id) = LOWER(?)
                )
          )
        LIMIT 1
      `,
      [target, target, actorEmail, actorEmail, actorEmail]
    );
    return rows.length > 0;
  }

  return false;
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get-data-points-score-all-ranges-coach-masking
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "profile_id": "PRF1001",        // required
 *     "dietitian_id": "RespyrD03",    // required (target)
 *     "date": "2026-05-27",           // optional; YYYY-MM-DD. Latest test on that
 *                                     // date; omit for the latest test overall.
 *     "actor_user_id": ""             // optional; if set, must match token email
 *   }
 */
const getDataPointsScoreAllRangesCoachMasking = async (req, res) => {
  const body = req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? req.body
    : null;

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return sendResponse(res, 405, false, "Only POST method is allowed");
  }

  if (!body) {
    return sendResponse(res, 400, false, "Invalid raw JSON body");
  }

  const actorUserId = normalizeEmail(body.actor_user_id);
  const profileId = typeof body.profile_id === "string" ? body.profile_id.trim() : "";
  const dietitianId = typeof body.dietitian_id === "string" ? body.dietitian_id.trim() : "";

  // Optional date filter (YYYY-MM-DD). Blank → latest test overall.
  const selectedDate = typeof body.date === "string" ? body.date.trim() : "";
  const dateProvided = selectedDate !== "";

  if (profileId === "") {
    return sendResponse(res, 400, false, "profile_id is required");
  }
  if (dietitianId === "") {
    return sendResponse(res, 400, false, "dietitian_id is required");
  }
  if (dateProvided && !isValidDateOnly(selectedDate)) {
    return sendResponse(res, 400, false, "Invalid date format. Use YYYY-MM-DD");
  }

  const auditIdentifier = dateProvided
    ? `${profileId}|${dietitianId}|${selectedDate}`
    : `${profileId}|${dietitianId}`;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorUserId || null,
        role: null,
        partnerCode: null,
        identifier: auditIdentifier,
        success: false,
        failureReason: resolved.error.message || "actor resolution failed",
      });
      return sendResponse(res, resolved.error.status, false, resolved.error.message);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getActorEffectiveCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });
      return sendResponse(res, 403, false, "actor_user_id does not match the authenticated user");
    }

    // ── 2. RBAC: actor must be allowed to view this dietitian's data ────────
    const canAccess = await actorCanAccessDietitianCode(actor, actorEmail, dietitianId);

    if (!canAccess) {
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "Actor not allowed for dietitian_id",
      });
      return sendResponse(res, 403, false, "You are not allowed to view this client data");
    }

    // ── 3. Total tests taken for this profile + dietitian ──────────────────
    const [countRows] = await pool.execute(
      `
        SELECT COUNT(*) AS total_test_taken
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(dietitian_id) = UPPER(?)
      `,
      [profileId, dietitianId]
    );
    const totalTestTaken = Number(countRows?.[0]?.total_test_taken || 0);

    // ── 4. Profile details (masked) ────────────────────────────────────────
    const [profileRows] = await pool.execute(
      `
        SELECT
          profile_id,
          dietician_id,
          profile_name,
          phone_no,
          email,
          profile_image,
          dob,
          age,
          gender,
          height,
          weight,
          region,
          location,
          level_type,
          dttm
        FROM table_clients
        WHERE profile_id = ?
          AND UPPER(dietician_id) = UPPER(?)
        LIMIT 1
      `,
      [profileId, dietitianId]
    );

    if (!profileRows.length) {
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "Profile details not found",
      });
      return sendResponse(res, 404, false, "Profile details not found");
    }

    const profileRow = profileRows[0];

    const profileDetails = {
      profile_id: cleanString(profileRow.profile_id, "NA"),
      dietitian_id: cleanString(profileRow.dietician_id, "NA"),
      profile_name: maskName(profileRow.profile_name),
      phone_no: maskPhone(profileRow.phone_no),
      email: maskEmail(profileRow.email),
      profile_image: null,
      dob: "hidden",
      age: "hidden",
      age_group: makeAgeGroup(profileRow.age),
      gender: cleanString(profileRow.gender, "NA"),
      height: cleanString(profileRow.height, "NA"),
      weight: cleanString(profileRow.weight, "NA"),
      region: "hidden",
      location: "hidden",
      joined_dttm: cleanString(formatDateTime(profileRow.dttm), "NA"),
      level_type: cleanString(profileRow.level_type, "NA"),
    };

    // ── 5. Latest user habits ──────────────────────────────────────────────
    const [habitRows] = await pool.execute(
      `
        SELECT
          profile_id,
          goal,
          activity,
          food_type,
          dttm,
          tsstamp
        FROM user_habits
        WHERE profile_id = ?
        ORDER BY id DESC
        LIMIT 1
      `,
      [profileId]
    );

    let userHabits;
    if (habitRows.length) {
      const habitsRow = habitRows[0];
      userHabits = {
        profile_id: cleanString(habitsRow.profile_id, "NA"),
        goal: cleanString(habitsRow.goal, "NA"),
        activity: cleanString(habitsRow.activity, "NA"),
        food_type: parseFoodType(habitsRow.food_type),
        dttm: cleanString(formatDateTime(habitsRow.dttm), "NA"),
        tsstamp: cleanString(formatDateTime(habitsRow.tsstamp), "NA"),
      };
    } else {
      userHabits = {
        profile_id: profileId,
        goal: "NA",
        activity: "NA",
        food_type: { raw: "NA", diet_type: "NA", primary_cuisine: "NA", secondary_cuisine: "NA" },
        dttm: "NA",
        tsstamp: "NA",
      };
    }

    // ── 6. Selected test: latest on `date` if given, else latest overall ───
    const dateFilterSql = dateProvided ? "AND DATE(date_time) = ?" : "";
    const testParams = dateProvided
      ? [profileId, dietitianId, selectedDate]
      : [profileId, dietitianId];

    const [testRows] = await pool.execute(
      `
        SELECT
          test_id,
          profile_id,
          test_json,
          date_time
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(dietitian_id) = UPPER(?)
          ${dateFilterSql}
        ORDER BY date_time DESC, test_id DESC
        LIMIT 1
      `,
      testParams
    );

    if (!testRows.length) {
      const noDataMessage = dateProvided
        ? "No data available for selected date"
        : "No data available";
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: noDataMessage,
      });
      return sendResponse(res, 404, false, noDataMessage);
    }

    const selectedRow = testRows[0];
    const parsedJson = parseJsonColumn(selectedRow.test_json);

    if (parsedJson.empty) {
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "test_json is empty",
      });
      return sendResponse(res, 404, false, "test_json is empty");
    }

    if (!parsedJson.ok) {
      await writeAuthLogSafe(req, {
        eventType: "coach_data_points_access_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: "Invalid JSON in test_json column",
      });
      return sendResponse(res, 500, false, "Invalid JSON in test_json column");
    }

    const decodedJson = parsedJson.data;

    // ── 7. Shape the data-points payload (parity with the unmasked sibling) ─
    const fatScore = cleanFloat(getValue(decodedJson, ["Fat_Use_Pattern_trend", "score"], 0));
    const fatZone = cleanString(getValue(decodedJson, ["Fat_Use_Pattern_trend", "zone"], "NA"));
    const fatTitle = cleanString(getValue(decodedJson, ["Fat_Use_Pattern_trend", "client_interpretation", "title"], "NA"));
    const fatText = cleanString(getValue(decodedJson, ["Fat_Use_Pattern_trend", "client_interpretation", "text"], "NA"));
    const fatScientificTitle = cleanString(getValue(decodedJson, ["Fat_Use_Pattern_trend", "scientific_interpretation", "title"], "NA"));
    const fatScientificText = cleanString(getValue(decodedJson, ["Fat_Use_Pattern_trend", "scientific_interpretation", "text"], "NA"));

    const digestiveActivity = buildTrendItem(decodedJson, "Digestive_Activity_Trend", "Digestive Activity Trend");
    const nutrientUtilization = buildTrendItem(decodedJson, "Nutrient_Utilization_Trend", "Nutrient Utilization Trend");
    const fuelUtilization = buildTrendItem(decodedJson, "Fuel_Utilization_Trend", "Fuel Utilization Trend");
    const energySource = buildTrendItem(decodedJson, "Energy_Source_Trend", "Energy Source Trend");
    const recoveryActivity = buildTrendItem(decodedJson, "Recovery_Activity_Trend", "Recovery Activity Trend");
    const metabolicLoad = buildTrendItem(decodedJson, "Metabolic_Load_Trend", "Metabolic Load Trend");

    const dayFocus = {
      title: cleanString(getValue(decodedJson, ["day_focus", "title"], "NA")),
      note: cleanString(getValue(decodedJson, ["day_focus", "note"], "NA")),
      why_today: cleanString(getValue(decodedJson, ["day_focus", "why_today"], "NA")),
      what_to_do: safeArray(getValue(decodedJson, ["day_focus", "what_to_do"], [])),
      avoid_today: safeArray(getValue(decodedJson, ["day_focus", "avoid_today"], [])),
      signals: safeArray(getValue(decodedJson, ["day_focus", "signals"], [])),
    };

    const energy = {
      mode: cleanString(getValue(decodedJson, ["energy", "mode"], "NA")),
      activity: cleanString(getValue(decodedJson, ["energy", "activity"], "NA")),
      bmr_kcal: cleanFloat(getValue(decodedJson, ["energy", "bmr_kcal"], 0)),
      tdee_kcal: cleanFloat(getValue(decodedJson, ["energy", "tdee_kcal"], 0)),
      target_kcal: cleanFloat(getValue(decodedJson, ["energy", "target_kcal"], 0)),
    };

    const breathMarkers = {
      acetone: {
        ppm: cleanFloat(getValue(decodedJson, ["breath_marker_analysis", "acetone", "ppm"], 0)),
        marker: cleanString(getValue(decodedJson, ["breath_marker_analysis", "acetone", "marker"], "acetone")),
      },
      ethanol: {
        ppm: cleanFloat(getValue(decodedJson, ["breath_marker_analysis", "ethanol", "ppm"], 0)),
        marker: cleanString(getValue(decodedJson, ["breath_marker_analysis", "ethanol", "marker"], "ethanol")),
      },
      hydrogen: {
        ppm: cleanFloat(getValue(decodedJson, ["breath_marker_analysis", "hydrogen", "ppm"], 0)),
        marker: cleanString(getValue(decodedJson, ["breath_marker_analysis", "hydrogen", "marker"], "hydrogen")),
      },
    };

    const metabolismScoreSummary = getValue(decodedJson, ["Metabolism_Score_Analysis", "metabolism_score_summary"], {});
    const aiStatus = getValue(decodedJson, ["ai_status"], {});

    const testDateOnly = toDateOnly(selectedRow.date_time);

    const responseData = {
      total_test_taken: totalTestTaken,

      profile_details: profileDetails,
      user_habits: userHabits,

      selected_test: {
        test_id: Number(selectedRow.test_id),
        profile_id: selectedRow.profile_id,
        dietitian_id: dietitianId,
        date: testDateOnly || "NA",
        display_date: testDateOnly ? formatDisplayDate(testDateOnly) : "NA",
        date_time: formatDateTime(selectedRow.date_time),
        bmi: cleanFloat(getValue(decodedJson, ["bmi"], 0)),
        mode: cleanString(getValue(decodedJson, ["mode"], "NA")),
        wellness_note: cleanString(getValue(decodedJson, ["wellness_note"], "NA")),
      },

      fat_use_pattern_trend: {
        title: "Fat-use pattern Trend",
        score: Number(fatScore.toFixed(2)),
        score_text: `${Math.round(fatScore)}%`,
        zone: fatZone,
        client_title: fatTitle,
        client_text: fatText,
        scientific_title: fatScientificTitle,
        scientific_text: fatScientificText,
      },

      trend_breakdown: {
        digestive_balance_trend: {
          tab_title: "Digestive Balance Trend",
          items: [nutrientUtilization, digestiveActivity],
        },
        fuel_and_energy_trend: {
          tab_title: "Fuel & Energy Trend",
          items: [fuelUtilization, energySource],
        },
        metabolic_recovery_trend: {
          tab_title: "Metabolic Recovery Trend",
          items: [recoveryActivity, metabolicLoad],
        },
      },

      trainer_note_section: {
        section_label: "TRAINER NOTE",
        sub_label: "What to focus on today",
        title: dayFocus.title,
        note: dayFocus.note,
        why_today: dayFocus.why_today,
        what_to_do: dayFocus.what_to_do,
        avoid_today: dayFocus.avoid_today,
        signals: dayFocus.signals,
      },

      energy,
      breath_markers: breathMarkers,

      metabolism_score_summary: safeObject(metabolismScoreSummary),
      ai_status: safeObject(aiStatus),

      // Key preserved for old frontend, but direct identifiers scrubbed out.
      raw_json: removeDirectIdentifiersFromJson(decodedJson),
    };

    // ── 8. Audit the masked read (fire-and-forget) ─────────────────────────
    writeAuthLogSafe(req, {
      eventType: "coach_data_points_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: auditIdentifier,
      success: true,
      failureReason: "Viewed masked coach data points",
    });

    return sendResponse(res, 200, true, "Data fetched successfully", responseData);
  } catch (err) {
    console.error("COACH_DATA_POINTS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "coach_data_points_error",
      userId: actorEmail || actorUserId || null,
      role: actorRole,
      partnerCode: actorCode,
      identifier: auditIdentifier,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return sendResponse(
      res,
      500,
      false,
      APP_DEBUG ? `Internal server error: ${err?.message}` : "Internal server error"
    );
  }
};

module.exports = { getDataPointsScoreAllRangesCoachMasking };
