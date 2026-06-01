"use strict";

/**
 * trainer-admin-clients-list-dir.js
 *
 * Converted from: trainer-admin-clients-list-dir.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/trainer-admin-clients-list-dir
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin (trainer admin) | super_admin
 *
 * Behaviour parity with the PHP:
 *  - Resolves the actor's "network" of partner codes = the actor's own
 *    effective code (partner_code, else dietician_id) PLUS the partner codes of
 *    every active trainer directly parented to the actor (one level, exactly as
 *    the PHP did — no extra recursion is introduced).
 *  - Optional trainer_id filter: must belong to the actor's network or the
 *    request is rejected (403) and audited. When valid, the listing is scoped to
 *    that single code.
 *  - Returns UNMASKED client PHI (name/email/phone/dob/location) after the RBAC
 *    gate, then writes a HIPAA access-audit record. profile_image is never
 *    returned (kept null), matching the PHP.
 *  - Response keys/shape match the PHP (status, message, mode, actor, filters,
 *    pagination, network_codes, privacy, clients). `ok` is mirrored alongside
 *    `status` to match the sibling Node controllers.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor is taken from the verified JWT (sub =
 *    dietician_id) and re-fetched from the DB on every call — NOT from
 *    body.actor_user_id as the PHP did. Trusting a client-supplied actor id is
 *    an IDOR / privilege-escalation hole; deriving identity from the token closes
 *    it. role + status are re-checked server-side so a stale/demoted token cannot
 *    read data. body.actor_user_id is still accepted for frontend/back-compat,
 *    but it is only cross-checked against the token email (mismatch → 403); it
 *    can never be used to act as a different user.
 *  - Fully parameterized queries. The dietician-code IN-list is bound with
 *    placeholders (?, ?, ...), never string-interpolated. LIMIT/OFFSET are the
 *    only inlined values and are hard-coerced to non-negative integers first
 *    (mysql2 prepared statements reject bound LIMIT/OFFSET on some MySQL builds).
 *  - LIKE search wildcards (% _ \) in the user term are escaped so a caller
 *    cannot widen the search beyond what they typed.
 *  - Internal error details are suppressed in production responses; server logs
 *    carry only error metadata (code/errno/sqlState), never row data or PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - The PHP ran `SET time_zone = '+05:30'` on the connection. That is NOT done
 *    here: this app uses a shared mysql2 pool and mutating the session TZ would
 *    leak into other concurrent requests. The 3-month test window uses the DB
 *    server clock via NOW(), which is acceptable for an approximate count.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns selected; no SELECT *.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - Every unmasked read is recorded in app_auth_logs.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const { resolveActorFromToken: sharedResolveActorFromToken } =
  require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["admin", "super_admin"]);

const MAX_LIMIT = 50;
const DEFAULT_LIMIT = 10;

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string" ? val.trim().toLowerCase() : String(val ?? "").trim().toLowerCase();
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

/** PHP getMetabolismZone(): >=80 Optimal, >=70 Moderate, else Focus; null/blank → null. */
function getMetabolismZone(score) {
  if (score === null || score === undefined || score === "") return null;
  const s = Number(score);
  if (Number.isNaN(s)) return null;
  if (s >= 80) return "Optimal";
  if (s >= 70) return "Moderate";
  return "Focus";
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

/** Format a mysql2 DATE as "YYYY-MM-DD". */
function toMysqlDate(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())}`;
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
    console.error("TRAINER_ADMIN_CLIENTS_AUDIT_FAILED:", err?.code || err?.message);
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
    role_not_allowed: { status: 403, message: "Only trainer admin can view this client list" },
  };
  const m = REASON_BODY[resolved.reason] || REASON_BODY.not_found;
  return { error: { status: m.status, body: { status: false, ok: false, message: m.message } } };
}

// ─── Network resolution ──────────────────────────────────────────────────────

/**
 * Port of PHP getTrainerAdminNetworkCodes(): actor's own effective code plus the
 * partner codes of active trainers directly parented to the actor. Returns a
 * de-duplicated array of UPPER-cased codes.
 */
async function getTrainerAdminNetworkCodes(actor, actorEmail) {
  const codes = new Map();

  const addCode = (code) => {
    const c = normalizeCode(code);
    if (c !== "") codes.set(c, c);
  };

  addCode(getActorEffectiveCode(actor));

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

function codeExistsInArray(codes, target) {
  const t = normalizeCode(target);
  return codes.some((c) => normalizeCode(c) === t);
}

// ─── Owner map ───────────────────────────────────────────────────────────────

function buildInPlaceholders(codes) {
  return codes.map(() => "?").join(",");
}

/**
 * Port of PHP getTrainerOwnerMap(): code → owner identity. Keyed by UPPER-cased
 * partner_code.
 */
async function getTrainerOwnerMap(codes) {
  const map = {};
  if (codes.length === 0) return map;

  const inList = buildInPlaceholders(codes);

  const [rows] = await pool.execute(
    `
      SELECT
        aur.user_id,
        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        td.dietician_id,
        td.name,
        td.email
      FROM app_user_roles aur
      LEFT JOIN table_dietician td
        ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE UPPER(aur.partner_code) IN (${inList})
    `,
    codes.map(normalizeCode)
  );

  for (const row of rows) {
    const code = normalizeCode(row.partner_code);
    if (code !== "") {
      map[code] = {
        user_id: normalizeEmail(row.user_id),
        name: row.name ?? null,
        email: normalizeEmail(row.email),
        role: row.role ?? null,
        partner_code: row.partner_code,
      };
    }
  }

  return map;
}

// ─── Count + fetch ───────────────────────────────────────────────────────────

async function countClientsForCodes(codes, escapedSearch) {
  if (codes.length === 0) return 0;

  const inList = buildInPlaceholders(codes);
  const params = codes.map(normalizeCode);

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
      WHERE UPPER(tc.dietician_id) IN (${inList})
      ${searchSql}
    `,
    params
  );

  return toInt(rows[0]?.total);
}

async function fetchClientsForCodes(codes, escapedSearch, limit, offset) {
  if (codes.length === 0) return [];

  const inList = buildInPlaceholders(codes);
  const params = codes.map(normalizeCode);

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

  // limit/offset are hard-coerced to non-negative ints by the caller, so inlining
  // them is injection-safe. mysql2 prepared statements reject bound LIMIT/OFFSET
  // on some MySQL builds, hence they are not passed as placeholders.
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
        tc.dob,
        tc.age,
        tc.gender,
        tc.height,
        tc.weight,
        tc.region,
        tc.location,
        tc.level_type,
        tc.dttm,

        IFNULL(uh.goal, '') AS fitness_goal,
        IFNULL(uh.activity, '') AS activity,

        latest.test_id AS latest_test_id,
        latest.date_time AS latest_test_date_time,
        latest.fat_loss_metabolism_score,
        latest.acetone_ppm,
        latest.ethanol_ppm,
        latest.h2_ppm,

        IFNULL(test_count.tests_count_3_months, 0) AS tests_count_3_months

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
          UPPER(dietitian_id) AS dietitian_id_key,
          profile_id,
          COUNT(DISTINCT DATE(date_time)) AS tests_count_3_months
        FROM table_test_data
        WHERE date_time >= DATE_SUB(NOW(), INTERVAL 3 MONTH)
        GROUP BY UPPER(dietitian_id), profile_id
      ) test_count
        ON test_count.dietitian_id_key = UPPER(tc.dietician_id)
        AND test_count.profile_id = tc.profile_id

      WHERE UPPER(tc.dietician_id) IN (${inList})
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

// ─── Row formatting ──────────────────────────────────────────────────────────

function formatClientRows(rows, ownerMap) {
  return rows.map((row) => {
    const dieticianCode = normalizeCode(row.dietician_id);
    const owner = ownerMap[dieticianCode] || null;
    const score = scoreValue(row.fat_loss_metabolism_score);

    return {
      profile_id: row.profile_id,
      dietician_id: row.dietician_id,

      // UNMASKED client data.
      profile_name: row.profile_name,
      client_name: row.profile_name,
      phone_no: row.phone_no,
      email: row.email,
      dob: toMysqlDate(row.dob),
      age: row.age,

      gender: cleanValue(row.gender),
      height: cleanValue(row.height),
      weight: cleanValue(row.weight),
      region: row.region,
      location: row.location,
      level_type: cleanValue(row.level_type),
      joined_dttm: cleanValue(toMysqlDateTime(row.dttm)),

      // Profile image is never returned.
      profile_image: null,

      fitness_goal: cleanValue(row.fitness_goal),
      activity: cleanValue(row.activity),

      trainer: {
        name: owner ? cleanValue(owner.name) : "Self/Trainer",
        email: owner ? normalizeEmail(owner.email) : null,
        role: owner ? owner.role : null,
        partner_code: row.dietician_id,
      },

      latest_test: {
        test_id: row.latest_test_id !== null && row.latest_test_id !== undefined
          ? toInt(row.latest_test_id)
          : null,
        date_time: toMysqlDateTime(row.latest_test_date_time),
        metabolism_score: score,
        zone: getMetabolismZone(score),
        acetone_ppm: scoreValue(row.acetone_ppm),
        ethanol_ppm: scoreValue(row.ethanol_ppm),
        h2_ppm: scoreValue(row.h2_ppm),
      },

      tests_count_3_months:
        row.tests_count_3_months !== null && row.tests_count_3_months !== undefined
          ? toInt(row.tests_count_3_months)
          : 0,
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
  const trainerIdFilter = src.trainer_id !== undefined && src.trainer_id !== null
    ? normalizeCode(src.trainer_id)
    : "";

  // Optional. Accepted for frontend/back-compat, but never authoritative — see
  // the cross-check in the controller. The JWT remains the source of truth.
  const actorUserId = normalizeEmail(src.actor_user_id);

  return { page, limit, search, trainerIdFilter, actorUserId, offset: (page - 1) * limit };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/trainer-admin-clients-list-dir
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "page": 1,
 *     "limit": 10,
 *     "search": "",
 *     "trainer_id": "",       // optional; must be in the actor's network
 *     "actor_user_id": ""     // optional; if set, must match the token email
 *   }
 */
const trainerAdminClientsListDir = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const { page, limit, search, trainerIdFilter, actorUserId, offset } = parseInputs(req);

  let actorEmail = null;
  let actorRole = null;
  let auditIdentifier = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_admin_clients_access_denied",
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

    const actorEffectiveCode = getActorEffectiveCode(actor);

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    // The field is accepted for frontend/back-compat, but it can never select a
    // different user: if supplied and it does not equal the token's email, the
    // request is rejected. This keeps the contract while closing the IDOR hole.
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await writeAuthLogSafe(req, {
        eventType: "trainer_admin_clients_access_denied",
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

    // ── 2. Resolve the actor's network of dietician codes ───────────────────
    let networkCodes = await getTrainerAdminNetworkCodes(actor, actorEmail);

    // ── 3. Optional trainer_id filter (must belong to the network) ──────────
    if (trainerIdFilter !== "") {
      if (!codeExistsInArray(networkCodes, trainerIdFilter)) {
        await writeAuthLogSafe(req, {
          eventType: "trainer_admin_clients_access_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorEffectiveCode,
          identifier: trainerIdFilter,
          success: false,
          failureReason: "Trainer filter outside actor network",
        });
        return res.status(403).json({
          status: false,
          ok: false,
          message: "You are not allowed to view this trainer clients",
        });
      }
      networkCodes = [trainerIdFilter];
    }

    // ── 4. Count → fetch → owner map ────────────────────────────────────────
    const escapedSearch = search !== "" ? escapeLike(search) : "";

    const total = await countClientsForCodes(networkCodes, escapedSearch);
    const rows = await fetchClientsForCodes(networkCodes, escapedSearch, limit, offset);
    const ownerMap = await getTrainerOwnerMap(networkCodes);

    // ── 5. Audit the unmasked read (fire-and-forget) ────────────────────────
    auditIdentifier =
      networkCodes.join(",") + "|page:" + page + "|search:" + search + "|unmasked:true";

    writeAuthLogSafe(req, {
      eventType: "trainer_admin_clients_unmasked_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorEffectiveCode,
      identifier: auditIdentifier,
      success: true,
      failureReason: "Viewed unmasked trainer admin clients list",
    });

    // ── 6. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(200).json({
      status: true,
      ok: true,
      message: "Trainer admin clients fetched successfully",
      mode: "trainer_admin_clients_list",

      actor: {
        user_id: actorEmail,
        role: actorRole,
        partner_code: actorEffectiveCode,
      },

      filters: {
        search,
        trainer_id: trainerIdFilter !== "" ? trainerIdFilter : null,
        actor_user_id: actorUserId !== "" ? actorUserId : null,
      },

      pagination: {
        page,
        limit,
        offset,
        total,
        has_more: offset + limit < total,
      },

      network_codes: networkCodes,

      privacy: {
        client_identity_masked: false,
        raw_name_returned: true,
        raw_email_returned: true,
        raw_phone_returned: true,
        dob_returned: true,
        location_returned: true,
        profile_image_returned: false,
        audit_logged: true,
      },

      clients: formatClientRows(rows, ownerMap),
    });
  } catch (err) {
    console.error("TRAINER_ADMIN_CLIENTS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "trainer_admin_clients_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: null,
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

module.exports = { trainerAdminClientsListDir };
