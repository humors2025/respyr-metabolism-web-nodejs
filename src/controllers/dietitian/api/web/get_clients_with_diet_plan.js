"use strict";

/**
 * get_clients_with_diet_plan.js
 *
 * Converted from: get_clients_with_diet_plan.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/get_clients_with_diet_plan
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : the dietician themselves (token-bound; no cross-dietician access)
 *
 * Behaviour parity with the PHP:
 *  - Lists every client for the dietician, attaches a profile-image URL, the
 *    metabolism-target lookup (ALWAYS diabetic=false), and the client's diet
 *    plans bucketed into active / completed / not_started with counts.
 *  - Returns { success, count, data } (empty data + count 0 when no clients).
 *  - Plan status is computed in Asia/Kolkata, matching computePlanStatus().
 *
 * VAPT / HIPAA hardening (intentional differences from the PHP):
 *  - IDOR closed. The PHP trusted dietician_id from the JSON body / query string
 *    / CLI argv with NO authentication — anyone could enumerate any dietician's
 *    clients (and their PHI). Here the dietician_id is bound to the verified JWT
 *    via requireDieticianSelfAccess(); a caller may only ever read their OWN
 *    clients. The body dietician_id is still accepted but must match the token.
 *  - Credential leak closed. The PHP SELECTed `password` from table_clients and
 *    echoed the entire row — leaking the stored client password/hash to the
 *    client. That column is never selected or returned here (minimum-necessary).
 *  - Fully parameterized queries; plans are fetched in a single IN(...) query
 *    instead of N per-client round-trips.
 *  - The external metabolism API is called over HTTPS with a hard timeout and
 *    bounded concurrency; any failure degrades gracefully to null (never throws,
 *    never hangs the request). The target host is a fixed constant — no
 *    user-controlled URL, so no SSRF surface.
 *  - Internal/SQL error details are suppressed in production (gated behind
 *    API_DEBUG_ERRORS). The PHP echoed raw DB error messages — closed here.
 *  - Cache-Control: no-store, Pragma: no-cache on every response (PHI).
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_clients and
 * table_diet_plan_strategy.
 */

const axios = require("axios");
const pool = require("../../../../config/db");
const { requireDieticianSelfAccess } = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SHOULD_EXPOSE_DEBUG = process.env.API_DEBUG_ERRORS === "true";

const METABOLISM_TARGET_URL =
  process.env.METABOLISM_TARGET_URL || "https://respyr.in/metabolism_target_get";

// Per-call hard timeout and how many external lookups run at once. Bounds the
// worst-case latency / outbound load when a dietician has many clients.
const METABOLISM_TIMEOUT_MS = 6000;
const METABOLISM_CONCURRENCY = 10;

const PLAN_TZ_OFFSET_MS = 5.5 * 60 * 60 * 1000; // Asia/Kolkata (UTC+05:30, no DST)

// ─── Generic helpers ─────────────────────────────────────────────────────────

const normalizeDieticianId = (value) => String(value || "").trim().toUpperCase();

const parseBodyIfNeeded = (req) => {
  if (typeof req.body === "string") {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      req.body = {};
    }
  }
  if (!req.body || typeof req.body !== "object" || Array.isArray(req.body)) {
    req.body = {};
  }
  return req.body;
};

/** Build the relative profile-image URL (matches the codebase convention). */
const buildProfileImageUrl = (dieticianId, profileId) =>
  `/dietitian/api/web/get_profile_image?profile_id=${encodeURIComponent(
    profileId
  )}&dietician_id=${encodeURIComponent(dieticianId)}`;

/** "today" as a YYYY-MM-DD string in Asia/Kolkata. */
const istTodayDateOnly = () =>
  new Date(Date.now() + PLAN_TZ_OFFSET_MS).toISOString().slice(0, 10);

/** Normalize a DB date/datetime value to a YYYY-MM-DD string in Asia/Kolkata. */
const toDateOnlyIst = (value) => {
  if (value === null || value === undefined || value === "") return null;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return null;
    return new Date(value.getTime() + PLAN_TZ_OFFSET_MS).toISOString().slice(0, 10);
  }
  const s = String(value).trim();
  // Accept "YYYY-MM-DD" or "YYYY-MM-DD HH:MM:SS" — take the date portion.
  const m = s.match(/^(\d{4}-\d{2}-\d{2})/);
  return m ? m[1] : null;
};

/**
 * Port of computePlanStatus(). YYYY-MM-DD strings compare lexically in calendar
 * order, so direct string comparison is correct and timezone-stable.
 */
const computePlanStatus = (start, end) => {
  const today = istTodayDateOnly();
  const startDate = toDateOnlyIst(start);
  const endDate = toDateOnlyIst(end);

  if (!startDate && !endDate) return "unknown";
  if (endDate && endDate < today) return "completed";
  if (startDate && endDate && startDate <= today && today <= endDate) return "active";
  if (startDate && startDate > today) return "not_started";
  if (!endDate && startDate && startDate <= today) return "active";
  if (!startDate && endDate && today <= endDate) return "active";
  return "unknown";
};

// ─── External metabolism target lookup ───────────────────────────────────────

const normalizeGender = (gender) => {
  const g = String(gender ?? "").trim().toLowerCase();
  if (g === "male" || g === "m") return "male";
  if (g === "female" || g === "f") return "female";
  return null;
};

/**
 * Calls the metabolism target API (ALWAYS diabetic=false). Returns the decoded
 * object or null on any validation/transport/parse failure. Never throws.
 */
const fetchMetabolismTarget = async (age, gender, heightCm, currentWeightKg) => {
  const ageInt = Number.parseInt(age, 10);
  const heightNum = Number.parseFloat(heightCm);
  const weightNum = Number.parseFloat(currentWeightKg);
  const genderNorm = normalizeGender(gender);

  if (!Number.isFinite(ageInt) || ageInt <= 0) return null;
  if (!Number.isFinite(heightNum) || heightNum <= 0) return null;
  if (!Number.isFinite(weightNum) || weightNum <= 0) return null;
  if (!genderNorm) return null;

  try {
    const response = await axios.get(METABOLISM_TARGET_URL, {
      params: {
        age: ageInt,
        gender: genderNorm,
        height_cm: heightNum,
        current_weight_kg: weightNum,
        diabetic: "false",
      },
      timeout: METABOLISM_TIMEOUT_MS,
      // Fixed host, JSON only. Do not follow redirects to other hosts (SSRF guard).
      maxRedirects: 0,
      responseType: "json",
      validateStatus: (s) => s >= 200 && s < 300,
    });

    return response.data && typeof response.data === "object" ? response.data : null;
  } catch {
    return null;
  }
};

/** Run async `worker` over `items` with a bounded concurrency pool. */
const mapWithConcurrency = async (items, limit, worker) => {
  const results = new Array(items.length);
  let next = 0;

  const runners = new Array(Math.min(limit, items.length)).fill(0).map(async () => {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  });

  await Promise.all(runners);
  return results;
};

// ─── Data access ─────────────────────────────────────────────────────────────

/** Minimum-necessary client columns — NOTE: `password` is deliberately excluded. */
const fetchClients = async (dieticianId) => {
  const [rows] = await pool.execute(
    `
      SELECT
        id,
        dietician_id,
        profile_id,
        phone_no,
        email,
        profile_name,
        age,
        gender,
        height,
        weight,
        region,
        location,
        is_notification_enabled,
        dttm
      FROM table_clients
      WHERE UPPER(TRIM(dietician_id)) = ?
      ORDER BY profile_name ASC
    `,
    [dieticianId]
  );
  return rows;
};

/**
 * Fetch all plans for the dietician across the given client profile_ids in one
 * query, then group by client_id (= profile_id). Preserves updated_at DESC order
 * within each client.
 */
const fetchPlansByClient = async (dieticianId, profileIds) => {
  const byClient = new Map();
  if (profileIds.length === 0) return byClient;

  const placeholders = profileIds.map(() => "?").join(", ");
  const [rows] = await pool.execute(
    `
      SELECT
        id,
        dietitian_id,
        client_id,
        plan_title,
        plan_start_date,
        plan_end_date,
        updated_at,
        calories_target,
        protein_target,
        fiber_target,
        water_target,
        goal,
        approach,
        status
      FROM table_diet_plan_strategy
      WHERE dietitian_id = ?
        AND client_id IN (${placeholders})
      ORDER BY updated_at DESC
    `,
    [dieticianId, ...profileIds]
  );

  for (const plan of rows) {
    const key = String(plan.client_id);
    if (!byClient.has(key)) byClient.set(key, []);
    byClient.get(key).push(plan);
  }
  return byClient;
};

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get_clients_with_diet_plan
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:    { "dietician_id": "RESPYR123" }   // must match the token's dietician
 */
exports.get_clients_with_diet_plan = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  let debugStep = "controller_started";

  try {
    // VAPT: method gate (the PHP accepted any method incl. GET/CLI).
    if (req.method !== "POST") {
      return res.status(405).json({ success: false, error: "Method not allowed" });
    }

    debugStep = "parse_body";
    const body = parseBodyIfNeeded(req);

    debugStep = "validate_dietician_id";
    const requestedDieticianId = normalizeDieticianId(body.dietician_id);
    if (!requestedDieticianId) {
      return res.status(400).json({ success: false, error: "dietician_id is required" });
    }

    // ── Token-bound access: caller may only read their own clients ──────────
    debugStep = "access_check";
    const access = requireDieticianSelfAccess(req, requestedDieticianId);
    if (!access.allowed) {
      return res.status(access.statusCode || 403).json({
        success: false,
        error: access.message || "Access denied",
      });
    }
    const dieticianId = normalizeDieticianId(access.dieticianId);

    // ── 1. Fetch this dietician's clients ───────────────────────────────────
    debugStep = "fetch_clients";
    const clients = await fetchClients(dieticianId);

    if (!Array.isArray(clients) || clients.length === 0) {
      return res.status(200).json({ success: true, count: 0, data: [] });
    }

    // ── 2. Fetch all plans for these clients in one query ───────────────────
    debugStep = "fetch_plans";
    const profileIds = clients.map((c) => c.profile_id);
    const plansByClient = await fetchPlansByClient(dieticianId, profileIds);

    // ── 3. Enrich each client with metabolism target (bounded concurrency) ──
    debugStep = "fetch_metabolism_targets";
    const metabolismTargets = await mapWithConcurrency(
      clients,
      METABOLISM_CONCURRENCY,
      (c) => fetchMetabolismTarget(c.age, c.gender, c.height, c.weight)
    );

    // ── 4. Assemble the response ────────────────────────────────────────────
    debugStep = "assemble_response";
    const data = clients.map((c, idx) => {
      const activePlans = [];
      const completedPlans = [];
      const notStartedPlans = [];

      const plans = plansByClient.get(String(c.profile_id)) || [];
      for (const plan of plans) {
        const planStatus = computePlanStatus(plan.plan_start_date, plan.plan_end_date);
        const withStatus = { ...plan, plan_status: planStatus };

        if (planStatus === "completed") completedPlans.push(withStatus);
        else if (planStatus === "active") activePlans.push(withStatus);
        else if (planStatus === "not_started") notStartedPlans.push(withStatus);
        // 'unknown'/'expired' are intentionally not bucketed (PHP parity).
      }

      return {
        ...c,
        profile_image_url: buildProfileImageUrl(c.dietician_id, c.profile_id),
        metabolism_target: metabolismTargets[idx],
        plans_summary: {
          active: activePlans,
          completed: completedPlans,
          not_started: notStartedPlans,
        },
        plans_count: {
          total: activePlans.length + completedPlans.length + notStartedPlans.length,
          active: activePlans.length,
          completed: completedPlans.length,
          not_started: notStartedPlans.length,
        },
      };
    });

    return res.status(200).json({
      success: true,
      count: data.length,
      data,
    });
  } catch (error) {
    const safeLog = {
      step: debugStep,
      message: error?.message,
      code: error?.code,
      errno: error?.errno,
      sqlState: error?.sqlState,
      sqlMessage: error?.sqlMessage,
      method: req.method,
      path: req.originalUrl,
    };
    console.error("get_clients_with_diet_plan error:", safeLog);

    const response = { success: false, error: "Internal server error" };
    if (SHOULD_EXPOSE_DEBUG) {
      response.debug = {
        step: debugStep,
        error: error?.sqlMessage || error?.message || "Unknown error",
        code: error?.code || null,
      };
    }
    return res.status(500).json(response);
  }
};
