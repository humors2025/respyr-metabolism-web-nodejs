"use strict";

/**
 * habits-manager.controller.js
 *
 * Platform : Respyr Dietitian API (api.respyr.ai)
 * Security : VAPT-hardened, HIPAA-aligned
 *
 * ONE dispatcher endpoint that consolidates THREE Archive controllers into a
 * single action-routed handler (the repo's "dispatcher" pattern — one route,
 * one controller, sub-handlers selected by `action` in the request body):
 *
 *   Archive source                       → actions in this file
 *   ───────────────────────────────────────────────────────────────────────
 *   selected_habits.controller.js        → habit_master, save_selected_habits,
 *                                           selected_status, track_habit,
 *                                           weekly_tracking
 *   habits_check.controller.js           → check_habits
 *   habits.controller.js  (user_habits)  → fetch_preferences, save_preferences,
 *                                           tracking_data, track_batch,
 *                                           update_glp1
 *
 * Endpoint (POST, behind authMiddleware):
 *   /dietitian/api/web/habits-manager
 *
 * Request body (common to every action):
 *   {
 *     "action":       "<one of the actions above>",
 *     "dietitian_id": "<optional — defaults to JWT; dietician_id also accepted>",
 *     "profile_id":   "<required — the client this action operates on>",
 *     ... action-specific fields ...
 *   }
 *
 * Security model (identical to habits_dashboard.controller.js / the other habit
 * endpoints in this repo):
 *  - The JWT belongs to a DIETITIAN. profile_id is supplied in the body and is
 *    verified via requireProfileAccess (table_clients dietician_id ↔ profile_id)
 *    BEFORE any habit data is read or written — closing BOLA/IDOR (OWASP API1).
 *  - A super_admin may pass an explicit dietitian_id; requireProfileAccess
 *    resolves the profile's true owning dietitian.
 *  - Fully parameterized queries — zero string interpolation.
 *  - Internal error details are suppressed in every client-facing response.
 *  - PHI is never logged; only error metadata (code/errno/sqlState).
 *  - Cache-Control: no-store on every response (PHI-adjacent).
 *
 * NOTE on dietitian/dietician spelling:
 *  - accessControl.js accepts BOTH spellings from body and JWT.
 *  - DB column reference uses dietician_id (legacy column name).
 *    Verify with: SHOW COLUMNS FROM table_clients LIKE '%diet%';
 *
 * ── Schema reference (verify before deploy with SHOW COLUMNS) ───────────────
 *   table_clients:          dietician_id, profile_id, profile_name, level_type,
 *                           dttm
 *   user_habits:            id, profile_id, goal, activity, food_type, glp_1,
 *                           dttm, tsstamp
 *   habit_master:           id, level_id, category, habit_name,
 *                           habit_description, frequency_type, target_count,
 *                           target_unit, tracking_type, sort_order, is_active
 *   client_selected_habits: id, profile_id, habit_id, level_id, start_date,
 *                           end_date, status('active'|'removed'), selected_at,
 *                           updated_at
 *   client_habit_tracking:  id, profile_id, selected_habit_id, habit_id,
 *                           tracking_date, target_count, completed_count,
 *                           is_completed, notes, updated_at
 *
 * ── Required DB constraints for the WRITE actions (idempotent upserts) ──────
 *   For track_habit / track_batch (ON DUPLICATE KEY UPDATE):
 *     ALTER TABLE client_habit_tracking
 *       ADD UNIQUE KEY uniq_track (selected_habit_id, tracking_date);
 *   save_preferences / update_glp1 do NOT depend on a unique key — they
 *   UPDATE-then-INSERT against the latest row (id DESC) to stay safe even if
 *   historical duplicate user_habits rows exist.
 */

const pool = require("../../../../config/db");
const {
  requireProfileAccess,
  getTokenDieticianId,
} = require("../../../../utils/accessControl");

// ───────────────────────────────────────────────────────────────────────────
//  Config
// ───────────────────────────────────────────────────────────────────────────

// habit_master currently only has rows at level_id = 1. Clients on level 2/3
// fall back to the level-1 catalog so the picker is never empty. When level
// 2/3 rows are added this fallback becomes inert automatically. Set to null to
// disable.
const HABIT_LEVEL_FALLBACK = 1;

// ───────────────────────────────────────────────────────────────────────────
//  Response helpers — house shape: { status, message, data, error }
// ───────────────────────────────────────────────────────────────────────────

function ok(res, status, payload) {
  return res.status(status).json({ status: true, error: null, ...payload });
}

function fail(res, status, message, code, extra = {}) {
  return res.status(status).json({
    status: false,
    message,
    data: null,
    error: { code },
    ...extra,
  });
}

function serverError(res) {
  return fail(res, 500, "Server error", "SERVER_ERROR");
}

// ───────────────────────────────────────────────────────────────────────────
//  Date helpers (UTC, calendar-only — no time-zone drift)
// ───────────────────────────────────────────────────────────────────────────

function pad(n) {
  return String(n).padStart(2, "0");
}

function ymd(d) {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function todayYmd() {
  return ymd(new Date());
}

/** mysql2 may hand back DATE columns as Date objects OR strings — normalise. */
function normDate(val) {
  if (!val) return null;
  if (val instanceof Date) return ymd(val);
  const s = String(val);
  return s.length >= 10 ? s.slice(0, 10) : s;
}

function getDayName(dateStr) {
  return new Date(`${dateStr}T00:00:00Z`).toLocaleDateString("en-US", {
    weekday: "short",
    timeZone: "UTC",
  });
}

/** Inclusive YYYY-MM-DD list from start..end (UTC). Empty if start > end. */
function buildDateRange(startStr, endStr) {
  const out = [];
  if (!startStr || !endStr) return out;
  const start = new Date(`${startStr}T00:00:00Z`);
  const end = new Date(`${endStr}T00:00:00Z`);
  if (isNaN(start) || isNaN(end) || start > end) return out;
  for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
    out.push(ymd(d));
  }
  return out;
}

/** Sun–Sat week range containing `dateStr` (matches Archive weekly_tracking). */
function weekRangeSunSat(dateStr) {
  const ms = new Date(`${dateStr}T00:00:00Z`).getTime();
  const dow = new Date(ms).getUTCDay(); // 0=Sun .. 6=Sat
  const startMs = ms - dow * 86400000;
  return {
    start: ymd(new Date(startMs)),
    end: ymd(new Date(startMs + 6 * 86400000)),
  };
}

function weekDates(startYmd) {
  const startMs = new Date(`${startYmd}T00:00:00Z`).getTime();
  const out = [];
  for (let i = 0; i < 7; i++) out.push(ymd(new Date(startMs + i * 86400000)));
  return out;
}

function round2(n) {
  return Math.round(n * 100) / 100;
}

/** Whole-number percentage (matches habits_dashboard.controller.js). */
function pct(numerator, denominator) {
  if (!denominator) return 0;
  return Math.round((numerator / denominator) * 100);
}

/** YYYY-MM-DD `n` days after (negative = before) a YYYY-MM-DD (UTC). */
function addDays(dateStr, n) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return ymd(d);
}

/** Inclusive whole-day count between two YYYY-MM-DD strings (UTC). 0 if from>to. */
function inclusiveDays(fromYmd, toYmd) {
  const from = new Date(`${fromYmd}T00:00:00Z`).getTime();
  const to = new Date(`${toYmd}T00:00:00Z`).getTime();
  if (isNaN(from) || isNaN(to) || from > to) return 0;
  return Math.floor((to - from) / 86400000) + 1;
}

// ───────────────────────────────────────────────────────────────────────────
//  Input validation helpers
// ───────────────────────────────────────────────────────────────────────────

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Strict positive integer (rejects floats, leading zeros mismatch, strings). */
function toPositiveInt(raw) {
  if (raw === undefined || raw === null || raw === "") return null;
  const n = parseInt(raw, 10);
  if (!Number.isInteger(n) || n <= 0) return null;
  if (String(n) !== String(raw).trim()) return null;
  return n;
}

/** Non-negative integer (0 allowed). */
function toNonNegInt(raw, fallback = null) {
  if (raw === undefined || raw === null || raw === "") return fallback;
  const n = parseInt(raw, 10);
  if (!Number.isInteger(n) || n < 0) return null;
  return n;
}

/** glp_1 → 0|1. Accepts boolean or 0/1 (number or string). Else null. */
function toGlp1(raw) {
  if (raw === true || raw === 1 || raw === "1") return 1;
  if (raw === false || raw === 0 || raw === "0") return 0;
  return null;
}

/** YYYY-MM-DD validator. Returns the string or null. */
function toYmd(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T00:00:00Z`);
  return isNaN(d) ? null : s;
}

// food_type stored as JSON. Parse back to the fixed object the client expects.
function buildFoodType(raw) {
  let parsed = {};
  if (raw) {
    try {
      const decoded = typeof raw === "string" ? JSON.parse(raw) : raw;
      if (isPlainObject(decoded)) parsed = decoded;
    } catch (_) {
      parsed = {};
    }
  }
  return {
    diet_type: parsed.diet_type || "",
    primary_cuisine: parsed.primary_cuisine || "",
    secondary_cuisine: parsed.secondary_cuisine || "",
  };
}

// Normalise food_type INPUT (string OR object) → JSON string for storage.
function normalizeFoodType(input) {
  if (input == null || input === "") return JSON.stringify({});
  if (typeof input === "string") return JSON.stringify({ diet_type: input });
  if (isPlainObject(input)) {
    return JSON.stringify({
      diet_type: input.diet_type || "",
      primary_cuisine: input.primary_cuisine || "",
      secondary_cuisine: input.secondary_cuisine || "",
    });
  }
  return JSON.stringify({});
}

// ───────────────────────────────────────────────────────────────────────────
//  Token-bound profile access (BOLA/IDOR guard) — runs before every action.
//  On success returns { dieticianId, profileId }; on failure writes the HTTP
//  response and returns null.
// ───────────────────────────────────────────────────────────────────────────

async function resolveProfileAccess(req, res, label) {
  const rawDietitianId =
    req.body?.dietitian_id ??
    req.body?.dietician_id ??
    getTokenDieticianId(req) ??
    "";
  const rawProfileId = req.body?.profile_id ?? "";

  let access;
  try {
    access = await requireProfileAccess(req, rawDietitianId, rawProfileId);
  } catch (authErr) {
    console.error(`${label}: requireProfileAccess threw`, authErr?.code);
    serverError(res);
    return null;
  }

  if (!access.allowed) {
    console.warn(`${label}: access denied`, {
      statusCode: access.statusCode,
      path: req.originalUrl,
      method: req.method,
    });
    res.status(access.statusCode).json({
      status: false,
      message: access.message,
      data: null,
      error: { code: "ACCESS_DENIED" },
    });
    return null;
  }

  return access;
}

/** Fetch the client header row (also a DB-level ownership re-confirm). */
async function fetchClient(dieticianId, profileId) {
  const [rows] = await pool.execute(
    `
      SELECT profile_name, level_type, dttm
      FROM table_clients
      WHERE UPPER(TRIM(dietician_id)) = ?
        AND profile_id = ?
      LIMIT 1
    `,
    [dieticianId, profileId]
  );
  return rows[0] || null;
}

// ═══════════════════════════════════════════════════════════════════════════
//  ACTION HANDLERS
//  Each receives ({ req, res, access }) where access = { dieticianId, profileId }.
// ═══════════════════════════════════════════════════════════════════════════

// ── habit_master ─ list available habits, grouped by category ───────────────
//   Body: { profile_id, level_id? }
//   level_id defaults to the client's level_type. Falls back to level 1 when
//   the requested level has no rows yet.
async function actionHabitMaster({ req, res, access }) {
  const { dieticianId, profileId } = access;

  const client = await fetchClient(dieticianId, profileId);
  if (!client) return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");

  let levelId = toPositiveInt(req.body?.level_id);
  if (levelId === null) {
    levelId = parseInt(client.level_type, 10) || HABIT_LEVEL_FALLBACK || 1;
  }

  const sql = `
    SELECT id, level_id, category, habit_name, habit_description,
           frequency_type, target_count, target_unit, tracking_type, sort_order
    FROM habit_master
    WHERE is_active = 1 AND level_id = ?
    ORDER BY sort_order ASC
  `;

  let [rows] = await pool.execute(sql, [levelId]);
  let servedLevelId = levelId;

  if (
    rows.length === 0 &&
    HABIT_LEVEL_FALLBACK !== null &&
    levelId !== HABIT_LEVEL_FALLBACK
  ) {
    [rows] = await pool.execute(sql, [HABIT_LEVEL_FALLBACK]);
    servedLevelId = HABIT_LEVEL_FALLBACK;
  }

  const grouped = {};
  for (const r of rows) {
    const cat = r.category || "Uncategorized";
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push({
      id: Number(r.id),
      level_id: Number(r.level_id),
      habit_name: r.habit_name,
      habit_description: r.habit_description,
      frequency_type: r.frequency_type,
      target_count: Number(r.target_count),
      target_unit: r.target_unit,
      tracking_type: r.tracking_type,
      sort_order: Number(r.sort_order),
    });
  }

  return ok(res, 200, {
    message: "Habit master fetched successfully",
    data: {
      profile_id: profileId,
      level_id: levelId, // requested
      served_level_id: servedLevelId, // actually returned
      data: grouped,
    },
  });
}

// ── save_selected_habits ─ swap out old set, save exactly 5 ─────────────────
//   Body: { profile_id, level_id, habit_ids: [5 positive ints] }
async function actionSaveSelectedHabits({ req, res, access }) {
  const { dieticianId, profileId } = access;

  const levelId = toPositiveInt(req.body?.level_id);
  if (levelId === null) {
    return fail(res, 422, "level_id must be a positive integer", "VALIDATION_ERROR");
  }

  const rawIds = req.body?.habit_ids;
  if (!Array.isArray(rawIds) || rawIds.length !== 5) {
    return fail(res, 422, "habit_ids must be an array of exactly 5 ids", "VALIDATION_ERROR");
  }
  const habitIds = rawIds.map(toPositiveInt);
  if (habitIds.some((x) => x === null)) {
    return fail(res, 422, "habit_ids must all be positive integers", "VALIDATION_ERROR");
  }
  if (new Set(habitIds).size !== habitIds.length) {
    return fail(res, 422, "habit_ids must be unique", "VALIDATION_ERROR");
  }

  // Confirm the client exists/owned (transaction below filters by profile_id).
  const client = await fetchClient(dieticianId, profileId);
  if (!client) return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const placeholders = habitIds.map(() => "?").join(",");
    const fallback = HABIT_LEVEL_FALLBACK ?? levelId;

    // Accept rows at the requested level OR the fallback tier.
    const [validRows] = await conn.query(
      `SELECT id, level_id FROM habit_master
        WHERE id IN (${placeholders})
          AND is_active = 1
          AND level_id IN (?, ?)`,
      [...habitIds, levelId, fallback]
    );

    if (validRows.length !== 5) {
      await conn.rollback();
      const validIds = validRows.map((r) => Number(r.id));
      const invalidIds = habitIds.filter((id) => !validIds.includes(id));
      return fail(
        res,
        400,
        "One or more selected habits are invalid",
        "INVALID_HABITS",
        {
          client_level_id: levelId,
          received_habit_ids: habitIds,
          valid_habit_ids: validIds,
          invalid_habit_ids: invalidIds,
        }
      );
    }

    const habitLevelMap = new Map(
      validRows.map((r) => [Number(r.id), Number(r.level_id)])
    );

    // Record the client's chosen tier.
    await conn.query(
      `UPDATE table_clients SET level_type = ? WHERE profile_id = ?`,
      [levelId, profileId]
    );

    // Retire ALL previously-active habits (a client has 5 active at a time).
    await conn.query(
      `UPDATE client_selected_habits
          SET status = 'removed', end_date = CURDATE()
        WHERE profile_id = ?
          AND status = 'active'`,
      [profileId]
    );

    // Insert each new habit with the level_id pulled from habit_master.
    for (const habitId of habitIds) {
      const habitLevel = habitLevelMap.get(habitId) ?? levelId;
      await conn.query(
        `INSERT INTO client_selected_habits
           (profile_id, habit_id, level_id, start_date, status)
         VALUES (?, ?, ?, CURDATE(), 'active')`,
        [profileId, habitId, habitLevel]
      );
    }

    await conn.commit();

    console.info("habits.save_selected: ok", {
      dietitian_id: dieticianId,
      profile_id: profileId,
      count: habitIds.length,
      ts: new Date().toISOString(),
    });

    return ok(res, 200, {
      message: "5 habits selected successfully",
      data: {
        profile_id: profileId,
        client_level_id: levelId,
        habit_level_ids_saved: [...new Set(habitLevelMap.values())],
        habit_ids: habitIds,
      },
    });
  } catch (err) {
    try {
      await conn.rollback();
    } catch (_) {}
    throw err;
  } finally {
    conn.release();
  }
}

// ── selected_status ─ active selected habits + today's + weekly tracking ────
//   Body: { profile_id, tracking_date? (defaults today) }
async function actionSelectedStatus({ req, res, access }) {
  const { profileId } = access;

  const trackingDate = req.body?.tracking_date
    ? toYmd(req.body.tracking_date)
    : todayYmd();
  if (trackingDate === null) {
    return fail(res, 422, "tracking_date must be YYYY-MM-DD", "VALIDATION_ERROR");
  }

  const { start: weekStart, end: weekEnd } = weekRangeSunSat(trackingDate);

  const [rows] = await pool.execute(
    `
      SELECT
        csh.id          AS selected_habit_id,
        csh.profile_id,
        csh.habit_id,
        csh.level_id,
        csh.start_date,
        csh.status      AS selected_status,

        hm.category,
        hm.habit_name,
        hm.habit_description,
        hm.frequency_type,
        hm.target_count,
        hm.target_unit,
        hm.tracking_type,
        hm.sort_order,

        daily_track.tracking_date              AS daily_tracking_date,
        IFNULL(daily_track.completed_count, 0) AS daily_completed_count,
        daily_track.notes                      AS daily_notes,

        IFNULL(weekly_track.week_completed_count, 0) AS weekly_completed_count,
        weekly_track.last_tracking_date              AS weekly_last_tracking_date

      FROM client_selected_habits csh
      INNER JOIN habit_master hm
        ON hm.id = csh.habit_id

      LEFT JOIN client_habit_tracking daily_track
        ON daily_track.selected_habit_id = csh.id
       AND daily_track.profile_id        = csh.profile_id
       AND daily_track.tracking_date     = ?

      LEFT JOIN (
        SELECT selected_habit_id, profile_id,
               SUM(completed_count) AS week_completed_count,
               MAX(tracking_date)   AS last_tracking_date
        FROM client_habit_tracking
        WHERE profile_id = ?
          AND tracking_date BETWEEN ? AND ?
        GROUP BY selected_habit_id, profile_id
      ) weekly_track
        ON weekly_track.selected_habit_id = csh.id
       AND weekly_track.profile_id        = csh.profile_id

      WHERE csh.profile_id = ?
        AND csh.status     = 'active'
      ORDER BY hm.sort_order ASC
    `,
    [trackingDate, profileId, weekStart, weekEnd, profileId]
  );

  let trackedCount = 0;
  let notTrackedCount = 0;
  let completedTotal = 0;
  let pendingCount = 0;

  const habits = rows.map((r) => {
    const freq = r.frequency_type;
    const required = Number(r.target_count);
    const dailyCompleted = Number(r.daily_completed_count);
    const weeklyCompleted = Number(r.weekly_completed_count);
    const isWeekly = freq === "weekly";

    const isTracked = dailyCompleted > 0;
    const isCompleted = isWeekly
      ? weeklyCompleted >= required
      : dailyCompleted >= required;

    if (isTracked) trackedCount++;
    else notTrackedCount++;
    if (isCompleted) completedTotal++;
    else pendingCount++;

    return {
      selected_habit_id: Number(r.selected_habit_id),
      profile_id: r.profile_id,
      habit_id: Number(r.habit_id),
      level_id: Number(r.level_id),

      category: r.category,
      habit_name: r.habit_name,
      habit_description: r.habit_description,

      frequency_type: freq,
      target_count: required,
      target_unit: r.target_unit,
      tracking_type: r.tracking_type,

      selected_date: trackingDate,
      week_start: isWeekly ? weekStart : null,
      week_end: isWeekly ? weekEnd : null,
      tracking_date: normDate(r.daily_tracking_date) || trackingDate,

      completed_count: dailyCompleted,
      weekly_completed_count: isWeekly ? weeklyCompleted : null,
      required_count: required,

      is_tracked: isTracked,
      tracked_status: isTracked ? "tracked" : "not_tracked",
      is_completed: isCompleted ? 1 : 0,
      completion_status: isCompleted ? "completed" : "pending",

      notes: isWeekly ? null : r.daily_notes,
      selected_status: r.selected_status,
      start_date: r.start_date,
    };
  });

  return ok(res, 200, {
    message: "Client habits fetched successfully",
    data: {
      profile_id: profileId,
      tracking_date: trackingDate,
      week_start: weekStart,
      week_end: weekEnd,
      total_habits: habits.length,
      tracked_habits: trackedCount,
      not_tracked_habits: notTrackedCount,
      completed_habits: completedTotal,
      pending_habits: pendingCount,
      data: habits,
    },
  });
}

// ── track_habit ─ record completion for one habit on a date ─────────────────
//   Body: { profile_id, habit_id, tracking_date?, completed_count?, notes? }
async function actionTrackHabit({ req, res, access }) {
  const { profileId } = access;

  const habitId = toPositiveInt(req.body?.habit_id);
  if (habitId === null) {
    return fail(res, 422, "habit_id must be a positive integer", "VALIDATION_ERROR");
  }

  const trackingDate = req.body?.tracking_date
    ? toYmd(req.body.tracking_date)
    : todayYmd();
  if (trackingDate === null) {
    return fail(res, 422, "tracking_date must be YYYY-MM-DD", "VALIDATION_ERROR");
  }

  const completedCount = toNonNegInt(req.body?.completed_count, 1);
  if (completedCount === null) {
    return fail(res, 422, "completed_count must be a non-negative integer", "VALIDATION_ERROR");
  }

  const notes =
    typeof req.body?.notes === "string" && req.body.notes.trim() !== ""
      ? req.body.notes.trim()
      : null;

  // Habit must be selected & active for THIS profile (BOLA layer 2).
  const [check] = await pool.execute(
    `SELECT csh.id AS selected_habit_id, hm.target_count
       FROM client_selected_habits csh
       INNER JOIN habit_master hm ON hm.id = csh.habit_id
      WHERE csh.profile_id = ?
        AND csh.habit_id   = ?
        AND csh.status     = 'active'
      LIMIT 1`,
    [profileId, habitId]
  );

  if (!check.length) {
    return fail(
      res,
      400,
      "This habit is not selected or not active for this profile",
      "HABIT_NOT_SELECTED"
    );
  }

  const selectedHabitId = Number(check[0].selected_habit_id);
  const targetCount = Number(check[0].target_count);
  const isCompleted = completedCount >= targetCount && completedCount > 0 ? 1 : 0;

  await pool.execute(
    `INSERT INTO client_habit_tracking
       (profile_id, selected_habit_id, habit_id, tracking_date,
        target_count, completed_count, is_completed, notes)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)
     ON DUPLICATE KEY UPDATE
       completed_count = VALUES(completed_count),
       is_completed    = VALUES(is_completed),
       notes           = VALUES(notes),
       updated_at      = CURRENT_TIMESTAMP`,
    [
      profileId,
      selectedHabitId,
      habitId,
      trackingDate,
      targetCount,
      completedCount,
      isCompleted,
      notes,
    ]
  );

  return ok(res, 200, {
    message: "Habit tracked successfully",
    data: {
      profile_id: profileId,
      selected_habit_id: selectedHabitId,
      habit_id: habitId,
      tracking_date: trackingDate,
      target_count: targetCount,
      completed_count: completedCount,
      is_completed: isCompleted,
    },
  });
}

// ── track_batch ─ upsert tracking for multiple habits at once ───────────────
//   Body: { profile_id, tracking_date?, notes?,
//           habits: [{ habit_id, completed_count }] }
async function actionTrackBatch({ req, res, access }) {
  const { profileId } = access;

  const items = req.body?.habits;
  if (!Array.isArray(items) || items.length === 0) {
    return fail(res, 422, "habits must be a non-empty array", "VALIDATION_ERROR");
  }
  if (items.length > 50) {
    return fail(res, 422, "habits cannot exceed 50 items", "VALIDATION_ERROR");
  }

  const normalized = [];
  for (const it of items) {
    if (!isPlainObject(it)) {
      return fail(res, 422, "each habits item must be an object", "VALIDATION_ERROR");
    }
    const hid = toPositiveInt(it.habit_id);
    const cc = toNonNegInt(it.completed_count, null);
    if (hid === null || cc === null) {
      return fail(
        res,
        422,
        "each habits item needs a positive habit_id and non-negative completed_count",
        "VALIDATION_ERROR"
      );
    }
    normalized.push({ habit_id: hid, completed_count: cc });
  }

  const trackingDate = req.body?.tracking_date
    ? toYmd(req.body.tracking_date)
    : todayYmd();
  if (trackingDate === null) {
    return fail(res, 422, "tracking_date must be YYYY-MM-DD", "VALIDATION_ERROR");
  }

  const notes =
    typeof req.body?.notes === "string" && req.body.notes.trim() !== ""
      ? req.body.notes.trim()
      : null;

  // Resolve (habit_id → {selected_habit_id, target_count}) for ACTIVE habits
  // owned by this profile. Anything else → failed (closes cross-profile spoof).
  const habitIds = normalized.map((it) => it.habit_id);
  const placeholders = habitIds.map(() => "?").join(",");
  const [activeRows] = await pool.execute(
    `SELECT csh.id AS selected_habit_id, csh.habit_id, hm.target_count
       FROM client_selected_habits csh
       INNER JOIN habit_master hm ON hm.id = csh.habit_id
      WHERE csh.profile_id = ?
        AND csh.habit_id IN (${placeholders})
        AND csh.status = 'active'`,
    [profileId, ...habitIds]
  );

  const activeMap = new Map();
  for (const r of activeRows) {
    activeMap.set(Number(r.habit_id), {
      selectedHabitId: Number(r.selected_habit_id),
      targetCount: Number(r.target_count),
    });
  }

  const tracked = [];
  const failedIds = [];

  for (const item of normalized) {
    const meta = activeMap.get(item.habit_id);
    if (!meta) {
      failedIds.push(item.habit_id);
      continue;
    }
    const cc = item.completed_count;
    const isCompleted = cc >= meta.targetCount && cc > 0 ? 1 : 0;

    try {
      await pool.execute(
        `INSERT INTO client_habit_tracking
           (profile_id, selected_habit_id, habit_id, tracking_date,
            target_count, completed_count, is_completed, notes)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON DUPLICATE KEY UPDATE
           completed_count = VALUES(completed_count),
           is_completed    = VALUES(is_completed),
           notes           = VALUES(notes),
           updated_at      = CURRENT_TIMESTAMP`,
        [
          profileId,
          meta.selectedHabitId,
          item.habit_id,
          trackingDate,
          meta.targetCount,
          cc,
          isCompleted,
          notes,
        ]
      );
      tracked.push({
        habit_id: item.habit_id,
        completed_count: cc,
        is_completed: isCompleted,
      });
    } catch (_) {
      failedIds.push(item.habit_id);
    }
  }

  return ok(res, 200, {
    message: "Habits updated successfully",
    data: {
      profile_id: profileId,
      tracking_date: trackingDate,
      tracked_count: tracked.length,
      failed_count: failedIds.length,
      tracked,
      failed_ids: failedIds,
    },
  });
}

// ── weekly_tracking ─ Sun–Sat week + all-time per-habit summary ─────────────
//   Body: { profile_id, date? (defaults today) }
//   Faithful port of Archive weekly_habit_tracking.php.
async function actionWeeklyTracking({ req, res, access }) {
  const { profileId } = access;

  const date = req.body?.date ? toYmd(req.body.date) : todayYmd();
  if (date === null) {
    return fail(res, 422, "date must be YYYY-MM-DD", "VALIDATION_ERROR");
  }

  // Client level_type
  const [clientRows] = await pool.execute(
    `SELECT level_type FROM table_clients WHERE profile_id = ? LIMIT 1`,
    [profileId]
  );
  if (!clientRows.length) {
    return fail(res, 404, "Profile not found", "PROFILE_NOT_FOUND");
  }

  const levelTypeRaw = clientRows[0].level_type;
  if (levelTypeRaw === null || levelTypeRaw === "") {
    return fail(res, 422, "User level not assigned", "LEVEL_NOT_SET");
  }
  const levelId = Number(levelTypeRaw);
  if (!Number.isFinite(levelId) || levelId <= 0) {
    return fail(res, 422, "User level not assigned", "LEVEL_NOT_SET");
  }

  const { start: weekStart, end: weekEnd } = weekRangeSunSat(date);
  const today = todayYmd();
  const weekList = weekDates(weekStart);

  // Last 5 selected habits (any status — weekly view shows the current cycle).
  const [habitsRows] = await pool.execute(
    `SELECT csh.id          AS selected_habit_id,
            csh.habit_id,
            csh.level_id,
            csh.start_date,
            csh.end_date,
            csh.status      AS selection_status,
            csh.selected_at,
            hm.category,
            hm.habit_name,
            hm.habit_description,
            hm.frequency_type,
            hm.target_count,
            hm.target_unit,
            hm.tracking_type,
            hm.is_active,
            hm.sort_order
       FROM client_selected_habits csh
       INNER JOIN habit_master hm ON csh.habit_id = hm.id
      WHERE csh.profile_id = ?
      ORDER BY csh.selected_at DESC, csh.id DESC
      LIMIT 5`,
    [profileId]
  );

  if (!habitsRows.length) {
    return ok(res, 200, {
      message: "No selected habits found for this user/level",
      data: {
        profile_id: profileId,
        level_id: levelId,
        week_start: weekStart,
        week_end: weekEnd,
        today,
        total_habits: 0,
        week_summary: { completed_total: 0, pending_total: 0, future_total: 0 },
        habits: [],
      },
    });
  }

  const selectedHabitIds = habitsRows.map((h) => Number(h.selected_habit_id));
  const placeholders = selectedHabitIds.map(() => "?").join(",");
  const [trackingRows] = await pool.execute(
    `SELECT selected_habit_id, habit_id, tracking_date, target_count,
            completed_count, is_completed, notes
       FROM client_habit_tracking
      WHERE profile_id          = ?
        AND selected_habit_id IN (${placeholders})
        AND tracking_date     <= ?`,
    [profileId, ...selectedHabitIds, today]
  );

  const weeklyMap = new Map(); // sid -> { date: row }
  const allTimeMap = new Map();
  for (const r of trackingRows) {
    const sid = Number(r.selected_habit_id);
    const t = normDate(r.tracking_date);
    if (!t) continue;
    if (t >= weekStart && t <= weekEnd) {
      if (!weeklyMap.has(sid)) weeklyMap.set(sid, {});
      weeklyMap.get(sid)[t] = r;
    }
    if (!allTimeMap.has(sid)) allTimeMap.set(sid, {});
    allTimeMap.get(sid)[t] = r;
  }

  const outputHabits = [];
  const weekSummary = { completed_total: 0, pending_total: 0, future_total: 0 };

  for (const h of habitsRows) {
    const sid = Number(h.selected_habit_id);
    const sidWeekly = weeklyMap.get(sid) || {};
    const sidAllTime = allTimeMap.get(sid) || {};
    const habitStart = normDate(h.start_date);
    const isWeekly = h.frequency_type === "weekly";

    const trackingArr = [];
    let habitCompleted = 0;
    let habitPending = 0;
    let habitFuture = 0;

    for (const d of weekList) {
      let statusVal = 0;
      let completedCount = 0;
      let targetCount = Number(h.target_count);
      let notes = null;

      if (d > today) {
        statusVal = 2;
        habitFuture++;
      } else if (habitStart && d < habitStart) {
        // Past, but before the user started this habit — neutral, excluded.
        statusVal = 2;
        habitFuture++;
      } else if (sidWeekly[d]) {
        const rec = sidWeekly[d];
        // WEEKLY: a day counts as done if any session was logged that day.
        // DAILY: only when that day met its own target (is_completed).
        const isDone = isWeekly
          ? (Number(rec.completed_count) || 0) > 0
          : Number(rec.is_completed) === 1;
        statusVal = isDone ? 1 : 0;
        completedCount = Number(rec.completed_count) || 0;
        if (rec.target_count !== null && rec.target_count !== undefined) {
          targetCount = Number(rec.target_count);
        }
        notes = rec.notes;
        if (isDone) habitCompleted++;
        else habitPending++;
      } else {
        habitPending++;
      }

      trackingArr.push({
        date: d,
        day: getDayName(d),
        status: statusVal, // 1=done, 0=not done, 2=future/neutral
        target_count: targetCount,
        completed_count: completedCount,
        notes,
      });
    }

    weekSummary.completed_total += habitCompleted;
    weekSummary.pending_total += habitPending;
    weekSummary.future_total += habitFuture;

    const habitPassedDays = habitCompleted + habitPending;
    // Target-based: weekly → target_count, daily → 7. Capped at 100%.
    const weeklyTarget = isWeekly
      ? (Number(h.target_count) > 0 ? Number(h.target_count) : 1)
      : 7;
    const habitCompletionRate = round2(
      Math.min(100, (habitCompleted / weeklyTarget) * 100)
    );
    const habitWeeklyRate = habitCompletionRate;

    // All-time tracking from start_date → today.
    const allTimeArr = [];
    let allTimeCompleted = 0;
    let allTimeNotDone = 0;

    if (habitStart && habitStart <= today) {
      if (isWeekly) {
        // WEEKLY: target_count session slots PER WEEK (start week → this week),
        // filled one-per-session-done that week (capped at target).
        const tgt = Number(h.target_count) > 0 ? Number(h.target_count) : 1;
        const perWeek = new Map();
        for (const d of Object.keys(sidAllTime)) {
          if ((Number(sidAllTime[d].completed_count) || 0) > 0) {
            const ws = weekRangeSunSat(d).start;
            perWeek.set(ws, (perWeek.get(ws) || 0) + 1);
          }
        }
        const curWs = weekRangeSunSat(today).start;
        let wsYmd = weekRangeSunSat(habitStart).start;
        while (wsYmd <= curWs) {
          const filled = Math.min(perWeek.get(wsYmd) || 0, tgt);
          for (let i = 0; i < tgt; i++) {
            const done = i < filled;
            if (done) allTimeCompleted++;
            else allTimeNotDone++;
            allTimeArr.push({
              date: wsYmd,
              day: getDayName(wsYmd),
              status: done ? 1 : -1, // 1=session done, -1=missed slot
              target_count: tgt,
              completed_count: done ? 1 : 0,
            });
          }
          wsYmd = addDays(wsYmd, 7);
        }
      } else {
        for (const d of buildDateRange(habitStart, today)) {
          let st;
          let cc;
          if (sidAllTime[d] && Number(sidAllTime[d].is_completed) === 1) {
            st = 1;
            cc = Number(sidAllTime[d].completed_count) || 0;
            allTimeCompleted++;
          } else {
            st = -1;
            cc = sidAllTime[d] ? Number(sidAllTime[d].completed_count) || 0 : 0;
            allTimeNotDone++;
          }
          allTimeArr.push({
            date: d,
            day: getDayName(d),
            status: st, // 1=tracked-done, -1=not-tracked
            target_count: Number(h.target_count),
            completed_count: cc,
          });
        }
      }
    }

    const allTimeTotal = allTimeArr.length;
    const allTimeRate =
      allTimeTotal > 0 ? round2((allTimeCompleted / allTimeTotal) * 100) : 0;

    outputHabits.push({
      selected_habit_id: sid,
      habit_id: Number(h.habit_id),
      level_id: Number(h.level_id),
      category: h.category,
      habit_name: h.habit_name,
      habit_description: h.habit_description,
      frequency_type: h.frequency_type,
      target_count: Number(h.target_count),
      target_unit: h.target_unit,
      tracking_type: h.tracking_type,
      is_active: Number(h.is_active),
      start_date: h.start_date,
      end_date: h.end_date,
      selection_status: h.selection_status,
      week_summary: {
        completed: habitCompleted,
        pending: habitPending,
        future: habitFuture,
        days_passed: habitPassedDays,
        completion_rate: habitCompletionRate,
        weekly_rate: habitWeeklyRate,
      },
      tracking: trackingArr,
      all_time_summary: {
        total_days: allTimeTotal,
        tracked_days: allTimeCompleted,
        untracked_days: allTimeNotDone,
        completion_rate: allTimeRate,
      },
      all_time_tracking: allTimeArr,
    });
  }

  const totalPassed = weekSummary.completed_total + weekSummary.pending_total;
  weekSummary.days_passed_total = totalPassed;
  // Average each habit's own rate (pooling would drag weekly habits toward
  // ~target/7 even at 100% of their weekly target).
  if (outputHabits.length > 0) {
    const rateSum = outputHabits.reduce(
      (s, x) => s + (x.week_summary.completion_rate || 0),
      0
    );
    const weeklySum = outputHabits.reduce(
      (s, x) => s + (x.week_summary.weekly_rate || 0),
      0
    );
    weekSummary.completion_rate = round2(rateSum / outputHabits.length);
    weekSummary.weekly_rate = round2(weeklySum / outputHabits.length);
  } else {
    weekSummary.completion_rate = 0;
    weekSummary.weekly_rate = 0;
  }

  return ok(res, 200, {
    message: "Weekly habit tracking fetched successfully",
    data: {
      profile_id: profileId,
      level_id: levelId,
      week_start: weekStart,
      week_end: weekEnd,
      today,
      total_habits: outputHabits.length,
      week_summary: weekSummary,
      habits: outputHabits,
    },
  });
}

// ── check_habits ─ does the client have active selected habits? ─────────────
//   Body: { profile_id }
async function actionCheckHabits({ req, res, access }) {
  const { profileId } = access;

  const [clientRows] = await pool.execute(
    `SELECT level_type FROM table_clients WHERE profile_id = ? LIMIT 1`,
    [profileId]
  );
  if (!clientRows.length) {
    return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");
  }

  const levelType = Number(clientRows[0].level_type ?? 1);

  // Active selected habits (not constrained to a single level — matches the
  // dashboard controller; Archive hard-coded level 1).
  const [habitRows] = await pool.execute(
    `SELECT id, profile_id, habit_id, level_id,
            start_date, end_date, status, selected_at, updated_at
       FROM client_selected_habits
      WHERE profile_id = ?
        AND status     = 'active'`,
    [profileId]
  );

  const habits = habitRows.map((row) => ({
    id: Number(row.id),
    profile_id: row.profile_id,
    habit_id: Number(row.habit_id),
    level_id: Number(row.level_id),
    start_date: row.start_date,
    end_date: row.end_date ?? null,
    status: row.status,
    selected_at: row.selected_at,
    updated_at: row.updated_at,
  }));

  return ok(res, 200, {
    message: habits.length > 0 ? "Client habits found" : "Client habits not added",
    data: {
      profile_id: profileId,
      level_type: levelType,
      is_habit_added: habits.length > 0,
      total_habits: habits.length,
      data: habits,
    },
  });
}

// ── fetch_preferences ─ latest user_habits (goal/activity/food_type/glp_1) ──
//   Body: { profile_id }
async function actionFetchPreferences({ req, res, access }) {
  const { profileId } = access;

  const [rows] = await pool.execute(
    `SELECT id, profile_id, goal, activity, food_type, glp_1, dttm, tsstamp
       FROM user_habits
      WHERE profile_id = ?
      ORDER BY id DESC
      LIMIT 1`,
    [profileId]
  );

  const row = rows[0];
  if (!row) {
    return fail(res, 404, "No habits found for this profile", "HABITS_NOT_FOUND");
  }

  return ok(res, 200, {
    message: "User habits fetched successfully",
    data: {
      id: Number(row.id),
      profile_id: row.profile_id,
      goal: row.goal,
      activity: row.activity,
      food_type: buildFoodType(row.food_type),
      glp_1: Number(row.glp_1 ?? 0),
      dttm: row.dttm,
      tsstamp: row.tsstamp,
    },
  });
}

// ── save_preferences ─ upsert user_habits for a profile ─────────────────────
//   Body: { profile_id, goal, activity, food_type?, glp_1? }
//   UPDATE the latest row; if none exists, INSERT. (No unique-key dependency.)
async function actionSavePreferences({ req, res, access }) {
  const { profileId } = access;

  const goal = typeof req.body?.goal === "string" ? req.body.goal.trim() : "";
  const activity =
    typeof req.body?.activity === "string" ? req.body.activity.trim() : "";
  if (!goal) return fail(res, 422, "goal is required", "VALIDATION_ERROR");
  if (!activity) return fail(res, 422, "activity is required", "VALIDATION_ERROR");

  let glp1 = 0;
  if (req.body?.glp_1 !== undefined) {
    const g = toGlp1(req.body.glp_1);
    if (g === null) {
      return fail(res, 422, "glp_1 must be boolean or 0/1", "VALIDATION_ERROR");
    }
    glp1 = g;
  }

  const foodTypeJson = normalizeFoodType(req.body?.food_type);
  const epoch = Math.floor(Date.now() / 1000);

  // Try UPDATE latest row first.
  const [existing] = await pool.execute(
    `SELECT id FROM user_habits WHERE profile_id = ? ORDER BY id DESC LIMIT 1`,
    [profileId]
  );

  let id;
  let updated;
  if (existing.length) {
    id = Number(existing[0].id);
    await pool.execute(
      `UPDATE user_habits
          SET goal = ?, activity = ?, food_type = ?, glp_1 = ?,
              dttm = CURDATE(), tsstamp = ?
        WHERE id = ?`,
      [goal, activity, foodTypeJson, glp1, epoch, id]
    );
    updated = true;
  } else {
    const [result] = await pool.execute(
      `INSERT INTO user_habits
         (profile_id, goal, activity, food_type, glp_1, dttm, tsstamp)
       VALUES (?, ?, ?, ?, ?, CURDATE(), ?)`,
      [profileId, goal, activity, foodTypeJson, glp1, epoch]
    );
    id = Number(result.insertId);
    updated = false;
  }

  return ok(res, updated ? 200 : 201, {
    message: updated
      ? "Habits updated successfully"
      : "Habits saved successfully",
    data: {
      id,
      profile_id: profileId,
      goal,
      activity,
      food_type: buildFoodType(foodTypeJson),
      glp_1: glp1,
      epoch_timestamp: epoch,
    },
  });
}

// ── update_glp1 ─ single-field update of the GLP-1 flag ─────────────────────
//   Body: { profile_id, glp_1 }
async function actionUpdateGlp1({ req, res, access }) {
  const { profileId } = access;

  const glp1 = toGlp1(req.body?.glp_1);
  if (glp1 === null) {
    return fail(res, 422, "glp_1 must be boolean or 0/1", "VALIDATION_ERROR");
  }

  const [result] = await pool.execute(
    `UPDATE user_habits
        SET glp_1 = ?, tsstamp = ?
      WHERE profile_id = ?
      ORDER BY id DESC
      LIMIT 1`,
    [glp1, Math.floor(Date.now() / 1000), profileId]
  );

  if (result.affectedRows === 0) {
    return fail(
      res,
      404,
      "No habits row found to update. Save preferences first.",
      "HABITS_NOT_FOUND"
    );
  }

  return ok(res, 200, {
    message: "GLP-1 flag updated",
    data: { profile_id: profileId, glp_1: glp1 },
  });
}

// ── dashboard ─ per-client habit dashboard (drives the HabitsAnalysis UI) ───
//   Body: { profile_id }
//   Returns the client header, each active habit's all-time completion % plus a
//   day-by-day breakdown, an overall adherence figure, an all-time summary, and
//   a week/month/all completion-rate trend. Response `data` shape is identical
//   to habits-dashboard so the dashboard's Overview / HabitsMonitoring /
//   RightHandSidebar components consume it unchanged.
async function actionDashboard({ req, res, access }) {
  const { dieticianId, profileId } = access;

  const client = await fetchClient(dieticianId, profileId);
  if (!client) return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");

  const levelType = parseInt(client.level_type, 10) || 0;
  const today = todayYmd();

  // Active selected habits (≤5) + master metadata.
  const [selectedHabits] = await pool.execute(
    `
      SELECT
        csh.id AS selected_habit_id,
        csh.habit_id,
        csh.level_id,
        csh.start_date,
        hm.habit_name,
        hm.category,
        hm.frequency_type,
        hm.target_count,
        hm.target_unit,
        hm.tracking_type
      FROM client_selected_habits csh
      INNER JOIN habit_master hm
        ON  hm.id = csh.habit_id
        AND hm.level_id = csh.level_id
        AND hm.is_active = 1
      WHERE csh.profile_id = ?
        AND csh.status = 'active'
      ORDER BY csh.id ASC
      LIMIT 5
    `,
    [profileId]
  );

  if (!selectedHabits.length) {
    return ok(res, 200, {
      message: "No active habits for this client",
      data: {
        profile_id: profileId,
        profile_name: client.profile_name,
        level_type: levelType,
        today,
        total_habits: 0,
        overall: { expected_days: 0, completed_days: 0, completion_percent: 0 },
        summary: {
          total_days: 0,
          total_days_tracked: 0,
          total_perfect_days: 0,
          tracking_rate: 0,
          completion_rate: 0,
        },
        completion_trend: {
          week: { range: "week", granularity: "day", points: [] },
          month: { range: "month", granularity: "day", points: [] },
          all: { range: "all", granularity: "week", points: [] },
        },
        habits: [],
      },
    });
  }

  // Pull tracking once for all habits, up to today.
  const ids = selectedHabits.map((h) => Number(h.selected_habit_id));
  const placeholders = ids.map(() => "?").join(",");
  const [trackRows] = await pool.execute(
    `
      SELECT selected_habit_id, tracking_date, completed_count, is_completed
      FROM client_habit_tracking
      WHERE profile_id = ?
        AND selected_habit_id IN (${placeholders})
        AND tracking_date <= ?
    `,
    [profileId, ...ids, today]
  );

  // Each habit's own start_date (rows before it don't count).
  const startBySid = {};
  for (const h of selectedHabits) {
    startBySid[Number(h.selected_habit_id)] = h.start_date
      ? normDate(h.start_date)
      : today;
  }

  // Index tracking by selected_habit_id → date.
  const trackBySid = {};
  for (const r of trackRows) {
    const sid = Number(r.selected_habit_id);
    const rowDate = normDate(r.tracking_date);
    if (rowDate < startBySid[sid]) continue;
    if (!trackBySid[sid]) trackBySid[sid] = {};
    trackBySid[sid][rowDate] = {
      completed_count: parseInt(r.completed_count, 10) || 0,
      is_completed: parseInt(r.is_completed, 10) === 1,
    };
  }

  let overallExpected = 0;
  let overallCompleted = 0;

  const habits = selectedHabits.map((h) => {
    const sid = Number(h.selected_habit_id);
    const startDate = startBySid[sid];
    const expectedDays = inclusiveDays(startDate, today);
    const dayMap = trackBySid[sid] || {};

    const days = [];
    let completedDays = 0;
    for (const dateKey of buildDateRange(startDate, today)) {
      const entry = dayMap[dateKey];
      const isCompleted = entry ? entry.is_completed : false;
      if (isCompleted) completedDays++;
      days.push({
        date: dateKey,
        day: getDayName(dateKey),
        completed_count: entry ? entry.completed_count : 0,
        is_completed: isCompleted,
      });
    }

    overallExpected += expectedDays;
    overallCompleted += completedDays;

    return {
      selected_habit_id: sid,
      habit_id: Number(h.habit_id),
      level_id: Number(h.level_id),
      habit_name: h.habit_name,
      category: h.category,
      frequency_type: h.frequency_type,
      target_count: parseInt(h.target_count, 10) || 1,
      target_unit: h.target_unit,
      tracking_type: h.tracking_type,
      start_date: startDate,
      expected_days: expectedDays,
      completed_days: completedDays,
      completion_percent: pct(completedDays, expectedDays),
      days,
    };
  });

  // Cross-habit daily aggregate (earliest start → today).
  const earliestStart = Object.values(startBySid).reduce(
    (min, d) => (d < min ? d : min),
    today
  );

  const dailyAgg = [];
  for (const dateKey of buildDateRange(earliestStart, today)) {
    let expected = 0;
    let tracked = 0;
    let completed = 0;
    for (const h of selectedHabits) {
      const sid = Number(h.selected_habit_id);
      if (startBySid[sid] <= dateKey) {
        expected++;
        const entry = trackBySid[sid] && trackBySid[sid][dateKey];
        if (entry) {
          tracked++;
          if (entry.is_completed) completed++;
        }
      }
    }
    dailyAgg.push({
      date: dateKey,
      day: getDayName(dateKey),
      expected,
      tracked,
      completed,
      completion_rate: pct(completed, expected),
    });
  }

  // Summary stats (all-time).
  let sumExpected = 0;
  let sumTracked = 0;
  let sumCompleted = 0;
  let daysTracked = 0;
  let perfectDays = 0;
  for (const d of dailyAgg) {
    sumExpected += d.expected;
    sumTracked += d.tracked;
    sumCompleted += d.completed;
    if (d.tracked > 0) daysTracked++;
    if (d.expected > 0 && d.completed === d.expected) perfectDays++;
  }

  const summary = {
    total_days: dailyAgg.length,
    total_days_tracked: daysTracked,
    total_perfect_days: perfectDays,
    tracking_rate: pct(sumTracked, sumExpected),
    completion_rate: pct(sumCompleted, sumExpected),
  };

  // Completion-rate trend (week / month / all).
  const dailyPointsFrom = (fromKey) =>
    dailyAgg
      .filter((d) => d.date >= fromKey)
      .map((d) => ({
        date: d.date,
        day: d.day,
        completed: d.completed,
        expected: d.expected,
        completion_rate: d.completion_rate,
      }));

  const weeklyBuckets = () => {
    const points = [];
    for (let i = 0; i < dailyAgg.length; i += 7) {
      const chunk = dailyAgg.slice(i, i + 7);
      const exp = chunk.reduce((s, d) => s + d.expected, 0);
      const comp = chunk.reduce((s, d) => s + d.completed, 0);
      points.push({
        week_start: chunk[0].date,
        week_end: chunk[chunk.length - 1].date,
        completed: comp,
        expected: exp,
        completion_rate: pct(comp, exp),
      });
    }
    return points;
  };

  const completion_trend = {
    week: {
      range: "week",
      granularity: "day",
      points: dailyPointsFrom(addDays(today, -6)),
    },
    month: {
      range: "month",
      granularity: "day",
      points: dailyPointsFrom(addDays(today, -29)),
    },
    all: { range: "all", granularity: "week", points: weeklyBuckets() },
  };

  console.info("habits.dashboard: ok", {
    dietitian_id: dieticianId,
    profile_id: profileId,
    total_habits: habits.length,
    ts: new Date().toISOString(),
  });

  return ok(res, 200, {
    message: "Habit dashboard fetched successfully",
    data: {
      profile_id: profileId,
      profile_name: client.profile_name,
      level_type: levelType,
      today,
      total_habits: habits.length,
      overall: {
        expected_days: overallExpected,
        completed_days: overallCompleted,
        completion_percent: pct(overallCompleted, overallExpected),
      },
      summary,
      completion_trend,
      habits,
    },
  });
}

// ── tracking_data ─ habit-tracking dataset fanned out day-by-day ────────────
//   Body: { profile_id }
//   Most-recently-selected 5 active habits across earliest start_date → today.
async function actionTrackingData({ req, res, access }) {
  const { profileId } = access;

  // 5 most recently selected active habits.
  const [habits] = await pool.execute(
    `SELECT csh.id AS selected_habit_id,
            csh.habit_id,
            csh.start_date,
            hm.habit_name,
            hm.category,
            hm.frequency_type,
            hm.target_count,
            hm.target_unit,
            hm.tracking_type
       FROM client_selected_habits csh
       INNER JOIN habit_master hm ON hm.id = csh.habit_id
      WHERE csh.profile_id = ?
        AND csh.status = 'active'
      ORDER BY csh.selected_at DESC
      LIMIT 5`,
    [profileId]
  );

  if (!habits.length) {
    // Legacy parity: 200 with status false = "empty state", not an error.
    return res.status(200).json({
      status: false,
      message: "No habits found for this client",
      data: null,
      error: null,
    });
  }

  // Earliest start_date drives the rendered range.
  let earliest = null;
  for (const h of habits) {
    const sStr = normDate(h.start_date);
    if (earliest === null || sStr < earliest) earliest = sStr;
  }
  const today = todayYmd();
  const allDates = buildDateRange(earliest, today);

  const ids = habits.map((h) => Number(h.selected_habit_id));
  const placeholders = ids.map(() => "?").join(",");
  const [trackingRows] = await pool.execute(
    `SELECT selected_habit_id, habit_id, tracking_date,
            is_completed, completed_count, notes
       FROM client_habit_tracking
      WHERE profile_id = ?
        AND selected_habit_id IN (${placeholders})
        AND tracking_date BETWEEN ? AND ?`,
    [profileId, ...ids, earliest, today]
  );

  const trackingMap = new Map();
  for (const r of trackingRows) {
    const dateStr = normDate(r.tracking_date);
    if (!trackingMap.has(dateStr)) trackingMap.set(dateStr, new Map());
    trackingMap.get(dateStr).set(Number(r.selected_habit_id), {
      is_completed: !!r.is_completed,
      completed_count: Number(r.completed_count ?? 0),
      notes: r.notes,
    });
  }

  const days = allDates.map((date) => ({
    date,
    habits: habits.map((h) => {
      const sId = Number(h.selected_habit_id);
      const t = trackingMap.get(date)?.get(sId) || null;
      return {
        habit_id: Number(h.habit_id),
        selected_habit_id: sId,
        habit_name: h.habit_name,
        category: h.category,
        frequency_type: h.frequency_type,
        target_count: Number(h.target_count),
        target_unit: h.target_unit,
        tracking_type: h.tracking_type,
        is_completed: t ? t.is_completed : false,
        completed_count: t ? t.completed_count : 0,
        notes: t ? t.notes : null,
      };
    }),
  }));

  return ok(res, 200, {
    message: "Habit tracking data fetched successfully",
    data: {
      profile_id: profileId,
      start_date: earliest,
      end_date: today,
      data: days,
    },
  });
}

// ═══════════════════════════════════════════════════════════════════════════
//  Dispatcher
// ═══════════════════════════════════════════════════════════════════════════

const HANDLERS = {
  // per-client dashboard (drives the HabitsAnalysis UI)
  dashboard: actionDashboard,
  // selected-habits (5-habit system)
  habit_master: actionHabitMaster,
  save_selected_habits: actionSaveSelectedHabits,
  selected_status: actionSelectedStatus,
  track_habit: actionTrackHabit,
  weekly_tracking: actionWeeklyTracking,
  // habits check
  check_habits: actionCheckHabits,
  // user_habits preferences + tracking
  fetch_preferences: actionFetchPreferences,
  save_preferences: actionSavePreferences,
  update_glp1: actionUpdateGlp1,
  tracking_data: actionTrackingData,
  track_batch: actionTrackBatch,
};

const VALID_ACTIONS = Object.keys(HANDLERS);

/**
 * POST /dietitian/api/web/habits-manager
 *
 * Body: { action, dietitian_id?, profile_id, ...actionFields }
 * Auth: Bearer JWT (authMiddleware must run before this handler).
 */
const habitsManager = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // Body shape.
  if (!isPlainObject(req.body)) {
    return fail(res, 400, "Invalid request body", "INVALID_BODY");
  }

  // Action selection.
  const action =
    typeof req.body.action === "string" ? req.body.action.trim() : "";
  const handler = HANDLERS[action];
  if (!handler) {
    return fail(
      res,
      422,
      `Invalid or missing action. Valid actions: ${VALID_ACTIONS.join(", ")}`,
      "INVALID_ACTION",
      { valid_actions: VALID_ACTIONS }
    );
  }

  // Token-bound ownership check (BOLA/IDOR) — runs for EVERY action.
  const access = await resolveProfileAccess(req, res, `habits.${action}`);
  if (!access) return; // response already sent

  if (!access.dieticianId || !access.profileId) {
    return fail(
      res,
      422,
      "dietitian_id and profile_id are required",
      "VALIDATION_ERROR"
    );
  }

  try {
    return await handler({ req, res, access });
  } catch (err) {
    console.error("habits-manager: unhandled error", {
      action,
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
    });
    return serverError(res);
  }
};

module.exports = { habitsManager };














// "use strict";

// /**
//  * habits-manager.controller.js
//  *
//  * Platform : Respyr Dietitian API (api.respyr.ai)
//  * Security : VAPT-hardened, HIPAA-aligned
//  *
//  * ONE dispatcher endpoint that consolidates THREE Archive controllers into a
//  * single action-routed handler (the repo's "dispatcher" pattern — one route,
//  * one controller, sub-handlers selected by `action` in the request body):
//  *
//  *   Archive source                       → actions in this file
//  *   ───────────────────────────────────────────────────────────────────────
//  *   selected_habits.controller.js        → habit_master, save_selected_habits,
//  *                                           selected_status, track_habit,
//  *                                           weekly_tracking
//  *   habits_check.controller.js           → check_habits
//  *   habits.controller.js  (user_habits)  → fetch_preferences, save_preferences,
//  *                                           tracking_data, track_batch,
//  *                                           update_glp1
//  *
//  * Endpoint (POST, behind authMiddleware):
//  *   /dietitian/api/web/habits-manager
//  *
//  * Request body (common to every action):
//  *   {
//  *     "action":       "<one of the actions above>",
//  *     "dietitian_id": "<optional — defaults to JWT; dietician_id also accepted>",
//  *     "profile_id":   "<required — the client this action operates on>",
//  *     ... action-specific fields ...
//  *   }
//  *
//  * Security model (identical to habits_dashboard.controller.js / the other habit
//  * endpoints in this repo):
//  *  - The JWT belongs to a DIETITIAN. profile_id is supplied in the body and is
//  *    verified via requireProfileAccess (table_clients dietician_id ↔ profile_id)
//  *    BEFORE any habit data is read or written — closing BOLA/IDOR (OWASP API1).
//  *  - A super_admin may pass an explicit dietitian_id; requireProfileAccess
//  *    resolves the profile's true owning dietitian.
//  *  - Fully parameterized queries — zero string interpolation.
//  *  - Internal error details are suppressed in every client-facing response.
//  *  - PHI is never logged; only error metadata (code/errno/sqlState).
//  *  - Cache-Control: no-store on every response (PHI-adjacent).
//  *
//  * NOTE on dietitian/dietician spelling:
//  *  - accessControl.js accepts BOTH spellings from body and JWT.
//  *  - DB column reference uses dietician_id (legacy column name).
//  *    Verify with: SHOW COLUMNS FROM table_clients LIKE '%diet%';
//  *
//  * ── Schema reference (verify before deploy with SHOW COLUMNS) ───────────────
//  *   table_clients:          dietician_id, profile_id, profile_name, level_type,
//  *                           dttm
//  *   user_habits:            id, profile_id, goal, activity, food_type, glp_1,
//  *                           dttm, tsstamp
//  *   habit_master:           id, level_id, category, habit_name,
//  *                           habit_description, frequency_type, target_count,
//  *                           target_unit, tracking_type, sort_order, is_active
//  *   client_selected_habits: id, profile_id, habit_id, level_id, start_date,
//  *                           end_date, status('active'|'removed'), selected_at,
//  *                           updated_at
//  *   client_habit_tracking:  id, profile_id, selected_habit_id, habit_id,
//  *                           tracking_date, target_count, completed_count,
//  *                           is_completed, notes, updated_at
//  *
//  * ── Required DB constraints for the WRITE actions (idempotent upserts) ──────
//  *   For track_habit / track_batch (ON DUPLICATE KEY UPDATE):
//  *     ALTER TABLE client_habit_tracking
//  *       ADD UNIQUE KEY uniq_track (selected_habit_id, tracking_date);
//  *   save_preferences / update_glp1 do NOT depend on a unique key — they
//  *   UPDATE-then-INSERT against the latest row (id DESC) to stay safe even if
//  *   historical duplicate user_habits rows exist.
//  */

// const pool = require("../../../../config/db");
// const {
//   requireProfileAccess,
//   getTokenDieticianId,
// } = require("../../../../utils/accessControl");

// // ───────────────────────────────────────────────────────────────────────────
// //  Config
// // ───────────────────────────────────────────────────────────────────────────

// // habit_master currently only has rows at level_id = 1. Clients on level 2/3
// // fall back to the level-1 catalog so the picker is never empty. When level
// // 2/3 rows are added this fallback becomes inert automatically. Set to null to
// // disable.
// const HABIT_LEVEL_FALLBACK = 1;

// // ───────────────────────────────────────────────────────────────────────────
// //  Response helpers — house shape: { status, message, data, error }
// // ───────────────────────────────────────────────────────────────────────────

// function ok(res, status, payload) {
//   return res.status(status).json({ status: true, error: null, ...payload });
// }

// function fail(res, status, message, code, extra = {}) {
//   return res.status(status).json({
//     status: false,
//     message,
//     data: null,
//     error: { code },
//     ...extra,
//   });
// }

// function serverError(res) {
//   return fail(res, 500, "Server error", "SERVER_ERROR");
// }

// // ───────────────────────────────────────────────────────────────────────────
// //  Date helpers (UTC, calendar-only — no time-zone drift)
// // ───────────────────────────────────────────────────────────────────────────

// function pad(n) {
//   return String(n).padStart(2, "0");
// }

// function ymd(d) {
//   return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
// }

// function todayYmd() {
//   return ymd(new Date());
// }

// /** mysql2 may hand back DATE columns as Date objects OR strings — normalise. */
// function normDate(val) {
//   if (!val) return null;
//   if (val instanceof Date) return ymd(val);
//   const s = String(val);
//   return s.length >= 10 ? s.slice(0, 10) : s;
// }

// function getDayName(dateStr) {
//   return new Date(`${dateStr}T00:00:00Z`).toLocaleDateString("en-US", {
//     weekday: "short",
//     timeZone: "UTC",
//   });
// }

// /** Inclusive YYYY-MM-DD list from start..end (UTC). Empty if start > end. */
// function buildDateRange(startStr, endStr) {
//   const out = [];
//   if (!startStr || !endStr) return out;
//   const start = new Date(`${startStr}T00:00:00Z`);
//   const end = new Date(`${endStr}T00:00:00Z`);
//   if (isNaN(start) || isNaN(end) || start > end) return out;
//   for (let d = new Date(start); d <= end; d.setUTCDate(d.getUTCDate() + 1)) {
//     out.push(ymd(d));
//   }
//   return out;
// }

// /** Sun–Sat week range containing `dateStr` (matches Archive weekly_tracking). */
// function weekRangeSunSat(dateStr) {
//   const ms = new Date(`${dateStr}T00:00:00Z`).getTime();
//   const dow = new Date(ms).getUTCDay(); // 0=Sun .. 6=Sat
//   const startMs = ms - dow * 86400000;
//   return {
//     start: ymd(new Date(startMs)),
//     end: ymd(new Date(startMs + 6 * 86400000)),
//   };
// }

// function weekDates(startYmd) {
//   const startMs = new Date(`${startYmd}T00:00:00Z`).getTime();
//   const out = [];
//   for (let i = 0; i < 7; i++) out.push(ymd(new Date(startMs + i * 86400000)));
//   return out;
// }

// function round2(n) {
//   return Math.round(n * 100) / 100;
// }

// /** Whole-number percentage (matches habits_dashboard.controller.js). */
// function pct(numerator, denominator) {
//   if (!denominator) return 0;
//   return Math.round((numerator / denominator) * 100);
// }

// /** YYYY-MM-DD `n` days after (negative = before) a YYYY-MM-DD (UTC). */
// function addDays(dateStr, n) {
//   const d = new Date(`${dateStr}T00:00:00Z`);
//   d.setUTCDate(d.getUTCDate() + n);
//   return ymd(d);
// }

// /** Inclusive whole-day count between two YYYY-MM-DD strings (UTC). 0 if from>to. */
// function inclusiveDays(fromYmd, toYmd) {
//   const from = new Date(`${fromYmd}T00:00:00Z`).getTime();
//   const to = new Date(`${toYmd}T00:00:00Z`).getTime();
//   if (isNaN(from) || isNaN(to) || from > to) return 0;
//   return Math.floor((to - from) / 86400000) + 1;
// }

// // ───────────────────────────────────────────────────────────────────────────
// //  Input validation helpers
// // ───────────────────────────────────────────────────────────────────────────

// function isPlainObject(v) {
//   return v !== null && typeof v === "object" && !Array.isArray(v);
// }

// /** Strict positive integer (rejects floats, leading zeros mismatch, strings). */
// function toPositiveInt(raw) {
//   if (raw === undefined || raw === null || raw === "") return null;
//   const n = parseInt(raw, 10);
//   if (!Number.isInteger(n) || n <= 0) return null;
//   if (String(n) !== String(raw).trim()) return null;
//   return n;
// }

// /** Non-negative integer (0 allowed). */
// function toNonNegInt(raw, fallback = null) {
//   if (raw === undefined || raw === null || raw === "") return fallback;
//   const n = parseInt(raw, 10);
//   if (!Number.isInteger(n) || n < 0) return null;
//   return n;
// }

// /** glp_1 → 0|1. Accepts boolean or 0/1 (number or string). Else null. */
// function toGlp1(raw) {
//   if (raw === true || raw === 1 || raw === "1") return 1;
//   if (raw === false || raw === 0 || raw === "0") return 0;
//   return null;
// }

// /** YYYY-MM-DD validator. Returns the string or null. */
// function toYmd(raw) {
//   if (typeof raw !== "string") return null;
//   const s = raw.trim();
//   if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
//   const d = new Date(`${s}T00:00:00Z`);
//   return isNaN(d) ? null : s;
// }

// // food_type stored as JSON. Parse back to the fixed object the client expects.
// function buildFoodType(raw) {
//   let parsed = {};
//   if (raw) {
//     try {
//       const decoded = typeof raw === "string" ? JSON.parse(raw) : raw;
//       if (isPlainObject(decoded)) parsed = decoded;
//     } catch (_) {
//       parsed = {};
//     }
//   }
//   return {
//     diet_type: parsed.diet_type || "",
//     primary_cuisine: parsed.primary_cuisine || "",
//     secondary_cuisine: parsed.secondary_cuisine || "",
//   };
// }

// // Normalise food_type INPUT (string OR object) → JSON string for storage.
// function normalizeFoodType(input) {
//   if (input == null || input === "") return JSON.stringify({});
//   if (typeof input === "string") return JSON.stringify({ diet_type: input });
//   if (isPlainObject(input)) {
//     return JSON.stringify({
//       diet_type: input.diet_type || "",
//       primary_cuisine: input.primary_cuisine || "",
//       secondary_cuisine: input.secondary_cuisine || "",
//     });
//   }
//   return JSON.stringify({});
// }

// // ───────────────────────────────────────────────────────────────────────────
// //  Token-bound profile access (BOLA/IDOR guard) — runs before every action.
// //  On success returns { dieticianId, profileId }; on failure writes the HTTP
// //  response and returns null.
// // ───────────────────────────────────────────────────────────────────────────

// async function resolveProfileAccess(req, res, label) {
//   const rawDietitianId =
//     req.body?.dietitian_id ??
//     req.body?.dietician_id ??
//     getTokenDieticianId(req) ??
//     "";
//   const rawProfileId = req.body?.profile_id ?? "";

//   let access;
//   try {
//     access = await requireProfileAccess(req, rawDietitianId, rawProfileId);
//   } catch (authErr) {
//     console.error(`${label}: requireProfileAccess threw`, authErr?.code);
//     serverError(res);
//     return null;
//   }

//   if (!access.allowed) {
//     console.warn(`${label}: access denied`, {
//       statusCode: access.statusCode,
//       path: req.originalUrl,
//       method: req.method,
//     });
//     res.status(access.statusCode).json({
//       status: false,
//       message: access.message,
//       data: null,
//       error: { code: "ACCESS_DENIED" },
//     });
//     return null;
//   }

//   return access;
// }

// /** Fetch the client header row (also a DB-level ownership re-confirm). */
// async function fetchClient(dieticianId, profileId) {
//   const [rows] = await pool.execute(
//     `
//       SELECT profile_name, level_type, dttm
//       FROM table_clients
//       WHERE UPPER(TRIM(dietician_id)) = ?
//         AND profile_id = ?
//       LIMIT 1
//     `,
//     [dieticianId, profileId]
//   );
//   return rows[0] || null;
// }

// // ═══════════════════════════════════════════════════════════════════════════
// //  ACTION HANDLERS
// //  Each receives ({ req, res, access }) where access = { dieticianId, profileId }.
// // ═══════════════════════════════════════════════════════════════════════════

// // ── habit_master ─ list available habits, grouped by category ───────────────
// //   Body: { profile_id, level_id? }
// //   level_id defaults to the client's level_type. Falls back to level 1 when
// //   the requested level has no rows yet.
// async function actionHabitMaster({ req, res, access }) {
//   const { dieticianId, profileId } = access;

//   const client = await fetchClient(dieticianId, profileId);
//   if (!client) return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");

//   let levelId = toPositiveInt(req.body?.level_id);
//   if (levelId === null) {
//     levelId = parseInt(client.level_type, 10) || HABIT_LEVEL_FALLBACK || 1;
//   }

//   const sql = `
//     SELECT id, level_id, category, habit_name, habit_description,
//            frequency_type, target_count, target_unit, tracking_type, sort_order
//     FROM habit_master
//     WHERE is_active = 1 AND level_id = ?
//     ORDER BY sort_order ASC
//   `;

//   let [rows] = await pool.execute(sql, [levelId]);
//   let servedLevelId = levelId;

//   if (
//     rows.length === 0 &&
//     HABIT_LEVEL_FALLBACK !== null &&
//     levelId !== HABIT_LEVEL_FALLBACK
//   ) {
//     [rows] = await pool.execute(sql, [HABIT_LEVEL_FALLBACK]);
//     servedLevelId = HABIT_LEVEL_FALLBACK;
//   }

//   const grouped = {};
//   for (const r of rows) {
//     const cat = r.category || "Uncategorized";
//     if (!grouped[cat]) grouped[cat] = [];
//     grouped[cat].push({
//       id: Number(r.id),
//       level_id: Number(r.level_id),
//       habit_name: r.habit_name,
//       habit_description: r.habit_description,
//       frequency_type: r.frequency_type,
//       target_count: Number(r.target_count),
//       target_unit: r.target_unit,
//       tracking_type: r.tracking_type,
//       sort_order: Number(r.sort_order),
//     });
//   }

//   return ok(res, 200, {
//     message: "Habit master fetched successfully",
//     data: {
//       profile_id: profileId,
//       level_id: levelId, // requested
//       served_level_id: servedLevelId, // actually returned
//       data: grouped,
//     },
//   });
// }

// // ── save_selected_habits ─ swap out old set, save exactly 5 ─────────────────
// //   Body: { profile_id, level_id, habit_ids: [5 positive ints] }
// async function actionSaveSelectedHabits({ req, res, access }) {
//   const { dieticianId, profileId } = access;

//   const levelId = toPositiveInt(req.body?.level_id);
//   if (levelId === null) {
//     return fail(res, 422, "level_id must be a positive integer", "VALIDATION_ERROR");
//   }

//   const rawIds = req.body?.habit_ids;
//   if (!Array.isArray(rawIds) || rawIds.length !== 5) {
//     return fail(res, 422, "habit_ids must be an array of exactly 5 ids", "VALIDATION_ERROR");
//   }
//   const habitIds = rawIds.map(toPositiveInt);
//   if (habitIds.some((x) => x === null)) {
//     return fail(res, 422, "habit_ids must all be positive integers", "VALIDATION_ERROR");
//   }
//   if (new Set(habitIds).size !== habitIds.length) {
//     return fail(res, 422, "habit_ids must be unique", "VALIDATION_ERROR");
//   }

//   // Confirm the client exists/owned (transaction below filters by profile_id).
//   const client = await fetchClient(dieticianId, profileId);
//   if (!client) return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");

//   const conn = await pool.getConnection();
//   try {
//     await conn.beginTransaction();

//     const placeholders = habitIds.map(() => "?").join(",");
//     const fallback = HABIT_LEVEL_FALLBACK ?? levelId;

//     // Accept rows at the requested level OR the fallback tier.
//     const [validRows] = await conn.query(
//       `SELECT id, level_id FROM habit_master
//         WHERE id IN (${placeholders})
//           AND is_active = 1
//           AND level_id IN (?, ?)`,
//       [...habitIds, levelId, fallback]
//     );

//     if (validRows.length !== 5) {
//       await conn.rollback();
//       const validIds = validRows.map((r) => Number(r.id));
//       const invalidIds = habitIds.filter((id) => !validIds.includes(id));
//       return fail(
//         res,
//         400,
//         "One or more selected habits are invalid",
//         "INVALID_HABITS",
//         {
//           client_level_id: levelId,
//           received_habit_ids: habitIds,
//           valid_habit_ids: validIds,
//           invalid_habit_ids: invalidIds,
//         }
//       );
//     }

//     const habitLevelMap = new Map(
//       validRows.map((r) => [Number(r.id), Number(r.level_id)])
//     );

//     // Record the client's chosen tier.
//     await conn.query(
//       `UPDATE table_clients SET level_type = ? WHERE profile_id = ?`,
//       [levelId, profileId]
//     );

//     // Retire ALL previously-active habits (a client has 5 active at a time).
//     await conn.query(
//       `UPDATE client_selected_habits
//           SET status = 'removed', end_date = CURDATE()
//         WHERE profile_id = ?
//           AND status = 'active'`,
//       [profileId]
//     );

//     // Insert each new habit with the level_id pulled from habit_master.
//     for (const habitId of habitIds) {
//       const habitLevel = habitLevelMap.get(habitId) ?? levelId;
//       await conn.query(
//         `INSERT INTO client_selected_habits
//            (profile_id, habit_id, level_id, start_date, status)
//          VALUES (?, ?, ?, CURDATE(), 'active')`,
//         [profileId, habitId, habitLevel]
//       );
//     }

//     await conn.commit();

//     console.info("habits.save_selected: ok", {
//       dietitian_id: dieticianId,
//       profile_id: profileId,
//       count: habitIds.length,
//       ts: new Date().toISOString(),
//     });

//     return ok(res, 200, {
//       message: "5 habits selected successfully",
//       data: {
//         profile_id: profileId,
//         client_level_id: levelId,
//         habit_level_ids_saved: [...new Set(habitLevelMap.values())],
//         habit_ids: habitIds,
//       },
//     });
//   } catch (err) {
//     try {
//       await conn.rollback();
//     } catch (_) {}
//     throw err;
//   } finally {
//     conn.release();
//   }
// }

// // ── selected_status ─ active selected habits + today's + weekly tracking ────
// //   Body: { profile_id, tracking_date? (defaults today) }
// async function actionSelectedStatus({ req, res, access }) {
//   const { profileId } = access;

//   const trackingDate = req.body?.tracking_date
//     ? toYmd(req.body.tracking_date)
//     : todayYmd();
//   if (trackingDate === null) {
//     return fail(res, 422, "tracking_date must be YYYY-MM-DD", "VALIDATION_ERROR");
//   }

//   const { start: weekStart, end: weekEnd } = weekRangeSunSat(trackingDate);

//   const [rows] = await pool.execute(
//     `
//       SELECT
//         csh.id          AS selected_habit_id,
//         csh.profile_id,
//         csh.habit_id,
//         csh.level_id,
//         csh.start_date,
//         csh.status      AS selected_status,

//         hm.category,
//         hm.habit_name,
//         hm.habit_description,
//         hm.frequency_type,
//         hm.target_count,
//         hm.target_unit,
//         hm.tracking_type,
//         hm.sort_order,

//         daily_track.tracking_date              AS daily_tracking_date,
//         IFNULL(daily_track.completed_count, 0) AS daily_completed_count,
//         daily_track.notes                      AS daily_notes,

//         IFNULL(weekly_track.week_completed_count, 0) AS weekly_completed_count,
//         weekly_track.last_tracking_date              AS weekly_last_tracking_date

//       FROM client_selected_habits csh
//       INNER JOIN habit_master hm
//         ON hm.id = csh.habit_id

//       LEFT JOIN client_habit_tracking daily_track
//         ON daily_track.selected_habit_id = csh.id
//        AND daily_track.profile_id        = csh.profile_id
//        AND daily_track.tracking_date     = ?

//       LEFT JOIN (
//         SELECT selected_habit_id, profile_id,
//                SUM(completed_count) AS week_completed_count,
//                MAX(tracking_date)   AS last_tracking_date
//         FROM client_habit_tracking
//         WHERE profile_id = ?
//           AND tracking_date BETWEEN ? AND ?
//         GROUP BY selected_habit_id, profile_id
//       ) weekly_track
//         ON weekly_track.selected_habit_id = csh.id
//        AND weekly_track.profile_id        = csh.profile_id

//       WHERE csh.profile_id = ?
//         AND csh.status     = 'active'
//       ORDER BY hm.sort_order ASC
//     `,
//     [trackingDate, profileId, weekStart, weekEnd, profileId]
//   );

//   let trackedCount = 0;
//   let notTrackedCount = 0;
//   let completedTotal = 0;
//   let pendingCount = 0;

//   const habits = rows.map((r) => {
//     const freq = r.frequency_type;
//     const required = Number(r.target_count);
//     const dailyCompleted = Number(r.daily_completed_count);
//     const weeklyCompleted = Number(r.weekly_completed_count);
//     const isWeekly = freq === "weekly";

//     const isTracked = dailyCompleted > 0;
//     const isCompleted = isWeekly
//       ? weeklyCompleted >= required
//       : dailyCompleted >= required;

//     if (isTracked) trackedCount++;
//     else notTrackedCount++;
//     if (isCompleted) completedTotal++;
//     else pendingCount++;

//     return {
//       selected_habit_id: Number(r.selected_habit_id),
//       profile_id: r.profile_id,
//       habit_id: Number(r.habit_id),
//       level_id: Number(r.level_id),

//       category: r.category,
//       habit_name: r.habit_name,
//       habit_description: r.habit_description,

//       frequency_type: freq,
//       target_count: required,
//       target_unit: r.target_unit,
//       tracking_type: r.tracking_type,

//       selected_date: trackingDate,
//       week_start: isWeekly ? weekStart : null,
//       week_end: isWeekly ? weekEnd : null,
//       tracking_date: normDate(r.daily_tracking_date) || trackingDate,

//       completed_count: dailyCompleted,
//       weekly_completed_count: isWeekly ? weeklyCompleted : null,
//       required_count: required,

//       is_tracked: isTracked,
//       tracked_status: isTracked ? "tracked" : "not_tracked",
//       is_completed: isCompleted ? 1 : 0,
//       completion_status: isCompleted ? "completed" : "pending",

//       notes: isWeekly ? null : r.daily_notes,
//       selected_status: r.selected_status,
//       start_date: r.start_date,
//     };
//   });

//   return ok(res, 200, {
//     message: "Client habits fetched successfully",
//     data: {
//       profile_id: profileId,
//       tracking_date: trackingDate,
//       week_start: weekStart,
//       week_end: weekEnd,
//       total_habits: habits.length,
//       tracked_habits: trackedCount,
//       not_tracked_habits: notTrackedCount,
//       completed_habits: completedTotal,
//       pending_habits: pendingCount,
//       data: habits,
//     },
//   });
// }

// // ── track_habit ─ record completion for one habit on a date ─────────────────
// //   Body: { profile_id, habit_id, tracking_date?, completed_count?, notes? }
// async function actionTrackHabit({ req, res, access }) {
//   const { profileId } = access;

//   const habitId = toPositiveInt(req.body?.habit_id);
//   if (habitId === null) {
//     return fail(res, 422, "habit_id must be a positive integer", "VALIDATION_ERROR");
//   }

//   const trackingDate = req.body?.tracking_date
//     ? toYmd(req.body.tracking_date)
//     : todayYmd();
//   if (trackingDate === null) {
//     return fail(res, 422, "tracking_date must be YYYY-MM-DD", "VALIDATION_ERROR");
//   }

//   const completedCount = toNonNegInt(req.body?.completed_count, 1);
//   if (completedCount === null) {
//     return fail(res, 422, "completed_count must be a non-negative integer", "VALIDATION_ERROR");
//   }

//   const notes =
//     typeof req.body?.notes === "string" && req.body.notes.trim() !== ""
//       ? req.body.notes.trim()
//       : null;

//   // Habit must be selected & active for THIS profile (BOLA layer 2).
//   const [check] = await pool.execute(
//     `SELECT csh.id AS selected_habit_id, hm.target_count
//        FROM client_selected_habits csh
//        INNER JOIN habit_master hm ON hm.id = csh.habit_id
//       WHERE csh.profile_id = ?
//         AND csh.habit_id   = ?
//         AND csh.status     = 'active'
//       LIMIT 1`,
//     [profileId, habitId]
//   );

//   if (!check.length) {
//     return fail(
//       res,
//       400,
//       "This habit is not selected or not active for this profile",
//       "HABIT_NOT_SELECTED"
//     );
//   }

//   const selectedHabitId = Number(check[0].selected_habit_id);
//   const targetCount = Number(check[0].target_count);
//   const isCompleted = completedCount >= targetCount && completedCount > 0 ? 1 : 0;

//   await pool.execute(
//     `INSERT INTO client_habit_tracking
//        (profile_id, selected_habit_id, habit_id, tracking_date,
//         target_count, completed_count, is_completed, notes)
//      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
//      ON DUPLICATE KEY UPDATE
//        completed_count = VALUES(completed_count),
//        is_completed    = VALUES(is_completed),
//        notes           = VALUES(notes),
//        updated_at      = CURRENT_TIMESTAMP`,
//     [
//       profileId,
//       selectedHabitId,
//       habitId,
//       trackingDate,
//       targetCount,
//       completedCount,
//       isCompleted,
//       notes,
//     ]
//   );

//   return ok(res, 200, {
//     message: "Habit tracked successfully",
//     data: {
//       profile_id: profileId,
//       selected_habit_id: selectedHabitId,
//       habit_id: habitId,
//       tracking_date: trackingDate,
//       target_count: targetCount,
//       completed_count: completedCount,
//       is_completed: isCompleted,
//     },
//   });
// }

// // ── track_batch ─ upsert tracking for multiple habits at once ───────────────
// //   Body: { profile_id, tracking_date?, notes?,
// //           habits: [{ habit_id, completed_count }] }
// async function actionTrackBatch({ req, res, access }) {
//   const { profileId } = access;

//   const items = req.body?.habits;
//   if (!Array.isArray(items) || items.length === 0) {
//     return fail(res, 422, "habits must be a non-empty array", "VALIDATION_ERROR");
//   }
//   if (items.length > 50) {
//     return fail(res, 422, "habits cannot exceed 50 items", "VALIDATION_ERROR");
//   }

//   const normalized = [];
//   for (const it of items) {
//     if (!isPlainObject(it)) {
//       return fail(res, 422, "each habits item must be an object", "VALIDATION_ERROR");
//     }
//     const hid = toPositiveInt(it.habit_id);
//     const cc = toNonNegInt(it.completed_count, null);
//     if (hid === null || cc === null) {
//       return fail(
//         res,
//         422,
//         "each habits item needs a positive habit_id and non-negative completed_count",
//         "VALIDATION_ERROR"
//       );
//     }
//     normalized.push({ habit_id: hid, completed_count: cc });
//   }

//   const trackingDate = req.body?.tracking_date
//     ? toYmd(req.body.tracking_date)
//     : todayYmd();
//   if (trackingDate === null) {
//     return fail(res, 422, "tracking_date must be YYYY-MM-DD", "VALIDATION_ERROR");
//   }

//   const notes =
//     typeof req.body?.notes === "string" && req.body.notes.trim() !== ""
//       ? req.body.notes.trim()
//       : null;

//   // Resolve (habit_id → {selected_habit_id, target_count}) for ACTIVE habits
//   // owned by this profile. Anything else → failed (closes cross-profile spoof).
//   const habitIds = normalized.map((it) => it.habit_id);
//   const placeholders = habitIds.map(() => "?").join(",");
//   const [activeRows] = await pool.execute(
//     `SELECT csh.id AS selected_habit_id, csh.habit_id, hm.target_count
//        FROM client_selected_habits csh
//        INNER JOIN habit_master hm ON hm.id = csh.habit_id
//       WHERE csh.profile_id = ?
//         AND csh.habit_id IN (${placeholders})
//         AND csh.status = 'active'`,
//     [profileId, ...habitIds]
//   );

//   const activeMap = new Map();
//   for (const r of activeRows) {
//     activeMap.set(Number(r.habit_id), {
//       selectedHabitId: Number(r.selected_habit_id),
//       targetCount: Number(r.target_count),
//     });
//   }

//   const tracked = [];
//   const failedIds = [];

//   for (const item of normalized) {
//     const meta = activeMap.get(item.habit_id);
//     if (!meta) {
//       failedIds.push(item.habit_id);
//       continue;
//     }
//     const cc = item.completed_count;
//     const isCompleted = cc >= meta.targetCount && cc > 0 ? 1 : 0;

//     try {
//       await pool.execute(
//         `INSERT INTO client_habit_tracking
//            (profile_id, selected_habit_id, habit_id, tracking_date,
//             target_count, completed_count, is_completed, notes)
//          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
//          ON DUPLICATE KEY UPDATE
//            completed_count = VALUES(completed_count),
//            is_completed    = VALUES(is_completed),
//            notes           = VALUES(notes),
//            updated_at      = CURRENT_TIMESTAMP`,
//         [
//           profileId,
//           meta.selectedHabitId,
//           item.habit_id,
//           trackingDate,
//           meta.targetCount,
//           cc,
//           isCompleted,
//           notes,
//         ]
//       );
//       tracked.push({
//         habit_id: item.habit_id,
//         completed_count: cc,
//         is_completed: isCompleted,
//       });
//     } catch (_) {
//       failedIds.push(item.habit_id);
//     }
//   }

//   return ok(res, 200, {
//     message: "Habits updated successfully",
//     data: {
//       profile_id: profileId,
//       tracking_date: trackingDate,
//       tracked_count: tracked.length,
//       failed_count: failedIds.length,
//       tracked,
//       failed_ids: failedIds,
//     },
//   });
// }

// // ── weekly_tracking ─ Sun–Sat week + all-time per-habit summary ─────────────
// //   Body: { profile_id, date? (defaults today) }
// //   Faithful port of Archive weekly_habit_tracking.php.
// async function actionWeeklyTracking({ req, res, access }) {
//   const { profileId } = access;

//   const date = req.body?.date ? toYmd(req.body.date) : todayYmd();
//   if (date === null) {
//     return fail(res, 422, "date must be YYYY-MM-DD", "VALIDATION_ERROR");
//   }

//   // Client level_type
//   const [clientRows] = await pool.execute(
//     `SELECT level_type FROM table_clients WHERE profile_id = ? LIMIT 1`,
//     [profileId]
//   );
//   if (!clientRows.length) {
//     return fail(res, 404, "Profile not found", "PROFILE_NOT_FOUND");
//   }

//   const levelTypeRaw = clientRows[0].level_type;
//   if (levelTypeRaw === null || levelTypeRaw === "") {
//     return fail(res, 422, "User level not assigned", "LEVEL_NOT_SET");
//   }
//   const levelId = Number(levelTypeRaw);
//   if (!Number.isFinite(levelId) || levelId <= 0) {
//     return fail(res, 422, "User level not assigned", "LEVEL_NOT_SET");
//   }

//   const { start: weekStart, end: weekEnd } = weekRangeSunSat(date);
//   const today = todayYmd();
//   const weekList = weekDates(weekStart);

//   // Last 5 selected habits (any status — weekly view shows the current cycle).
//   const [habitsRows] = await pool.execute(
//     `SELECT csh.id          AS selected_habit_id,
//             csh.habit_id,
//             csh.level_id,
//             csh.start_date,
//             csh.end_date,
//             csh.status      AS selection_status,
//             csh.selected_at,
//             hm.category,
//             hm.habit_name,
//             hm.habit_description,
//             hm.frequency_type,
//             hm.target_count,
//             hm.target_unit,
//             hm.tracking_type,
//             hm.is_active,
//             hm.sort_order
//        FROM client_selected_habits csh
//        INNER JOIN habit_master hm ON csh.habit_id = hm.id
//       WHERE csh.profile_id = ?
//       ORDER BY csh.selected_at DESC, csh.id DESC
//       LIMIT 5`,
//     [profileId]
//   );

//   if (!habitsRows.length) {
//     return ok(res, 200, {
//       message: "No selected habits found for this user/level",
//       data: {
//         profile_id: profileId,
//         level_id: levelId,
//         week_start: weekStart,
//         week_end: weekEnd,
//         today,
//         total_habits: 0,
//         week_summary: { completed_total: 0, pending_total: 0, future_total: 0 },
//         habits: [],
//       },
//     });
//   }

//   const selectedHabitIds = habitsRows.map((h) => Number(h.selected_habit_id));
//   const placeholders = selectedHabitIds.map(() => "?").join(",");
//   const [trackingRows] = await pool.execute(
//     `SELECT selected_habit_id, habit_id, tracking_date, target_count,
//             completed_count, is_completed, notes
//        FROM client_habit_tracking
//       WHERE profile_id          = ?
//         AND selected_habit_id IN (${placeholders})
//         AND tracking_date     <= ?`,
//     [profileId, ...selectedHabitIds, today]
//   );

//   const weeklyMap = new Map(); // sid -> { date: row }
//   const allTimeMap = new Map();
//   for (const r of trackingRows) {
//     const sid = Number(r.selected_habit_id);
//     const t = normDate(r.tracking_date);
//     if (!t) continue;
//     if (t >= weekStart && t <= weekEnd) {
//       if (!weeklyMap.has(sid)) weeklyMap.set(sid, {});
//       weeklyMap.get(sid)[t] = r;
//     }
//     if (!allTimeMap.has(sid)) allTimeMap.set(sid, {});
//     allTimeMap.get(sid)[t] = r;
//   }

//   const outputHabits = [];
//   const weekSummary = { completed_total: 0, pending_total: 0, future_total: 0 };

//   for (const h of habitsRows) {
//     const sid = Number(h.selected_habit_id);
//     const sidWeekly = weeklyMap.get(sid) || {};
//     const sidAllTime = allTimeMap.get(sid) || {};
//     const habitStart = normDate(h.start_date);

//     const trackingArr = [];
//     let habitCompleted = 0;
//     let habitPending = 0;
//     let habitFuture = 0;

//     for (const d of weekList) {
//       let statusVal = 0;
//       let completedCount = 0;
//       let targetCount = Number(h.target_count);
//       let notes = null;

//       if (d > today) {
//         statusVal = 2;
//         habitFuture++;
//       } else if (habitStart && d < habitStart) {
//         // Past, but before the user started this habit — neutral, excluded.
//         statusVal = 2;
//         habitFuture++;
//       } else if (sidWeekly[d]) {
//         const rec = sidWeekly[d];
//         const isDone = Number(rec.is_completed) === 1;
//         statusVal = isDone ? 1 : 0;
//         completedCount = Number(rec.completed_count) || 0;
//         if (rec.target_count !== null && rec.target_count !== undefined) {
//           targetCount = Number(rec.target_count);
//         }
//         notes = rec.notes;
//         if (isDone) habitCompleted++;
//         else habitPending++;
//       } else {
//         habitPending++;
//       }

//       trackingArr.push({
//         date: d,
//         day: getDayName(d),
//         status: statusVal, // 1=done, 0=not done, 2=future/neutral
//         target_count: targetCount,
//         completed_count: completedCount,
//         notes,
//       });
//     }

//     weekSummary.completed_total += habitCompleted;
//     weekSummary.pending_total += habitPending;
//     weekSummary.future_total += habitFuture;

//     const habitPassedDays = habitCompleted + habitPending;
//     const habitCompletionRate =
//       habitPassedDays > 0
//         ? round2((habitCompleted / habitPassedDays) * 100)
//         : 0;
//     const habitWeeklyRate = round2((habitCompleted / 7) * 100);

//     // All-time tracking from start_date → today.
//     const allTimeArr = [];
//     let allTimeCompleted = 0;
//     let allTimeNotDone = 0;

//     if (habitStart && habitStart <= today) {
//       for (const d of buildDateRange(habitStart, today)) {
//         let st;
//         let cc;
//         if (sidAllTime[d] && Number(sidAllTime[d].is_completed) === 1) {
//           st = 1;
//           cc = Number(sidAllTime[d].completed_count) || 0;
//           allTimeCompleted++;
//         } else {
//           st = -1;
//           cc = sidAllTime[d] ? Number(sidAllTime[d].completed_count) || 0 : 0;
//           allTimeNotDone++;
//         }
//         allTimeArr.push({
//           date: d,
//           day: getDayName(d),
//           status: st, // 1=tracked-done, -1=not-tracked
//           target_count: Number(h.target_count),
//           completed_count: cc,
//         });
//       }
//     }

//     const allTimeTotal = allTimeArr.length;
//     const allTimeRate =
//       allTimeTotal > 0 ? round2((allTimeCompleted / allTimeTotal) * 100) : 0;

//     outputHabits.push({
//       selected_habit_id: sid,
//       habit_id: Number(h.habit_id),
//       level_id: Number(h.level_id),
//       category: h.category,
//       habit_name: h.habit_name,
//       habit_description: h.habit_description,
//       frequency_type: h.frequency_type,
//       target_count: Number(h.target_count),
//       target_unit: h.target_unit,
//       tracking_type: h.tracking_type,
//       is_active: Number(h.is_active),
//       start_date: h.start_date,
//       end_date: h.end_date,
//       selection_status: h.selection_status,
//       week_summary: {
//         completed: habitCompleted,
//         pending: habitPending,
//         future: habitFuture,
//         days_passed: habitPassedDays,
//         completion_rate: habitCompletionRate,
//         weekly_rate: habitWeeklyRate,
//       },
//       tracking: trackingArr,
//       all_time_summary: {
//         total_days: allTimeTotal,
//         tracked_days: allTimeCompleted,
//         untracked_days: allTimeNotDone,
//         completion_rate: allTimeRate,
//       },
//       all_time_tracking: allTimeArr,
//     });
//   }

//   const totalPassed = weekSummary.completed_total + weekSummary.pending_total;
//   weekSummary.days_passed_total = totalPassed;
//   weekSummary.completion_rate =
//     totalPassed > 0
//       ? round2((weekSummary.completed_total / totalPassed) * 100)
//       : 0;
//   weekSummary.weekly_rate =
//     outputHabits.length > 0
//       ? round2(
//           (weekSummary.completed_total / (outputHabits.length * 7)) * 100
//         )
//       : 0;

//   return ok(res, 200, {
//     message: "Weekly habit tracking fetched successfully",
//     data: {
//       profile_id: profileId,
//       level_id: levelId,
//       week_start: weekStart,
//       week_end: weekEnd,
//       today,
//       total_habits: outputHabits.length,
//       week_summary: weekSummary,
//       habits: outputHabits,
//     },
//   });
// }

// // ── check_habits ─ does the client have active selected habits? ─────────────
// //   Body: { profile_id }
// async function actionCheckHabits({ req, res, access }) {
//   const { profileId } = access;

//   const [clientRows] = await pool.execute(
//     `SELECT level_type FROM table_clients WHERE profile_id = ? LIMIT 1`,
//     [profileId]
//   );
//   if (!clientRows.length) {
//     return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");
//   }

//   const levelType = Number(clientRows[0].level_type ?? 1);

//   // Active selected habits (not constrained to a single level — matches the
//   // dashboard controller; Archive hard-coded level 1).
//   const [habitRows] = await pool.execute(
//     `SELECT id, profile_id, habit_id, level_id,
//             start_date, end_date, status, selected_at, updated_at
//        FROM client_selected_habits
//       WHERE profile_id = ?
//         AND status     = 'active'`,
//     [profileId]
//   );

//   const habits = habitRows.map((row) => ({
//     id: Number(row.id),
//     profile_id: row.profile_id,
//     habit_id: Number(row.habit_id),
//     level_id: Number(row.level_id),
//     start_date: row.start_date,
//     end_date: row.end_date ?? null,
//     status: row.status,
//     selected_at: row.selected_at,
//     updated_at: row.updated_at,
//   }));

//   return ok(res, 200, {
//     message: habits.length > 0 ? "Client habits found" : "Client habits not added",
//     data: {
//       profile_id: profileId,
//       level_type: levelType,
//       is_habit_added: habits.length > 0,
//       total_habits: habits.length,
//       data: habits,
//     },
//   });
// }

// // ── fetch_preferences ─ latest user_habits (goal/activity/food_type/glp_1) ──
// //   Body: { profile_id }
// async function actionFetchPreferences({ req, res, access }) {
//   const { profileId } = access;

//   const [rows] = await pool.execute(
//     `SELECT id, profile_id, goal, activity, food_type, glp_1, dttm, tsstamp
//        FROM user_habits
//       WHERE profile_id = ?
//       ORDER BY id DESC
//       LIMIT 1`,
//     [profileId]
//   );

//   const row = rows[0];
//   if (!row) {
//     return fail(res, 404, "No habits found for this profile", "HABITS_NOT_FOUND");
//   }

//   return ok(res, 200, {
//     message: "User habits fetched successfully",
//     data: {
//       id: Number(row.id),
//       profile_id: row.profile_id,
//       goal: row.goal,
//       activity: row.activity,
//       food_type: buildFoodType(row.food_type),
//       glp_1: Number(row.glp_1 ?? 0),
//       dttm: row.dttm,
//       tsstamp: row.tsstamp,
//     },
//   });
// }

// // ── save_preferences ─ upsert user_habits for a profile ─────────────────────
// //   Body: { profile_id, goal, activity, food_type?, glp_1? }
// //   UPDATE the latest row; if none exists, INSERT. (No unique-key dependency.)
// async function actionSavePreferences({ req, res, access }) {
//   const { profileId } = access;

//   const goal = typeof req.body?.goal === "string" ? req.body.goal.trim() : "";
//   const activity =
//     typeof req.body?.activity === "string" ? req.body.activity.trim() : "";
//   if (!goal) return fail(res, 422, "goal is required", "VALIDATION_ERROR");
//   if (!activity) return fail(res, 422, "activity is required", "VALIDATION_ERROR");

//   let glp1 = 0;
//   if (req.body?.glp_1 !== undefined) {
//     const g = toGlp1(req.body.glp_1);
//     if (g === null) {
//       return fail(res, 422, "glp_1 must be boolean or 0/1", "VALIDATION_ERROR");
//     }
//     glp1 = g;
//   }

//   const foodTypeJson = normalizeFoodType(req.body?.food_type);
//   const epoch = Math.floor(Date.now() / 1000);

//   // Try UPDATE latest row first.
//   const [existing] = await pool.execute(
//     `SELECT id FROM user_habits WHERE profile_id = ? ORDER BY id DESC LIMIT 1`,
//     [profileId]
//   );

//   let id;
//   let updated;
//   if (existing.length) {
//     id = Number(existing[0].id);
//     await pool.execute(
//       `UPDATE user_habits
//           SET goal = ?, activity = ?, food_type = ?, glp_1 = ?,
//               dttm = CURDATE(), tsstamp = ?
//         WHERE id = ?`,
//       [goal, activity, foodTypeJson, glp1, epoch, id]
//     );
//     updated = true;
//   } else {
//     const [result] = await pool.execute(
//       `INSERT INTO user_habits
//          (profile_id, goal, activity, food_type, glp_1, dttm, tsstamp)
//        VALUES (?, ?, ?, ?, ?, CURDATE(), ?)`,
//       [profileId, goal, activity, foodTypeJson, glp1, epoch]
//     );
//     id = Number(result.insertId);
//     updated = false;
//   }

//   return ok(res, updated ? 200 : 201, {
//     message: updated
//       ? "Habits updated successfully"
//       : "Habits saved successfully",
//     data: {
//       id,
//       profile_id: profileId,
//       goal,
//       activity,
//       food_type: buildFoodType(foodTypeJson),
//       glp_1: glp1,
//       epoch_timestamp: epoch,
//     },
//   });
// }

// // ── update_glp1 ─ single-field update of the GLP-1 flag ─────────────────────
// //   Body: { profile_id, glp_1 }
// async function actionUpdateGlp1({ req, res, access }) {
//   const { profileId } = access;

//   const glp1 = toGlp1(req.body?.glp_1);
//   if (glp1 === null) {
//     return fail(res, 422, "glp_1 must be boolean or 0/1", "VALIDATION_ERROR");
//   }

//   const [result] = await pool.execute(
//     `UPDATE user_habits
//         SET glp_1 = ?, tsstamp = ?
//       WHERE profile_id = ?
//       ORDER BY id DESC
//       LIMIT 1`,
//     [glp1, Math.floor(Date.now() / 1000), profileId]
//   );

//   if (result.affectedRows === 0) {
//     return fail(
//       res,
//       404,
//       "No habits row found to update. Save preferences first.",
//       "HABITS_NOT_FOUND"
//     );
//   }

//   return ok(res, 200, {
//     message: "GLP-1 flag updated",
//     data: { profile_id: profileId, glp_1: glp1 },
//   });
// }

// // ── dashboard ─ per-client habit dashboard (drives the HabitsAnalysis UI) ───
// //   Body: { profile_id }
// //   Returns the client header, each active habit's all-time completion % plus a
// //   day-by-day breakdown, an overall adherence figure, an all-time summary, and
// //   a week/month/all completion-rate trend. Response `data` shape is identical
// //   to habits-dashboard so the dashboard's Overview / HabitsMonitoring /
// //   RightHandSidebar components consume it unchanged.
// async function actionDashboard({ req, res, access }) {
//   const { dieticianId, profileId } = access;

//   const client = await fetchClient(dieticianId, profileId);
//   if (!client) return fail(res, 404, "Client not found", "CLIENT_NOT_FOUND");

//   const levelType = parseInt(client.level_type, 10) || 0;
//   const today = todayYmd();

//   // Active selected habits (≤5) + master metadata.
//   const [selectedHabits] = await pool.execute(
//     `
//       SELECT
//         csh.id AS selected_habit_id,
//         csh.habit_id,
//         csh.level_id,
//         csh.start_date,
//         hm.habit_name,
//         hm.category,
//         hm.frequency_type,
//         hm.target_count,
//         hm.target_unit,
//         hm.tracking_type
//       FROM client_selected_habits csh
//       INNER JOIN habit_master hm
//         ON  hm.id = csh.habit_id
//         AND hm.level_id = csh.level_id
//         AND hm.is_active = 1
//       WHERE csh.profile_id = ?
//         AND csh.status = 'active'
//       ORDER BY csh.id ASC
//       LIMIT 5
//     `,
//     [profileId]
//   );

//   if (!selectedHabits.length) {
//     return ok(res, 200, {
//       message: "No active habits for this client",
//       data: {
//         profile_id: profileId,
//         profile_name: client.profile_name,
//         level_type: levelType,
//         today,
//         total_habits: 0,
//         overall: { expected_days: 0, completed_days: 0, completion_percent: 0 },
//         summary: {
//           total_days: 0,
//           total_days_tracked: 0,
//           total_perfect_days: 0,
//           tracking_rate: 0,
//           completion_rate: 0,
//         },
//         completion_trend: {
//           week: { range: "week", granularity: "day", points: [] },
//           month: { range: "month", granularity: "day", points: [] },
//           all: { range: "all", granularity: "week", points: [] },
//         },
//         habits: [],
//       },
//     });
//   }

//   // Pull tracking once for all habits, up to today.
//   const ids = selectedHabits.map((h) => Number(h.selected_habit_id));
//   const placeholders = ids.map(() => "?").join(",");
//   const [trackRows] = await pool.execute(
//     `
//       SELECT selected_habit_id, tracking_date, completed_count, is_completed
//       FROM client_habit_tracking
//       WHERE profile_id = ?
//         AND selected_habit_id IN (${placeholders})
//         AND tracking_date <= ?
//     `,
//     [profileId, ...ids, today]
//   );

//   // Each habit's own start_date (rows before it don't count).
//   const startBySid = {};
//   for (const h of selectedHabits) {
//     startBySid[Number(h.selected_habit_id)] = h.start_date
//       ? normDate(h.start_date)
//       : today;
//   }

//   // Index tracking by selected_habit_id → date.
//   const trackBySid = {};
//   for (const r of trackRows) {
//     const sid = Number(r.selected_habit_id);
//     const rowDate = normDate(r.tracking_date);
//     if (rowDate < startBySid[sid]) continue;
//     if (!trackBySid[sid]) trackBySid[sid] = {};
//     trackBySid[sid][rowDate] = {
//       completed_count: parseInt(r.completed_count, 10) || 0,
//       is_completed: parseInt(r.is_completed, 10) === 1,
//     };
//   }

//   let overallExpected = 0;
//   let overallCompleted = 0;

//   const habits = selectedHabits.map((h) => {
//     const sid = Number(h.selected_habit_id);
//     const startDate = startBySid[sid];
//     const expectedDays = inclusiveDays(startDate, today);
//     const dayMap = trackBySid[sid] || {};

//     const days = [];
//     let completedDays = 0;
//     for (const dateKey of buildDateRange(startDate, today)) {
//       const entry = dayMap[dateKey];
//       const isCompleted = entry ? entry.is_completed : false;
//       if (isCompleted) completedDays++;
//       days.push({
//         date: dateKey,
//         day: getDayName(dateKey),
//         completed_count: entry ? entry.completed_count : 0,
//         is_completed: isCompleted,
//       });
//     }

//     overallExpected += expectedDays;
//     overallCompleted += completedDays;

//     return {
//       selected_habit_id: sid,
//       habit_id: Number(h.habit_id),
//       level_id: Number(h.level_id),
//       habit_name: h.habit_name,
//       category: h.category,
//       frequency_type: h.frequency_type,
//       target_count: parseInt(h.target_count, 10) || 1,
//       target_unit: h.target_unit,
//       tracking_type: h.tracking_type,
//       start_date: startDate,
//       expected_days: expectedDays,
//       completed_days: completedDays,
//       completion_percent: pct(completedDays, expectedDays),
//       days,
//     };
//   });

//   // Cross-habit daily aggregate (earliest start → today).
//   const earliestStart = Object.values(startBySid).reduce(
//     (min, d) => (d < min ? d : min),
//     today
//   );

//   const dailyAgg = [];
//   for (const dateKey of buildDateRange(earliestStart, today)) {
//     let expected = 0;
//     let tracked = 0;
//     let completed = 0;
//     for (const h of selectedHabits) {
//       const sid = Number(h.selected_habit_id);
//       if (startBySid[sid] <= dateKey) {
//         expected++;
//         const entry = trackBySid[sid] && trackBySid[sid][dateKey];
//         if (entry) {
//           tracked++;
//           if (entry.is_completed) completed++;
//         }
//       }
//     }
//     dailyAgg.push({
//       date: dateKey,
//       day: getDayName(dateKey),
//       expected,
//       tracked,
//       completed,
//       completion_rate: pct(completed, expected),
//     });
//   }

//   // Summary stats (all-time).
//   let sumExpected = 0;
//   let sumTracked = 0;
//   let sumCompleted = 0;
//   let daysTracked = 0;
//   let perfectDays = 0;
//   for (const d of dailyAgg) {
//     sumExpected += d.expected;
//     sumTracked += d.tracked;
//     sumCompleted += d.completed;
//     if (d.tracked > 0) daysTracked++;
//     if (d.expected > 0 && d.completed === d.expected) perfectDays++;
//   }

//   const summary = {
//     total_days: dailyAgg.length,
//     total_days_tracked: daysTracked,
//     total_perfect_days: perfectDays,
//     tracking_rate: pct(sumTracked, sumExpected),
//     completion_rate: pct(sumCompleted, sumExpected),
//   };

//   // Completion-rate trend (week / month / all).
//   const dailyPointsFrom = (fromKey) =>
//     dailyAgg
//       .filter((d) => d.date >= fromKey)
//       .map((d) => ({
//         date: d.date,
//         day: d.day,
//         completed: d.completed,
//         expected: d.expected,
//         completion_rate: d.completion_rate,
//       }));

//   const weeklyBuckets = () => {
//     const points = [];
//     for (let i = 0; i < dailyAgg.length; i += 7) {
//       const chunk = dailyAgg.slice(i, i + 7);
//       const exp = chunk.reduce((s, d) => s + d.expected, 0);
//       const comp = chunk.reduce((s, d) => s + d.completed, 0);
//       points.push({
//         week_start: chunk[0].date,
//         week_end: chunk[chunk.length - 1].date,
//         completed: comp,
//         expected: exp,
//         completion_rate: pct(comp, exp),
//       });
//     }
//     return points;
//   };

//   const completion_trend = {
//     week: {
//       range: "week",
//       granularity: "day",
//       points: dailyPointsFrom(addDays(today, -6)),
//     },
//     month: {
//       range: "month",
//       granularity: "day",
//       points: dailyPointsFrom(addDays(today, -29)),
//     },
//     all: { range: "all", granularity: "week", points: weeklyBuckets() },
//   };

//   console.info("habits.dashboard: ok", {
//     dietitian_id: dieticianId,
//     profile_id: profileId,
//     total_habits: habits.length,
//     ts: new Date().toISOString(),
//   });

//   return ok(res, 200, {
//     message: "Habit dashboard fetched successfully",
//     data: {
//       profile_id: profileId,
//       profile_name: client.profile_name,
//       level_type: levelType,
//       today,
//       total_habits: habits.length,
//       overall: {
//         expected_days: overallExpected,
//         completed_days: overallCompleted,
//         completion_percent: pct(overallCompleted, overallExpected),
//       },
//       summary,
//       completion_trend,
//       habits,
//     },
//   });
// }

// // ── tracking_data ─ habit-tracking dataset fanned out day-by-day ────────────
// //   Body: { profile_id }
// //   Most-recently-selected 5 active habits across earliest start_date → today.
// async function actionTrackingData({ req, res, access }) {
//   const { profileId } = access;

//   // 5 most recently selected active habits.
//   const [habits] = await pool.execute(
//     `SELECT csh.id AS selected_habit_id,
//             csh.habit_id,
//             csh.start_date,
//             hm.habit_name,
//             hm.category,
//             hm.frequency_type,
//             hm.target_count,
//             hm.target_unit,
//             hm.tracking_type
//        FROM client_selected_habits csh
//        INNER JOIN habit_master hm ON hm.id = csh.habit_id
//       WHERE csh.profile_id = ?
//         AND csh.status = 'active'
//       ORDER BY csh.selected_at DESC
//       LIMIT 5`,
//     [profileId]
//   );

//   if (!habits.length) {
//     // Legacy parity: 200 with status false = "empty state", not an error.
//     return res.status(200).json({
//       status: false,
//       message: "No habits found for this client",
//       data: null,
//       error: null,
//     });
//   }

//   // Earliest start_date drives the rendered range.
//   let earliest = null;
//   for (const h of habits) {
//     const sStr = normDate(h.start_date);
//     if (earliest === null || sStr < earliest) earliest = sStr;
//   }
//   const today = todayYmd();
//   const allDates = buildDateRange(earliest, today);

//   const ids = habits.map((h) => Number(h.selected_habit_id));
//   const placeholders = ids.map(() => "?").join(",");
//   const [trackingRows] = await pool.execute(
//     `SELECT selected_habit_id, habit_id, tracking_date,
//             is_completed, completed_count, notes
//        FROM client_habit_tracking
//       WHERE profile_id = ?
//         AND selected_habit_id IN (${placeholders})
//         AND tracking_date BETWEEN ? AND ?`,
//     [profileId, ...ids, earliest, today]
//   );

//   const trackingMap = new Map();
//   for (const r of trackingRows) {
//     const dateStr = normDate(r.tracking_date);
//     if (!trackingMap.has(dateStr)) trackingMap.set(dateStr, new Map());
//     trackingMap.get(dateStr).set(Number(r.selected_habit_id), {
//       is_completed: !!r.is_completed,
//       completed_count: Number(r.completed_count ?? 0),
//       notes: r.notes,
//     });
//   }

//   const days = allDates.map((date) => ({
//     date,
//     habits: habits.map((h) => {
//       const sId = Number(h.selected_habit_id);
//       const t = trackingMap.get(date)?.get(sId) || null;
//       return {
//         habit_id: Number(h.habit_id),
//         selected_habit_id: sId,
//         habit_name: h.habit_name,
//         category: h.category,
//         frequency_type: h.frequency_type,
//         target_count: Number(h.target_count),
//         target_unit: h.target_unit,
//         tracking_type: h.tracking_type,
//         is_completed: t ? t.is_completed : false,
//         completed_count: t ? t.completed_count : 0,
//         notes: t ? t.notes : null,
//       };
//     }),
//   }));

//   return ok(res, 200, {
//     message: "Habit tracking data fetched successfully",
//     data: {
//       profile_id: profileId,
//       start_date: earliest,
//       end_date: today,
//       data: days,
//     },
//   });
// }

// // ═══════════════════════════════════════════════════════════════════════════
// //  Dispatcher
// // ═══════════════════════════════════════════════════════════════════════════

// const HANDLERS = {
//   // per-client dashboard (drives the HabitsAnalysis UI)
//   dashboard: actionDashboard,
//   // selected-habits (5-habit system)
//   habit_master: actionHabitMaster,
//   save_selected_habits: actionSaveSelectedHabits,
//   selected_status: actionSelectedStatus,
//   track_habit: actionTrackHabit,
//   weekly_tracking: actionWeeklyTracking,
//   // habits check
//   check_habits: actionCheckHabits,
//   // user_habits preferences + tracking
//   fetch_preferences: actionFetchPreferences,
//   save_preferences: actionSavePreferences,
//   update_glp1: actionUpdateGlp1,
//   tracking_data: actionTrackingData,
//   track_batch: actionTrackBatch,
// };

// const VALID_ACTIONS = Object.keys(HANDLERS);

// /**
//  * POST /dietitian/api/web/habits-manager
//  *
//  * Body: { action, dietitian_id?, profile_id, ...actionFields }
//  * Auth: Bearer JWT (authMiddleware must run before this handler).
//  */
// const habitsManager = async (req, res) => {
//   res.setHeader("Cache-Control", "no-store");
//   res.setHeader("Pragma", "no-cache");

//   // Body shape.
//   if (!isPlainObject(req.body)) {
//     return fail(res, 400, "Invalid request body", "INVALID_BODY");
//   }

//   // Action selection.
//   const action =
//     typeof req.body.action === "string" ? req.body.action.trim() : "";
//   const handler = HANDLERS[action];
//   if (!handler) {
//     return fail(
//       res,
//       422,
//       `Invalid or missing action. Valid actions: ${VALID_ACTIONS.join(", ")}`,
//       "INVALID_ACTION",
//       { valid_actions: VALID_ACTIONS }
//     );
//   }

//   // Token-bound ownership check (BOLA/IDOR) — runs for EVERY action.
//   const access = await resolveProfileAccess(req, res, `habits.${action}`);
//   if (!access) return; // response already sent

//   if (!access.dieticianId || !access.profileId) {
//     return fail(
//       res,
//       422,
//       "dietitian_id and profile_id are required",
//       "VALIDATION_ERROR"
//     );
//   }

//   try {
//     return await handler({ req, res, access });
//   } catch (err) {
//     console.error("habits-manager: unhandled error", {
//       action,
//       code: err?.code,
//       errno: err?.errno,
//       sqlState: err?.sqlState,
//     });
//     return serverError(res);
//   }
// };

// module.exports = { habitsManager };