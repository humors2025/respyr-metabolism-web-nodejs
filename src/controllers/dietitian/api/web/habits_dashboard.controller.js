"use strict";

/**
 * habits_dashboard.controller.js
 *
 * Adapted for: Respyr Dietitian API (api.respyr.ai)
 * Self-contained controller (direct pool.execute, no services layer) — matches
 * selected_habits.controller.js / habits.controller.js.
 *
 * Endpoint (POST, behind authMiddleware):
 *   /habits/dashboard   getHabitsDashboard
 *
 * Per-CLIENT habit dashboard. Returns the client header (name + level), each
 * active selected habit with its ALL-TIME completion % (since the habit's
 * start_date through today), and an overall all-time adherence figure.
 *
 * Security model (identical to the other habit endpoints in this repo):
 *  - JWT belongs to a DIETITIAN. profile_id comes from the body and is verified
 *    via requireProfileAccess (table_clients dietician_id ↔ profile_id),
 *    preventing BOLA/IDOR. A super-admin may pass an explicit dietitian_id.
 *  - Fully parameterized queries. Internal errors suppressed from responses.
 *
 * Schema reference:
 *   table_clients:          dietician_id, profile_id, profile_name, level_type
 *   client_selected_habits: id, profile_id, habit_id, level_id, start_date,
 *                           status('active'|'completed'|'removed')
 *   habit_master:           id, level_id, habit_name, category, frequency_type,
 *                           target_count, target_unit, tracking_type, is_active
 *   client_habit_tracking:  selected_habit_id, tracking_date, completed_count,
 *                           is_completed
 *
 * All-time completion % definition:
 *   expected_days  = inclusive day-count from start_date → today (day-based, to
 *                    match the daily fan-out used elsewhere in this repo)
 *   completed_days = tracking rows with is_completed = 1 in [start_date, today]
 *   completion_percent = round(completed_days / expected_days * 100)
 */

const pool = require("../../../../config/db");
const {
  requireProfileAccess,
  getTokenDieticianId,
} = require("../../../../utils/accessControl");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function pad(n) {
  return String(n).padStart(2, "0");
}

/** Today as YYYY-MM-DD in UTC (server clock). */
function todayYmd() {
  const d = new Date();
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function normDate(val) {
  if (val instanceof Date) return val.toISOString().slice(0, 10);
  return String(val).slice(0, 10);
}

/**
 * Inclusive whole-day count between two YYYY-MM-DD strings (UTC). Returns 0 when
 * `from` is after `to` (e.g. a habit whose start_date is in the future).
 */
function inclusiveDays(fromYmd, toYmd) {
  const from = new Date(`${fromYmd}T00:00:00Z`).getTime();
  const to = new Date(`${toYmd}T00:00:00Z`).getTime();
  if (isNaN(from) || isNaN(to) || from > to) return 0;
  return Math.floor((to - from) / 86400000) + 1;
}

function pct(numerator, denominator) {
  if (!denominator) return 0;
  return Math.round((numerator / denominator) * 100);
}

function serverError(res) {
  return res.status(500).json({
    status: false,
    message: "Server error",
    data: null,
    error: { code: "SERVER_ERROR" },
  });
}

/**
 * Token-bound profile access. On success returns { dieticianId, profileId }.
 * On failure it has already written the HTTP response and returns null.
 */
async function resolveProfileAccess(req, res, contextLabel) {
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
    console.error(`${contextLabel}: requireProfileAccess threw`, authErr?.code);
    serverError(res);
    return null;
  }

  if (!access.allowed) {
    console.warn(`${contextLabel}: access denied`, {
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

// ─── POST /habits/dashboard ─────────────────────────────────────────────────────
//
// Per-client habit dashboard: client header + each active habit's all-time
// completion % + an overall all-time adherence figure.
async function getHabitsDashboard(req, res) {
  res.setHeader("Cache-Control", "no-store");

  const access = await resolveProfileAccess(req, res, "habits.dashboard");
  if (!access) return;
  const { dieticianId, profileId } = access;

  try {
    // Client header (and a DB-level re-confirm of ownership).
    const [clientRows] = await pool.execute(
      `
        SELECT profile_name, level_type
        FROM table_clients
        WHERE UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
      `,
      [dieticianId, profileId]
    );

    if (!clientRows.length) {
      return res.status(404).json({
        status: false,
        message: "Client not found",
        data: null,
        error: { code: "CLIENT_NOT_FOUND" },
      });
    }

    const levelType = parseInt(clientRows[0].level_type, 10) || 0;
    const today = todayYmd();

    // Active selected habits (≤5), with the master metadata.
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
      return res.status(200).json({
        status: true,
        message: "No active habits for this client",
        data: {
          profile_id: profileId,
          profile_name: clientRows[0].profile_name,
          level_type: levelType,
          today,
          total_habits: 0,
          overall: {
            expected_days: 0,
            completed_days: 0,
            completion_percent: 0,
          },
          habits: [],
        },
        error: null,
      });
    }

    // One pass over tracking: completed-day counts since each habit's start.
    // Filtering by tracking_date >= start_date per habit is handled in JS after
    // we pull the per-habit totals; the SQL caps to today to ignore any future
    // rows and groups by selected_habit_id.
    const ids = selectedHabits.map((h) => Number(h.selected_habit_id));
    const placeholders = ids.map(() => "?").join(",");
    const [trackRows] = await pool.execute(
      `
        SELECT
          selected_habit_id,
          tracking_date,
          is_completed
        FROM client_habit_tracking
        WHERE profile_id = ?
          AND selected_habit_id IN (${placeholders})
          AND tracking_date <= ?
      `,
      [profileId, ...ids, today]
    );

    // Index completed-day counts by selected_habit_id, honouring each habit's
    // own start_date (a row before start_date doesn't count toward that habit).
    const startBySid = {};
    for (const h of selectedHabits) {
      startBySid[Number(h.selected_habit_id)] = h.start_date
        ? normDate(h.start_date)
        : today;
    }

    const completedBySid = {};
    for (const r of trackRows) {
      const sid = Number(r.selected_habit_id);
      const rowDate = normDate(r.tracking_date);
      if (rowDate < startBySid[sid]) continue; // before this habit started
      if (parseInt(r.is_completed, 10) === 1) {
        completedBySid[sid] = (completedBySid[sid] || 0) + 1;
      }
    }

    let overallExpected = 0;
    let overallCompleted = 0;

    const habits = selectedHabits.map((h) => {
      const sid = Number(h.selected_habit_id);
      const startDate = startBySid[sid];
      const expectedDays = inclusiveDays(startDate, today);
      const completedDays = completedBySid[sid] || 0;

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
      };
    });

    console.info("habits.dashboard: access granted", {
      dietitian_id: dieticianId,
      profile_id: profileId,
      total_habits: habits.length,
      ts: new Date().toISOString(),
    });

    return res.status(200).json({
      status: true,
      message: "Habit dashboard fetched successfully",
      data: {
        profile_id: profileId,
        profile_name: clientRows[0].profile_name,
        level_type: levelType,
        today,
        total_habits: habits.length,
        overall: {
          expected_days: overallExpected,
          completed_days: overallCompleted,
          completion_percent: pct(overallCompleted, overallExpected),
        },
        habits,
      },
      error: null,
    });
  } catch (err) {
    console.error("habits.dashboard: unhandled error", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
    });
    return serverError(res);
  }
}

module.exports = { getHabitsDashboard };
