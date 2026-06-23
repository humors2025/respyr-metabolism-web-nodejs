"use strict";

/**
 * habits_dashboard.controller.js
 *
 * Adapted for: Respyr Dietitian API (api.respyr.ai)
 * Self-contained controller (direct pool.execute, no services layer) — matches
 * selected_habits.controller.js / habits.controller.js.
 *
 * Endpoint (POST, behind authMiddleware):
 *   /dietitian/api/web/habits-dashboard   getHabitsDashboard
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

/** Short weekday name (e.g. "Mon") for a YYYY-MM-DD string. */
function getDayName(dateStr) {
  return new Date(`${dateStr}T00:00:00`).toLocaleDateString("en-US", {
    weekday: "short",
  });
}

/** YYYY-MM-DD `n` days after (negative = before) the given YYYY-MM-DD (UTC). */
function addDays(ymd, n) {
  const d = new Date(`${ymd}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(
    d.getUTCDate()
  )}`;
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
          completed_count,
          is_completed
        FROM client_habit_tracking
        WHERE profile_id = ?
          AND selected_habit_id IN (${placeholders})
          AND tracking_date <= ?
      `,
      [profileId, ...ids, today]
    );

    // Each habit's own start_date (a row before start_date doesn't count).
    const startBySid = {};
    for (const h of selectedHabits) {
      startBySid[Number(h.selected_habit_id)] = h.start_date
        ? normDate(h.start_date)
        : today;
    }

    // Index every tracking row by selected_habit_id → date so we can both count
    // completed days and emit a per-day breakdown.
    const trackBySid = {};
    for (const r of trackRows) {
      const sid = Number(r.selected_habit_id);
      const rowDate = normDate(r.tracking_date);
      if (rowDate < startBySid[sid]) continue; // before this habit started
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

      // Day-by-day fan-out from start_date → today (inclusive).
      const days = [];
      let completedDays = 0;
      const cursor = new Date(`${startDate}T00:00:00Z`);
      const last = new Date(`${today}T00:00:00Z`);
      while (cursor <= last) {
        const dateKey = `${cursor.getUTCFullYear()}-${pad(
          cursor.getUTCMonth() + 1
        )}-${pad(cursor.getUTCDate())}`;
        const entry = dayMap[dateKey];
        const isCompleted = entry ? entry.is_completed : false;
        if (isCompleted) completedDays++;
        days.push({
          date: dateKey,
          day: getDayName(dateKey),
          completed_count: entry ? entry.completed_count : 0,
          is_completed: isCompleted,
        });
        cursor.setUTCDate(cursor.getUTCDate() + 1);
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

    // ── Cross-habit daily aggregate (earliest start_date → today) ────────────
    // For each calendar day: how many habits were expected (already started),
    // how many were tracked (any entry), and how many were completed. Every
    // summary stat and the trend graph derive from this single pass.
    const earliestStart = Object.values(startBySid).reduce(
      (min, d) => (d < min ? d : min),
      today
    );

    const dailyAgg = [];
    {
      const cursor = new Date(`${earliestStart}T00:00:00Z`);
      const last = new Date(`${today}T00:00:00Z`);
      while (cursor <= last) {
        const dateKey = `${cursor.getUTCFullYear()}-${pad(
          cursor.getUTCMonth() + 1
        )}-${pad(cursor.getUTCDate())}`;

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
        cursor.setUTCDate(cursor.getUTCDate() + 1);
      }
    }

    // ── Summary stats (all-time) ─────────────────────────────────────────────
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
      total_days: dailyAgg.length, // calendar days since the first habit started
      total_days_tracked: daysTracked, // days with at least one habit logged
      total_perfect_days: perfectDays, // days where every active habit was done
      tracking_rate: pct(sumTracked, sumExpected), // logged vs expected habit-days
      completion_rate: pct(sumCompleted, sumExpected), // completed vs expected
    };

    // ── Completion-rate trend (week / month / all) ───────────────────────────
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
      all: {
        range: "all",
        granularity: "week",
        points: weeklyBuckets(),
      },
    };

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
        summary,
        completion_trend,
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
