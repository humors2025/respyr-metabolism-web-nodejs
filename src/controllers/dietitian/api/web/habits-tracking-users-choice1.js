"use strict";

/**
 * habits-tracking-users-choice1.js
 *
 * Converted from: habits-tracking-users-choice1.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * VAPT Controls applied:
 *  - Token-bound authorization (prevents BOLA/IDOR): dietitian_id from JWT
 *    is validated against the dietitian who owns the requested profile via
 *    requireProfileAccess (table_clients ownership check).
 *  - Input validation and strict ID normalization before any DB call.
 *  - Fully parameterized queries — zero string interpolation.
 *  - Internal error details suppressed in all client-facing responses.
 *  - Result cap (LIMIT 5 on habits, LIMIT 1 on client lookup).
 *  - Belt-and-suspenders cache headers (no-store) inherited from index.js
 *    middleware; also enforced explicitly here for PHI-adjacent endpoints.
 *
 * HIPAA Controls applied:
 *  - No PHI (patient name, DOB, contact info) is logged anywhere in this file.
 *  - Minimum-necessary data principle: only columns needed for habit
 *    monitoring are selected — no blanket SELECT *.
 *  - Access control: every request is bound to an authenticated dietitian's
 *    JWT sub claim, and that identity is verified against the DB before
 *    any habit data is returned.
 *  - Audit trail: structured console.warn on access-denied paths (without
 *    PHI), allowing downstream log aggregation (CloudWatch / SIEM).
 *
 * NOTE on dietitian/dietician spelling:
 *  - accessControl.js accepts both spellings from request bodies and JWT.
 *  - This controller reads dietitian_id from req.body (either spelling
 *    accepted by normalizeDieticianId via the compatibility layer).
 *  - DB column reference in requireProfileAccess uses dietician_id
 *    (legacy column name). Verify your actual column name with:
 *    SHOW COLUMNS FROM table_clients LIKE '%diet%';
 */

const pool = require("../../../../config/db");
const { requireProfileAccess } = require("../../../../utils/accessControl");

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Derive ISO week bounds (Monday–Sunday) for a given date.
 *
 * @param {Date} now
 * @returns {{ weekStart: string, weekEnd: string, today: string }}
 */
function getWeekBounds(now) {
  const pad = (n) => String(n).padStart(2, "0");
  const fmt = (d) =>
    `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;

  const dayOfWeek = now.getDay(); // 0=Sun
  const diffToMonday = dayOfWeek === 0 ? -6 : 1 - dayOfWeek;

  const monday = new Date(now);
  monday.setDate(now.getDate() + diffToMonday);

  const sunday = new Date(monday);
  sunday.setDate(monday.getDate() + 6);

  return {
    today:     fmt(now),
    weekStart: fmt(monday),
    weekEnd:   fmt(sunday),
  };
}

/**
 * Build a zero-initialised daily map for a given week start (7 days).
 *
 * @param {string} weekStart  YYYY-MM-DD
 * @returns {{ [date: string]: number }}
 */
function buildDailyMap(weekStart) {
  const map = {};
  for (let i = 0; i < 7; i++) {
    const d = new Date(weekStart);
    d.setDate(d.getDate() + i);
    const key = d.toISOString().slice(0, 10);
    map[key] = 0;
  }
  return map;
}

/**
 * Day-of-week abbreviation (Mon, Tue … Sun).
 *
 * @param {string} dateStr  YYYY-MM-DD
 * @returns {string}
 */
function getDayName(dateStr) {
  return new Date(dateStr).toLocaleDateString("en-US", { weekday: "short" });
}

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/habits-tracking-users-choice1
 *
 * Body: { dietitian_id, profile_id }
 * Auth: Bearer JWT (authMiddleware must run before this handler)
 */
const habitsTrackingUsersChoice = async (req, res) => {
  // Enforce no-store explicitly for this PHI-adjacent endpoint
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // ── 1. Authorization: token-bound ownership check (BOLA/IDOR prevention) ──
  //    Accepts both "dietitian_id" and "dietician_id" spellings from body.
  const rawDietitianId =
    req.body?.dietitian_id ?? req.body?.dietician_id ?? "";
  const rawProfileId = req.body?.profile_id ?? "";

  let access;
  try {
    access = await requireProfileAccess(req, rawDietitianId, rawProfileId);
  } catch (authErr) {
    console.error("requireProfileAccess threw unexpectedly:", authErr?.code);
    return res.status(500).json({
      status:  false,
      message: "Server error",
      data:    null,
      error:   { code: "SERVER_ERROR" },
    });
  }

  if (!access.allowed) {
    console.warn("habits_tracking: access denied", {
      statusCode: access.statusCode,
      path:       req.originalUrl,
      method:     req.method,
    });

    return res.status(access.statusCode).json({
      status:  false,
      message: access.message,
      data:    null,
      error:   { code: "ACCESS_DENIED" },
    });
  }

  const { dieticianId, profileId } = access;

  // ── 2. Input validation (belt-and-suspenders after accessControl) ──────────
  if (!dieticianId || !profileId) {
    return res.status(422).json({
      status:  false,
      message: "dietitian_id and profile_id are required",
      data:    null,
      error:   { code: "VALIDATION_ERROR" },
    });
  }

  // ── 3. Business logic ──────────────────────────────────────────────────────
  try {
    const now = new Date();
    const { today, weekStart, weekEnd } = getWeekBounds(now);

    // ── 3a. Fetch client metadata (level_type, registration date) ────────────
    //    Column name: dietician_id (legacy DB spelling — verify with SHOW COLUMNS)
    const [clientRows] = await pool.execute(
      `
        SELECT level_type, dttm
        FROM table_clients
        WHERE UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
      `,
      [dieticianId, profileId]
    );

    if (!clientRows.length) {
      return res.status(404).json({
        status:  false,
        message: "Client not found",
        data:    null,
        error:   { code: "CLIENT_NOT_FOUND" },
      });
    }

    const levelType        = parseInt(clientRows[0].level_type, 10) || 0;
    const profileCreatedAt = clientRows[0].dttm;

    const profileCreatedDate = new Date(profileCreatedAt)
      .toISOString()
      .slice(0, 10);

    const msPerDay = 86400 * 1000;
    let daysTracked =
      Math.floor(
        (new Date(today).getTime() - new Date(profileCreatedDate).getTime()) /
          msPerDay
      ) + 1;
    if (daysTracked < 1) daysTracked = 1;

    // ── 3b. Fetch selected habits (capped at 5) ──────────────────────────────
    const [selectedHabits] = await pool.execute(
      `
        SELECT
          csh.id            AS selected_habit_id,
          csh.profile_id,
          csh.habit_id,
          csh.level_id,
          csh.start_date,
          csh.end_date,
          csh.status,
          csh.selected_at,
          csh.updated_at,

          hm.habit_name,
          hm.habit_description,
          hm.category,
          hm.frequency_type,
          hm.target_count,
          hm.target_unit,
          hm.tracking_type,

          COUNT(cht.id) AS tracking_rows

        FROM client_selected_habits csh

        INNER JOIN habit_master hm
          ON  hm.id       = csh.habit_id
          AND hm.level_id = csh.level_id

        LEFT JOIN client_habit_tracking cht
          ON  cht.profile_id        = csh.profile_id
          AND cht.selected_habit_id = csh.id
          AND cht.habit_id          = csh.habit_id
          AND cht.tracking_date BETWEEN ? AND ?

        WHERE csh.profile_id = ?
          AND hm.is_active   = 1
          AND (
            csh.status = 'active'
            OR cht.id IS NOT NULL
          )

        GROUP BY csh.id

        ORDER BY
          CASE WHEN COUNT(cht.id) > 0 THEN 0 ELSE 1 END,
          csh.id ASC

        LIMIT 5
      `,
      [weekStart, weekEnd, profileId]
    );

    // ── 3c. Per-habit tracking detail ────────────────────────────────────────
    const habits = [];

    let totalTrackedThisWeek   = 0;
    let totalCompletedThisWeek = 0;
    let totalPossibleThisWeek  = 0;

    const dailyCompletedMap = buildDailyMap(weekStart);
    const dailyPossibleMap  = buildDailyMap(weekStart);

    for (const habit of selectedHabits) {
      const selectedHabitId = parseInt(habit.selected_habit_id, 10);
      const habitId         = parseInt(habit.habit_id, 10);
      const frequencyType   = String(habit.frequency_type || "").toLowerCase();
      let targetCount       = parseInt(habit.target_count, 10) || 1;
      if (targetCount < 1) targetCount = 1;

      const expectedCount = frequencyType === "weekly" ? targetCount : 7;

      const [trackingRows] = await pool.execute(
        `
          SELECT tracking_date, target_count, completed_count, is_completed
          FROM client_habit_tracking
          WHERE profile_id        = ?
            AND selected_habit_id = ?
            AND habit_id          = ?
            AND tracking_date BETWEEN ? AND ?
          ORDER BY tracking_date ASC
        `,
        [profileId, selectedHabitId, habitId, weekStart, weekEnd]
      );

      const trackingMap = {};
      let trackedCount   = 0;
      let completedCount = 0;

      for (const track of trackingRows) {
        const trackingDate = track.tracking_date instanceof Date
          ? track.tracking_date.toISOString().slice(0, 10)
          : String(track.tracking_date).slice(0, 10);

        if (!trackingMap[trackingDate]) {
          trackedCount++;
        }

        if (parseInt(track.is_completed, 10) === 1) {
          completedCount++;
        }

        trackingMap[trackingDate] = {
          target_count:    parseInt(track.target_count, 10)    || 0,
          completed_count: parseInt(track.completed_count, 10) || 0,
          is_completed:    parseInt(track.is_completed, 10)    || 0,
        };
      }

      trackedCount   = Math.min(trackedCount,   expectedCount);
      completedCount = Math.min(completedCount, expectedCount);

      let weeklyCompletionRate =
        expectedCount > 0
          ? Math.round((completedCount / expectedCount) * 100)
          : 0;
      if (weeklyCompletionRate > 100) weeklyCompletionRate = 100;

      const weekTracking = [];
      let completedDays  = 0;

      for (let i = 0; i < 7; i++) {
        const d = new Date(weekStart);
        d.setDate(d.getDate() + i);
        const dateKey = d.toISOString().slice(0, 10);
        const dayName = getDayName(dateKey);

        let isCompleted       = false;
        let completedDayCount = 0;

        if (
          trackingMap[dateKey] &&
          parseInt(trackingMap[dateKey].is_completed, 10) === 1
        ) {
          isCompleted       = true;
          completedDays++;
          completedDayCount = trackingMap[dateKey].completed_count;
        }

        weekTracking.push({
          date:            dateKey,
          day:             dayName,
          is_completed:    isCompleted,
          completed_count: completedDayCount,
        });

        dailyPossibleMap[dateKey]  = (dailyPossibleMap[dateKey]  || 0) + 1;
        if (isCompleted) {
          dailyCompletedMap[dateKey] = (dailyCompletedMap[dateKey] || 0) + 1;
        }
      }

      const isCompletedThisWeek = completedCount >= expectedCount;

      totalTrackedThisWeek   += trackedCount;
      totalCompletedThisWeek += completedCount;
      totalPossibleThisWeek  += expectedCount;

      habits.push({
        selected_habit_id: selectedHabitId,
        habit_id:          habitId,
        level_id:          parseInt(habit.level_id, 10) || 0,

        title:             habit.habit_name,
        habit_name:        habit.habit_name,
        habit_description: habit.habit_description,
        category:          habit.category,

        frequency_type: habit.frequency_type,
        target_count:   targetCount,
        target_unit:    habit.target_unit,
        tracking_type:  habit.tracking_type,

        completed_days:         completedDays,
        total_days:             7,
        weekly_completion_rate: weeklyCompletionRate,
        is_completed_this_week: isCompletedThisWeek,

        week_tracking: weekTracking,

        start_date:     habit.start_date,
        end_date:       habit.end_date,
        status:         habit.status,
        display_status: habit.status === "removed" ? "completed_cycle" : habit.status,
        selected_at:    habit.selected_at,
        updated_at:     habit.updated_at,
      });
    }

    // ── 3d. Aggregate metrics ─────────────────────────────────────────────────
    const trackingRate =
      totalPossibleThisWeek > 0
        ? Math.round((totalTrackedThisWeek / totalPossibleThisWeek) * 100)
        : 0;

    const completionRate =
      totalPossibleThisWeek > 0
        ? Math.round((totalCompletedThisWeek / totalPossibleThisWeek) * 100)
        : 0;

    let totalPerfectDays = 0;
    for (const [date, possibleCount] of Object.entries(dailyPossibleMap)) {
      if (possibleCount > 0 && dailyCompletedMap[date] === possibleCount) {
        totalPerfectDays++;
      }
    }

    // ── 4. Success response ───────────────────────────────────────────────────
    return res.status(200).json({
      status:  true,
      message: "Habit monitoring data fetched successfully",
      data: {
        dietitian_id: dieticianId,
        profile_id:   profileId,
        level_type:   levelType,

        profile_created_at: profileCreatedAt,
        days_tracked:       daysTracked,

        week_start: weekStart,
        week_end:   weekEnd,
        today,

        total_habits: habits.length,

        tracking_rate:      trackingRate,
        completion_rate:    completionRate,
        total_perfect_days: totalPerfectDays,

        habits,
      },
      error: null,
    });
  } catch (err) {
    // ── 5. Error handling — suppress internals ────────────────────────────────
    console.error("habits-tracking-users-choice1: unhandled error", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
    });

    return res.status(500).json({
      status:  false,
      message: "Server error",
      data:    null,
      error:   { code: "SERVER_ERROR" },
    });
  }
};

module.exports = { habitsTrackingUsersChoice };