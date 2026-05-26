"use strict";

/**
 * get-client-selected-habit-detail.js
 *
 * Converted from: get-client-selected-habit-detail.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * VAPT Controls applied:
 *  - Token-bound authorization (prevents BOLA/IDOR): dietitian_id from JWT
 *    is validated against the dietitian who owns the requested profile via
 *    requireProfileAccess (table_clients ownership check).
 *  - selected_habit_id is validated as a positive integer and then verified
 *    to belong to the requesting profile in the habit query itself — a second
 *    BOLA layer preventing cross-profile habit access.
 *  - Input validation and strict ID normalization before any DB call.
 *  - Fully parameterized queries — zero string interpolation.
 *  - Internal error details suppressed in all client-facing responses.
 *  - Result caps (LIMIT 1 on all single-row fetches).
 *  - Belt-and-suspenders cache headers (no-store) enforced per-response.
 *
 * HIPAA Controls applied:
 *  - No PHI (patient name, DOB, contact info) is logged anywhere in this file.
 *  - Minimum-necessary data principle: only columns needed for the habit
 *    detail view are selected — no blanket SELECT *.
 *  - Access control: every request is bound to an authenticated dietitian's
 *    JWT sub claim, verified against the DB before any habit data is returned.
 *  - Audit trail: structured console.warn on access-denied paths (without
 *    PHI), allowing downstream log aggregation (CloudWatch / SIEM).
 *
 * NOTE on dietitian/dietician spelling:
 *  - accessControl.js accepts both spellings from request bodies and JWT.
 *  - DB column reference uses dietician_id (legacy column name).
 *    Verify with: SHOW COLUMNS FROM table_clients LIKE '%diet%';
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

  const dayOfWeek    = now.getDay(); // 0=Sun
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
 * Day-of-week abbreviation (Mon, Tue … Sun).
 *
 * @param {string} dateStr  YYYY-MM-DD
 * @returns {string}
 */
function getDayName(dateStr) {
  return new Date(dateStr).toLocaleDateString("en-US", { weekday: "short" });
}

/**
 * Normalize a tracking_date value coming from mysql2.
 * mysql2 can return DATE columns as JS Date objects or strings depending on
 * driver config — this handles both safely.
 *
 * @param {Date|string} val
 * @returns {string}  YYYY-MM-DD
 */
function normDate(val) {
  if (val instanceof Date) return val.toISOString().slice(0, 10);
  return String(val).slice(0, 10);
}

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/get-client-selected-habit-detail
 *
 * Body: { dietitian_id, profile_id, selected_habit_id }
 * Auth: Bearer JWT (authMiddleware must run before this handler)
 */
const getClientSelectedHabitDetail = async (req, res) => {
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
    console.warn("get-client-selected-habit-detail: access denied", {
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

  // ── 2. Validate selected_habit_id ─────────────────────────────────────────
  //    Must be a positive integer — reject strings, floats, negatives, zero.
  const rawSelectedHabitId = req.body?.selected_habit_id;

  const parsedSelectedHabitId = parseInt(rawSelectedHabitId, 10);

  if (
    rawSelectedHabitId === undefined ||
    rawSelectedHabitId === null ||
    rawSelectedHabitId === "" ||
    !Number.isInteger(parsedSelectedHabitId) ||
    parsedSelectedHabitId <= 0 ||
    String(parsedSelectedHabitId) !== String(rawSelectedHabitId).trim()
  ) {
    return res.status(422).json({
      status:  false,
      message: "selected_habit_id must be a valid positive integer",
      data:    null,
      error:   { code: "VALIDATION_ERROR" },
    });
  }

  const selectedHabitId = parsedSelectedHabitId;

  // ── 3. Business logic ──────────────────────────────────────────────────────
  try {
    const now = new Date();
    const { today, weekStart, weekEnd } = getWeekBounds(now);

    // ── 3a. Fetch client metadata ─────────────────────────────────────────────
    //    Also re-confirms dietitian→profile ownership at the DB level.
    //    Column: dietician_id (legacy DB spelling — verify with SHOW COLUMNS)
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
        message: "Client not found or does not belong to this dietitian",
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

    // ── 3b. Fetch the single selected habit ───────────────────────────────────
    //    WHERE csh.id = ? AND csh.profile_id = ? is the second BOLA guard:
    //    even if selected_habit_id is valid, it must belong to this profile.
    const [habitRows] = await pool.execute(
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
          hm.target_count   AS habit_target_count,
          hm.target_unit,
          hm.tracking_type

        FROM client_selected_habits csh

        INNER JOIN habit_master hm
          ON  hm.id       = csh.habit_id
          AND hm.level_id = csh.level_id
          AND hm.is_active = 1

        WHERE csh.id         = ?
          AND csh.profile_id = ?

        LIMIT 1
      `,
      [selectedHabitId, profileId]
    );

    if (!habitRows.length) {
      return res.status(404).json({
        status:  false,
        message: "Habit not found or does not belong to this profile",
        data:    null,
        error:   { code: "HABIT_NOT_FOUND" },
      });
    }

    const habit = habitRows[0];

    const habitId       = parseInt(habit.habit_id, 10);
    const frequencyType = String(habit.frequency_type || "").toLowerCase();
    let targetCount     = parseInt(habit.habit_target_count, 10) || 1;
    if (targetCount < 1) targetCount = 1;

    const expectedCount = frequencyType === "weekly" ? targetCount : 7;

    // ── 3c. Fetch this week's tracking rows for this habit ────────────────────
    const [trackingRows] = await pool.execute(
      `
        SELECT tracking_date, target_count, completed_count, is_completed, notes
        FROM client_habit_tracking
        WHERE profile_id        = ?
          AND selected_habit_id = ?
          AND habit_id          = ?
          AND tracking_date BETWEEN ? AND ?
        ORDER BY tracking_date ASC
      `,
      [profileId, selectedHabitId, habitId, weekStart, weekEnd]
    );

    // Build date-keyed map; count unique tracked dates & completions
    const trackingMap = {};
    let trackedCount   = 0;
    let completedCount = 0;

    for (const track of trackingRows) {
      const trackingDate = normDate(track.tracking_date);

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
        notes:           track.notes ?? null,
      };
    }

    trackedCount   = Math.min(trackedCount,   expectedCount);
    completedCount = Math.min(completedCount, expectedCount);

    let weeklyCompletionRate =
      expectedCount > 0
        ? Math.round((completedCount / expectedCount) * 100)
        : 0;
    if (weeklyCompletionRate > 100) weeklyCompletionRate = 100;

    // ── 3d. Build 7-day week tracking array ───────────────────────────────────
    const weekTracking = [];
    let completedDays  = 0;

    for (let i = 0; i < 7; i++) {
      const d = new Date(weekStart);
      d.setDate(d.getDate() + i);
      const dateKey = d.toISOString().slice(0, 10);
      const dayName = getDayName(dateKey);

      let isCompleted       = false;
      let completedDayCount = 0;
      let notes             = null;

      if (
        trackingMap[dateKey] &&
        parseInt(trackingMap[dateKey].is_completed, 10) === 1
      ) {
        isCompleted       = true;
        completedDays++;
        completedDayCount = trackingMap[dateKey].completed_count;
        notes             = trackingMap[dateKey].notes;
      }

      weekTracking.push({
        date:            dateKey,
        day:             dayName,
        is_completed:    isCompleted,
        completed_count: completedDayCount,
        notes,
      });
    }

    const isCompletedThisWeek = completedCount >= expectedCount;

    // ── 4. Success response ───────────────────────────────────────────────────
    return res.status(200).json({
      status:  true,
      message: "Habit detail fetched successfully",
      data: {
        dietitian_id: dieticianId,
        profile_id:   profileId,
        level_type:   levelType,

        profile_created_at: profileCreatedAt,
        days_tracked:       daysTracked,

        week_start: weekStart,
        week_end:   weekEnd,
        today,

        habit: {
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
        },
      },
      error: null,
    });
  } catch (err) {
    // ── 5. Error handling — suppress internals ────────────────────────────────
    //    Log error code/type only; never log PHI, query text, or stack in prod.
    console.error("get-client-selected-habit-detail: unhandled error", {
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

module.exports = { getClientSelectedHabitDetail };