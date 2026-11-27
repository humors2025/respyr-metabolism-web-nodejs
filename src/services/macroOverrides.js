"use strict";

/**
 * macroOverrides.js
 *
 * Shared logic for hand-edited macro targets (table `macro_overrides`,
 * migration 015). Used by:
 *   - macro-overrides.js controller  (dashboard: save / list / remove)
 *   - get_macro_summary_by_date.js   (dashboard: real vs edited)
 *   - get_latest_72hr_tests.js and fetch-single-client-worker-job-test.js
 *     (diet-plan worker feed: edited numbers replace final_macro_summary)
 *
 * Dates are India calendar dates, the same calendar the weekly diet plan uses
 * (store_weekly_food_json_suggestion_newtest: Friday → Thursday, Asia/Kolkata).
 *
 * The table may not exist on every database (prod has refused new tables
 * before). Every reader here treats a missing table as "no overrides", so the
 * worker feed and the Macros Analysis tab keep working exactly as before.
 */

const pool = require("../config/db");

const IST_OFFSET_MS = 5.5 * 60 * 60 * 1000;

// Edited values must stay in a sane range. Upper limits are generous on
// purpose: they only catch typos (e.g. 1500 g protein), not clinical choices.
const MACRO_LIMITS = {
  protein_g: { min: 0, max: 600 },
  carbs_g: { min: 0, max: 1000 },
  fat_g: { min: 0, max: 400 },
  fiber_g: { min: 0, max: 150 },
};

// How many days one edit may cover, counting both the start and end day:
// at least one full plan week, at most about two months.
const MIN_RANGE_DAYS = 7;
const MAX_RANGE_DAYS = 60;

/* ─── Dates ─────────────────────────────────────────────────────────────── */

function pad(n) {
  return String(n).padStart(2, "0");
}

function formatUtcDate(date) {
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
}

/** Today's date in India, YYYY-MM-DD. */
function istToday(nowMs = Date.now()) {
  return formatUtcDate(new Date(nowMs + IST_OFFSET_MS));
}

/** Adds whole days to a YYYY-MM-DD string. */
function addDays(ymd, days) {
  const [y, m, d] = ymd.split("-").map(Number);
  const date = new Date(Date.UTC(y, m - 1, d));
  date.setUTCDate(date.getUTCDate() + days);
  return formatUtcDate(date);
}

/** Days from a to b (b − a), both YYYY-MM-DD. */
function daysBetween(a, b) {
  const [ay, am, ad] = a.split("-").map(Number);
  const [by, bm, bd] = b.split("-").map(Number);
  return Math.round((Date.UTC(by, bm - 1, bd) - Date.UTC(ay, am - 1, ad)) / 86400000);
}

/**
 * The diet-plan week the generator writes to at `nowMs`, in India. Same rule
 * as store_weekly_food_json_suggestion_newtest.js computeWeekWindow() — the
 * store the dashboard's Diet plan tab reads: weeks run Friday → Thursday, the
 * generator runs on Thursday for the week starting the next day, so the week
 * is worked out from "tomorrow":
 *   Thursday  → the Friday-to-Thursday week starting tomorrow
 *   Friday    → the week starting today
 *   Sat … Wed → the week in progress (started the most recent Friday)
 */
function currentPlanWeek(nowMs = Date.now()) {
  const tomorrow = addDays(istToday(nowMs), 1);
  const [y, m, d] = tomorrow.split("-").map(Number);
  const dayOfWeek = new Date(Date.UTC(y, m - 1, d)).getUTCDay(); // 0 = Sunday, 5 = Friday
  const weekStart = addDays(tomorrow, -((dayOfWeek - 5 + 7) % 7));
  return { week_start_date: weekStart, week_end_date: addDays(weekStart, 6) };
}

/** Strict YYYY-MM-DD → same string, or null. */
function normalizeYmd(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return null;
  const [y, m, d] = trimmed.split("-").map(Number);
  const parsed = new Date(Date.UTC(y, m - 1, d));
  if (
    parsed.getUTCFullYear() !== y ||
    parsed.getUTCMonth() !== m - 1 ||
    parsed.getUTCDate() !== d
  ) {
    return null;
  }
  return trimmed;
}

/** mysql2 returns DATE columns as Date or string depending on config. */
function dateColumnToYmd(value) {
  if (!value) return null;
  if (value instanceof Date) {
    // DATE columns come back as local-midnight Dates; read local parts.
    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  }
  return String(value).slice(0, 10);
}

function dateTimeColumnToString(value) {
  if (!value) return null;
  if (value instanceof Date) {
    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())} ${pad(value.getHours())}:${pad(value.getMinutes())}:${pad(value.getSeconds())}`;
  }
  return String(value).slice(0, 19);
}

/* ─── Macros ────────────────────────────────────────────────────────────── */

function roundOne(value) {
  return Math.round(value * 10) / 10;
}

function toNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

const KCAL_PER_GRAM = { protein_g: 4, carbs_g: 4, fat_g: 9, fiber_g: 2 };

/**
 * Calories for edited macros.
 *
 * With the test's own macros (base), the result is the test's calories moved
 * by only what was changed: protein 4, carbs 4, fat 9, fiber 2 kcal per gram.
 * So saving the test's numbers unchanged keeps the test's calories exactly
 * (the engine's calorie figure does not always equal a plain 4/4/9 sum).
 * Without a base it is the plain sum with the same weights.
 */
function caloriesFromMacros(macros, base = null) {
  const sum = (m) =>
    Object.entries(KCAL_PER_GRAM).reduce((acc, [k, w]) => acc + toNumber(m?.[k]) * w, 0);
  if (base && toNumber(base.calories) > 0) {
    return Math.max(0, Math.round(toNumber(base.calories) + sum(macros) - sum(base)));
  }
  return Math.round(sum(macros));
}

/**
 * Validates edited macros from a request body. Returns
 * { ok: true, macros } or { ok: false, message }.
 */
function parseMacroInput(body) {
  const macros = {};
  for (const [key, { min, max }] of Object.entries(MACRO_LIMITS)) {
    const raw = body?.[key];
    if (raw === undefined || raw === null || raw === "") {
      return { ok: false, message: `${key} is required` };
    }
    const num = typeof raw === "number" ? raw : Number(String(raw).trim());
    if (!Number.isFinite(num)) {
      return { ok: false, message: `${key} must be a number` };
    }
    if (num < min || num > max) {
      return { ok: false, message: `${key} must be between ${min} and ${max}` };
    }
    macros[key] = roundOne(num);
  }
  // Without the test's numbers; the save handler recomputes it from the base.
  macros.calories = caloriesFromMacros(macros);
  return { ok: true, macros };
}

/**
 * Validates the date range. valid_from may not be in the past (India date):
 * an edit only ever changes plans from today onward.
 */
function parseRangeInput(body, nowMs = Date.now()) {
  const validFrom = normalizeYmd(body?.valid_from);
  const validTo = normalizeYmd(body?.valid_to);
  if (!validFrom || !validTo) {
    return { ok: false, message: "valid_from and valid_to are required (YYYY-MM-DD)" };
  }
  const today = istToday(nowMs);
  if (validFrom < today) {
    return { ok: false, message: "valid_from cannot be in the past" };
  }
  if (validTo < validFrom) {
    return { ok: false, message: "valid_to must be on or after valid_from" };
  }
  const rangeDays = daysBetween(validFrom, validTo) + 1; // both days count
  if (rangeDays < MIN_RANGE_DAYS) {
    return { ok: false, message: `Use until must be at least ${MIN_RANGE_DAYS} days (start and end day included)` };
  }
  if (rangeDays > MAX_RANGE_DAYS) {
    return { ok: false, message: `Use until can be at most ${MAX_RANGE_DAYS} days (start and end day included)` };
  }
  return { ok: true, valid_from: validFrom, valid_to: validTo };
}

/* ─── Table presence ────────────────────────────────────────────────────── */

let tableCheck = { exists: null, checkedAt: 0 };
const MISSING_RECHECK_MS = 5 * 60 * 1000;

function isMissingTableError(err) {
  return err?.code === "ER_NO_SUCH_TABLE" || err?.errno === 1146;
}

/**
 * True when macro_overrides exists. A positive answer is cached for the life
 * of the process; a negative one is re-checked every 5 minutes so running the
 * migration takes effect without a redeploy.
 */
async function macroOverridesTableExists(db = pool) {
  const now = Date.now();
  if (tableCheck.exists === true) return true;
  if (tableCheck.exists === false && now - tableCheck.checkedAt < MISSING_RECHECK_MS) {
    return false;
  }
  try {
    const [rows] = await db.execute(
      `SELECT 1 FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = 'macro_overrides'
        LIMIT 1`
    );
    tableCheck = { exists: rows.length > 0, checkedAt: now };
  } catch (err) {
    console.error("MACRO_OVERRIDES_TABLE_CHECK_FAILED:", err?.code || err?.message);
    tableCheck = { exists: false, checkedAt: now };
  }
  return tableCheck.exists;
}

/** Test hook. */
function resetTableCheckCache() {
  tableCheck = { exists: null, checkedAt: 0 };
}

/* ─── Row shaping ───────────────────────────────────────────────────────── */

function macroOrNull(value) {
  return value === null || value === undefined ? null : toNumber(value);
}

/** DB row → API object (dashboard and worker feed share this shape). */
function shapeOverride(row, today = istToday()) {
  if (!row) return null;
  const validFrom = dateColumnToYmd(row.valid_from);
  const validTo = dateColumnToYmd(row.valid_to);

  let status = "active";
  if (row.removed_at) status = "removed";
  else if (validTo < today) status = "expired";
  else if (validFrom > today) status = "upcoming";

  const hasBase = row.base_protein_g !== null && row.base_protein_g !== undefined;

  return {
    id: Number(row.id),
    profile_id: row.profile_id,
    status,
    valid_from: validFrom,
    valid_to: validTo,
    note: row.note || null,
    edited_macro_summary: {
      calories: toNumber(row.calories),
      protein_g: toNumber(row.protein_g),
      carbs_g: toNumber(row.carbs_g),
      fat_g: toNumber(row.fat_g),
      fiber_g: toNumber(row.fiber_g),
    },
    original_macro_summary: hasBase
      ? {
          calories: macroOrNull(row.base_calories),
          protein_g: macroOrNull(row.base_protein_g),
          carbs_g: macroOrNull(row.base_carbs_g),
          fat_g: macroOrNull(row.base_fat_g),
          fiber_g: macroOrNull(row.base_fiber_g),
        }
      : null,
    base_test_id: row.base_test_id === null || row.base_test_id === undefined ? null : Number(row.base_test_id),
    base_test_date: dateTimeColumnToString(row.base_test_date),
    edited_by: {
      user_id: row.edited_by_user_id,
      name: row.edited_by_name || null,
      dietician_id: row.edited_by_dietician_id || null,
      role: row.edited_by_role || null,
    },
    removed_by: row.removed_at
      ? { user_id: row.removed_by_user_id || null, name: row.removed_by_name || null }
      : null,
    removed_at: dateTimeColumnToString(row.removed_at),
    created_at: dateTimeColumnToString(row.created_at),
    updated_at: dateTimeColumnToString(row.updated_at),
  };
}

const OVERRIDE_COLUMNS = `
  id, profile_id, dietician_id,
  protein_g, carbs_g, fat_g, fiber_g, calories,
  valid_from, valid_to, note,
  base_test_id, base_test_date,
  base_protein_g, base_carbs_g, base_fat_g, base_fiber_g, base_calories,
  edited_by_user_id, edited_by_name, edited_by_dietician_id, edited_by_role,
  removed_at, removed_by_user_id, removed_by_name,
  created_at, updated_at
`;

/* ─── Readers ───────────────────────────────────────────────────────────── */

/**
 * The override that applies to a date window for each (dietician_id,
 * profile_id) pair: not removed, range overlapping [windowStart, windowEnd],
 * and — when several overlap — the most recently saved one.
 *
 * pairs: [{ dietician_id, profile_id }]. Returns Map keyed
 * "DIETICIAN|profile_id" → DB row. Empty Map when the table is missing.
 */
async function findOverridesForWindow(pairs, windowStart, windowEnd, db = pool) {
  const result = new Map();
  const cleaned = (pairs || []).filter((p) => p && p.profile_id && p.dietician_id);
  if (!cleaned.length) return result;
  if (!(await macroOverridesTableExists(db))) return result;

  const profileIds = [...new Set(cleaned.map((p) => String(p.profile_id)))];
  const wanted = new Set(
    cleaned.map((p) => `${String(p.dietician_id).trim().toUpperCase()}|${p.profile_id}`)
  );

  // Chunked so a 500-row feed page never builds an oversized IN list.
  const CHUNK = 200;
  for (let i = 0; i < profileIds.length; i += CHUNK) {
    const chunk = profileIds.slice(i, i + CHUNK);
    let rows;
    try {
      [rows] = await db.execute(
        `SELECT ${OVERRIDE_COLUMNS}
           FROM macro_overrides
          WHERE profile_id IN (${chunk.map(() => "?").join(", ")})
            AND removed_at IS NULL
            AND valid_from <= ?
            AND valid_to >= ?
          ORDER BY updated_at DESC, id DESC`,
        [...chunk, windowEnd, windowStart]
      );
    } catch (err) {
      if (isMissingTableError(err)) {
        resetTableCheckCache();
        return result;
      }
      throw err;
    }
    for (const row of rows) {
      const key = `${String(row.dietician_id).trim().toUpperCase()}|${row.profile_id}`;
      if (!wanted.has(key) || result.has(key)) continue; // first = newest
      result.set(key, row);
    }
  }
  return result;
}

/**
 * Every override for one client, newest first (history list for the tab).
 * Returns null when the table is missing so the caller can say so.
 */
async function listOverridesForProfile(dieticianId, profileId, db = pool) {
  if (!(await macroOverridesTableExists(db))) return null;
  try {
    const [rows] = await db.execute(
      `SELECT ${OVERRIDE_COLUMNS}
         FROM macro_overrides
        WHERE profile_id = ?
          AND UPPER(TRIM(dietician_id)) = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 100`,
      [profileId, String(dieticianId).trim().toUpperCase()]
    );
    return rows;
  } catch (err) {
    if (isMissingTableError(err)) {
      resetTableCheckCache();
      return null;
    }
    throw err;
  }
}

/* ─── Worker feed ───────────────────────────────────────────────────────── */

/**
 * Applies overrides to worker-feed entries in place. For an entry with an
 * override covering the plan week:
 *   final_macro_summary    → the edited numbers (what the worker plans from)
 *   original_macro_summary → the test's own numbers
 *   macro_override         → { id, valid_from, valid_to, edited_by, ... }
 * Entries without one get original_macro_summary = final_macro_summary and
 * macro_override = null, so the worker always sees the same keys.
 *
 * Never throws: on any failure the entries keep their test numbers, because a
 * broken override lookup must not stop clients from getting a plan.
 */
async function applyOverridesToFeed(entries, { nowMs = Date.now(), db = pool } = {}) {
  const week = currentPlanWeek(nowMs);
  const today = istToday(nowMs);

  for (const entry of entries) {
    entry.original_macro_summary = { ...entry.final_macro_summary };
    entry.macro_override = null;
  }

  let overrides;
  try {
    overrides = await findOverridesForWindow(
      entries.map((e) => ({ dietician_id: e.dietitian_id, profile_id: e.profile_id })),
      week.week_start_date,
      week.week_end_date,
      db
    );
  } catch (err) {
    console.error("MACRO_OVERRIDES_FEED_LOOKUP_FAILED:", err?.code || err?.message);
    return entries;
  }

  for (const entry of entries) {
    const key = `${String(entry.dietitian_id).trim().toUpperCase()}|${entry.profile_id}`;
    const row = overrides.get(key);
    if (!row) continue;
    const shaped = shapeOverride(row, today);
    entry.final_macro_summary = { ...shaped.edited_macro_summary };
    entry.macro_override = {
      id: shaped.id,
      valid_from: shaped.valid_from,
      valid_to: shaped.valid_to,
      plan_week_start: week.week_start_date,
      plan_week_end: week.week_end_date,
      note: shaped.note,
      edited_by: shaped.edited_by,
      updated_at: shaped.updated_at,
    };
  }
  return entries;
}

/**
 * Extra rows for the batch feed's "latest test per client" sub-query, so a
 * client whose macros were just edited (or whose edit starts today) is
 * re-planned even without a new test in the last 72 hours.
 *
 * Returns { sql, params } to UNION ALL into the derived table — or
 * { sql: "", params: [] } when the table is missing (feed unchanged).
 * Selects (dietitian_id, profile_id, test_id) like the 72-hour branch.
 */
async function recentOverrideFeedUnion({ nowMs = Date.now(), db = pool } = {}) {
  if (!(await macroOverridesTableExists(db))) return { sql: "", params: [] };
  const today = istToday(nowMs);
  return {
    sql: `
            UNION ALL
            SELECT t2.dietitian_id, t2.profile_id, t2.test_id
            FROM table_test_data t2
            INNER JOIN (
                SELECT DISTINCT profile_id, UPPER(TRIM(dietician_id)) AS dietician_id
                FROM macro_overrides
                WHERE removed_at IS NULL
                  AND valid_to >= ?
                  AND (
                    updated_at >= (NOW() - INTERVAL 72 HOUR)
                    OR valid_from BETWEEN ? AND ?
                  )
            ) mo
                ON mo.profile_id = t2.profile_id
                AND mo.dietician_id = UPPER(TRIM(t2.dietitian_id))`,
    params: [today, addDays(today, -3), today],
  };
}

module.exports = {
  MACRO_LIMITS,
  MIN_RANGE_DAYS,
  MAX_RANGE_DAYS,
  KCAL_PER_GRAM,
  istToday,
  addDays,
  currentPlanWeek,
  normalizeYmd,
  caloriesFromMacros,
  parseMacroInput,
  parseRangeInput,
  macroOverridesTableExists,
  resetTableCheckCache,
  isMissingTableError,
  shapeOverride,
  findOverridesForWindow,
  listOverridesForProfile,
  applyOverridesToFeed,
  recentOverrideFeedUnion,
};
