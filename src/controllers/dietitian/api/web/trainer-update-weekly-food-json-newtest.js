"use strict";

/**
 * trainer-update-weekly-food-json-newtest.js
 *
 * Cloned from: trainer-update-weekly-food-json.js — identical logic, but the
 * business table is weekly_food_json_suggestions_newtest instead of
 * weekly_food_json_suggestions. Keep the two files in sync.
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/trainer-update-weekly-food-json-newtest
 * Auth     : Bearer JWT (authMiddleware must run before this handler)
 *
 * Purpose  : Single API to add / update / delete one food item inside
 *            weekly_food_json_suggestions_newtest.food_json, then recompute the weekly
 *            macro averages and persist them (food_json, cal, cabs, fats,
 *            `Protein`, `Fibre`).
 *
 * Behaviour parity with the PHP:
 *  - Payload key spelling is dietitian_id; DB column remains dietician_id.
 *  - status is NEVER read as an edit gate and is NEVER written here. status=0
 *    (draft) and status=1 (mobile-visible) both stay editable from the dashboard.
 *  - add  : append a fully-validated food object to the meal.
 *    update: patch an existing food object at food_index (omitted fields kept).
 *    delete: splice out the food object at food_index.
 *  - Weekly macros = sum of every food across all days / day-count (min 7),
 *    rounded to 2 dp, with the same default note string.
 *  - Response keys/shape match the PHP (ok, message, action, id, dietitian_id,
 *    profile_id, week_start_date, week_end_date, status_value, day_code,
 *    meal_type, food_index, changed_food, deleted_food, meal_summary,
 *    day_summary, weekly_json_data, food_json).
 *  - Same DB tables only: weekly_food_json_suggestions_newtest (read+write), and the
 *    house authz/audit tables (table_clients via requireProfileAccess,
 *    app_auth_logs for the access trail). Nothing else added or removed.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. dietitian_id from the body is only honoured after the
 *    JWT proves the caller IS that dietician (requireDieticianSelfAccess), and
 *    the target profile_id is verified to belong to that dietician
 *    (requireProfileAccess). The PHP trusted the body row keys outright, letting
 *    any authenticated caller mutate another tenant's diet plan (IDOR).
 *  - The mutation runs inside a transaction with SELECT ... FOR UPDATE so two
 *    concurrent edits to the same week can't clobber each other (lost update).
 *  - All queries are parameterized (already true in the PHP — preserved).
 *  - Internal error detail is suppressed in production; gated behind APP_DEBUG.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT *.
 *  - The access trail (who mutated which plan) is written to app_auth_logs with
 *    IP / user-agent / identifier HMAC-SHA256 hashed using SECURITY_PEPPER —
 *    never stored in clear text. Never throws (fail-safe).
 *  - Server logs carry only error metadata (code/errno/sqlState), never PHI.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  requireDieticianSelfAccess,
  normalizeId,
} = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTIONS = new Set(["add", "update", "delete"]);
const ALLOWED_MEALS = ["breakfast", "lunch", "snacks", "dinner"];

const REQUIRED_TEXT_FIELDS = ["food_name", "portion_with_metric", "category"];
const REQUIRED_MACRO_FIELDS = ["calories", "carbs_g", "protein_g", "fat_g", "fiber_g"];

const DEFAULT_WEEKLY_NOTE =
  "These values represent the average daily nutrient intake across the full 7-day week.";

// ─── ApiError ────────────────────────────────────────────────────────────────

class ApiError extends Error {
  constructor(statusCode, message, extra = {}) {
    super(message);
    this.statusCode = statusCode;
    this.payload = { ok: false, message, ...extra };
  }
}

function fail(statusCode, message, extra = {}) {
  throw new ApiError(statusCode, message, extra);
}

// ─── Generic helpers ─────────────────────────────────────────────────────────

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isNumericValue(value) {
  if (typeof value === "number") return Number.isFinite(value);
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed !== "" && Number.isFinite(Number(trimmed));
  }
  return false;
}

/** round() to 2 dp, half away from zero — matches PHP round(). */
function roundMacro(value) {
  const n = Number(value) || 0;
  return Math.sign(n) * Math.round(Math.abs(n) * 100 + Number.EPSILON) / 100;
}

function requiredString(payload, key) {
  if (
    payload[key] === undefined ||
    payload[key] === null ||
    String(payload[key]).trim() === ""
  ) {
    fail(400, `${key} is required`);
  }
  return String(payload[key]).trim();
}

function isValidDateString(date) {
  if (typeof date !== "string" || date === "") return false;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime())) return false;
  const [y, m, d] = date.split("-").map(Number);
  return (
    parsed.getUTCFullYear() === y &&
    parsed.getUTCMonth() + 1 === m &&
    parsed.getUTCDate() === d
  );
}

/** Format a mysql2 DATE/DATETIME to "YYYY-MM-DD" (PHP echoed the raw column). */
function formatDateOnly(value) {
  if (!value) return null;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  }
  return String(value).slice(0, 10);
}

// ─── Day resolution ──────────────────────────────────────────────────────────

/**
 * Keys a stored day object may use to identify itself. The PHP only ever
 * looked at day_code, but generated plans (and the dashboard) have used other
 * spellings, so every one of these is accepted.
 */
const DAY_ID_KEYS = ["day_code", "day", "day_key", "day_id", "code", "day_name", "name"];

const WEEKDAY_NAMES = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];

/**
 * Canonicalise a day identifier so that "d1", "D-1", "day_1", "Day 01" all
 * become "d1" and "Monday" / "MON" become "mon". Anything else is returned
 * lower-cased with separators stripped.
 */
function canonicalDayCode(value) {
  const norm = String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
  if (!norm) return "";
  const positional = norm.match(/^(?:d|day)0*(\d{1,2})$/);
  if (positional) return `d${Number(positional[1])}`;
  const weekday = WEEKDAY_NAMES.find((w) => norm === w || norm.startsWith(w));
  return weekday || norm;
}

/** Every identifier a stored day object exposes, canonicalised. */
function storedDayCodes(day) {
  if (!isPlainObject(day)) return [];
  const codes = [];
  for (const key of DAY_ID_KEYS) {
    if (day[key] !== undefined && day[key] !== null && day[key] !== "") {
      const canon = canonicalDayCode(day[key]);
      if (canon) codes.push(canon);
    }
  }
  return codes;
}

/**
 * Find the index of the requested day inside food_json.days.
 *
 *  1. Match the canonical request code against every identifier key on each
 *     stored day (day_code, day, day_id, ...).
 *  2. If the request is positional ("d1", "day_3") and nothing matched by
 *     name, fall back to the array position (d1 → days[0]).
 *
 * Returns -1 when the day cannot be resolved.
 */
function resolveDayIndex(days, requestedCode) {
  const target = canonicalDayCode(requestedCode);
  if (!target || !Array.isArray(days)) return -1;

  for (let i = 0; i < days.length; i++) {
    if (storedDayCodes(days[i]).includes(target)) return i;
  }

  const positional = target.match(/^d(\d{1,2})$/);
  if (positional) {
    const idx = Number(positional[1]) - 1;
    if (idx >= 0 && idx < days.length && isPlainObject(days[idx])) return idx;
  }

  return -1;
}

// ─── Meal resolution ─────────────────────────────────────────────────────────

/**
 * The PHP assumed every day looks like { breakfast: { foods: [...] }, ... }.
 * Generated plans have not always honoured that, so meal access is resolved
 * through the helpers below, which accept:
 *   - day.breakfast.foods            (canonical)
 *   - day.Breakfast / day.BREAKFAST  (case-insensitive key)
 *   - day.breakfast = [ ...foods ]   (meal is the array itself)
 *   - day.breakfast.items / .food_items / .food_list / .food / .dishes
 *   - day.meals.breakfast.foods      (meals keyed by type)
 *   - day.meals = [ { meal_type: "breakfast", foods: [...] }, ... ]
 *     (identifier may be meal_type, meal, type, name, meal_name, title, slot)
 * Every accessor returns the LIVE array so mutations persist into food_json.
 */
const MEAL_CONTAINER_KEYS = ["meals", "meal", "meal_plan", "mealplan", "menu", "diet", "plan"];
const MEAL_ID_KEYS = ["meal_type", "meal", "type", "name", "meal_name", "title", "slot", "code", "key"];
const FOODS_KEYS = ["foods", "items", "food_items", "food_list", "food", "dishes", "list", "entries"];

function canonicalToken(value) {
  return String(value ?? "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

/** "Breakfast", "morning_snack", "SNACK", "Evening Snacks" → one of ALLOWED_MEALS. */
function canonicalMealType(value) {
  const norm = canonicalToken(value);
  if (!norm) return "";
  if (norm.includes("breakfast")) return "breakfast";
  if (norm.includes("lunch")) return "lunch";
  if (norm.includes("dinner")) return "dinner";
  if (norm.includes("snack")) return "snacks";
  return norm;
}

/** Find the real key on obj whose canonical form matches one of the wanted tokens. */
function findKeyCI(obj, wanted) {
  if (!isPlainObject(obj)) return null;
  const targets = (Array.isArray(wanted) ? wanted : [wanted]).map(canonicalToken);
  for (const key of Object.keys(obj)) {
    if (targets.includes(canonicalToken(key))) return key;
  }
  return null;
}

/**
 * Given a meal node (object or array), return its live foods array.
 * With create=true a missing array is created as meal.foods = [].
 */
function foodsArrayOf(meal, create) {
  if (Array.isArray(meal)) return meal;
  if (!isPlainObject(meal)) return null;

  for (const key of FOODS_KEYS) {
    if (Array.isArray(meal[key])) return meal[key];
  }
  const ciKey = findKeyCI(meal, FOODS_KEYS);
  if (ciKey && Array.isArray(meal[ciKey])) return meal[ciKey];

  if (create) {
    meal.foods = [];
    return meal.foods;
  }
  return null;
}

/** Locate the meal node for mealType inside a day. Returns null when absent. */
function findMealNode(day, mealType) {
  if (!isPlainObject(day)) return null;
  const want = canonicalMealType(mealType);

  // 1. Direct key on the day (exact, then case/format-insensitive).
  if (day[mealType] !== undefined && day[mealType] !== null) return day[mealType];
  for (const key of Object.keys(day)) {
    if (canonicalMealType(key) === want && day[key] !== null && typeof day[key] === "object") {
      return day[key];
    }
  }

  // 2. Inside a meals container.
  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;

  if (Array.isArray(container)) {
    for (const entry of container) {
      if (!isPlainObject(entry)) continue;
      for (const idKey of MEAL_ID_KEYS) {
        if (entry[idKey] !== undefined && canonicalMealType(entry[idKey]) === want) return entry;
      }
    }
    return null;
  }

  if (isPlainObject(container)) {
    for (const key of Object.keys(container)) {
      if (canonicalMealType(key) === want && container[key] !== null && typeof container[key] === "object") {
        return container[key];
      }
    }
  }
  return null;
}

/**
 * Return the live foods array for mealType in day, or null.
 * With create=true the meal (and its foods array) is created in whichever
 * layout the day already uses, so the stored shape stays consistent.
 */
function resolveMealFoods(day, mealType, create = false) {
  if (!isPlainObject(day)) return null;

  const existing = findMealNode(day, mealType);
  if (existing !== null) {
    const foods = foodsArrayOf(existing, create);
    if (foods) return foods;
  }
  if (!create) return null;

  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;

  if (Array.isArray(container)) {
    const entry = { meal_type: mealType, foods: [] };
    container.push(entry);
    return entry.foods;
  }
  if (isPlainObject(container)) {
    container[mealType] = { foods: [] };
    return container[mealType].foods;
  }
  day[mealType] = { foods: [] };
  return day[mealType].foods;
}

/** Non-PHI structural hint for 404 diagnostics: which keys/meals the day exposes. */
function describeDayShape(day) {
  if (!isPlainObject(day)) return { day_type: Array.isArray(day) ? "array" : typeof day };
  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;
  let mealIds = null;
  if (Array.isArray(container)) {
    mealIds = container.map((entry) => {
      if (!isPlainObject(entry)) return null;
      const idKey = MEAL_ID_KEYS.find((k) => entry[k] !== undefined && entry[k] !== null);
      return idKey ? String(entry[idKey]) : null;
    });
  } else if (isPlainObject(container)) {
    mealIds = Object.keys(container);
  }
  return {
    day_keys: Object.keys(day),
    meals_container: containerKey,
    meal_ids: mealIds,
    meals_found: ALLOWED_MEALS.filter((m) => Array.isArray(resolveMealFoods(day, m, false))),
  };
}

// ─── food_json (de)serialization ─────────────────────────────────────────────

function sanitizeJsonText(value) {
  return String(value)
    .replace(/^﻿/, "") // strip UTF-8 BOM
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "") // strip hidden control chars
    .trim();
}

/**
 * Decode the stored food_json column (string / Buffer / already-parsed object)
 * into a JS object. Mirrors the PHP cleanStoredJson + json_decode, with the
 * sibling controller's Buffer handling for mysql2 long/blob columns.
 */
function decodeStoredFoodJson(columnValue) {
  if (columnValue === null || columnValue === undefined) {
    fail(400, "Stored food_json is invalid JSON", { json_error: "empty column" });
  }

  if (isPlainObject(columnValue) || Array.isArray(columnValue)) {
    return columnValue;
  }

  let text;
  if (Buffer.isBuffer(columnValue)) {
    text = columnValue.toString("utf8");
  } else if (
    isPlainObject(columnValue) &&
    columnValue.type === "Buffer" &&
    Array.isArray(columnValue.data)
  ) {
    text = Buffer.from(columnValue.data).toString("utf8");
  } else {
    text = String(columnValue);
  }

  const jsonText = sanitizeJsonText(text);

  if (!jsonText) {
    fail(400, "Stored food_json is invalid JSON", { json_error: "empty value" });
  }

  try {
    const decoded = JSON.parse(jsonText);
    if (!isPlainObject(decoded)) {
      fail(400, "Stored food_json does not contain days array");
    }
    return decoded;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    fail(400, "Stored food_json is invalid JSON", { json_error: err.message });
  }
}

// ─── Food normalization ──────────────────────────────────────────────────────

function normalizeFoodForAdd(food) {
  if (!isPlainObject(food)) {
    fail(400, "food must be an object");
  }

  for (const field of REQUIRED_TEXT_FIELDS) {
    if (food[field] === undefined || food[field] === null || String(food[field]).trim() === "") {
      fail(400, `food.${field} is required`);
    }
  }

  for (const field of REQUIRED_MACRO_FIELDS) {
    if (!(field in food) || food[field] === "" || !isNumericValue(food[field])) {
      fail(400, `food.${field} must be numeric`);
    }
    if (Number(food[field]) < 0) {
      fail(400, `food.${field} cannot be negative`);
    }
  }

  return {
    food_name: String(food.food_name).trim(),
    calories: roundMacro(food.calories),
    carbs_g: roundMacro(food.carbs_g),
    protein_g: roundMacro(food.protein_g),
    fat_g: roundMacro(food.fat_g),
    fiber_g: roundMacro(food.fiber_g),
    portion_with_metric: String(food.portion_with_metric).trim(),
    category: String(food.category).trim(),
  };
}

function patchExistingFood(existingFood, incomingFood) {
  const updatedFood = isPlainObject(existingFood) ? { ...existingFood } : {};

  if (!isPlainObject(incomingFood)) {
    fail(400, "food must be an object");
  }

  for (const field of REQUIRED_TEXT_FIELDS) {
    if (field in incomingFood) {
      const value = String(incomingFood[field]).trim();
      if (value === "") {
        fail(400, `food.${field} cannot be empty`);
      }
      updatedFood[field] = value;
    }
  }

  for (const field of REQUIRED_MACRO_FIELDS) {
    if (field in incomingFood) {
      if (incomingFood[field] === "" || !isNumericValue(incomingFood[field])) {
        fail(400, `food.${field} must be numeric`);
      }
      if (Number(incomingFood[field]) < 0) {
        fail(400, `food.${field} cannot be negative`);
      }
      updatedFood[field] = roundMacro(incomingFood[field]);
    }
  }

  return updatedFood;
}

// ─── Macro aggregation ───────────────────────────────────────────────────────

function sumFoods(foods) {
  const total = { calories: 0, carbs_g: 0, protein_g: 0, fat_g: 0, fiber_g: 0 };

  for (const food of Array.isArray(foods) ? foods : []) {
    total.calories += Number(food?.calories ?? 0) || 0;
    total.carbs_g += Number(food?.carbs_g ?? 0) || 0;
    total.protein_g += Number(food?.protein_g ?? 0) || 0;
    total.fat_g += Number(food?.fat_g ?? 0) || 0;
    total.fiber_g += Number(food?.fiber_g ?? 0) || 0;
  }

  return {
    calories: roundMacro(total.calories),
    carbs_g: roundMacro(total.carbs_g),
    protein_g: roundMacro(total.protein_g),
    fat_g: roundMacro(total.fat_g),
    fiber_g: roundMacro(total.fiber_g),
  };
}

function sumDay(day) {
  let allFoods = [];
  for (const mealType of ALLOWED_MEALS) {
    const foods = resolveMealFoods(day, mealType, false);
    if (Array.isArray(foods)) {
      allFoods = allFoods.concat(foods);
    }
  }
  return sumFoods(allFoods);
}

function recalculateWeeklyMacros(foodJson) {
  if (!Array.isArray(foodJson.days)) {
    fail(400, "Invalid food_json structure. days array missing.");
  }

  const weeklyTotal = { calories: 0, carbs_g: 0, protein_g: 0, fat_g: 0, fiber_g: 0 };

  for (const day of foodJson.days) {
    for (const mealType of ALLOWED_MEALS) {
      const foods = resolveMealFoods(day, mealType, false);
      if (!Array.isArray(foods)) continue;
      for (const food of foods) {
        weeklyTotal.calories += Number(food?.calories ?? 0) || 0;
        weeklyTotal.carbs_g += Number(food?.carbs_g ?? 0) || 0;
        weeklyTotal.protein_g += Number(food?.protein_g ?? 0) || 0;
        weeklyTotal.fat_g += Number(food?.fat_g ?? 0) || 0;
        weeklyTotal.fiber_g += Number(food?.fiber_g ?? 0) || 0;
      }
    }
  }

  let dayCount = foodJson.days.length;
  if (dayCount <= 0) dayCount = 7;

  const note =
    foodJson.weekly_json_data && typeof foodJson.weekly_json_data.note === "string"
      ? foodJson.weekly_json_data.note
      : DEFAULT_WEEKLY_NOTE;

  const weeklyMacros = {
    calories: roundMacro(weeklyTotal.calories / dayCount),
    carbs_g: roundMacro(weeklyTotal.carbs_g / dayCount),
    protein_g: roundMacro(weeklyTotal.protein_g / dayCount),
    fat_g: roundMacro(weeklyTotal.fat_g / dayCount),
    fiber_g: roundMacro(weeklyTotal.fiber_g / dayCount),
    note,
  };

  foodJson.weekly_json_data = weeklyMacros;
  return weeklyMacros;
}

// ─── Audit log (fail-safe, HMAC-hashed PII) ──────────────────────────────────

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

async function writeAuthLogSafe(req, {
  eventType,
  userId,
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
       VALUES (?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
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
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/trainer-update-weekly-food-json-newtest
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "action": "add" | "update" | "delete",
 *     "id": <weekly row id>,
 *     "dietitian_id": "<code>",          // must match the token dietician
 *     "profile_id": "<client profile>",  // must belong to that dietician
 *     "day_code": "mon" | ...,
 *     "meal_type": "breakfast" | "lunch" | "snacks" | "dinner",
 *     "food_index": <int>,               // required for update/delete
 *     "food": { ... },                   // required for add/update
 *     "week_start_date": "YYYY-MM-DD",   // optional, tighter row match
 *     "week_end_date": "YYYY-MM-DD"      // optional, tighter row match
 *   }
 */
const trainerUpdateWeeklyFoodJsonNewtest = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Only POST method is allowed" });
  }

  let connection = null;
  let auditDietitianId = null;
  let auditProfileId = null;
  let auditAction = null;

  try {
    const payload = req.body;

    if (!isPlainObject(payload)) {
      fail(400, "Invalid JSON payload");
    }

    // ── 1. Validate action / id ─────────────────────────────────────────────
    const action = String(payload.action ?? "").trim().toLowerCase();
    if (!ALLOWED_ACTIONS.has(action)) {
      fail(400, "Invalid action. Allowed: add, update, delete");
    }
    auditAction = action;

    const id = Number.parseInt(payload.id, 10);
    if (!Number.isInteger(id) || id <= 0) {
      fail(400, "id is required");
    }

    // ── 2. Validate identity / target fields ────────────────────────────────
    // Payload spelling is dietitian_id; DB column remains dietician_id.
    const dietitianId = String(payload.dietitian_id ?? "").trim();
    if (dietitianId === "") {
      fail(400, "dietitian_id is required");
    }

    const profileId = requiredString(payload, "profile_id");
    const dayCode = requiredString(payload, "day_code").toLowerCase();
    const mealType = requiredString(payload, "meal_type").toLowerCase();

    if (!ALLOWED_MEALS.includes(mealType)) {
      fail(400, "Invalid meal_type. Allowed: breakfast, lunch, snacks, dinner");
    }

    // Optional but safer row matching.
    const weekStartDate = String(payload.week_start_date ?? "").trim();
    const weekEndDate = String(payload.week_end_date ?? "").trim();

    if (weekStartDate !== "" && !isValidDateString(weekStartDate)) {
      fail(400, "week_start_date must be YYYY-MM-DD");
    }
    if (weekEndDate !== "" && !isValidDateString(weekEndDate)) {
      fail(400, "week_end_date must be YYYY-MM-DD");
    }

    // ── 3. food_index / food presence checks ────────────────────────────────
    let foodIndex = null;
    if (action === "update" || action === "delete") {
      if (payload.food_index === undefined || !isNumericValue(payload.food_index)) {
        fail(400, "food_index is required for update/delete");
      }
      foodIndex = Number.parseInt(payload.food_index, 10);
      if (!Number.isInteger(foodIndex) || foodIndex < 0) {
        fail(400, "food_index cannot be negative");
      }
    }

    if ((action === "add" || action === "update") && !isPlainObject(payload.food)) {
      fail(400, "food object is required for add/update");
    }

    // ── 4. Token-bound authorization (IDOR fix) ─────────────────────────────
    // The JWT must prove the caller IS this dietician. Object-level ownership of
    // the target row is then enforced by the weekly-row WHERE filter below
    // (dietician_id + profile_id), exactly as the PHP did — no extra table.
    const self = requireDieticianSelfAccess(req, dietitianId);
    if (!self.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "weekly_food_json_denied",
        userId: String(req.user?.sub || req.user?.dietician?.dietician_id || ""),
        partnerCode: null,
        identifier: profileId,
        success: false,
        failureReason: self.message,
      });
      return res.status(self.statusCode).json({ ok: false, message: self.message });
    }

    const normalizedProfileId = normalizeId(profileId);
    if (!normalizedProfileId) {
      fail(400, "Invalid profile_id");
    }

    const access = {
      dieticianId: self.dieticianId,
      profileId: normalizedProfileId,
    };

    auditDietitianId = access.dieticianId;
    auditProfileId = access.profileId;

    // ── 5. Transaction: lock the row, mutate food_json, persist ─────────────
    connection = await pool.getConnection();
    await connection.beginTransaction();

    // status is intentionally NOT used as an edit gate (draft + approved both
    // remain editable). It is only selected to echo status_value back.
    const selectParams = [access.dieticianId, access.profileId];
    let selectSql = `
      SELECT
        id,
        dietician_id,
        profile_id,
        week_start_date,
        week_end_date,
        status,
        food_json
      FROM weekly_food_json_suggestions_newtest
      WHERE id = ?
        AND UPPER(TRIM(dietician_id)) = ?
        AND profile_id = ?
    `;
    // Bind id first to keep placeholder order aligned.
    selectParams.unshift(id);

    if (weekStartDate !== "") {
      selectSql += " AND week_start_date = ? ";
      selectParams.push(weekStartDate);
    }
    if (weekEndDate !== "") {
      selectSql += " AND week_end_date = ? ";
      selectParams.push(weekEndDate);
    }
    selectSql += " LIMIT 1 FOR UPDATE ";

    const [rows] = await connection.execute(selectSql, selectParams);
    const row = rows[0];

    if (!row) {
      fail(404, "Diet plan row not found. No row matched id + dietitian_id + profile_id.");
    }

    const foodJson = decodeStoredFoodJson(row.food_json);

    if (!Array.isArray(foodJson.days)) {
      fail(400, "Stored food_json does not contain days array");
    }

    // ── 6. Locate the day ────────────────────────────────────────────────────
    const dayIndex = resolveDayIndex(foodJson.days, dayCode);
    if (dayIndex < 0) {
      fail(404, "day_code not found in food_json", {
        requested_day_code: dayCode,
        available_day_codes: foodJson.days.map((d, i) => {
          if (!isPlainObject(d)) return null;
          const key = DAY_ID_KEYS.find((k) => d[k] !== undefined && d[k] !== null && d[k] !== "");
          return key ? String(d[key]) : `d${i + 1}`;
        }),
      });
    }
    const resolvedDay = foodJson.days[dayIndex];
    const resolvedDayCode =
      isPlainObject(resolvedDay) && resolvedDay.day_code !== undefined && resolvedDay.day_code !== null
        ? String(resolvedDay.day_code)
        : dayCode;

    // ── 7. Apply the mutation ────────────────────────────────────────────────
    let changedFood = null;
    let deletedFood = null;
    let finalFoodIndex = null;

    const day = foodJson.days[dayIndex];
    if (!isPlainObject(day)) {
      fail(400, "Stored day entry is not an object", { day_code: resolvedDayCode });
    }

    // Live reference into food_json; for "add" the meal/foods array is created
    // in whatever layout this day already uses.
    const mealFoods = resolveMealFoods(day, mealType, action === "add");
    if (!Array.isArray(mealFoods)) {
      fail(404, "Meal foods not found in food_json", {
        day_code: resolvedDayCode,
        meal_type: mealType,
        ...describeDayShape(day),
      });
    }

    if (action === "add") {
      const newFood = normalizeFoodForAdd(payload.food);
      finalFoodIndex = mealFoods.length;
      mealFoods.push(newFood);
      changedFood = newFood;
    }

    if (action === "update" || action === "delete") {
      if (foodIndex >= mealFoods.length || mealFoods[foodIndex] === undefined) {
        fail(404, "Food index not found", {
          day_code: resolvedDayCode,
          meal_type: mealType,
          food_index: foodIndex,
          food_count: mealFoods.length,
        });
      }
    }

    if (action === "update") {
      const updatedFood = patchExistingFood(mealFoods[foodIndex], payload.food);
      mealFoods[foodIndex] = updatedFood;
      finalFoodIndex = foodIndex;
      changedFood = updatedFood;
    }

    if (action === "delete") {
      deletedFood = mealFoods[foodIndex];
      mealFoods.splice(foodIndex, 1);
      finalFoodIndex = foodIndex;
    }

    // ── 8. Recompute weekly macros + persist ─────────────────────────────────
    const weeklyMacros = recalculateWeeklyMacros(foodJson);

    let updatedFoodJson;
    try {
      updatedFoodJson = JSON.stringify(foodJson);
    } catch (err) {
      fail(500, "Failed to encode updated food_json");
    }

    // status is intentionally NOT touched in this API.
    const updateParams = [
      updatedFoodJson,
      String(weeklyMacros.calories),
      String(weeklyMacros.carbs_g),
      String(weeklyMacros.fat_g),
      String(weeklyMacros.protein_g),
      String(weeklyMacros.fiber_g),
      id,
      access.dieticianId,
      access.profileId,
    ];
    let updateSql = `
      UPDATE weekly_food_json_suggestions_newtest
      SET
        food_json = ?,
        cal = ?,
        cabs = ?,
        fats = ?,
        \`Protein\` = ?,
        \`Fibre\` = ?,
        updated_at = NOW()
      WHERE id = ?
        AND UPPER(TRIM(dietician_id)) = ?
        AND profile_id = ?
    `;
    if (weekStartDate !== "") {
      updateSql += " AND week_start_date = ? ";
      updateParams.push(weekStartDate);
    }
    if (weekEndDate !== "") {
      updateSql += " AND week_end_date = ? ";
      updateParams.push(weekEndDate);
    }
    updateSql += " LIMIT 1 ";

    await connection.execute(updateSql, updateParams);
    await connection.commit();

    // ── 9. Build response summaries ──────────────────────────────────────────
    const selectedDay = foodJson.days[dayIndex];
    const selectedMealFoods = resolveMealFoods(selectedDay, mealType, false) || [];

    // Audit — success (fire-and-forget).
    writeAuthLogSafe(req, {
      eventType: `weekly_food_json_${action}`,
      userId: access.dieticianId,
      partnerCode: access.dieticianId,
      identifier: access.profileId,
      success: true,
      failureReason: `Diet plan food ${action} successful`,
    });

    return res.status(200).json({
      ok: true,
      message: `Diet plan food ${action} successful`,
      action,
      id,
      dietitian_id: access.dieticianId,
      profile_id: access.profileId,
      week_start_date: formatDateOnly(row.week_start_date),
      week_end_date: formatDateOnly(row.week_end_date),
      status_value:
        row.status === null || row.status === undefined ? null : Number(row.status),
      day_code: dayCode,
      resolved_day_code: resolvedDayCode,
      day_index: dayIndex,
      meal_type: mealType,
      food_index: finalFoodIndex,
      changed_food: changedFood,
      deleted_food: deletedFood,
      meal_summary: sumFoods(selectedMealFoods),
      day_summary: sumDay(selectedDay),
      weekly_json_data: weeklyMacros,
      food_json: foodJson,
    });
  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackErr) {
        console.error("WEEKLY_FOOD_JSON_NEWTEST_ROLLBACK_FAILED:", rollbackErr?.code || rollbackErr?.message);
      }
    }

    if (err instanceof ApiError) {
      await writeAuthLogSafe(req, {
        eventType: `weekly_food_json_${auditAction || "error"}_failed`,
        userId: auditDietitianId || String(req.user?.sub || ""),
        partnerCode: auditDietitianId,
        identifier: auditProfileId,
        success: false,
        failureReason: err.message,
      });
      return res.status(err.statusCode).json(err.payload);
    }

    console.error("WEEKLY_FOOD_JSON_NEWTEST_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "weekly_food_json_error",
      userId: auditDietitianId || String(req.user?.sub || ""),
      partnerCode: auditDietitianId,
      identifier: auditProfileId,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok: false,
      message: "Something went wrong while managing diet plan food",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  } finally {
    if (connection) connection.release();
  }
};

module.exports = { trainerUpdateWeeklyFoodJsonNewtest };
