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
// Recipe metadata the plan screen sends alongside a food (Method / ingredients /
// FitChef identifiers). Stored on the meal object exactly as received so the
// read endpoint can hand them back; never validated or reshaped here.
const RECIPE_PASSTHROUGH_FIELDS = ["recipe", "ingredients", "recipeId", "variantId", "hash", "eatingMomentId", "fitchefKey"];

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

/** Copy RECIPE_PASSTHROUGH_FIELDS that are present on source onto target, as received. */
function copyRecipePassthrough(source, target) {
  if (!isPlainObject(source)) return target;
  for (const key of RECIPE_PASSTHROUGH_FIELDS) {
    if (source[key] !== undefined) target[key] = source[key];
  }
  return target;
}

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
 * Real rows in weekly_food_json_suggestions_newtest do not always honour that,
 * so every meal access goes through a small accessor that understands:
 *
 *  A. "foods" layouts — a meal node that holds an array of food objects:
 *     - day.breakfast.foods                (canonical)
 *     - day.Breakfast / day.BREAKFAST      (case-insensitive key)
 *     - day.breakfast = [ ...foods ]       (meal is the array itself)
 *     - day.breakfast.items / .food_items / .food_list / .food / .dishes
 *     - day.meals.breakfast.foods          (meals keyed by type)
 *     - day.meals = [ { meal_type: "breakfast", foods: [...] }, ... ]
 *
 *  B. "recipe" layout — the generated-plan output where each entry of
 *     day.meals IS one recipe:
 *       { mealName: "breakfast", name, type, recipeId, variantId, recipe {..},
 *         nutrition: { kcals, carbohydrate, protein, fat, fiber },
 *         ingredients [..], alternatives [ ...same shape... ] }
 *     Here the recipe is exposed as food_index 0. Updating index 0 with a
 *     food whose name matches one of the entry's alternatives swaps the whole
 *     alternative in (recipe, image, ingredients, nutrition) and keeps the old
 *     recipe as an alternative, so the choice is reversible. Any other update
 *     patches name / nutrition in place. Extra foods a dietitian adds to such a
 *     meal live in entry.extra_foods and appear as index 1..n.
 *
 * All accessors operate on the LIVE objects so mutations persist to food_json.
 */
const MEAL_CONTAINER_KEYS = ["meals", "meal", "meal_plan", "mealplan", "menu", "diet", "plan"];
const MEAL_ID_KEYS = [
  "meal_type", "mealtype", "meal_name", "mealname", "meal", "slot", "title",
  "eating_moment", "eatingmoment", "code", "key", "type", "name",
];
const FOODS_KEYS = ["foods", "items", "food_items", "food_list", "food", "dishes", "list", "entries"];
const EXTRA_FOODS_KEY = "extra_foods";

/** Map generated-plan nutrition keys → the API's food macro keys. */
const NUTRITION_TO_MACRO = {
  calories: ["kcals", "kcal", "calories", "energy"],
  carbs_g: ["carbohydrate", "carbohydrates", "carbs", "carbs_g"],
  protein_g: ["protein", "proteins", "protein_g"],
  fat_g: ["fat", "fats", "fat_g"],
  fiber_g: ["fiber", "fibre", "fiber_g", "fibre_g"],
};

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

/** Does this meal entry identify itself as mealType (via any known id key)? */
function entryMatchesMeal(entry, want) {
  if (!isPlainObject(entry)) return false;
  const idTokens = MEAL_ID_KEYS.map(canonicalToken);
  for (const key of Object.keys(entry)) {
    if (!idTokens.includes(canonicalToken(key))) continue;
    const value = entry[key];
    if (typeof value !== "string" && typeof value !== "number") continue;
    if (canonicalMealType(value) === want) return true;
  }
  // Generated plans also carry recipe.recipe_meal_type: ["Breakfast"].
  const rmt = entry.recipe?.recipe_meal_type;
  if (Array.isArray(rmt) && rmt.length === 1 && canonicalMealType(rmt[0]) === want) return true;
  return false;
}

/** The label a meal entry carries, for diagnostics only. */
function entryMealLabel(entry) {
  if (!isPlainObject(entry)) return null;
  const preferred = ["mealName", "meal_name", "meal_type", "mealType", "meal", "slot", "title"];
  for (const key of preferred) {
    if (typeof entry[key] === "string" && entry[key] !== "") return entry[key];
  }
  const idTokens = MEAL_ID_KEYS.map(canonicalToken);
  for (const key of Object.keys(entry)) {
    if (idTokens.includes(canonicalToken(key)) && (typeof entry[key] === "string" || typeof entry[key] === "number")) {
      return String(entry[key]);
    }
  }
  return null;
}

/** Given a meal node (object or array), return its live foods array (or null). */
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

/** A generated-plan entry: one recipe per meal, macros under nutrition. */
function isRecipeMeal(entry) {
  if (!isPlainObject(entry)) return false;
  if (foodsArrayOf(entry, false)) return false;
  return (
    isPlainObject(entry.nutrition) ||
    entry.recipeId !== undefined ||
    entry.recipe_id !== undefined ||
    isPlainObject(entry.recipe) ||
    typeof entry.name === "string"
  );
}

function readNutritionValue(nutrition, macroKey) {
  if (!isPlainObject(nutrition)) return 0;
  for (const key of NUTRITION_TO_MACRO[macroKey]) {
    if (nutrition[key] !== undefined && nutrition[key] !== null && isNumericValue(nutrition[key])) {
      return Number(nutrition[key]);
    }
  }
  const ciKey = findKeyCI(nutrition, NUTRITION_TO_MACRO[macroKey]);
  return ciKey && isNumericValue(nutrition[ciKey]) ? Number(nutrition[ciKey]) : 0;
}

/** Write a macro into a nutrition object using the key it already uses (or the generated-plan default). */
function writeNutritionValue(nutrition, macroKey, value) {
  const ciKey = findKeyCI(nutrition, NUTRITION_TO_MACRO[macroKey]);
  nutrition[ciKey || NUTRITION_TO_MACRO[macroKey][0]] = roundMacro(value);
}

function servingsText(entry) {
  if (typeof entry.portion_with_metric === "string" && entry.portion_with_metric.trim() !== "") {
    return entry.portion_with_metric;
  }
  const people = entry.recipe?.recipe_amount_of_people;
  if (Array.isArray(people) && people.length && isNumericValue(people[0])) {
    return `serves ${Number(people[0])}`;
  }
  return "serves 1";
}

function capitalize(s) {
  const t = String(s ?? "");
  return t ? t[0].toUpperCase() + t.slice(1) : t;
}

/** Compact view of an alternative recipe for the response payload. */
function alternativeSummary(alt) {
  if (!isPlainObject(alt)) return null;
  return {
    food_name: String(alt.name ?? ""),
    calories: roundMacro(readNutritionValue(alt.nutrition, "calories")),
    carbs_g: roundMacro(readNutritionValue(alt.nutrition, "carbs_g")),
    protein_g: roundMacro(readNutritionValue(alt.nutrition, "protein_g")),
    fat_g: roundMacro(readNutritionValue(alt.nutrition, "fat_g")),
    fiber_g: roundMacro(readNutritionValue(alt.nutrition, "fiber_g")),
    recipe_id: alt.recipeId ?? alt.recipe_id ?? null,
    variant_id: alt.variantId ?? alt.variant_id ?? null,
    image: alt.recipe?.image ?? null,
  };
}

/** Present a generated-plan recipe entry in the API's food shape (read-only view). */
function recipeMealToFood(entry, mealType) {
  return {
    food_name: String(entry.name ?? ""),
    calories: roundMacro(readNutritionValue(entry.nutrition, "calories")),
    carbs_g: roundMacro(readNutritionValue(entry.nutrition, "carbs_g")),
    protein_g: roundMacro(readNutritionValue(entry.nutrition, "protein_g")),
    fat_g: roundMacro(readNutritionValue(entry.nutrition, "fat_g")),
    fiber_g: roundMacro(readNutritionValue(entry.nutrition, "fiber_g")),
    portion_with_metric: servingsText(entry),
    category: typeof entry.category === "string" && entry.category !== "" ? entry.category : capitalize(mealType),
    recipe_id: entry.recipeId ?? entry.recipe_id ?? null,
    variant_id: entry.variantId ?? entry.variant_id ?? null,
    image: entry.recipe?.image ?? null,
    ingredients: Array.isArray(entry.ingredients) ? entry.ingredients : [],
    alternatives: Array.isArray(entry.alternatives)
      ? entry.alternatives.map(alternativeSummary).filter(Boolean)
      : [],
  };
}

/**
 * Apply an API food object to the recipe entry at parent[key].
 * If food_name names one of the entry's alternatives, the alternative becomes
 * the recipe and the previous recipe takes its slot in alternatives.
 * Then name / nutrition / portion / category are written from the food.
 */
function applyFoodToRecipeMeal(parent, key, food) {
  let entry = parent[key];
  const wantName = canonicalToken(food.food_name);
  const alts = Array.isArray(entry.alternatives) ? entry.alternatives : [];
  const altIdx = alts.findIndex((alt) => isPlainObject(alt) && canonicalToken(alt.name) === wantName);

  if (altIdx >= 0 && canonicalToken(entry.name) !== wantName) {
    const chosen = alts[altIdx];
    const { alternatives: _ignored, [EXTRA_FOODS_KEY]: extras, ...previousRecipe } = entry;
    const swapped = { ...chosen };
    swapped.alternatives = alts.slice();
    swapped.alternatives[altIdx] = previousRecipe;
    if (swapped.mealName === undefined && entry.mealName !== undefined) swapped.mealName = entry.mealName;
    if (swapped.eatingMomentId === undefined && entry.eatingMomentId !== undefined) {
      swapped.eatingMomentId = entry.eatingMomentId;
    }
    if (extras !== undefined) swapped[EXTRA_FOODS_KEY] = extras;
    parent[key] = swapped;
    entry = swapped;
  }

  entry.name = String(food.food_name);
  if (!isPlainObject(entry.nutrition)) entry.nutrition = {};
  for (const macroKey of REQUIRED_MACRO_FIELDS) {
    if (food[macroKey] !== undefined && isNumericValue(food[macroKey])) {
      writeNutritionValue(entry.nutrition, macroKey, food[macroKey]);
    }
  }
  if (typeof food.portion_with_metric === "string" && food.portion_with_metric.trim() !== "") {
    entry.portion_with_metric = food.portion_with_metric.trim();
  }
  if (typeof food.category === "string" && food.category.trim() !== "") {
    entry.category = food.category.trim();
  }
  copyRecipePassthrough(food, entry);
  return entry;
}

/** Build a brand-new recipe-style entry from an API food (used by "add" on a missing meal). */
function newRecipeMealFromFood(mealType, food) {
  const nutrition = {};
  for (const macroKey of REQUIRED_MACRO_FIELDS) writeNutritionValue(nutrition, macroKey, food[macroKey]);
  return {
    mealName: mealType,
    name: String(food.food_name),
    nutrition,
    portion_with_metric: food.portion_with_metric,
    category: food.category,
    ingredients: [],
    alternatives: [],
    custom: true,
    ...copyRecipePassthrough(food, {}),
  };
}

/** Accessor over a plain foods array. */
function makeFoodsAccessor(arr) {
  return {
    kind: "foods",
    list: () => arr,
    count: () => arr.length,
    get: (i) => arr[i],
    set: (i, food) => { arr[i] = food; },
    push: (food) => { arr.push(food); return arr.length - 1; },
    remove: (i) => arr.splice(i, 1)[0],
  };
}

/** Accessor over a generated-plan recipe entry living at parent[key]. */
function makeRecipeAccessor(parent, key, mealType) {
  const entry = () => parent[key];
  const hasPrimary = () => {
    const e = entry();
    return isPlainObject(e) && e.name !== null && e.name !== undefined && String(e.name) !== "";
  };
  const extras = (create) => {
    const e = entry();
    if (!Array.isArray(e[EXTRA_FOODS_KEY])) {
      if (!create) return [];
      e[EXTRA_FOODS_KEY] = [];
    }
    return e[EXTRA_FOODS_KEY];
  };
  return {
    kind: "recipe",
    list: () => (hasPrimary() ? [recipeMealToFood(entry(), mealType)] : []).concat(extras(false)),
    count: () => (hasPrimary() ? 1 : 0) + extras(false).length,
    get: (i) => (i === 0 && hasPrimary() ? recipeMealToFood(entry(), mealType) : extras(false)[i - (hasPrimary() ? 1 : 0)]),
    set: (i, food) => {
      if (i === 0 && hasPrimary()) applyFoodToRecipeMeal(parent, key, food);
      else extras(true)[i - (hasPrimary() ? 1 : 0)] = food;
    },
    push: (food) => {
      if (!hasPrimary()) {
        applyFoodToRecipeMeal(parent, key, food);
        return 0;
      }
      const e = extras(true);
      e.push(food);
      return e.length; // index = 1 + (e.length - 1)
    },
    remove: (i) => {
      if (i === 0 && hasPrimary()) {
        if (extras(false).length > 0) {
          fail(400, "Remove the added foods of this meal before deleting its recipe");
        }
        const removed = recipeMealToFood(entry(), mealType);
        if (Array.isArray(parent)) parent.splice(key, 1);
        else delete parent[key];
        return removed;
      }
      return extras(true).splice(i - (hasPrimary() ? 1 : 0), 1)[0];
    },
  };
}

/** Locate the meal node for mealType. Returns { parent, key } (node = parent[key]) or null. */
function locateMeal(day, mealType) {
  if (!isPlainObject(day)) return null;
  const want = canonicalMealType(mealType);

  // 1. Direct key on the day (exact, then case/format-insensitive).
  if (day[mealType] !== null && typeof day[mealType] === "object") return { parent: day, key: mealType };
  for (const key of Object.keys(day)) {
    if (canonicalMealType(key) === want && day[key] !== null && typeof day[key] === "object") {
      return { parent: day, key };
    }
  }

  // 2. Inside a meals container.
  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;

  if (Array.isArray(container)) {
    for (let i = 0; i < container.length; i++) {
      if (entryMatchesMeal(container[i], want)) return { parent: container, key: i };
    }
    return null;
  }
  if (isPlainObject(container)) {
    for (const key of Object.keys(container)) {
      if (canonicalMealType(key) === want && container[key] !== null && typeof container[key] === "object") {
        return { parent: container, key };
      }
    }
  }
  return null;
}

/**
 * Resolve an accessor for mealType in day, or null when absent.
 * With create=true the meal is created in whichever layout the day already
 * uses (recipe entry in a generated plan, foods array otherwise).
 */
function resolveMealAccessor(day, mealType, create = false) {
  if (!isPlainObject(day)) return null;

  const located = locateMeal(day, mealType);
  if (located) {
    const node = located.parent[located.key];
    const foods = foodsArrayOf(node, false);
    if (foods) return makeFoodsAccessor(foods);
    if (isRecipeMeal(node)) return makeRecipeAccessor(located.parent, located.key, mealType);
    if (create && isPlainObject(node)) return makeFoodsAccessor(foodsArrayOf(node, true));
    return null;
  }
  if (!create) return null;

  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;

  if (Array.isArray(container)) {
    if (container.some(isRecipeMeal)) {
      // Generated-plan layout: placeholder recipe entry, filled by the first push().
      container.push({ mealName: mealType, name: "", nutrition: {}, ingredients: [], alternatives: [], custom: true });
      return makeRecipeAccessor(container, container.length - 1, mealType);
    }
    const entry = { meal_type: mealType, foods: [] };
    container.push(entry);
    return makeFoodsAccessor(entry.foods);
  }
  if (isPlainObject(container)) {
    container[mealType] = { foods: [] };
    return makeFoodsAccessor(container[mealType].foods);
  }
  day[mealType] = { foods: [] };
  return makeFoodsAccessor(day[mealType].foods);
}

/** Every food in a day (all four meal types, plus any unlabeled recipe entries), as API food objects. */
function listDayFoods(day) {
  if (!isPlainObject(day)) return [];
  const seen = new Set();
  let all = [];
  for (const mealType of ALLOWED_MEALS) {
    const located = locateMeal(day, mealType);
    if (!located) continue;
    const node = located.parent[located.key];
    if (seen.has(node)) continue;
    seen.add(node);
    const accessor = resolveMealAccessor(day, mealType, false);
    if (accessor) all = all.concat(accessor.list());
  }
  // Recipe entries whose label is not one of the four meal types still count.
  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;
  if (Array.isArray(container)) {
    container.forEach((entry, i) => {
      if (seen.has(entry) || !isRecipeMeal(entry)) return;
      seen.add(entry);
      all = all.concat(makeRecipeAccessor(container, i, entryMealLabel(entry) || "meal").list());
    });
  }
  return all;
}

/** Keep a generated plan's own day.nutrition rollup consistent after an edit. */
function syncDayNutrition(day, totals) {
  if (!isPlainObject(day) || !isPlainObject(day.nutrition)) return;
  for (const macroKey of REQUIRED_MACRO_FIELDS) {
    const ciKey = findKeyCI(day.nutrition, NUTRITION_TO_MACRO[macroKey]);
    if (ciKey) day.nutrition[ciKey] = roundMacro(totals[macroKey]);
  }
}

/** Non-PHI structural hint for 404 diagnostics: which keys/meals the day exposes. */
function describeDayShape(day) {
  if (!isPlainObject(day)) return { day_type: Array.isArray(day) ? "array" : typeof day };
  const containerKey = findKeyCI(day, MEAL_CONTAINER_KEYS);
  const container = containerKey ? day[containerKey] : null;
  let mealIds = null;
  if (Array.isArray(container)) {
    mealIds = container.map(entryMealLabel);
  } else if (isPlainObject(container)) {
    mealIds = Object.keys(container);
  }
  return {
    day_keys: Object.keys(day),
    meals_container: containerKey,
    meal_ids: mealIds,
    meals_found: ALLOWED_MEALS.filter((m) => resolveMealAccessor(day, m, false) !== null),
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
    ...copyRecipePassthrough(food, {}),
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

  copyRecipePassthrough(incomingFood, updatedFood);

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
  return sumFoods(listDayFoods(day));
}

function recalculateWeeklyMacros(foodJson) {
  if (!Array.isArray(foodJson.days)) {
    fail(400, "Invalid food_json structure. days array missing.");
  }

  const weeklyTotal = { calories: 0, carbs_g: 0, protein_g: 0, fat_g: 0, fiber_g: 0 };

  for (const day of foodJson.days) {
    for (const food of listDayFoods(day)) {
      weeklyTotal.calories += Number(food?.calories ?? 0) || 0;
      weeklyTotal.carbs_g += Number(food?.carbs_g ?? 0) || 0;
      weeklyTotal.protein_g += Number(food?.protein_g ?? 0) || 0;
      weeklyTotal.fat_g += Number(food?.fat_g ?? 0) || 0;
      weeklyTotal.fiber_g += Number(food?.fiber_g ?? 0) || 0;
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

    // Accessor over the live food_json; for "add" the meal is created in
    // whatever layout this day already uses (see "Meal resolution").
    const meal = resolveMealAccessor(day, mealType, action === "add");
    if (!meal) {
      fail(404, "Meal foods not found in food_json", {
        day_code: resolvedDayCode,
        meal_type: mealType,
        ...describeDayShape(day),
      });
    }

    if (action === "add") {
      const newFood = normalizeFoodForAdd(payload.food);
      finalFoodIndex = meal.push(newFood);
      changedFood = meal.get(finalFoodIndex);
    }

    if (action === "update" || action === "delete") {
      if (foodIndex >= meal.count() || meal.get(foodIndex) === undefined) {
        fail(404, "Food index not found", {
          day_code: resolvedDayCode,
          meal_type: mealType,
          food_index: foodIndex,
          food_count: meal.count(),
        });
      }
    }

    if (action === "update") {
      const updatedFood = patchExistingFood(meal.get(foodIndex), payload.food);
      meal.set(foodIndex, updatedFood);
      finalFoodIndex = foodIndex;
      changedFood = meal.get(foodIndex);
    }

    if (action === "delete") {
      deletedFood = meal.remove(foodIndex);
      finalFoodIndex = foodIndex;
    }

    // Generated plans carry their own per-day nutrition rollup; keep it in step.
    syncDayNutrition(day, sumDay(day));

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
    const selectedMeal = resolveMealAccessor(selectedDay, mealType, false);
    const selectedMealFoods = selectedMeal ? selectedMeal.list() : [];

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
