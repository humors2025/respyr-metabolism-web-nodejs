"use strict";

/**
 * reset-weekly-food-json-newtest.js
 *
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/reset-weekly-food-json-newtest
 * Auth     : Bearer JWT (authMiddleware must run before this handler)
 *
 * Purpose  : "Reset week" — discard every trainer edit made to a week's plan
 *            and restore weekly_food_json_suggestions_newtest.food_json to
 *            original_food_json, the untouched snapshot written once by
 *            store_weekly_food_json_suggestion_newtest.js at generation time
 *            and never modified by trainer-update-weekly-food-json-newtest.js.
 *
 * Behaviour:
 *  - Same identity contract as trainer-update-weekly-food-json-newtest.js:
 *    { id, dietitian_id, profile_id, week_start_date?, week_end_date? }.
 *  - Locks the row with SELECT ... FOR UPDATE inside a transaction, same as
 *    the sibling endpoint, so a reset cannot race a concurrent trainer edit.
 *  - If original_food_json is NULL (a row written before this column existed,
 *    or one the generator has never populated), this fails with 409 rather
 *    than silently wiping food_json to nothing.
 *  - Weekly macros (cal, cabs, fats, Protein, Fibre) are recalculated from
 *    the restored plan using the same aggregation logic as
 *    trainer-update-weekly-food-json-newtest.js, never trusted from a stored
 *    value, so they can never drift from what food_json actually contains.
 *  - digestive_score / recovery_score are untouched — trainer edits never
 *    change them either, so there is nothing to restore there.
 *  - status is left as-is. Reset does not re-approve or un-approve a plan;
 *    that is a separate, deliberate action the dietitian takes.
 *
 * VAPT hardening:
 *  - Token-bound identity via requireDieticianSelfAccess (same as the sibling).
 *  - SELECT ... FOR UPDATE transaction locking.
 *  - Parameterized SQL.
 *  - Production-safe error responses.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

const {
  requireDieticianSelfAccess,
  normalizeId,
} = require("../../../../utils/accessControl");

// =============================================================================
// CONSTANTS
// =============================================================================

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const REQUIRED_MACRO_FIELDS = [
  "calories",
  "carbs_g",
  "protein_g",
  "fat_g",
  "fiber_g",
];

const DEFAULT_WEEKLY_NOTE =
  "These values represent the average daily nutrient intake across the full 7-day week.";

// =============================================================================
// API ERROR
// =============================================================================

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

// =============================================================================
// GENERIC HELPERS
// (mirrors trainer-update-weekly-food-json-newtest.js exactly, so the two
//  files treat the same stored food_json shape identically)
// =============================================================================

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

function formatDateOnly(value) {
  if (!value) return null;
  if (value instanceof Date) {
    if (Number.isNaN(value.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return `${value.getFullYear()}-${pad(value.getMonth() + 1)}-${pad(value.getDate())}`;
  }
  return String(value).slice(0, 10);
}

function roundMacro(value) {
  const n = Number(value) || 0;
  return (Math.sign(n) * Math.round(Math.abs(n) * 100 + Number.EPSILON)) / 100;
}

function sanitizeJsonText(value) {
  return String(value)
    .replace(/^﻿/, "")
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "")
    .trim();
}

/**
 * Decode a stored food_json column value. Same contract as
 * trainer-update-weekly-food-json-newtest.js's decodeStoredFoodJson, applied
 * here to original_food_json instead — same column type (longtext), same
 * possible encodings (object already parsed, Buffer, or raw string).
 */
function decodeStoredFoodJson(columnValue, label) {
  if (columnValue === null || columnValue === undefined) {
    fail(409, `${label} is empty — nothing to reset`);
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
    fail(500, `${label} is corrupted (empty after decode)`);
  }

  try {
    const decoded = JSON.parse(jsonText);
    if (!isPlainObject(decoded)) {
      fail(500, `${label} does not contain a valid plan object`);
    }
    return decoded;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    fail(500, `${label} is corrupted (invalid JSON)`, { json_error: err.message });
  }
}

// =============================================================================
// MACRO RECALCULATION
// (same aggregation shape as trainer-update-weekly-food-json-newtest.js's
//  recalculateWeeklyMacros — kept independent/local per this codebase's
//  established convention of self-contained endpoint files)
// =============================================================================

function listDayFoodsFlat(day) {
  if (!isPlainObject(day)) return [];
  const foods = [];
  for (const mealKey of ["breakfast", "lunch", "snacks", "dinner"]) {
    const meal = day[mealKey];
    if (Array.isArray(meal)) {
      foods.push(...meal);
    } else if (isPlainObject(meal) && Array.isArray(meal.foods)) {
      foods.push(...meal.foods);
    } else if (isPlainObject(meal) && typeof meal.name === "string") {
      // Single recipe-shaped meal (mirrors recipeMealToFood in the sibling file)
      foods.push({
        calories: meal?.nutrition?.calories ?? meal?.nutrition?.kcal ?? 0,
        carbs_g: meal?.nutrition?.carbs_g ?? meal?.nutrition?.carbohydrate ?? 0,
        protein_g: meal?.nutrition?.protein_g ?? meal?.nutrition?.protein ?? 0,
        fat_g: meal?.nutrition?.fat_g ?? meal?.nutrition?.fat ?? 0,
        fiber_g: meal?.nutrition?.fiber_g ?? meal?.nutrition?.fiber ?? 0,
      });
      if (Array.isArray(meal[EXTRA_FOODS_KEY])) {
        foods.push(...meal[EXTRA_FOODS_KEY]);
      }
    }
  }
  return foods;
}

const EXTRA_FOODS_KEY = "extra_foods";

function recalculateWeeklyMacros(foodJson) {
  if (!Array.isArray(foodJson.days)) {
    fail(500, "original_food_json is invalid: days array missing");
  }

  const total = { calories: 0, carbs_g: 0, protein_g: 0, fat_g: 0, fiber_g: 0 };

  for (const day of foodJson.days) {
    for (const food of listDayFoodsFlat(day)) {
      total.calories += Number(food?.calories ?? 0) || 0;
      total.carbs_g += Number(food?.carbs_g ?? 0) || 0;
      total.protein_g += Number(food?.protein_g ?? 0) || 0;
      total.fat_g += Number(food?.fat_g ?? 0) || 0;
      total.fiber_g += Number(food?.fiber_g ?? 0) || 0;
    }
  }

  const dayCount = foodJson.days.length > 0 ? foodJson.days.length : 7;

  const note =
    foodJson.weekly_json_data && typeof foodJson.weekly_json_data.note === "string"
      ? foodJson.weekly_json_data.note
      : DEFAULT_WEEKLY_NOTE;

  const weeklyMacros = {
    calories: roundMacro(total.calories / dayCount),
    carbs_g: roundMacro(total.carbs_g / dayCount),
    protein_g: roundMacro(total.protein_g / dayCount),
    fat_g: roundMacro(total.fat_g / dayCount),
    fiber_g: roundMacro(total.fiber_g / dayCount),
    note,
  };

  foodJson.weekly_json_data = weeklyMacros;
  return weeklyMacros;
}

// =============================================================================
// AUDIT LOG (same shape as the sibling endpoints)
// =============================================================================

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

async function writeAuthLogSafe(req, { eventType, userId, partnerCode, identifier, success, failureReason }) {
  try {
    await pool.execute(
      `INSERT INTO app_auth_logs (
         event_type, user_id, role, partner_code, identifier_hash,
         ip_hash, user_agent_hash, session_id_hash, success, failure_reason
       ) VALUES (?, ?, NULL, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
        partnerCode ?? null,
        identifier !== null && identifier !== undefined ? authLogHash(identifier) : null,
        authLogHash(getClientIp(req)),
        authLogHash(getUserAgent(req)),
        success ? 1 : 0,
        failureReason !== null && failureReason !== undefined ? String(failureReason).slice(0, 255) : null,
      ]
    );
  } catch (err) {
    console.error("RESET_WEEKLY_FOOD_JSON_NEWTEST_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// =============================================================================
// CONTROLLER
// =============================================================================

/**
 * POST /dietitian/api/web/reset-weekly-food-json-newtest
 * Body: { id, dietitian_id, profile_id, week_start_date?, week_end_date? }
 */
const resetWeeklyFoodJsonNewtest = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Only POST method is allowed" });
  }

  let connection = null;
  let auditDietitianId = null;
  let auditProfileId = null;

  try {
    const payload = req.body;
    if (!isPlainObject(payload)) fail(400, "Invalid JSON payload");

    const id = Number.parseInt(payload.id, 10);
    if (!Number.isInteger(id) || id <= 0) fail(400, "id is required");

    const dietitianId = String(payload.dietitian_id ?? "").trim();
    if (dietitianId === "") fail(400, "dietitian_id is required");

    const profileId = requiredString(payload, "profile_id");

    const weekStartDate = String(payload.week_start_date ?? "").trim();
    const weekEndDate = String(payload.week_end_date ?? "").trim();

    if (weekStartDate !== "" && !isValidDateString(weekStartDate)) {
      fail(400, "week_start_date must be YYYY-MM-DD");
    }
    if (weekEndDate !== "" && !isValidDateString(weekEndDate)) {
      fail(400, "week_end_date must be YYYY-MM-DD");
    }

    // ── Auth ──────────────────────────────────────────────────────────────
    const self = requireDieticianSelfAccess(req, dietitianId);
    if (!self.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "weekly_food_json_reset_denied",
        userId: String(req.user?.sub || req.user?.dietician?.dietician_id || ""),
        partnerCode: null,
        identifier: profileId,
        success: false,
        failureReason: self.message,
      });
      return res.status(self.statusCode).json({ ok: false, message: self.message });
    }

    const normalizedProfileId = normalizeId(profileId);
    if (!normalizedProfileId) fail(400, "Invalid profile_id");

    const access = { dieticianId: self.dieticianId, profileId: normalizedProfileId };
    auditDietitianId = access.dieticianId;
    auditProfileId = access.profileId;

    // ── Lock + read ──────────────────────────────────────────────────────
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const selectParams = [id, access.dieticianId, access.profileId];
    let selectSql = `
      SELECT id, week_start_date, week_end_date, status, original_food_json
      FROM weekly_food_json_suggestions_newtest
      WHERE id = ?
        AND UPPER(TRIM(dietician_id)) = ?
        AND profile_id = ?
    `;
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

    const originalPlan = decodeStoredFoodJson(row.original_food_json, "original_food_json");

    // ── Recalculate macros from the restored plan ───────────────────────
    const weeklyMacros = recalculateWeeklyMacros(originalPlan);

    let restoredFoodJson;
    try {
      restoredFoodJson = JSON.stringify(originalPlan);
    } catch (err) {
      fail(500, "Failed to encode restored food_json");
    }

    // ── Write ────────────────────────────────────────────────────────────
    const [updateResult] = await connection.execute(
      `
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
        LIMIT 1
      `,
      [
        restoredFoodJson,
        String(weeklyMacros.calories),
        String(weeklyMacros.carbs_g),
        String(weeklyMacros.fat_g),
        String(weeklyMacros.protein_g),
        String(weeklyMacros.fiber_g),
        id,
      ]
    );

    if (!updateResult || updateResult.affectedRows !== 1) {
      fail(409, "Diet plan row could not be reset");
    }

    await connection.commit();

    await writeAuthLogSafe(req, {
      eventType: "weekly_food_json_reset",
      userId: access.dieticianId,
      partnerCode: access.dieticianId,
      identifier: access.profileId,
      success: true,
      failureReason: "Week reset to originally generated plan",
    });

    return res.status(200).json({
      ok: true,
      message: "Week reset to the originally generated plan",
      id,
      dietitian_id: access.dieticianId,
      profile_id: access.profileId,
      week_start_date: formatDateOnly(row.week_start_date),
      week_end_date: formatDateOnly(row.week_end_date),
      status_value: row.status === null || row.status === undefined ? null : Number(row.status),
      weekly_json_data: weeklyMacros,
      food_json: originalPlan,
    });
  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackErr) {
        console.error("RESET_WEEKLY_FOOD_JSON_NEWTEST_ROLLBACK_FAILED:", rollbackErr?.code || rollbackErr?.message);
      }
    }

    if (err instanceof ApiError) {
      await writeAuthLogSafe(req, {
        eventType: "weekly_food_json_reset_failed",
        userId: auditDietitianId || String(req.user?.sub || ""),
        partnerCode: auditDietitianId,
        identifier: auditProfileId,
        success: false,
        failureReason: err.message,
      });
      return res.status(err.statusCode).json(err.payload);
    }

    console.error("RESET_WEEKLY_FOOD_JSON_NEWTEST_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "weekly_food_json_reset_error",
      userId: auditDietitianId || String(req.user?.sub || ""),
      partnerCode: auditDietitianId,
      identifier: auditProfileId,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      ok: false,
      message: "Something went wrong while resetting the diet plan",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  } finally {
    if (connection) connection.release();
  }
};

module.exports = { resetWeeklyFoodJsonNewtest };