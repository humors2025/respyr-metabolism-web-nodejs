"use strict";

/**
 * undo-weekly-food-json-newtest.js
 *
 * Endpoints : POST /dietitian/api/web/undo-weekly-food-json-newtest
 *             GET  /dietitian/api/web/undo-depth-weekly-food-json-newtest
 * Auth      : Bearer JWT (authMiddleware must run before these handlers)
 *
 * Purpose   : Step the plan back ONE action — the server-side twin of the
 *             FitChef trainer dashboard's /api/undo. Every write to
 *             weekly_food_json_suggestions_newtest.food_json (trainer update,
 *             custom meal) snapshots the row first (src/utils/
 *             weeklyFoodJsonUndo.js); this pops the newest snapshot back into
 *             the row and recomputes the weekly macro columns from it, the
 *             same way reset-weekly-food-json-newtest does for the original.
 *
 *             Reset clears the stack (nothing to step back to is the truth
 *             after a reset), so Undo can never step INTO a state that Reset
 *             threw away.
 *
 * VAPT hardening (same as the sibling newtest endpoints):
 *  - Token-bound identity (dietitian_id must equal the JWT's).
 *  - SELECT ... FOR UPDATE transaction locking on the plan row AND the
 *    snapshot, so two Undos cannot pop the same step.
 *  - Parameterized SQL, no-store cache headers, audit log rows.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

const { requireDieticianSelfAccess, normalizeId } = require("../../../../utils/accessControl");
const { peekUndoSnapshot, deleteUndoSnapshot, undoDepth } = require("../../../../utils/weeklyFoodJsonUndo");

// =============================================================================
// CONSTANTS
// =============================================================================

const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

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
// GENERIC HELPERS (mirror reset-weekly-food-json-newtest.js)
// =============================================================================

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function readString(source, key) {
  if (source[key] === undefined || source[key] === null) return "";
  return String(source[key]).trim();
}

function isValidDateString(date) {
  if (typeof date !== "string" || date === "") return false;
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) return false;
  const parsed = new Date(`${date}T00:00:00.000Z`);
  if (Number.isNaN(parsed.getTime())) return false;
  const [y, m, d] = date.split("-").map(Number);
  return parsed.getUTCFullYear() === y && parsed.getUTCMonth() + 1 === m && parsed.getUTCDate() === d;
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

function decodeStoredFoodJson(columnValue, label) {
  if (columnValue === null || columnValue === undefined) {
    fail(409, `${label} is empty — nothing to restore`);
  }
  if (isPlainObject(columnValue) || Array.isArray(columnValue)) return columnValue;

  let text;
  if (Buffer.isBuffer(columnValue)) {
    text = columnValue.toString("utf8");
  } else if (isPlainObject(columnValue) && columnValue.type === "Buffer" && Array.isArray(columnValue.data)) {
    text = Buffer.from(columnValue.data).toString("utf8");
  } else {
    text = String(columnValue);
  }

  const jsonText = sanitizeJsonText(text);
  if (!jsonText) fail(500, `${label} is corrupted (empty after decode)`);

  try {
    const decoded = JSON.parse(jsonText);
    if (!isPlainObject(decoded)) fail(500, `${label} does not contain a valid plan object`);
    return decoded;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    fail(500, `${label} is corrupted (invalid JSON)`, { json_error: err.message });
  }
}

// =============================================================================
// MACRO RECALCULATION (same aggregation as the sibling newtest files)
// =============================================================================

const EXTRA_FOODS_KEY = "extra_foods";

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
      foods.push({
        calories: meal?.nutrition?.calories ?? meal?.nutrition?.kcal ?? 0,
        carbs_g: meal?.nutrition?.carbs_g ?? meal?.nutrition?.carbohydrate ?? 0,
        protein_g: meal?.nutrition?.protein_g ?? meal?.nutrition?.protein ?? 0,
        fat_g: meal?.nutrition?.fat_g ?? meal?.nutrition?.fat ?? 0,
        fiber_g: meal?.nutrition?.fiber_g ?? meal?.nutrition?.fiber ?? 0,
      });
      if (Array.isArray(meal[EXTRA_FOODS_KEY])) foods.push(...meal[EXTRA_FOODS_KEY]);
    }
  }
  return foods;
}

function recalculateWeeklyMacros(foodJson) {
  if (!Array.isArray(foodJson.days)) fail(500, "snapshot is invalid: days array missing");

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
// AUDIT LOG
// =============================================================================

function getClientIp(req) {
  const ip = (typeof req.ip === "string" && req.ip) || req.socket?.remoteAddress || req.connection?.remoteAddress || "0.0.0.0";
  return String(ip).slice(0, 64);
}

function getUserAgent(req) {
  const ua = (typeof req.get === "function" && req.get("user-agent")) || req.headers?.["user-agent"] || "";
  return String(ua).slice(0, 500);
}

function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto.createHmac("sha256", SECURITY_PEPPER).update(String(value).trim().toLowerCase()).digest("hex");
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
    console.error("UNDO_WEEKLY_FOOD_JSON_NEWTEST_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// =============================================================================
// SHARED: read + authorize the identity fields from body or query
// =============================================================================

async function resolveIdentity(req, source, eventPrefix) {
  if (!isPlainObject(source)) fail(400, "Invalid payload");

  const id = Number.parseInt(source.id ?? source.record_id, 10);
  if (!Number.isInteger(id) || id <= 0) fail(400, "id is required");

  // dietitian_id falls back to the token, the way custom-meal does
  const dietitianId = readString(source, "dietitian_id") || String(req.user?.sub || req.user?.dietician?.dietician_id || "").trim();
  if (dietitianId === "") fail(400, "dietitian_id is required");

  const profileId = readString(source, "profile_id");
  if (profileId === "") fail(400, "profile_id is required");

  const weekStartDate = readString(source, "week_start_date");
  const weekEndDate = readString(source, "week_end_date");
  if (weekStartDate !== "" && !isValidDateString(weekStartDate)) fail(400, "week_start_date must be YYYY-MM-DD");
  if (weekEndDate !== "" && !isValidDateString(weekEndDate)) fail(400, "week_end_date must be YYYY-MM-DD");

  const self = requireDieticianSelfAccess(req, dietitianId);
  if (!self.allowed) {
    await writeAuthLogSafe(req, {
      eventType: `${eventPrefix}_denied`,
      userId: String(req.user?.sub || req.user?.dietician?.dietician_id || ""),
      partnerCode: null,
      identifier: profileId,
      success: false,
      failureReason: self.message,
    });
    fail(self.statusCode, self.message);
  }

  const normalizedProfileId = normalizeId(profileId);
  if (!normalizedProfileId) fail(400, "Invalid profile_id");

  return { id, dieticianId: self.dieticianId, profileId: normalizedProfileId, weekStartDate, weekEndDate };
}

// =============================================================================
// POST /dietitian/api/web/undo-weekly-food-json-newtest
// Body: { id, dietitian_id, profile_id, week_start_date?, week_end_date? }
// =============================================================================

const undoWeeklyFoodJsonNewtest = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Only POST method is allowed" });
  }

  let connection = null;
  let access = null;

  try {
    access = await resolveIdentity(req, req.body, "weekly_food_json_undo");
    const { id, dieticianId, profileId, weekStartDate, weekEndDate } = access;

    // ── Lock + read the plan row ─────────────────────────────────────────
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const selectParams = [id, dieticianId, profileId];
    let selectSql = `
      SELECT id, week_start_date, week_end_date, status
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
    if (!row) fail(404, "Diet plan row not found. No row matched id + dietitian_id + profile_id.");

    // An approved / locked week is read-only everywhere else; the same here.
    if (row.status !== null && row.status !== undefined && Number(row.status) > 0) {
      fail(409, "This week is approved and can no longer be edited");
    }

    // ── The newest snapshot ──────────────────────────────────────────────
    const snapshot = await peekUndoSnapshot(connection, id);
    if (!snapshot) fail(404, "Nothing to undo");

    const restoredPlan = decodeStoredFoodJson(snapshot.food_json, "undo snapshot");
    const weeklyMacros = recalculateWeeklyMacros(restoredPlan);

    let restoredFoodJson;
    try {
      restoredFoodJson = JSON.stringify(restoredPlan);
    } catch (err) {
      fail(500, "Failed to encode restored food_json");
    }

    // ── Write the snapshot back, then drop it from the stack ─────────────
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
    if (!updateResult || updateResult.affectedRows !== 1) fail(409, "Diet plan row could not be restored");

    await deleteUndoSnapshot(connection, snapshot.id);
    const { depth: left } = await undoDepth(connection, id);

    await connection.commit();

    await writeAuthLogSafe(req, {
      eventType: "weekly_food_json_undo",
      userId: dieticianId,
      partnerCode: dieticianId,
      identifier: profileId,
      success: true,
      failureReason: `Undid: ${snapshot.label || "one step"} (${left} left)`,
    });

    return res.status(200).json({
      ok: true,
      message: `Undid ${snapshot.label || "one step"}`,
      id,
      dietitian_id: dieticianId,
      profile_id: profileId,
      week_start_date: formatDateOnly(row.week_start_date),
      week_end_date: formatDateOnly(row.week_end_date),
      status_value: row.status === null || row.status === undefined ? null : Number(row.status),
      undid: snapshot.label || "",
      left,
      weekly_json_data: weeklyMacros,
      food_json: restoredPlan,
    });
  } catch (err) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackErr) {
        console.error("UNDO_WEEKLY_FOOD_JSON_NEWTEST_ROLLBACK_FAILED:", rollbackErr?.message);
      }
    }
    if (err instanceof ApiError) {
      if (access) {
        await writeAuthLogSafe(req, {
          eventType: "weekly_food_json_undo",
          userId: access.dieticianId,
          partnerCode: access.dieticianId,
          identifier: access.profileId,
          success: false,
          failureReason: err.message,
        });
      }
      return res.status(err.statusCode).json(err.payload);
    }
    console.error("UNDO_WEEKLY_FOOD_JSON_NEWTEST_ERROR:", err);
    return res.status(500).json({
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG ? { error: err?.message } : {}),
    });
  } finally {
    if (connection) connection.release();
  }
};

// =============================================================================
// GET /dietitian/api/web/undo-depth-weekly-food-json-newtest
// Query: ?id=&profile_id=&dietitian_id=
// =============================================================================

const undoDepthWeeklyFoodJsonNewtest = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  try {
    const { id, dieticianId, profileId } = await resolveIdentity(req, req.query, "weekly_food_json_undo_depth");

    // the row must be the caller's — otherwise the depth of someone else's
    // plan would leak through this read
    const [rows] = await pool.execute(
      `SELECT id FROM weekly_food_json_suggestions_newtest
        WHERE id = ? AND UPPER(TRIM(dietician_id)) = ? AND profile_id = ? LIMIT 1`,
      [id, dieticianId, profileId]
    );
    if (!rows.length) fail(404, "Diet plan row not found. No row matched id + dietitian_id + profile_id.");

    const { depth, lastLabel } = await undoDepth(pool, id);
    return res.status(200).json({ ok: true, id, depth, last: lastLabel || "" });
  } catch (err) {
    if (err instanceof ApiError) return res.status(err.statusCode).json(err.payload);
    console.error("UNDO_DEPTH_WEEKLY_FOOD_JSON_NEWTEST_ERROR:", err);
    return res.status(500).json({ ok: false, message: "Internal server error", ...(APP_DEBUG ? { error: err?.message } : {}) });
  }
};

module.exports = {
  undoWeeklyFoodJsonNewtest,
  undoDepthWeeklyFoodJsonNewtest,
};
