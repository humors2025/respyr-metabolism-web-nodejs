"use strict";

/**
 * custom-meal.js
 *
 * Production "Make my meal" flow. The frontend never talks to the Python
 * FitChef service directly and never sends the full weekly plan — it sends
 * just what changed (profile, record, day, meal slot, ingredients), and
 * this controller:
 *
 *   1. Authenticates + authorizes the caller (requireProfileAccess, same as
 *      every other newtest controller — dietitian_id must match the JWT,
 *      profile_id must belong to that dietitian).
 *   2. Locks and reads the weekly row from weekly_food_json_suggestions_newtest
 *      (SELECT ... FOR UPDATE inside a transaction — same pattern
 *      trainer-update-weekly-food-json-newtest.js uses).
 *   3. Calls FitChef's POST /api/custom_meal_json with that row's food_json
 *      as the `plan` — the Python EC2 box builds the meal and computes
 *      nutrition/method/photo the same way /api/custom_meal always has, but
 *      touches no file on its own disk; it just returns the updated JSON.
 *   4. Only on a successful FitChef reply, writes the returned food_json
 *      back into the SAME row and commits. Any failure before that point
 *      rolls back — the stored plan is never partially updated.
 *
 * This endpoint is additive: it does not touch get_weekly_food_json_suggestions
 * _weeks_newtest.js or trainer-update-weekly-food-json-newtest.js, and the
 * Python side's original disk-backed /api/custom_meal keeps working
 * unchanged for local/testing use.
 */

const axios = require("axios");

const pool = require("../../../../config/db");
const { requireProfileAccess } = require("../../../../utils/accessControl");

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
|
| Base URL: search-foods.js already reads FITCHEF_API_BASE_URL for the
| Node -> FitChef direction, so that stays the primary name. This endpoint
| also accepts FITCHEF_DASHBOARD_URL (the name used in the tested Python
| contract doc) as a fallback so either env var name works without a
| deploy-time rename.
|
| Service key: FITCHEF_SERVICE_KEY was previously optional on search
| ("leave it empty for now"); this endpoint REQUIRES it, because it writes,
| where search only reads. Per the tested Python /api/custom_meal_json
| contract, the header name is X-FitChef-Service-Key (NOT the X-Service-Key
| name search-foods.js sends — the two Python endpoints check different
| header names, confirmed against the working curl test).
|--------------------------------------------------------------------------
*/

const FITCHEF_API_BASE_URL = String(
  process.env.FITCHEF_API_BASE_URL || process.env.FITCHEF_DASHBOARD_URL || ""
)
  .trim()
  .replace(/\/+$/, "");

const FITCHEF_API_TIMEOUT_MS = Number(process.env.FITCHEF_API_TIMEOUT_MS) || 15000;

const FITCHEF_SERVICE_KEY = String(process.env.FITCHEF_SERVICE_KEY || "").trim();

const FITCHEF_SERVICE_KEY_HEADER = "X-FitChef-Service-Key";

const sendResponse = (res, statusCode, response) => res.status(statusCode).json(response);

const isPlainObject = (value) =>
  value !== null && typeof value === "object" && !Array.isArray(value);

/** Ingredient validation per the tested contract: [{ key: "usa_breakfast:741", grams: 150 }].
 * `key` must be a non-empty string, `grams` a finite positive number. Returns
 * a normalized array (grams coerced to Number) or an error message. */
function validateIngredients(list) {
  if (!Array.isArray(list) || list.length === 0) {
    return { ok: false, error: "ingredients[] is required" };
  }
  const normalized = [];
  for (let i = 0; i < list.length; i += 1) {
    const item = list[i];
    if (!isPlainObject(item)) {
      return { ok: false, error: `ingredients[${i}] must be an object` };
    }
    const key = typeof item.key === "string" ? item.key.trim() : "";
    if (!key) {
      return { ok: false, error: `ingredients[${i}].key is required` };
    }
    const grams = Number(item.grams);
    if (!Number.isFinite(grams) || grams <= 0) {
      return { ok: false, error: `ingredients[${i}].grams must be a positive number` };
    }
    normalized.push({ key, grams });
  }
  return { ok: true, data: normalized };
}

/** food_json as stored may be a JSON string, a Buffer, or already an object
 * (mysql2 sometimes auto-parses JSON columns depending on config) — accept
 * all three, same defensiveness as the other newtest controllers. */
function parseFoodJson(columnValue) {
  if (columnValue === null || columnValue === undefined) {
    return { ok: false, error: "food_json is empty in database" };
  }
  if (isPlainObject(columnValue) || Array.isArray(columnValue)) {
    return { ok: true, data: columnValue };
  }
  let text;
  if (Buffer.isBuffer(columnValue)) {
    text = columnValue.toString("utf8");
  } else {
    text = String(columnValue);
  }
  text = text.replace(/^\uFEFF/, "").trim();
  try {
    return { ok: true, data: JSON.parse(text) };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

/*
|--------------------------------------------------------------------------
| POST /dietitian/api/web/custom-meal
|--------------------------------------------------------------------------
|
| Body:
| {
|   "profile_id": "profile405",
|   "record_id": 18,
|   "dietitian_id": "RespyrD01",       // optional — falls back to the JWT
|   "day": 0,
|   "meal_name": "breakfast",
|   "name": "My Custom Breakfast",     // optional
|   "method": "",                      // optional trainer note
|   "ingredients": [{ "key": "usa_breakfast:741", "grams": 150 }, ...]
| }
*/
const customMeal = async (req, res) => {
  let connection = null;

  try {
    const body = isPlainObject(req.body) ? req.body : {};

    const profileId = body.profile_id;
    const recordId = Number(body.record_id);
    const dietitianId = body.dietitian_id || req.user?.dietician_id || req.user?.sub;

    if (!profileId) {
      return sendResponse(res, 400, { status: false, message: "profile_id is required" });
    }
    if (!Number.isInteger(recordId) || recordId <= 0) {
      return sendResponse(res, 400, { status: false, message: "record_id is required" });
    }

    let day;
    try {
      day = Number.parseInt(body.day, 10);
    } catch {
      day = NaN;
    }
    if (!Number.isInteger(day) || day < 0) {
      return sendResponse(res, 400, { status: false, message: "day must be a non-negative integer" });
    }

    const mealName = String(body.meal_name || "").trim();
    if (!mealName) {
      return sendResponse(res, 400, { status: false, message: "meal_name is required" });
    }

    const ingredientsCheck = validateIngredients(body.ingredients);
    if (!ingredientsCheck.ok) {
      return sendResponse(res, 400, { status: false, message: ingredientsCheck.error });
    }
    const ingredients = ingredientsCheck.data;

    // ── 1. auth: dietitian_id must match the JWT, profile must belong to them ──
    const access = await requireProfileAccess(req, dietitianId, profileId);
    if (!access.allowed) {
      return sendResponse(res, access.statusCode, { status: false, message: access.message });
    }

    // ── 2. lock and read the row ──────────────────────────────────────────
    connection = await pool.getConnection();
    await connection.beginTransaction();

    const [rows] = await connection.execute(
      `
        SELECT id, dietician_id, profile_id, week_start_date, week_end_date, food_json
        FROM weekly_food_json_suggestions_newtest
        WHERE id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [recordId, access.dieticianId, access.profileId]
    );

    if (!rows.length) {
      await connection.rollback();
      return sendResponse(res, 404, {
        status: false,
        message: "No weekly plan found for that record_id / profile_id",
      });
    }

    const row = rows[0];
    const parsed = parseFoodJson(row.food_json);
    if (!parsed.ok) {
      await connection.rollback();
      console.error("custom-meal: invalid food_json in DB", {
        record_id: recordId,
        profile_id: access.profileId,
        error: parsed.error,
      });
      return sendResponse(res, 500, {
        status: false,
        message: "Stored weekly plan is not valid JSON",
        ...(!isProduction && { error: parsed.error }),
      });
    }

    const weekStartDate =
      row.week_start_date instanceof Date
        ? row.week_start_date.toISOString().slice(0, 10)
        : String(row.week_start_date || "").slice(0, 10);

    // ── 3. call FitChef with the plan taken from THIS row ─────────────────
    if (!FITCHEF_API_BASE_URL) {
      await connection.rollback();
      console.error("custom-meal: FITCHEF_API_BASE_URL_MISSING");
      return sendResponse(res, 500, { status: false, message: "FitChef service is not configured" });
    }
    if (!FITCHEF_SERVICE_KEY) {
      await connection.rollback();
      console.error("custom-meal: FITCHEF_SERVICE_KEY_MISSING");
      return sendResponse(res, 500, { status: false, message: "FitChef service auth is not configured" });
    }

    const fitchefPayload = {
      record_id: recordId,
      profile_id: access.profileId,
      week_start_date: weekStartDate,
      day,
      meal_name: mealName,
      name: body.name || "",
      method: body.method || "",
      prep_minutes: body.prep_minutes || "",
      ingredients,
      plan: parsed.data,
    };

    const requestStartedAt = Date.now();
    let fitchefResponse;
    try {
      fitchefResponse = await axios.post(
        `${FITCHEF_API_BASE_URL}/api/custom_meal_json`,
        fitchefPayload,
        {
          headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
            [FITCHEF_SERVICE_KEY_HEADER]: FITCHEF_SERVICE_KEY,
          },
          timeout: FITCHEF_API_TIMEOUT_MS,
          maxRedirects: 0,
          validateStatus: () => true, // read the body ourselves for both 2xx and error cases
        }
      );
    } catch (error) {
      await connection.rollback();
      const isTimeout = error.code === "ECONNABORTED";
      console.error("custom-meal: FITCHEF_UPSTREAM_UNREACHABLE", {
        record_id: recordId,
        day,
        meal_name: mealName,
        message: error.message,
        timeout: isTimeout,
        duration_ms: Date.now() - requestStartedAt,
      });
      return sendResponse(res, 502, {
        status: false,
        message: isTimeout ? "FitChef service timed out" : "FitChef service unreachable",
      });
    }

    const fitchefBody = isPlainObject(fitchefResponse.data) ? fitchefResponse.data : {};
    const fitchefDurationMs = Date.now() - requestStartedAt;

    if (fitchefResponse.status < 200 || fitchefResponse.status >= 300 || !fitchefBody.ok) {
      // The DB is never touched on any FitChef failure — the transaction
      // rolls back and the stored plan is untouched, exactly as it was
      // before this request.
      await connection.rollback();
      console.error("custom-meal: FITCHEF_REJECTED", {
        record_id: recordId,
        day,
        meal_name: mealName,
        upstream_status: fitchefResponse.status,
        upstream_error: fitchefBody.error,
        duration_ms: fitchefDurationMs,
      });

      // 401 = service-key mismatch / Python-side misconfiguration, not a
      // fault of the calling dietitian — surface as a server error, not an
      // auth failure the frontend would try to "fix" by re-logging-in.
      if (fitchefResponse.status === 401) {
        return sendResponse(res, 500, {
          status: false,
          message: "FitChef service authentication failed (service key mismatch)",
        });
      }
      // 400 (invalid plan/meal/ingredients) and 404 (day/meal not found)
      // are the caller's problem and are forwarded as-is. Everything else
      // (500, or anything unrecognized) becomes a 502 — Python's fault,
      // surfaced as an upstream failure.
      const forwardStatus = [400, 404].includes(fitchefResponse.status) ? fitchefResponse.status : 502;
      return sendResponse(res, forwardStatus, {
        status: false,
        message: fitchefBody.error || `FitChef custom meal failed (${fitchefResponse.status})`,
      });
    }

    if (!isPlainObject(fitchefBody.food_json)) {
      await connection.rollback();
      console.error("custom-meal: FITCHEF_MISSING_FOOD_JSON", {
        record_id: recordId,
        day,
        meal_name: mealName,
        duration_ms: fitchefDurationMs,
      });
      return sendResponse(res, 502, {
        status: false,
        message: "FitChef did not return an updated plan",
      });
    }

    // ── 4. persist the updated plan back into the SAME row ────────────────
    const updatedFoodJson = JSON.stringify(fitchefBody.food_json);

    let updateResult;
    try {
      [updateResult] = await connection.execute(
        `
          UPDATE weekly_food_json_suggestions_newtest
          SET food_json = ?, updated_at = NOW()
          WHERE id = ?
            AND UPPER(TRIM(dietician_id)) = ?
            AND profile_id = ?
          LIMIT 1
        `,
        [updatedFoodJson, recordId, access.dieticianId, access.profileId]
      );
    } catch (dbError) {
      await connection.rollback();
      // FitChef already generated the meal/image successfully at this point;
      // the failure is purely ours. Logged distinctly so an on-call engineer
      // doesn't mistake this for a FitChef-side problem.
      console.error("custom-meal: DB_PERSIST_FAILED_AFTER_FITCHEF_SUCCESS", {
        record_id: recordId,
        day,
        meal_name: mealName,
        db_error: dbError.message,
      });
      return sendResponse(res, 500, {
        status: false,
        message: "FitChef generated the meal, but saving it failed. Nothing was changed — please retry.",
      });
    }

    if (!updateResult || updateResult.affectedRows !== 1) {
      await connection.rollback();
      console.error("custom-meal: DB_PERSIST_NO_ROWS_AFFECTED_AFTER_FITCHEF_SUCCESS", {
        record_id: recordId,
        day,
        meal_name: mealName,
        affected_rows: updateResult ? updateResult.affectedRows : null,
      });
      return sendResponse(res, 409, {
        status: false,
        message: "Weekly plan row changed ownership or was removed before the update could be saved. Please retry.",
      });
    }

    await connection.commit();

    console.log("custom-meal: SUCCESS", {
      record_id: recordId,
      profile_id: access.profileId,
      day,
      meal_name: mealName,
      fitchef_status: fitchefResponse.status,
      duration_ms: fitchefDurationMs,
    });

    return sendResponse(res, 200, {
      status: true,
      message: "Custom meal updated successfully",
      data: {
        record_id: recordId,
        profile_id: access.profileId,
        day,
        meal_index: fitchefBody.meal_index,
        meal_name: mealName,
        meal: fitchefBody.meal,
        image: fitchefBody.image,
        nutrition: isPlainObject(fitchefBody.nutrition) ? fitchefBody.nutrition : undefined,
        warnings: fitchefBody.warnings || [],
      },
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (rollbackError) {
        console.error("custom-meal: rollback failed", rollbackError.message);
      }
    }
    console.error("custom-meal error:", {
      message: error.message,
      stack: isProduction ? undefined : error.stack,
    });
    return sendResponse(res, 500, {
      status: false,
      message: isProduction ? "Internal server error" : "Server error",
      ...(!isProduction && { error: error.message }),
    });
  } finally {
    if (connection) connection.release();
  }
};

module.exports = { customMeal };