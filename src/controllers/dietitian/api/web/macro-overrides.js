"use strict";

/**
 * macro-overrides.js
 *
 * Hand-edited macro targets from the dashboard's "Macros Analysis" tab.
 *
 * Endpoints (all POST, Bearer JWT via authMiddleware):
 *   /dietitian/api/web/get_macro_overrides    { profile_id, dietitian_id }
 *   /dietitian/api/web/save_macro_override    { profile_id, dietitian_id,
 *                                               protein_g, carbs_g, fat_g, fiber_g,
 *                                               valid_from, valid_to, note?, base_test_id? }
 *   /dietitian/api/web/remove_macro_override  { profile_id, dietitian_id, id }
 *
 * Who edited is taken from the verified access token (user_id = login email,
 * dietician.name, sub, role) — never from the request body.
 *
 * Access is the same as reading the client's macros: requireProfileAccess
 * (own clients; super-admin any client). "View as" sessions are refused by
 * authMiddleware because the write routes contain "save" / "remove".
 *
 * The edited numbers replace the test's macros in the diet-plan worker feed
 * while their date range covers the week being planned — see
 * services/macroOverrides.js applyOverridesToFeed. The test data itself is
 * never changed.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");
const {
  MACRO_LIMITS,
  MAX_RANGE_DAYS,
  istToday,
  currentPlanWeek,
  parseMacroInput,
  parseRangeInput,
  caloriesFromMacros,
  macroOverridesTableExists,
  shapeOverride,
  listOverridesForProfile,
  findOverridesForWindow,
} = require("../../../../services/macroOverrides");

const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";
const isProduction =
  process.env.NODE_ENV === "production" || Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

const TABLE_MISSING_MESSAGE =
  "Macro editing is not set up on this server yet (macro_overrides table missing)";

/* ─── Helpers ──────────────────────────────────────────────────────────── */

function noStore(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function readBody(req) {
  const body = req.body;
  if (!body || typeof body !== "object" || Array.isArray(body)) return null;
  return body;
}

/** The signed-in user, from the verified access token. */
function tokenEditor(req) {
  const user = req.user || {};
  const userId = String(user.user_id || user.dietician?.user_id || user.dietician?.email || "")
    .trim()
    .toLowerCase()
    .slice(0, 191);
  const name = String(user.dietician?.name || user.name || "").trim().slice(0, 191) || null;
  const dieticianId = String(user.sub || user.dietician?.dietician_id || "").trim().slice(0, 64) || null;
  const role = String(user.role || user.dietician?.role || "").trim().slice(0, 40) || null;
  return { userId: userId || null, name, dieticianId, role };
}

const authLogHash = (value) =>
  value === null || value === undefined
    ? null
    : crypto.createHmac("sha256", SECURITY_PEPPER).update(String(value).trim().toLowerCase()).digest("hex");

async function writeAuthLogSafe(req, { eventType, userId, identifier, success, failureReason }) {
  try {
    const ip = String(req.ip || req.socket?.remoteAddress || "0.0.0.0").slice(0, 64);
    const ua = String((typeof req.get === "function" && req.get("user-agent")) || "").slice(0, 500);
    await pool.execute(
      `INSERT INTO app_auth_logs (
         event_type, user_id, role, partner_code, identifier_hash,
         ip_hash, user_agent_hash, session_id_hash, success, failure_reason
       ) VALUES (?, ?, NULL, NULL, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType).slice(0, 60),
        userId ? String(userId).slice(0, 191) : null,
        authLogHash(identifier),
        authLogHash(ip),
        authLogHash(ua),
        success ? 1 : 0,
        failureReason ? String(failureReason).slice(0, 255) : null,
      ]
    );
  } catch (err) {
    console.error("MACRO_OVERRIDE_AUDIT_FAILED:", err?.code || err?.message);
  }
}

function serverError(res, err, label) {
  console.error(`${label}:`, { code: err?.code, message: err?.message });
  return res.status(500).json({
    success: false,
    message: isProduction ? "Something went wrong" : err?.message || "Something went wrong",
  });
}

/**
 * Common gate: body shape, ids, and profile access. Returns
 * { ok: true, body, access } or sends the error response and returns { ok: false }.
 */
async function gate(req, res, eventPrefix) {
  noStore(res);
  if (req.method !== "POST") {
    res.status(405).json({ success: false, message: "Only POST method is allowed" });
    return { ok: false };
  }
  const body = readBody(req);
  if (!body) {
    res.status(400).json({ success: false, message: "Invalid request body" });
    return { ok: false };
  }
  const profileId = normalizeId(body.profile_id);
  const dietitianId = normalizeDieticianId(body.dietitian_id);
  if (!profileId || !dietitianId) {
    res.status(400).json({ success: false, message: "Valid profile_id and dietitian_id are required" });
    return { ok: false };
  }

  const access = await requireProfileAccess(req, dietitianId, profileId);
  if (!access.allowed) {
    await writeAuthLogSafe(req, {
      eventType: `${eventPrefix}_denied`,
      userId: tokenEditor(req).userId,
      identifier: `${profileId}|${dietitianId}`,
      success: false,
      failureReason: access.message || "access denied",
    });
    res.status(access.statusCode || 403).json({ success: false, message: access.message || "Access denied" });
    return { ok: false };
  }
  return { ok: true, body, access };
}

function parseTestJson(raw) {
  try {
    if (!raw) return null;
    if (Buffer.isBuffer(raw)) raw = raw.toString("utf8");
    if (typeof raw === "object") return raw;
    if (typeof raw !== "string") return null;
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/** Same lookup order as get_macro_summary_by_date: respyr_response first. */
function macroSummaryFromTestJson(raw) {
  const decoded = parseTestJson(raw);
  const macro = decoded?.respyr_response?.final_macro_summary || decoded?.final_macro_summary;
  if (!macro || typeof macro !== "object") return null;
  const n = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  return {
    calories: n(macro.calories),
    protein_g: n(macro.protein_g),
    carbs_g: n(macro.carbs_g),
    fat_g: n(macro.fat_g),
    fiber_g: n(macro.fiber_g),
  };
}

/**
 * The test whose macros the edit starts from: the requested base_test_id if
 * it belongs to this client, otherwise the client's newest test that has a
 * macro summary. Returns { test_id, date_time, macros } or null.
 */
async function findBaseTest(dieticianId, profileId, requestedTestId) {
  const params = [profileId, dieticianId];
  let extra = "";
  const testId = Number.parseInt(requestedTestId, 10);
  if (Number.isFinite(testId) && testId > 0) {
    extra = "AND test_id = ?";
    params.push(testId);
  }
  const [rows] = await pool.execute(
    `SELECT test_id, DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time, test_json
       FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        ${extra}
      ORDER BY date_time DESC
      LIMIT 10`,
    params
  );
  for (const row of rows) {
    const macros = macroSummaryFromTestJson(row.test_json);
    if (macros) return { test_id: Number(row.test_id), date_time: row.date_time, macros };
  }
  return null;
}

/** List + which override the next diet plan will use. */
async function buildListPayload(dieticianId, profileId) {
  const rows = await listOverridesForProfile(dieticianId, profileId);
  if (rows === null) {
    return { available: false, overrides: [], applies_to_current_plan_week: null };
  }
  const today = istToday();
  const week = currentPlanWeek();
  const current = await findOverridesForWindow(
    [{ dietician_id: dieticianId, profile_id: profileId }],
    week.week_start_date,
    week.week_end_date
  );
  const currentRow = current.values().next().value || null;
  return {
    available: true,
    today,
    plan_week: week,
    limits: MACRO_LIMITS,
    max_range_days: MAX_RANGE_DAYS,
    applies_to_current_plan_week: currentRow ? Number(currentRow.id) : null,
    overrides: rows.map((row) => shapeOverride(row, today)),
  };
}

/* ─── Controllers ──────────────────────────────────────────────────────── */

const get_macro_overrides = async (req, res) => {
  try {
    const g = await gate(req, res, "macro_overrides_list");
    if (!g.ok) return;
    const { dieticianId, profileId } = g.access;
    const payload = await buildListPayload(dieticianId, profileId);
    return res.status(200).json({ success: true, data: payload });
  } catch (err) {
    return serverError(res, err, "GET_MACRO_OVERRIDES_ERROR");
  }
};

const save_macro_override = async (req, res) => {
  try {
    const g = await gate(req, res, "macro_override_save");
    if (!g.ok) return;
    const { body, access } = g;
    const { dieticianId, profileId } = access;

    const editor = tokenEditor(req);
    if (!editor.userId) {
      return res.status(401).json({ success: false, message: "Invalid authentication token" });
    }

    const macroInput = parseMacroInput(body);
    if (!macroInput.ok) return res.status(400).json({ success: false, message: macroInput.message });

    const range = parseRangeInput(body);
    if (!range.ok) return res.status(400).json({ success: false, message: range.message });

    const note =
      typeof body.note === "string" && body.note.trim() ? body.note.trim().slice(0, 500) : null;

    if (!(await macroOverridesTableExists())) {
      return res.status(503).json({ success: false, message: TABLE_MISSING_MESSAGE });
    }

    const base = await findBaseTest(dieticianId, profileId, body.base_test_id);
    const m = macroInput.macros;
    // Test calories moved by only what changed (see caloriesFromMacros).
    m.calories = caloriesFromMacros(m, base ? base.macros : null);

    const [result] = await pool.execute(
      `INSERT INTO macro_overrides (
         profile_id, dietician_id,
         protein_g, carbs_g, fat_g, fiber_g, calories,
         valid_from, valid_to, note,
         base_test_id, base_test_date,
         base_protein_g, base_carbs_g, base_fat_g, base_fiber_g, base_calories,
         edited_by_user_id, edited_by_name, edited_by_dietician_id, edited_by_role
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        profileId,
        dieticianId,
        m.protein_g,
        m.carbs_g,
        m.fat_g,
        m.fiber_g,
        m.calories,
        range.valid_from,
        range.valid_to,
        note,
        base ? base.test_id : null,
        base ? base.date_time : null,
        base ? base.macros.protein_g : null,
        base ? base.macros.carbs_g : null,
        base ? base.macros.fat_g : null,
        base ? base.macros.fiber_g : null,
        base ? base.macros.calories : null,
        editor.userId,
        editor.name,
        editor.dieticianId,
        editor.role,
      ]
    );

    await writeAuthLogSafe(req, {
      eventType: "macro_override_saved",
      userId: editor.userId,
      identifier: `${profileId}|${dieticianId}|${result.insertId}`,
      success: true,
    });

    const payload = await buildListPayload(dieticianId, profileId);
    return res.status(200).json({
      success: true,
      message: "Macros saved",
      id: Number(result.insertId),
      data: payload,
    });
  } catch (err) {
    return serverError(res, err, "SAVE_MACRO_OVERRIDE_ERROR");
  }
};

const remove_macro_override = async (req, res) => {
  try {
    const g = await gate(req, res, "macro_override_remove");
    if (!g.ok) return;
    const { body, access } = g;
    const { dieticianId, profileId } = access;

    const id = Number.parseInt(body.id, 10);
    if (!Number.isFinite(id) || id <= 0) {
      return res.status(400).json({ success: false, message: "Valid id is required" });
    }
    const editor = tokenEditor(req);
    if (!editor.userId) {
      return res.status(401).json({ success: false, message: "Invalid authentication token" });
    }
    if (!(await macroOverridesTableExists())) {
      return res.status(503).json({ success: false, message: TABLE_MISSING_MESSAGE });
    }

    // Scoped to this client + owner, so an id from another client is a 404.
    const [result] = await pool.execute(
      `UPDATE macro_overrides
          SET removed_at = NOW(), removed_by_user_id = ?, removed_by_name = ?
        WHERE id = ?
          AND profile_id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND removed_at IS NULL`,
      [editor.userId, editor.name, id, profileId, dieticianId]
    );
    if (!result.affectedRows) {
      return res.status(404).json({ success: false, message: "Edited macros not found" });
    }

    await writeAuthLogSafe(req, {
      eventType: "macro_override_removed",
      userId: editor.userId,
      identifier: `${profileId}|${dieticianId}|${id}`,
      success: true,
    });

    const payload = await buildListPayload(dieticianId, profileId);
    return res.status(200).json({ success: true, message: "Edited macros removed", data: payload });
  } catch (err) {
    return serverError(res, err, "REMOVE_MACRO_OVERRIDE_ERROR");
  }
};

module.exports = {
  get_macro_overrides,
  save_macro_override,
  remove_macro_override,
};
