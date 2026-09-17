"use strict";

/**
 * food-log.js
 *
 * Platform : Respyr Dietitian API (api.respyr.ai)
 * Security : VAPT-hardened, HIPAA-aligned
 *
 * Read-only view of a client's `food_log` for the dietitian dashboard.
 *
 * Endpoint (POST, behind authMiddleware):
 *   /dietitian/api/web/food-log
 *
 * Request body:
 *   {
 *     "profile_id":      "<required — the client whose food log to read>",
 *     "dietitian_id":    "<optional — defaults to JWT; dietician_id also accepted>",
 *     "date":            "YYYY-MM-DD"   // single day, OR
 *     "start_date":      "YYYY-MM-DD",  // inclusive range (≤ 92 days)
 *     "end_date":        "YYYY-MM-DD",
 *     "slot":            "breakfast | lunch | dinner | snack"   (optional filter)
 *     "source":          "plan | chef | …"                       (optional filter)
 *   }
 *   No date at all → today.
 *
 * Only live rows (deleted = 0) are ever returned; soft-deleted entries are
 * invisible to this endpoint.
 *
 * Response: every day in the range × every slot is present (empty ones with
 * zero totals) so the UI can render a fixed grid, with per-slot, per-day and
 * overall macro totals.
 *
 * Security model (identical to habits-manager.controller.js / custom-meal.js):
 *  - The JWT belongs to a DIETITIAN. profile_id is supplied in the body and is
 *    verified via requireProfileAccess (table_clients dietician_id ↔ profile_id)
 *    BEFORE any food_log row is read — closing BOLA/IDOR (OWASP API1).
 *  - A super_admin may pass an explicit dietitian_id; requireProfileAccess
 *    resolves the profile's true owning dietitian.
 *  - The query is additionally scoped by `profile_id = ?`.
 *  - Fully parameterized — only the constant integer LIMIT is inlined (bound
 *    LIMIT fails with ER_WRONG_ARGUMENTS on the prod MySQL).
 *  - Internal error details are suppressed in every client-facing response.
 *  - PHI is never logged (no food names / macros); only ids, counts and error
 *    metadata (code/errno/sqlState).
 *  - Cache-Control: no-store on every response.
 *
 * ── Schema reference (verified 2026-09-12 with DESCRIBE food_log) ───────────
 *   food_log: id (bigint PK), user_id (int), profile_id varchar(64),
 *             log_date DATE, slot varchar(12), source varchar(16),
 *             source_ref varchar(120) NULL, batch_id char(32) NULL,
 *             food_name varchar(160), brand varchar(120) NULL,
 *             serving_desc varchar(120), quantity decimal(7,2),
 *             grams decimal(8,1) NULL, kcal/protein/carbs/fat decimal(8,1),
 *             fiber decimal(8,1) NULL, has_photo tinyint(1),
 *             logged_at TIMESTAMP, updated_at TIMESTAMP,
 *             deleted tinyint(1), deleted_at DATETIME NULL
 */

const pool = require("../../../../config/db");
const {
  requireProfileAccess,
  getTokenDieticianId,
} = require("../../../../utils/accessControl");

// ───────────────────────────────────────────────────────────────────────────
//  Config
// ───────────────────────────────────────────────────────────────────────────

const SLOTS = Object.freeze(["breakfast", "lunch", "dinner", "snack"]);
const SLOT_ORDER_SQL = "FIELD(slot, 'breakfast', 'lunch', 'dinner', 'snack')";

const MAX_RANGE_DAYS = 92; // inclusive days a request may span
const MAX_LIST_ROWS = 2000; // hard cap, constant, inlined

// ───────────────────────────────────────────────────────────────────────────
//  Response helpers — house shape: { status, message, data, error }
// ───────────────────────────────────────────────────────────────────────────

function ok(res, status, payload) {
  return res.status(status).json({ status: true, error: null, ...payload });
}

function fail(res, status, message, code) {
  return res.status(status).json({
    status: false,
    message,
    data: null,
    error: { code },
  });
}

function serverError(res) {
  return fail(res, 500, "Server error", "SERVER_ERROR");
}

// ───────────────────────────────────────────────────────────────────────────
//  Date / number helpers (UTC, calendar-only — no time-zone drift)
// ───────────────────────────────────────────────────────────────────────────

function pad(n) {
  return String(n).padStart(2, "0");
}

function ymd(d) {
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

function todayYmd() {
  return ymd(new Date());
}

/** YYYY-MM-DD validator. Returns the string or null. */
function toYmd(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
  const d = new Date(`${s}T00:00:00Z`);
  if (isNaN(d) || ymd(d) !== s) return null; // rejects 2026-02-31 etc.
  return s;
}

/** YYYY-MM-DD `n` days after a YYYY-MM-DD (UTC). */
function addDays(dateStr, n) {
  const d = new Date(`${dateStr}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + n);
  return ymd(d);
}

/** Inclusive whole-day count between two YYYY-MM-DD strings. 0 if from>to. */
function inclusiveDays(fromYmd, toYmd) {
  const from = new Date(`${fromYmd}T00:00:00Z`).getTime();
  const to = new Date(`${toYmd}T00:00:00Z`).getTime();
  if (isNaN(from) || isNaN(to) || from > to) return 0;
  return Math.floor((to - from) / 86400000) + 1;
}

/** Inclusive YYYY-MM-DD list from start..end (UTC). */
function buildDateRange(startStr, endStr) {
  const out = [];
  const n = inclusiveDays(startStr, endStr);
  for (let i = 0; i < n; i++) out.push(addDays(startStr, i));
  return out;
}

/** mysql2 may hand back DATE columns as Date objects OR strings — normalise. */
function normDate(val) {
  if (!val) return null;
  if (val instanceof Date) return isNaN(val) ? null : ymd(val);
  const s = String(val);
  return s.length >= 10 ? s.slice(0, 10) : s;
}

/** Format MySQL DATETIME / TIMESTAMP as "YYYY-MM-DD HH:MM:SS" (PHP parity). */
function toMysqlDateTime(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (isNaN(val.getTime())) return null;
    return (
      `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
      `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
    );
  }
  return String(val);
}

function round1(n) {
  return Math.round(n * 10) / 10;
}

/** DECIMAL columns come back from mysql2 as strings — coerce, keep NULL. */
function numOrNull(val) {
  if (val === null || val === undefined) return null;
  const n = Number(val);
  return Number.isFinite(n) ? n : null;
}

function numOrZero(val) {
  return numOrNull(val) ?? 0;
}

// ───────────────────────────────────────────────────────────────────────────
//  Input validation helpers
// ───────────────────────────────────────────────────────────────────────────

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isMissing(v) {
  return v === undefined || v === null || v === "";
}

function toSlot(raw) {
  if (isMissing(raw)) return null;
  const s = String(raw).trim().toLowerCase();
  return SLOTS.includes(s) ? s : null;
}

/** source: short lowercase token (plan | chef | manual | …). */
function toSource(raw) {
  if (isMissing(raw)) return null;
  const s = String(raw).trim().toLowerCase();
  return /^[a-z][a-z0-9_-]{0,15}$/.test(s) ? s : null;
}

/**
 * Resolve the date window.
 *   date                     → single day
 *   start_date + end_date    → inclusive range (≤ MAX_RANGE_DAYS)
 *   nothing                  → today
 *   → { ok, start, end } | { ok: false, error }
 */
function resolveDateRange(body) {
  if (!isMissing(body.date)) {
    const d = toYmd(body.date);
    if (!d) return { ok: false, error: "date must be YYYY-MM-DD" };
    return { ok: true, start: d, end: d };
  }
  if (!isMissing(body.start_date) || !isMissing(body.end_date)) {
    const start = toYmd(body.start_date);
    const end = toYmd(body.end_date);
    if (!start || !end) {
      return { ok: false, error: "start_date and end_date must both be YYYY-MM-DD" };
    }
    const n = inclusiveDays(start, end);
    if (n === 0) return { ok: false, error: "start_date must be on or before end_date" };
    if (n > MAX_RANGE_DAYS) {
      return { ok: false, error: `date range may span at most ${MAX_RANGE_DAYS} days` };
    }
    return { ok: true, start, end };
  }
  const today = todayYmd();
  return { ok: true, start: today, end: today };
}

// ───────────────────────────────────────────────────────────────────────────
//  Row → response shape
// ───────────────────────────────────────────────────────────────────────────

function serializeRow(r) {
  return {
    id: Number(r.id),
    user_id: Number(r.user_id),
    profile_id: r.profile_id,
    log_date: normDate(r.log_date),
    slot: r.slot,
    source: r.source,
    source_ref: r.source_ref ?? null,
    batch_id: r.batch_id ?? null,
    food_name: r.food_name,
    brand: r.brand ?? null,
    serving_desc: r.serving_desc,
    quantity: numOrZero(r.quantity),
    grams: numOrNull(r.grams),
    kcal: numOrZero(r.kcal),
    protein: numOrZero(r.protein),
    carbs: numOrZero(r.carbs),
    fat: numOrZero(r.fat),
    fiber: numOrNull(r.fiber),
    has_photo: Boolean(Number(r.has_photo)),
    logged_at: toMysqlDateTime(r.logged_at),
    updated_at: toMysqlDateTime(r.updated_at),
  };
}

function emptyTotals() {
  return { entries: 0, kcal: 0, protein: 0, carbs: 0, fat: 0, fiber: 0 };
}

function addToTotals(t, row) {
  t.entries += 1;
  t.kcal += row.kcal;
  t.protein += row.protein;
  t.carbs += row.carbs;
  t.fat += row.fat;
  t.fiber += row.fiber ?? 0;
}

function roundTotals(t) {
  return {
    entries: t.entries,
    kcal: round1(t.kcal),
    protein: round1(t.protein),
    carbs: round1(t.carbs),
    fat: round1(t.fat),
    fiber: round1(t.fiber),
  };
}

// ───────────────────────────────────────────────────────────────────────────
//  Token-bound profile access (BOLA/IDOR guard).
//  On success returns { dieticianId, profileId }; on failure writes the HTTP
//  response and returns null.
// ───────────────────────────────────────────────────────────────────────────

async function resolveProfileAccess(req, res) {
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
    console.error("food_log.list: requireProfileAccess threw", authErr?.code);
    serverError(res);
    return null;
  }

  if (!access.allowed) {
    console.warn("food_log.list: access denied", {
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

// ═══════════════════════════════════════════════════════════════════════════
//  POST /dietitian/api/web/food-log
// ═══════════════════════════════════════════════════════════════════════════

const foodLog = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (!isPlainObject(req.body)) {
    return fail(res, 400, "Invalid request body", "INVALID_BODY");
  }
  const body = req.body;

  // Token-bound ownership check (BOLA/IDOR) — before any PHI is read.
  const access = await resolveProfileAccess(req, res);
  if (!access) return; // response already sent

  if (!access.dieticianId || !access.profileId) {
    return fail(res, 422, "dietitian_id and profile_id are required", "VALIDATION_ERROR");
  }
  const { profileId } = access;

  // ── filters ─────────────────────────────────────────────────────────────
  const range = resolveDateRange(body);
  if (!range.ok) return fail(res, 422, range.error, "VALIDATION_ERROR");

  // Soft-deleted rows are never returned.
  const where = ["profile_id = ?", "log_date BETWEEN ? AND ?", "deleted = 0"];
  const params = [profileId, range.start, range.end];

  if (!isMissing(body.slot)) {
    const slot = toSlot(body.slot);
    if (!slot) {
      return fail(res, 422, `slot must be one of ${SLOTS.join(", ")}`, "VALIDATION_ERROR");
    }
    where.push("slot = ?");
    params.push(slot);
  }
  if (!isMissing(body.source)) {
    const source = toSource(body.source);
    if (!source) return fail(res, 422, "source is invalid", "VALIDATION_ERROR");
    where.push("source = ?");
    params.push(source);
  }

  try {
    const [rows] = await pool.execute(
      `SELECT id, user_id, profile_id, log_date, slot, source, source_ref, batch_id,
              food_name, brand, serving_desc, quantity, grams,
              kcal, protein, carbs, fat, fiber, has_photo,
              logged_at, updated_at
         FROM food_log
        WHERE ${where.join(" AND ")}
        ORDER BY log_date ASC, ${SLOT_ORDER_SQL}, logged_at ASC, id ASC
        LIMIT ${MAX_LIST_ROWS}`,
      params
    );

    const entries = rows.map(serializeRow);

    // day → slot grid.
    const dayMap = new Map();
    for (const date of buildDateRange(range.start, range.end)) {
      dayMap.set(date, {
        log_date: date,
        totals: emptyTotals(),
        slots: SLOTS.map((slot) => ({ slot, totals: emptyTotals(), entries: [] })),
      });
    }
    const overall = emptyTotals();
    for (const e of entries) {
      const day = dayMap.get(e.log_date);
      if (!day) continue;
      const slot = day.slots.find((s) => s.slot === e.slot);
      if (!slot) continue;
      slot.entries.push(e);
      addToTotals(slot.totals, e);
      addToTotals(day.totals, e);
      addToTotals(overall, e);
    }

    const days = [...dayMap.values()].map((d) => ({
      log_date: d.log_date,
      totals: roundTotals(d.totals),
      slots: d.slots.map((s) => ({
        slot: s.slot,
        totals: roundTotals(s.totals),
        entries: s.entries,
      })),
    }));

    console.info("food_log.list: ok", {
      dietitian_id: access.dieticianId,
      profile_id: profileId,
      start_date: range.start,
      end_date: range.end,
      rows: entries.length,
      truncated: entries.length >= MAX_LIST_ROWS,
    });

    return ok(res, 200, {
      message: "Food log fetched successfully",
      data: {
        profile_id: profileId,
        start_date: range.start,
        end_date: range.end,
        truncated: entries.length >= MAX_LIST_ROWS,
        count: entries.length,
        totals: roundTotals(overall),
        days,
      },
    });
  } catch (err) {
    console.error("food-log: unhandled error", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
    });
    if (!res.headersSent) return serverError(res);
    return undefined;
  }
};

module.exports = { foodLog };
