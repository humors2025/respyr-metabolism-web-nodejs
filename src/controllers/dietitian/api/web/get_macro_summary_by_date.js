"use strict";

/**
 * get_macro_summary_by_date.js
 *
 * Converted from: get_macro_summary_by_date.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/get_macro_summary_by_date
 * Auth     : Bearer JWT (authMiddleware runs before this handler)
 *
 * Behaviour parity with the PHP:
 *  - Takes profile_id and date (YYYY-MM-DD) and returns the latest test on that
 *    date plus the most recent test strictly before it.
 *  - Extracts final_macro_summary from test_json (respyr_response.* or top-level).
 *  - Computes macro_percentage and macro_change_from_previous exactly as the PHP.
 *  - Same JSON keys/ordering as the PHP success/empty envelopes.
 *
 * VAPT hardening (beyond the PHP):
 *  - Token-bound identity. The actor dietitian comes from the verified JWT
 *    (sub = dietician_id), NOT the request body. dietitian_id must equal the
 *    token dietitian, and profile_id must belong to that dietitian
 *    (requireProfileAccess). The PHP trusted the body profile_id with no
 *    ownership check — an IDOR hole this closes. Queries are additionally scoped
 *    to the authorized dietitian as defense-in-depth.
 *  - Fully parameterized queries (? placeholders); no string interpolation.
 *  - POST-only method gate, plus strict YYYY-MM-DD date validation.
 *  - Internal error details are suppressed in production; server logs carry only
 *    error metadata, never row data or PHI. (The PHP leaked DB messages.)
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns only.
 *  - Every read (grant or denial) is recorded in app_auth_logs. PHI in the audit
 *    trail (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER (falls back to JWT_SECRET) — never stored in clear text.
 *  - The audit writer is fail-safe: a failure never breaks the request and never
 *    leaks to the client.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_test_data
 * (table_clients is read only by requireProfileAccess for ownership).
 * app_auth_logs is the shared audit sink used across these controllers.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

/* ===============================
   Helpers
================================ */

function toNumber(value) {
  const num = Number(value);
  return Number.isFinite(num) ? num : 0;
}

/**
 * Validates a calendar date in strict YYYY-MM-DD form. Queries are parameterized
 * so this is not the SQL-injection guard — it rejects malformed input early.
 * Returns the normalized "YYYY-MM-DD" string, or null if invalid.
 */
function normalizeDate(value) {
  if (typeof value !== "string") return null;

  const trimmed = value.trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) return null;

  const [year, month, day] = trimmed.split("-").map(Number);

  const parsed = new Date(Date.UTC(year, month - 1, day));

  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    return null;
  }

  return trimmed;
}

function roundOne(value) {
  return Math.round(value * 10) / 10;
}

function calculateMacroPercentage(macroSummary) {
  const carbsKcal = toNumber(macroSummary?.carbs_g) * 4;
  const proteinKcal = toNumber(macroSummary?.protein_g) * 4;
  const fatKcal = toNumber(macroSummary?.fat_g) * 9;
  const fiberKcal = toNumber(macroSummary?.fiber_g) * 2;

  const totalKcal = carbsKcal + proteinKcal + fatKcal + fiberKcal;

  if (totalKcal <= 0) {
    return {
      carbs_percent: 0,
      fat_percent: 0,
      protein_percent: 0,
      fiber_percent: 0,
    };
  }

  return {
    carbs_percent: roundOne((carbsKcal / totalKcal) * 100),
    fat_percent: roundOne((fatKcal / totalKcal) * 100),
    protein_percent: roundOne((proteinKcal / totalKcal) * 100),
    fiber_percent: roundOne((fiberKcal / totalKcal) * 100),
  };
}

function calculateChangePercentage(currentValue, previousValue) {
  const current = toNumber(currentValue);
  const previous = toNumber(previousValue);

  if (previous === 0) {
    return {
      change_percent: current > 0 ? 100 : 0,
      change_type: current > 0 ? "increase" : "no_change",
    };
  }

  const change = ((current - previous) / previous) * 100;

  return {
    change_percent: roundOne(Math.abs(change)),
    change_type:
      change > 0 ? "increase" : change < 0 ? "decrease" : "no_change",
  };
}

function parseTestJson(testJsonRaw) {
  try {
    if (!testJsonRaw) return null;

    if (Buffer.isBuffer(testJsonRaw)) {
      testJsonRaw = testJsonRaw.toString("utf8");
    }

    if (typeof testJsonRaw === "object") {
      return testJsonRaw;
    }

    if (typeof testJsonRaw !== "string") {
      return null;
    }

    return JSON.parse(testJsonRaw);
  } catch (error) {
    return null;
  }
}

function extractMacroSummary(row) {
  if (!row) return null;

  const decodedJson = parseTestJson(row.test_json);

  if (!decodedJson) return null;

  let macroSummary = null;

  if (decodedJson?.respyr_response?.final_macro_summary) {
    macroSummary = decodedJson.respyr_response.final_macro_summary;
  } else if (decodedJson?.final_macro_summary) {
    macroSummary = decodedJson.final_macro_summary;
  }

  if (!macroSummary) return null;

  const finalMacroSummary = {
    calories: toNumber(macroSummary.calories),
    carbs_g: toNumber(macroSummary.carbs_g),
    fat_g: toNumber(macroSummary.fat_g),
    fiber_g: toNumber(macroSummary.fiber_g),
    protein_g: toNumber(macroSummary.protein_g),
  };

  return {
    test_id: Number(row.test_id),
    profile_id: row.profile_id,
    date_time: row.date_time,
    final_macro_summary: finalMacroSummary,
    macro_percentage: calculateMacroPercentage(finalMacroSummary),
  };
}

/* ===============================
   Audit log (HIPAA accountability)
================================ */

const getClientIp = (req) => {
  const ip =
    (typeof req.ip === "string" && req.ip) ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "0.0.0.0";

  return String(ip).slice(0, 64);
};

const getUserAgent = (req) => {
  const ua =
    (typeof req.get === "function" && req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";

  return String(ua).slice(0, 500);
};

const authLogHash = (value) => {
  if (value === null || value === undefined) return null;

  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
};

/**
 * Fail-safe audit writer mirroring the sibling controllers. Never throws — audit
 * failures must not surface to the client.
 *   app_auth_logs(event_type, user_id, role, partner_code, identifier_hash,
 *                 ip_hash, user_agent_hash, session_id_hash, success, failure_reason)
 */
const writeAuthLogSafe = async (
  req,
  { eventType, userId, identifier, success, failureReason }
) => {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined
        ? authLogHash(identifier)
        : null;

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
       VALUES (?, ?, NULL, NULL, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined
          ? String(userId).slice(0, 191)
          : null,
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
    console.error("MACRO_SUMMARY_AUDIT_FAILED:", err?.code || err?.message);
  }
};

/* ===============================
   Controller
================================ */

const get_macro_summary_by_date = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate.
  if (req.method !== "POST") {
    return res
      .status(405)
      .json({ success: false, message: "Only POST method is allowed" });
  }

  const body = req.body || {};

  if (typeof body !== "object" || Array.isArray(body)) {
    return res.status(400).json({
      success: false,
      message: "Invalid request body",
    });
  }

  const profile_id = normalizeId(body.profile_id);
  const requestedDietitianId = normalizeDieticianId(body.dietitian_id);
  const date = normalizeDate(body.date);

  if (!body.profile_id || !body.dietitian_id || !body.date) {
    return res.status(400).json({
      success: false,
      message: "profile_id, dietitian_id and date are required",
    });
  }

  if (!profile_id) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid profile_id" });
  }

  if (!requestedDietitianId) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid dietitian_id" });
  }

  if (!date) {
    return res.status(400).json({
      success: false,
      message: "Invalid date (expected YYYY-MM-DD)",
    });
  }

  // Hashed before storage by writeAuthLogSafe — never persisted in clear text.
  const auditIdentifier = `${profile_id}|${requestedDietitianId}|${date}`;

  try {
    /**
     * VAPT / object-level authorization:
     * 1. JWT dietician id must match requested dietitian_id
     * 2. profile_id must belong to this dietitian in table_clients
     * Blocks IDOR — a dietitian cannot read another dietitian's client PHI.
     */
    const access = await requireProfileAccess(
      req,
      requestedDietitianId,
      profile_id
    );

    if (!access.allowed) {
      await writeAuthLogSafe(req, {
        eventType: "macro_summary_access_denied",
        userId: requestedDietitianId,
        identifier: auditIdentifier,
        success: false,
        failureReason: access.message || "access denied",
      });

      return res.status(access.statusCode || 403).json({
        success: false,
        message: access.message || "Access denied",
      });
    }

    const dietitianId = access.dieticianId;
    const authorizedProfileId = access.profileId;

    /**
     * Same logic as PHP (WHERE profile_id = ? AND DATE(date_time) = ?),
     * additionally scoped to the authorized dietitian as defense-in-depth.
     */
    const currentSql = `
      SELECT
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        AND DATE(date_time) = ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [currentRows] = await pool.execute(currentSql, [
      authorizedProfileId,
      dietitianId,
      date,
    ]);

    const currentData = extractMacroSummary(currentRows[0]);

    const selectedDateStart = `${date} 00:00:00`;

    const previousSql = `
      SELECT
        test_id,
        profile_id,
        DATE_FORMAT(date_time, '%Y-%m-%d %H:%i:%s') AS date_time,
        test_json
      FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        AND date_time < ?
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [previousRows] = await pool.execute(previousSql, [
      authorizedProfileId,
      dietitianId,
      selectedDateStart,
    ]);

    const previousData = extractMacroSummary(previousRows[0]);

    let macroChange = null;

    if (currentData && previousData) {
      const current = currentData.final_macro_summary;
      const previous = previousData.final_macro_summary;

      macroChange = {
        calories: calculateChangePercentage(
          current.calories,
          previous.calories
        ),
        carbs_g: calculateChangePercentage(current.carbs_g, previous.carbs_g),
        fat_g: calculateChangePercentage(current.fat_g, previous.fat_g),
        fiber_g: calculateChangePercentage(current.fiber_g, previous.fiber_g),
        protein_g: calculateChangePercentage(
          current.protein_g,
          previous.protein_g
        ),
      };
    }

    if (!currentData) {
      await writeAuthLogSafe(req, {
        eventType: "macro_summary_read",
        userId: dietitianId,
        identifier: auditIdentifier,
        success: false,
        failureReason: "No macro summary found for selected date",
      });

      return res.status(200).json({
        success: false,
        message: "No macro summary found for selected date",
        profile_id: authorizedProfileId,
        selected_date: date,
        previous_data: previousData,
      });
    }

    await writeAuthLogSafe(req, {
      eventType: "macro_summary_read",
      userId: dietitianId,
      identifier: auditIdentifier,
      success: true,
      failureReason: null,
    });

    return res.status(200).json({
      success: true,
      message: "Macro summary fetched successfully",
      profile_id: authorizedProfileId,
      selected_date: date,
      current_data: currentData,
      previous_data: previousData,
      macro_change_from_previous: macroChange,
    });
  } catch (error) {
    console.error("get_macro_summary_by_date error:", {
      message: error.message,
      code: error.code,
      stack: isProduction ? undefined : error.stack,
    });

    return res.status(500).json({
      success: false,
      message: "Internal server error",
    });
  }
};

module.exports = {
  get_macro_summary_by_date,
};
