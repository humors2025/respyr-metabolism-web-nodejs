"use strict";

/**
 * weight-tracking.js
 *
 * Endpoint:
 * POST /dietitian/api/web/weight-tracking
 *
 * Authorization:
 * - admin
 * - super_admin
 * - trainer
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const {
  normalizeCode,
  getAdminGroupPeerCodes,
} = require("./admin_group_visibility");

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set([
  "admin",
  "super_admin",
  "trainer",
]);

const ID_MAX_LENGTH = 64;

// ─────────────────────────────────────────────────────────────────────────────
// Generic helpers
// ─────────────────────────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string"
    ? val.trim().toLowerCase()
    : String(val ?? "").trim().toLowerCase();
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

function toFloat(val) {
  const n = parseFloat(val);
  return Number.isFinite(n) ? n : null;
}

/**
 * Format MySQL DATETIME as:
 * YYYY-MM-DD HH:MM:SS
 */
function toMysqlDateTime(val) {
  if (val === null || val === undefined) {
    return null;
  }

  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) {
      return null;
    }

    const pad = (n) => String(n).padStart(2, "0");

    return (
      `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(
        val.getDate()
      )} ` +
      `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(
        val.getSeconds()
      )}`
    );
  }

  return String(val);
}

/**
 * Format MySQL DATE as:
 * YYYY-MM-DD
 */
function toMysqlDate(val) {
  if (val === null || val === undefined) {
    return null;
  }

  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) {
      return null;
    }

    const pad = (n) => String(n).padStart(2, "0");

    return `${val.getFullYear()}-${pad(
      val.getMonth() + 1
    )}-${pad(val.getDate())}`;
  }

  return String(val);
}

/**
 * PHP effective code:
 *
 * partner_code
 *     ↓
 * dietician_id
 *     ↓
 * null
 */
function getActorEffectiveCode(actor) {
  if (
    actor.partner_code !== null &&
    actor.partner_code !== undefined &&
    String(actor.partner_code).trim() !== ""
  ) {
    return String(actor.partner_code);
  }

  if (
    actor.dietician_id !== null &&
    actor.dietician_id !== undefined &&
    String(actor.dietician_id).trim() !== ""
  ) {
    return String(actor.dietician_id);
  }

  return null;
}

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
  if (value === null || value === undefined) {
    return null;
  }

  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

// ─────────────────────────────────────────────────────────────────────────────
// Audit logging
// ─────────────────────────────────────────────────────────────────────────────

async function writeAuthLogSafe(req, {
  eventType,
  userId,
  role,
  partnerCode,
  identifier,
  success,
  failureReason,
}) {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined
        ? authLogHash(identifier)
        : null;

    await pool.execute(
      `
        INSERT INTO app_auth_logs (
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
        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
      `,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined
          ? String(userId).slice(0, 191)
          : null,
        role ?? null,
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
    console.error(
      "WEIGHT_TRACKING_AUDIT_FAILED:",
      err?.code || err?.message
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Actor resolution
// ─────────────────────────────────────────────────────────────────────────────

async function resolveActorFromToken(req) {
  const payload = req.user || {};

  const dieticianId = String(
    payload.sub ||
      payload.dietician_id ||
      ""
  ).trim();

  if (
    !dieticianId ||
    dieticianId.length > ID_MAX_LENGTH
  ) {
    return {
      error: {
        status: 401,
        body: {
          status: false,
          message: "Invalid token user",
          data: null,
          error: {
            code: "UNAUTHENTICATED",
          },
        },
      },
    };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.dietician_id,
        td.name,
        td.email,
        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        aur.status
      FROM table_dietician td
      INNER JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE td.dietician_id = ?
      LIMIT 1
    `,
    [dieticianId]
  );

  const actor = rows[0];

  if (!actor) {
    return {
      error: {
        status: 403,
        body: {
          status: false,
          message: "Actor user not found",
          data: null,
          error: {
            code: "FORBIDDEN",
          },
        },
      },
    };
  }

  if (String(actor.status) !== "active") {
    return {
      error: {
        status: 403,
        body: {
          status: false,
          message: "Actor account is not active",
          data: null,
          error: {
            code: "FORBIDDEN",
          },
        },
      },
    };
  }

  if (
    !ALLOWED_ACTOR_ROLES.has(
      String(actor.role)
    )
  ) {
    return {
      error: {
        status: 403,
        body: {
          status: false,
          message: "Not allowed to access weight logs",
          data: null,
          error: {
            code: "FORBIDDEN",
          },
        },
      },
    };
  }

  return {
    actor,
    actorEmail: normalizeEmail(actor.email),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Authorization
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build the set of dietician codes whose clients
 * the actor may view.
 *
 * Includes:
 *
 * - own effective code
 * - active child trainers
 * - admin-group peers
 *
 * super_admin does not need this list.
 */
async function getAllowedCodes(
  actor,
  actorEmail
) {
  const codes = new Set();

  // Own code
  const own = normalizeCode(
    getActorEffectiveCode(actor)
  );

  if (own !== "") {
    codes.add(own);
  }

  // Active child trainers
  const [trainerRows] = await pool.execute(
    `
      SELECT partner_code
      FROM app_user_roles
      WHERE role = 'trainer'
        AND status = 'active'
        AND partner_code IS NOT NULL
        AND partner_code <> ''
        AND LOWER(parent_user_id) = LOWER(?)
    `,
    [actorEmail]
  );

  for (const row of trainerRows) {
    const code = normalizeCode(
      row.partner_code
    );

    if (code !== "") {
      codes.add(code);
    }
  }

  // Admin-group peers
  const peers = await getAdminGroupPeerCodes(
    own
  );

  for (const code of peers) {
    const normalized = normalizeCode(code);

    if (normalized !== "") {
      codes.add(normalized);
    }
  }

  return codes;
}

// ─────────────────────────────────────────────────────────────────────────────
// Client lookup
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Get the client by profile_id.
 *
 * IMPORTANT:
 *
 * This function intentionally returns the client's actual dietician_id.
 *
 * This is required for super_admin access.
 */
async function getClientByProfileId(
  profileId
) {
  const [rows] = await pool.execute(
    `
      SELECT
        profile_id,
        dietician_id
      FROM table_clients
      WHERE profile_id = ?
      LIMIT 1
    `,
    [profileId]
  );

  return rows.length > 0
    ? rows[0]
    : null;
}

/**
 * Confirm that a client belongs to the
 * requested dietician.
 *
 * Used ONLY for non-super-admin users.
 */
async function clientPairExists(
  profileId,
  dieticianId
) {
  const [rows] = await pool.execute(
    `
      SELECT 1 AS hit
      FROM table_clients
      WHERE profile_id = ?
        AND UPPER(TRIM(dietician_id)) =
            UPPER(TRIM(?))
      LIMIT 1
    `,
    [
      profileId,
      dieticianId,
    ]
  );

  return rows.length > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Weight logs
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch weight logs from the database.
 * Gets target_weight directly from the weight_log table (same as app code).
 * The most recent non-zero target_weight is used as the user's current target.
 */
async function fetchWeightLogs(
  profileId
) {
  // First, get the most recent non-zero target_weight
  // This mimics the app's carry-forward logic
  const [targetRow] = await pool.execute(
    `
      SELECT target_weight
      FROM weight_log
      WHERE profile_id = ?
        AND (target_weight IS NOT NULL AND target_weight != 0)
      ORDER BY log_date DESC, log_time DESC, id DESC
      LIMIT 1
    `,
    [profileId]
  );

  // If no non-zero target found, use null
  const currentTargetWeight = targetRow.length > 0 
    ? toFloat(targetRow[0].target_weight) 
    : null;

  // Now fetch all logs
  const [rows] = await pool.execute(
    `
      SELECT
        id,
        profile_id,
        weight_kg,
        target_weight,
        weight_change_type,
        logged_by,
        log_date,
        log_time,
        created_at
      FROM weight_log
      WHERE profile_id = ?
      ORDER BY
        log_date DESC,
        log_time DESC,
        id DESC
    `,
    [profileId]
  );

  return rows.map((row) => {
    const logTargetWeight = toFloat(row.target_weight);
    
    // For each log, use the log's target_weight if it's non-zero,
    // otherwise use the current target weight (carry-forward logic)
    const effectiveTargetWeight = (logTargetWeight && logTargetWeight > 0) 
      ? logTargetWeight 
      : currentTargetWeight;

    return {
      id: toInt(row.id),
      profile_id: row.profile_id,
      weight_kg: toFloat(row.weight_kg),
      target_weight: effectiveTargetWeight,  // Use the effective target weight
      weight_change_type: row.weight_change_type,
      logged_by: row.logged_by,
      log_date: toMysqlDate(row.log_date),
      log_time: row.log_time !== null && row.log_time !== undefined
        ? String(row.log_time)
        : null,
      created_at: toMysqlDateTime(row.created_at),
    };
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// Test JSON parsing
// ─────────────────────────────────────────────────────────────────────────────

function parseTestJson(columnValue) {
  if (
    columnValue === null ||
    columnValue === undefined
  ) {
    return null;
  }

  let jsonText = "";

  if (Buffer.isBuffer(columnValue)) {
    jsonText =
      columnValue.toString("utf8");
  } else if (
    typeof columnValue === "string"
  ) {
    jsonText = columnValue;
  } else if (
    columnValue &&
    columnValue.type === "Buffer" &&
    Array.isArray(columnValue.data)
  ) {
    jsonText =
      Buffer.from(
        columnValue.data
      ).toString("utf8");
  } else if (
    typeof columnValue === "object" &&
    !Array.isArray(columnValue)
  ) {
    return columnValue;
  } else {
    return null;
  }

  jsonText = jsonText.trim();

  if (!jsonText) {
    return null;
  }

  try {
    const parsed =
      JSON.parse(jsonText);

    return typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed)
      ? parsed
      : null;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Metabolism scores
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Fetch date-wise metabolism scores.
 */
async function fetchMetabolismScoresByDate(
  profileId,
  dieticianId,
  fitnessGoal
) {
  const [rows] = await pool.execute(
    `
      SELECT
        t1.test_json,
        t1.date_time
      FROM table_test_data t1

      INNER JOIN (
        SELECT
          DATE(date_time) AS test_date,
          MAX(date_time) AS max_date_time
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(TRIM(dietitian_id)) =
              UPPER(TRIM(?))
        GROUP BY DATE(date_time)
      ) t2
        ON t1.date_time = t2.max_date_time
        AND DATE(t1.date_time) = t2.test_date

      WHERE t1.profile_id = ?
        AND UPPER(TRIM(t1.dietitian_id)) =
            UPPER(TRIM(?))

      ORDER BY
        t1.date_time DESC
    `,
    [
      profileId,
      dieticianId,
      profileId,
      dieticianId,
    ]
  );

  const trendKey =
    String(fitnessGoal)
      .trim()
      .toLowerCase() ===
    "muscle_gain"
      ? "Muscle_Gain_Trend"
      : "Fat_Use_Pattern_trend";

  const scores = [];

  for (const row of rows) {
    const json =
      parseTestJson(
        row.test_json
      );

    const rawValue =
      json?.[trendKey]?.value;

    if (
      rawValue === null ||
      rawValue === undefined ||
      rawValue === ""
    ) {
      continue;
    }

    const n = Number(rawValue);

    if (Number.isNaN(n)) {
      continue;
    }

    scores.push({
      date:
        toMysqlDate(
          row.date_time
        ),
      score: n,
    });
  }

  return scores;
}

// ─────────────────────────────────────────────────────────────────────────────
// Fitness goal
// ─────────────────────────────────────────────────────────────────────────────

async function fetchFitnessGoal(
  profileId
) {
  const [rows] = await pool.execute(
    `
      SELECT goal
      FROM user_habits
      WHERE profile_id = ?
      ORDER BY id DESC
      LIMIT 1
    `,
    [profileId]
  );

  const raw =
    String(
      rows[0]?.goal ?? ""
    ).trim();

  return raw !== ""
    ? raw
    : "weight_loss";
}

// ─────────────────────────────────────────────────────────────────────────────
// Input parsing
// ─────────────────────────────────────────────────────────────────────────────

function parseInputs(req) {
  const src =
    req.body &&
    typeof req.body === "object" &&
    !Array.isArray(req.body)
      ? req.body
      : null;

  if (src === null) {
    return {
      invalidBody: true,
    };
  }

  const profileId =
    typeof src.profile_id === "string"
      ? src.profile_id.trim()
      : String(
          src.profile_id ?? ""
        ).trim();

  const dieticianId =
    typeof src.dietician_id === "string"
      ? src.dietician_id.trim()
      : String(
          src.dietician_id ?? ""
        ).trim();

  const actorUserId =
    normalizeEmail(
      src.actor_user_id
    );

  return {
    invalidBody: false,
    profileId,
    dieticianId,
    actorUserId,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Controller
// ─────────────────────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/weight-tracking
 */
const weightTracking = async (
  req,
  res
) => {
  // HIPAA:
  // Prevent intermediaries from caching PHI.
  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.setHeader(
    "Pragma",
    "no-cache"
  );

  // ───────────────────────────────────────────────────────────────────────────
  // Method validation
  // ───────────────────────────────────────────────────────────────────────────

  if (req.method !== "POST") {
    return res.status(405).json({
      status: false,
      message: "Only POST method is allowed",
      data: null,
      error: {
        code: "METHOD_NOT_ALLOWED",
      },
    });
  }

  // ───────────────────────────────────────────────────────────────────────────
  // Parse body
  // ───────────────────────────────────────────────────────────────────────────

  const parsed =
    parseInputs(req);

  if (parsed.invalidBody) {
    return res.status(400).json({
      status: false,
      message: "Invalid JSON payload",
      data: null,
      error: {
        code: "INVALID_JSON",
      },
    });
  }

  const {
    profileId,
    dieticianId,
    actorUserId,
  } = parsed;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  try {
    // ─────────────────────────────────────────────────────────────────────────
    // 1. Validate inputs
    // ─────────────────────────────────────────────────────────────────────────

    if (
      profileId === "" ||
      dieticianId === ""
    ) {
      return res.status(422).json({
        status: false,
        message: "profile_id and dietician_id are required",
        data: null,
        error: {
          code: "VALIDATION_ERROR",
        },
      });
    }

    if (
      profileId.length >
        ID_MAX_LENGTH ||
      dieticianId.length >
        ID_MAX_LENGTH
    ) {
      return res.status(422).json({
        status: false,
        message: "profile_id or dietician_id is too long",
        data: null,
        error: {
          code: "VALIDATION_ERROR",
        },
      });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Resolve actor from JWT
    // ─────────────────────────────────────────────────────────────────────────

    const resolved =
      await resolveActorFromToken(
        req
      );

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "weight_logs_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: profileId + "|" + dieticianId,
        success: false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });

      return res
        .status(resolved.error.status)
        .json(resolved.error.body);
    }

    const {
      actor,
    } = resolved;

    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = normalizeCode(getActorEffectiveCode(actor));

    const isSuperAdmin =
      actorRole === "super_admin";

    // ─────────────────────────────────────────────────────────────────────────
    // 2b. actor_user_id must match JWT identity
    // ─────────────────────────────────────────────────────────────────────────

    if (
      actorUserId !== "" &&
      actorUserId !== actorEmail
    ) {
      await writeAuthLogSafe(req, {
        eventType: "weight_logs_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: actorUserId,
        success: false,
        failureReason: "actor_user_id does not match token identity",
      });

      return res.status(403).json({
        status: false,
        message: "actor_user_id does not match the authenticated user",
        data: null,
        error: {
          code: "FORBIDDEN",
        },
      });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Entitlement check
    // ─────────────────────────────────────────────────────────────────────────

    if (!isSuperAdmin) {
      const allowedCodes =
        await getAllowedCodes(
          actor,
          actorEmail
        );

      if (
        !allowedCodes.has(
          normalizeCode(
            dieticianId
          )
        )
      ) {
        await writeAuthLogSafe(req, {
          eventType: "weight_logs_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: profileId + "|" + dieticianId,
          success: false,
          failureReason: "dietician_id outside actor visibility",
        });

        return res.status(403).json({
          status: false,
          message: "You are not allowed to view this client's weight logs",
          data: null,
          error: {
            code: "FORBIDDEN",
          },
        });
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Find client
    // ─────────────────────────────────────────────────────────────────────────

    const client =
      await getClientByProfileId(
        profileId
      );

    if (!client) {
      await writeAuthLogSafe(req, {
        eventType: "weight_logs_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: profileId + "|" + dieticianId,
        success: false,
        failureReason: "Client not found",
      });

      return res.status(404).json({
        status: false,
        message: "Client not found",
        data: null,
        error: {
          code: "NOT_FOUND",
        },
      });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Determine actual client dietician
    // ─────────────────────────────────────────────────────────────────────────

    const actualClientDieticianId =
      String(
        client.dietician_id ??
          ""
      ).trim();

    if (
      actualClientDieticianId === ""
    ) {
      await writeAuthLogSafe(req, {
        eventType: "weight_logs_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: profileId + "|" + dieticianId,
        success: false,
        failureReason: "Client has no dietician_id",
      });

      return res.status(404).json({
        status: false,
        message: "Client not found",
        data: null,
        error: {
          code: "NOT_FOUND",
        },
      });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. Ownership check for NON-super-admin
    // ─────────────────────────────────────────────────────────────────────────

    if (!isSuperAdmin) {
      const ownsClient =
        await clientPairExists(
          profileId,
          dieticianId
        );

      if (!ownsClient) {
        await writeAuthLogSafe(req, {
          eventType: "weight_logs_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: profileId + "|" + dieticianId,
          success: false,
          failureReason: "Client not found for dietician",
        });

        return res.status(404).json({
          status: false,
          message: "Client not found",
          data: null,
          error: {
            code: "NOT_FOUND",
          },
        });
      }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. Determine dietician used for data lookup
    // ─────────────────────────────────────────────────────────────────────────

    const lookupDieticianId =
      isSuperAdmin
        ? actualClientDieticianId
        : dieticianId;

    // ─────────────────────────────────────────────────────────────────────────
    // 8. Fetch fitness goal
    // ─────────────────────────────────────────────────────────────────────────

    const fitnessGoal =
      await fetchFitnessGoal(
        profileId
      );

    // ─────────────────────────────────────────────────────────────────────────
    // 9. Fetch weight logs + metabolism scores
    // ─────────────────────────────────────────────────────────────────────────

    const [
      logs,
      metabolismScores,
    ] = await Promise.all([
      fetchWeightLogs(profileId),  // ← Uses weight_log.target_weight column
      fetchMetabolismScoresByDate(
        profileId,
        lookupDieticianId,
        fitnessGoal
      ),
    ]);

    // Latest score = first entry because
    // results are ordered newest first.
    const metabolismScore =
      metabolismScores.length > 0
        ? metabolismScores[0].score
        : null;

    // ─────────────────────────────────────────────────────────────────────────
    // 10. Audit successful PHI read
    // ─────────────────────────────────────────────────────────────────────────

    writeAuthLogSafe(req, {
      eventType: "weight_logs_viewed",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: profileId + "|" + dieticianId + "|rows:" + logs.length,
      success: true,
      failureReason: "Weight logs viewed",
    });

    // ─────────────────────────────────────────────────────────────────────────
    // 11. Get current target weight (most recent non-zero value)
    // ─────────────────────────────────────────────────────────────────────────

    const [targetRow] = await pool.execute(
      `
        SELECT target_weight
        FROM weight_log
        WHERE profile_id = ?
          AND (target_weight IS NOT NULL AND target_weight != 0)
        ORDER BY log_date DESC, log_time DESC, id DESC
        LIMIT 1
      `,
      [profileId]
    );

    const currentTargetWeight = targetRow.length > 0 
      ? toFloat(targetRow[0].target_weight) 
      : null;

    // ─────────────────────────────────────────────────────────────────────────
    // 12. Return response
    // ─────────────────────────────────────────────────────────────────────────

    const responseData = {
      status: true,
      message: "Weight logs fetched successfully",
      fitness_goal: fitnessGoal,
      target_weight: currentTargetWeight,  // ← Current target weight from weight_log
      metabolism_score: metabolismScore,
      metabolism_scores: metabolismScores,
      data: logs,
      error: null,
    };

    if (logs.length === 0) {
      responseData.status = false;
      responseData.message = "No weight logs found";
      responseData.error = {
        code: "NOT_FOUND",
      };
    }

    return res.status(logs.length > 0 ? 200 : 404).json(responseData);

  } catch (err) {
    // ─────────────────────────────────────────────────────────────────────────
    // Error handling
    // ─────────────────────────────────────────────────────────────────────────

    console.error("WEIGHT_TRACKING_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "weight_logs_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: profileId + "|" + dieticianId,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      message: "Server error",
      data: null,
      error: {
        code: "SERVER_ERROR",
        ...(APP_DEBUG && {
          details: err?.message,
        }),
      },
    });
  }
};

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────

module.exports = {
  weightTracking,
};








// "use strict";

// /**
//  * weight-tracking.js
//  *
//  * Converted from: weight-tracking.php
//  * Platform      : Respyr Dietitian API (api.respyr.ai)
//  * Security      : VAPT-hardened, HIPAA-aligned
//  *
//  * Endpoint   : POST /dietitian/api/web/weight-tracking
//  * Auth       : Bearer JWT (authMiddleware must run before this handler)
//  * Authorized : any active dietician (admin | super_admin | trainer) — but access
//  *              to a given client's logs is gated by OWNERSHIP, not role.
//  *
//  * Purpose: return the weight_log history for one client (profile_id).
//  *
//  * ──────────────────────────────────────────────────────────────────────────
//  *  WHY THIS IS A REWRITE, NOT A LINE PORT
//  * ──────────────────────────────────────────────────────────────────────────
//  * The PHP performed NO authorization: it read profile_id / dietician_id /
//  * actor_user_id straight from the request body and returned that client's weight
//  * PHI to anyone who asked. That is a textbook IDOR — any authenticated (or, with
//  * `Access-Control-Allow-Origin: *` and no token, ANY) caller could enumerate
//  * profile_ids and pull other patients' weight history. The core VAPT/HIPAA fix is
//  * to bind identity to the verified JWT and enforce that the actor is entitled to
//  * the requested client before a single row is returned.
//  *
//  * Authorization model (chosen scope: own + trainers + group peers):
//  *  - Identity is the verified JWT (sub = dietician_id); role + status re-checked.
//  *  - allowedCodes = actor's own effective code
//  *                 + partner_codes of active trainers parented to the actor
//  *                 + admin-group peers (getAdminGroupPeerCodes → ta_admin_groups).
//  *  - super_admin bypasses the code filter (may view any client).
//  *  - The (profile_id, dietician_id) pair MUST exist in table_clients, and
//  *    dietician_id MUST be in allowedCodes (unless super_admin). Otherwise the
//  *    request is denied and audited.
//  *
//  * Behaviour parity with the PHP (post-authorization):
//  *  - Same weight_log query, same column list, same ordering
//  *    (log_date DESC, log_time DESC, id DESC).
//  *  - Response shape { status, message, data, error } is preserved; 404 with an
//  *    empty data array + { code: "NOT_FOUND" } when there are no logs.
//  *
//  * VAPT hardening (intentional differences from the PHP):
//  *  - Token-bound identity; body.actor_user_id only cross-checked (mismatch → 403).
//  *  - Fully parameterized queries (already true for the fetch; extended to the
//  *    authorization lookups).
//  *  - Internal error details (PDOException getMessage) are NO LONGER echoed to the
//  *    client — they leak schema/PII. Gated behind APP_DEBUG; server logs carry
//  *    only error metadata (code/errno/sqlState).
//  *  - `Access-Control-Allow-Origin: *` is removed — CORS is handled centrally by
//  *    the app middleware, and a wildcard on a PHI endpoint is itself a finding.
//  *  - Cache-Control: no-store, Pragma: no-cache on every response.
//  *
//  * HIPAA controls:
//  *  - Minimum-necessary columns; no SELECT * .
//  *  - Every read (and every denial) is recorded in app_auth_logs with PHI
//  *    (identifier / IP / user-agent) HMAC-SHA256 hashed with SECURITY_PEPPER —
//  *    never stored in clear text.
//  *
//  * Tables touched: weight_log (business data), plus the auth layer
//  * (table_dietician, app_user_roles, table_clients, ta_admin_groups via the
//  * shared visibility helper) and app_auth_logs.
//  */

// const crypto = require("crypto");
// const pool = require("../../../../config/db");
// const { normalizeCode, getAdminGroupPeerCodes } = require("./admin_group_visibility");

// // ─── Constants ───────────────────────────────────────────────────────────────

// const SECURITY_PEPPER =
//   process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

// const APP_DEBUG = process.env.NODE_ENV !== "production";

// const ALLOWED_ACTOR_ROLES = new Set(["admin", "super_admin", "trainer"]);

// // Defensive bound on identifier inputs (VAPT: reject absurd payloads early).
// const ID_MAX_LENGTH = 64;

// // ─── Generic helpers ─────────────────────────────────────────────────────────

// function normalizeEmail(val) {
//   return typeof val === "string"
//     ? val.trim().toLowerCase()
//     : String(val ?? "").trim().toLowerCase();
// }

// function toInt(val) {
//   const n = Number(val);
//   return Number.isFinite(n) ? Math.trunc(n) : 0;
// }

// /** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS" (matches PHP string output). */
// function toMysqlDateTime(val) {
//   if (val === null || val === undefined) return null;
//   if (val instanceof Date) {
//     if (Number.isNaN(val.getTime())) return null;
//     const pad = (n) => String(n).padStart(2, "0");
//     return (
//       `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
//       `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
//     );
//   }
//   return String(val);
// }

// /** Format a mysql2 DATE as "YYYY-MM-DD". */
// function toMysqlDate(val) {
//   if (val === null || val === undefined) return null;
//   if (val instanceof Date) {
//     if (Number.isNaN(val.getTime())) return null;
//     const pad = (n) => String(n).padStart(2, "0");
//     return `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())}`;
//   }
//   return String(val);
// }

// /** PHP effective code: partner_code, else dietician_id, else null. */
// function getActorEffectiveCode(actor) {
//   if (actor.partner_code !== null && actor.partner_code !== undefined &&
//       String(actor.partner_code).trim() !== "") {
//     return String(actor.partner_code);
//   }
//   if (actor.dietician_id !== null && actor.dietician_id !== undefined &&
//       String(actor.dietician_id).trim() !== "") {
//     return String(actor.dietician_id);
//   }
//   return null;
// }

// function getClientIp(req) {
//   const ip =
//     (typeof req.ip === "string" && req.ip) ||
//     req.socket?.remoteAddress ||
//     req.connection?.remoteAddress ||
//     "0.0.0.0";
//   return String(ip).slice(0, 64);
// }

// function getUserAgent(req) {
//   const ua =
//     (typeof req.get === "function" && req.get("user-agent")) ||
//     req.headers?.["user-agent"] ||
//     "";
//   return String(ua).slice(0, 500);
// }

// function authLogHash(value) {
//   if (value === null || value === undefined) return null;
//   return crypto
//     .createHmac("sha256", SECURITY_PEPPER)
//     .update(String(value).trim().toLowerCase())
//     .digest("hex");
// }

// // ─── Audit log ───────────────────────────────────────────────────────────────

// async function writeAuthLogSafe(req, {
//   eventType,
//   userId,
//   role,
//   partnerCode,
//   identifier,
//   success,
//   failureReason,
// }) {
//   try {
//     const ipHash = authLogHash(getClientIp(req));
//     const userAgentHash = authLogHash(getUserAgent(req));
//     const identifierHash =
//       identifier !== null && identifier !== undefined ? authLogHash(identifier) : null;

//     await pool.execute(
//       `INSERT INTO app_auth_logs (
//          event_type,
//          user_id,
//          role,
//          partner_code,
//          identifier_hash,
//          ip_hash,
//          user_agent_hash,
//          session_id_hash,
//          success,
//          failure_reason
//        )
//        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
//       [
//         String(eventType || "").slice(0, 60),
//         userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
//         role ?? null,
//         partnerCode ?? null,
//         identifierHash,
//         ipHash,
//         userAgentHash,
//         success ? 1 : 0,
//         failureReason !== null && failureReason !== undefined
//           ? String(failureReason).slice(0, 255)
//           : null,
//       ]
//     );
//   } catch (err) {
//     console.error("WEIGHT_TRACKING_AUDIT_FAILED:", err?.code || err?.message);
//   }
// }

// // ─── Actor resolution (token-bound) ──────────────────────────────────────────

// async function resolveActorFromToken(req) {
//   const payload = req.user || {};
//   const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

//   if (!dieticianId || dieticianId.length > ID_MAX_LENGTH) {
//     return { error: { status: 401, body: { status: false, message: "Invalid token user", data: null, error: { code: "UNAUTHENTICATED" } } } };
//   }

//   const [rows] = await pool.execute(
//     `
//       SELECT
//         td.dietician_id,
//         td.name,
//         td.email,
//         aur.role,
//         aur.partner_code,
//         aur.parent_user_id,
//         aur.status
//       FROM table_dietician td
//       INNER JOIN app_user_roles aur
//         ON LOWER(aur.user_id) = LOWER(td.email)
//       WHERE td.dietician_id = ?
//       LIMIT 1
//     `,
//     [dieticianId]
//   );

//   const actor = rows[0];

//   if (!actor) {
//     return { error: { status: 403, body: { status: false, message: "Actor user not found", data: null, error: { code: "FORBIDDEN" } } } };
//   }

//   if (String(actor.status) !== "active") {
//     return { error: { status: 403, body: { status: false, message: "Actor account is not active", data: null, error: { code: "FORBIDDEN" } } } };
//   }

//   if (!ALLOWED_ACTOR_ROLES.has(String(actor.role))) {
//     return { error: { status: 403, body: { status: false, message: "Not allowed to access weight logs", data: null, error: { code: "FORBIDDEN" } } } };
//   }

//   return { actor, actorEmail: normalizeEmail(actor.email) };
// }

// // ─── Authorization: allowed dietician codes ──────────────────────────────────

// /**
//  * Build the set of dietician codes whose clients the actor may view:
//  *   own effective code
//  *   + active trainers parented to the actor (their partner_code)
//  *   + admin-group peers (getAdminGroupPeerCodes, ta_admin_groups).
//  * All UPPER-cased. super_admin does not use this (it bypasses the filter).
//  */
// async function getAllowedCodes(actor, actorEmail) {
//   const codes = new Set();

//   const own = normalizeCode(getActorEffectiveCode(actor));
//   if (own !== "") codes.add(own);

//   // Active child trainers parented to this actor.
//   const [trainerRows] = await pool.execute(
//     `
//       SELECT partner_code
//       FROM app_user_roles
//       WHERE role = 'trainer'
//         AND status = 'active'
//         AND partner_code IS NOT NULL
//         AND partner_code <> ''
//         AND LOWER(parent_user_id) = LOWER(?)
//     `,
//     [actorEmail]
//   );
//   for (const row of trainerRows) {
//     const c = normalizeCode(row.partner_code);
//     if (c !== "") codes.add(c);
//   }

//   // Admin-group peers (shares an active ta_admin_groups group). Always includes
//   // `own`; safe to union in.
//   const peers = await getAdminGroupPeerCodes(own);
//   for (const c of peers) {
//     const nc = normalizeCode(c);
//     if (nc !== "") codes.add(nc);
//   }

//   return codes;
// }

// /**
//  * Confirm the requested (profile_id, dietician_id) pair is a real client owned by
//  * that dietician. Returns true/false. Case-insensitive on dietician_id to match
//  * the rest of the project.
//  */
// async function clientPairExists(profileId, dieticianId) {
//   const [rows] = await pool.execute(
//     `
//       SELECT 1 AS hit
//       FROM table_clients
//       WHERE profile_id = ?
//         AND UPPER(dietician_id) = UPPER(?)
//       LIMIT 1
//     `,
//     [profileId, dieticianId]
//   );
//   return rows.length > 0;
// }

// // ─── Fetch ───────────────────────────────────────────────────────────────────

// async function fetchWeightLogs(profileId) {
//   const [rows] = await pool.execute(
//     `
//       SELECT
//         id,
//         profile_id,
//         weight_kg,
//         weight_change_type,
//         logged_by,
//         log_date,
//         log_time,
//         created_at
//       FROM weight_log
//       WHERE profile_id = ?
//       ORDER BY log_date DESC, log_time DESC, id DESC
//     `,
//     [profileId]
//   );

//   return rows.map((row) => ({
//     id: toInt(row.id),
//     profile_id: row.profile_id,
//     weight_kg: row.weight_kg,
//     weight_change_type: row.weight_change_type,
//     logged_by: row.logged_by,
//     log_date: toMysqlDate(row.log_date),
//     // TIME columns come back as "HH:MM:SS" strings from mysql2; pass through.
//     log_time: row.log_time !== null && row.log_time !== undefined ? String(row.log_time) : null,
//     created_at: toMysqlDateTime(row.created_at),
//   }));
// }

// /**
//  * Blob/string-safe parse of the table_test_data.test_json column.
//  * Mirrors parseJsonColumn in get_data_points_score_all_ranges_coach.js.
//  * Returns a plain object or null.
//  */
// function parseTestJson(columnValue) {
//   if (columnValue === null || columnValue === undefined) return null;

//   let jsonText = "";

//   if (Buffer.isBuffer(columnValue)) {
//     jsonText = columnValue.toString("utf8");
//   } else if (typeof columnValue === "string") {
//     jsonText = columnValue;
//   } else if (
//     columnValue &&
//     columnValue.type === "Buffer" &&
//     Array.isArray(columnValue.data)
//   ) {
//     jsonText = Buffer.from(columnValue.data).toString("utf8");
//   } else if (typeof columnValue === "object" && !Array.isArray(columnValue)) {
//     return columnValue;
//   } else {
//     return null;
//   }

//   jsonText = jsonText.trim();
//   if (!jsonText) return null;

//   try {
//     const parsed = JSON.parse(jsonText);
//     return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
//       ? parsed
//       : null;
//   } catch {
//     return null;
//   }
// }

// /**
//  * Date-wise metabolism scores for the graph, goal-aware (same source as
//  * get-data-points-score-all-ranges-coach: table_test_data.test_json):
//  *   fitness_goal === "muscle_gain"  → test_json.Muscle_Gain_Trend.value
//  *   anything else (fat_loss, ...)   → test_json.Fat_Use_Pattern_trend.value
//  * Key casing matches the stored JSON exactly — note the lowercase "trend"
//  * in Fat_Use_Pattern_trend.
//  *
//  * One score per date: the LATEST test of each date (same rule as the coach
//  * endpoint's ORDER BY date_time DESC LIMIT 1 for a selected date).
//  * Ordered newest date first, matching the weight logs. Dates whose test_json
//  * lacks a numeric value for the goal's key are skipped.
//  *
//  * NOTE: table_test_data uses the `dietitian_id` spelling (unlike table_clients'
//  * `dietician_id`).
//  *
//  * Returns [{ date: "YYYY-MM-DD", score: Number }, ...]
//  */
// async function fetchMetabolismScoresByDate(profileId, dieticianId, fitnessGoal) {
//   const [rows] = await pool.execute(
//     `
//       SELECT
//         t1.test_json,
//         t1.date_time
//       FROM table_test_data t1
//       INNER JOIN (
//         SELECT
//           DATE(date_time) AS test_date,
//           MAX(date_time) AS max_date_time
//         FROM table_test_data
//         WHERE profile_id = ?
//           AND UPPER(TRIM(dietitian_id)) = UPPER(TRIM(?))
//         GROUP BY DATE(date_time)
//       ) t2
//         ON t1.date_time = t2.max_date_time
//         AND DATE(t1.date_time) = t2.test_date
//       WHERE t1.profile_id = ?
//         AND UPPER(TRIM(t1.dietitian_id)) = UPPER(TRIM(?))
//       ORDER BY t1.date_time DESC
//     `,
//     [profileId, dieticianId, profileId, dieticianId]
//   );

//   const trendKey =
//     String(fitnessGoal).trim().toLowerCase() === "muscle_gain"
//       ? "Muscle_Gain_Trend"
//       : "Fat_Use_Pattern_trend";

//   const scores = [];

//   for (const row of rows) {
//     const json = parseTestJson(row.test_json);
//     const rawValue = json?.[trendKey]?.value;

//     if (rawValue === null || rawValue === undefined || rawValue === "") continue;

//     const n = Number(rawValue);
//     if (Number.isNaN(n)) continue;

//     scores.push({
//       date: toMysqlDate(row.date_time),
//       score: n,
//     });
//   }

//   return scores;
// }

// /**
//  * Client's fitness goal from the latest user_habits row (same source as the
//  * dashboard). Defaults to "weight_loss" when no habits row / empty goal,
//  * matching get_clients_data_total_missed_test.js.
//  */
// async function fetchFitnessGoal(profileId) {
//   const [rows] = await pool.execute(
//     `
//       SELECT goal
//       FROM user_habits
//       WHERE profile_id = ?
//       ORDER BY id DESC
//       LIMIT 1
//     `,
//     [profileId]
//   );

//   const raw = String(rows[0]?.goal ?? "").trim();
//   return raw !== "" ? raw : "weight_loss";
// }

// // ─── Input parsing ───────────────────────────────────────────────────────────

// function parseInputs(req) {
//   const src = req.body && typeof req.body === "object" && !Array.isArray(req.body)
//     ? req.body
//     : null;

//   if (src === null) return { invalidBody: true };

//   const profileId =
//     typeof src.profile_id === "string" ? src.profile_id.trim() : String(src.profile_id ?? "").trim();
//   const dieticianId =
//     typeof src.dietician_id === "string" ? src.dietician_id.trim() : String(src.dietician_id ?? "").trim();
//   const actorUserId = normalizeEmail(src.actor_user_id);

//   return { invalidBody: false, profileId, dieticianId, actorUserId };
// }

// // ─── Controller ──────────────────────────────────────────────────────────────

// /**
//  * POST /dietitian/api/web/weight-tracking
//  *
//  * Headers: Authorization: Bearer <JWT>
//  * Body:
//  *   {
//  *     "profile_id": "PRF10023",       // required
//  *     "dietician_id": "RESPYRD05",     // required; must own the client + be visible to actor
//  *     "actor_user_id": ""              // optional; if set, must match the token email
//  *   }
//  */
// const weightTracking = async (req, res) => {
//   // HIPAA: never let intermediaries cache PHI responses.
//   res.setHeader("Cache-Control", "no-store");
//   res.setHeader("Pragma", "no-cache");

//   // VAPT: method gate (matches the PHP).
//   if (req.method !== "POST") {
//     return res.status(405).json({
//       status: false, message: "Only POST method is allowed", data: null,
//       error: { code: "METHOD_NOT_ALLOWED" },
//     });
//   }

//   const parsed = parseInputs(req);

//   if (parsed.invalidBody) {
//     return res.status(400).json({
//       status: false, message: "Invalid JSON payload", data: null,
//       error: { code: "INVALID_JSON" },
//     });
//   }

//   const { profileId, dieticianId, actorUserId } = parsed;

//   let actorEmail = null;
//   let actorRole = null;
//   let actorCode = null;

//   try {
//     // ── 1. Validate required inputs ─────────────────────────────────────────
//     if (profileId === "" || dieticianId === "") {
//       return res.status(422).json({
//         status: false,
//         message: "profile_id and dietician_id are required",
//         data: null,
//         error: { code: "VALIDATION_ERROR" },
//       });
//     }
//     if (profileId.length > ID_MAX_LENGTH || dieticianId.length > ID_MAX_LENGTH) {
//       return res.status(422).json({
//         status: false,
//         message: "profile_id or dietician_id is too long",
//         data: null,
//         error: { code: "VALIDATION_ERROR" },
//       });
//     }

//     // ── 2. Resolve + authorize actor from JWT ───────────────────────────────
//     const resolved = await resolveActorFromToken(req);

//     if (resolved.error) {
//       await writeAuthLogSafe(req, {
//         eventType: "weight_logs_denied",
//         userId: null,
//         role: null,
//         partnerCode: null,
//         identifier: profileId + "|" + dieticianId,
//         success: false,
//         failureReason: resolved.error.body?.message || "actor resolution failed",
//       });
//       return res.status(resolved.error.status).json(resolved.error.body);
//     }

//     const { actor } = resolved;
//     actorEmail = resolved.actorEmail;
//     actorRole = String(actor.role);
//     actorCode = normalizeCode(getActorEffectiveCode(actor));
//     const isSuperAdmin = actorRole === "super_admin";

//     // ── 2b. Cross-check optional actor_user_id against the token identity ────
//     if (actorUserId !== "" && actorUserId !== actorEmail) {
//       await writeAuthLogSafe(req, {
//         eventType: "weight_logs_denied",
//         userId: actorEmail,
//         role: actorRole,
//         partnerCode: actorCode,
//         identifier: actorUserId,
//         success: false,
//         failureReason: "actor_user_id does not match token identity",
//       });
//       return res.status(403).json({
//         status: false,
//         message: "actor_user_id does not match the authenticated user",
//         data: null,
//         error: { code: "FORBIDDEN" },
//       });
//     }

//     // ── 3. Entitlement: may the actor view this dietician's clients? ─────────
//     if (!isSuperAdmin) {
//       const allowedCodes = await getAllowedCodes(actor, actorEmail);
//       if (!allowedCodes.has(normalizeCode(dieticianId))) {
//         await writeAuthLogSafe(req, {
//           eventType: "weight_logs_denied",
//           userId: actorEmail,
//           role: actorRole,
//           partnerCode: actorCode,
//           identifier: profileId + "|" + dieticianId,
//           success: false,
//           failureReason: "dietician_id outside actor visibility",
//         });
//         return res.status(403).json({
//           status: false,
//           message: "You are not allowed to view this client's weight logs",
//           data: null,
//           error: { code: "FORBIDDEN" },
//         });
//       }
//     }

//     // ── 4. Ownership: the (profile_id, dietician_id) pair must be a real client ─
//     if (!(await clientPairExists(profileId, dieticianId))) {
//       await writeAuthLogSafe(req, {
//         eventType: "weight_logs_denied",
//         userId: actorEmail,
//         role: actorRole,
//         partnerCode: actorCode,
//         identifier: profileId + "|" + dieticianId,
//         success: false,
//         failureReason: "Client not found for dietician",
//       });
//       return res.status(404).json({
//         status: false,
//         message: "Client not found",
//         data: null,
//         error: { code: "NOT_FOUND" },
//       });
//     }

//     // ── 5. Fetch fitness goal, then weight logs + date-wise metabolism scores ─
//     // Goal first: it decides which test_json trend key the scores come from.
//     const fitnessGoal = await fetchFitnessGoal(profileId);

//     const [logs, metabolismScores] = await Promise.all([
//       fetchWeightLogs(profileId),
//       fetchMetabolismScoresByDate(profileId, dieticianId, fitnessGoal),
//     ]);

//     // Latest score = first entry (newest date first); null if no tests.
//     const metabolismScore = metabolismScores.length > 0 ? metabolismScores[0].score : null;

//     // ── 6. Audit the PHI read (fire-and-forget) ─────────────────────────────
//     writeAuthLogSafe(req, {
//       eventType: "weight_logs_viewed",
//       userId: actorEmail,
//       role: actorRole,
//       partnerCode: actorCode,
//       identifier: profileId + "|" + dieticianId + "|rows:" + logs.length,
//       success: true,
//       failureReason: "Weight logs viewed",
//     });

//     // ── 7. Respond (matches the PHP JSON shape) ─────────────────────────────
//     if (logs.length > 0) {
//       return res.status(200).json({
//         status: true,
//         message: "Weight logs fetched successfully",
//         fitness_goal: fitnessGoal,
//         metabolism_score: metabolismScore,
//         metabolism_scores: metabolismScores,
//         data: logs,
//         error: null,
//       });
//     }

//     return res.status(404).json({
//       status: false,
//       message: "No weight logs found",
//       fitness_goal: fitnessGoal,
//       metabolism_score: metabolismScore,
//       metabolism_scores: metabolismScores,
//       data: [],
//       error: { code: "NOT_FOUND" },
//     });
//   } catch (err) {
//     console.error("WEIGHT_TRACKING_ERROR:", {
//       code: err?.code,
//       errno: err?.errno,
//       sqlState: err?.sqlState,
//       message: err?.message,
//     });

//     await writeAuthLogSafe(req, {
//       eventType: "weight_logs_error",
//       userId: actorEmail,
//       role: actorRole,
//       partnerCode: actorCode,
//       identifier: profileId + "|" + dieticianId,
//       success: false,
//       failureReason: err?.code || "internal_error",
//     });

//     return res.status(500).json({
//       status: false,
//       message: "Server error",
//       data: null,
//       error: {
//         code: "SERVER_ERROR",
//         ...(APP_DEBUG && { details: err?.message }),
//       },
//     });
//   }
// };

// module.exports = { weightTracking };



// "use strict";

// /**
//  * weight-tracking.js
//  *
//  * Converted from: weight-tracking.php
//  * Platform      : Respyr Dietitian API (api.respyr.ai)
//  * Security      : VAPT-hardened, HIPAA-aligned
//  *
//  * Endpoint   : POST /dietitian/api/web/weight-tracking
//  * Auth       : Bearer JWT (authMiddleware must run before this handler)
//  * Authorized : any active dietician (admin | super_admin | trainer) — but access
//  *              to a given client's logs is gated by OWNERSHIP, not role.
//  *
//  * Purpose: return the weight_log history for one client (profile_id).
//  *
//  * ──────────────────────────────────────────────────────────────────────────
//  *  WHY THIS IS A REWRITE, NOT A LINE PORT
//  * ──────────────────────────────────────────────────────────────────────────
//  * The PHP performed NO authorization: it read profile_id / dietician_id /
//  * actor_user_id straight from the request body and returned that client's weight
//  * PHI to anyone who asked. That is a textbook IDOR — any authenticated (or, with
//  * `Access-Control-Allow-Origin: *` and no token, ANY) caller could enumerate
//  * profile_ids and pull other patients' weight history. The core VAPT/HIPAA fix is
//  * to bind identity to the verified JWT and enforce that the actor is entitled to
//  * the requested client before a single row is returned.
//  *
//  * Authorization model (chosen scope: own + trainers + group peers):
//  *  - Identity is the verified JWT (sub = dietician_id); role + status re-checked.
//  *  - allowedCodes = actor's own effective code
//  *                 + partner_codes of active trainers parented to the actor
//  *                 + admin-group peers (getAdminGroupPeerCodes → ta_admin_groups).
//  *  - super_admin bypasses the code filter (may view any client).
//  *  - The (profile_id, dietician_id) pair MUST exist in table_clients, and
//  *    dietician_id MUST be in allowedCodes (unless super_admin). Otherwise the
//  *    request is denied and audited.
//  *
//  * Behaviour parity with the PHP (post-authorization):
//  *  - Same weight_log query, same column list, same ordering
//  *    (log_date DESC, log_time DESC, id DESC).
//  *  - Response shape { status, message, data, error } is preserved; 404 with an
//  *    empty data array + { code: "NOT_FOUND" } when there are no logs.
//  *
//  * VAPT hardening (intentional differences from the PHP):
//  *  - Token-bound identity; body.actor_user_id only cross-checked (mismatch → 403).
//  *  - Fully parameterized queries (already true for the fetch; extended to the
//  *    authorization lookups).
//  *  - Internal error details (PDOException getMessage) are NO LONGER echoed to the
//  *    client — they leak schema/PII. Gated behind APP_DEBUG; server logs carry
//  *    only error metadata (code/errno/sqlState).
//  *  - `Access-Control-Allow-Origin: *` is removed — CORS is handled centrally by
//  *    the app middleware, and a wildcard on a PHI endpoint is itself a finding.
//  *  - Cache-Control: no-store, Pragma: no-cache on every response.
//  *
//  * HIPAA controls:
//  *  - Minimum-necessary columns; no SELECT * .
//  *  - Every read (and every denial) is recorded in app_auth_logs with PHI
//  *    (identifier / IP / user-agent) HMAC-SHA256 hashed with SECURITY_PEPPER —
//  *    never stored in clear text.
//  *
//  * Tables touched: weight_log (business data), plus the auth layer
//  * (table_dietician, app_user_roles, table_clients, ta_admin_groups via the
//  * shared visibility helper) and app_auth_logs.
//  */

// const crypto = require("crypto");
// const pool = require("../../../../config/db");
// const { normalizeCode, getAdminGroupPeerCodes } = require("./admin_group_visibility");

// // ─── Constants ───────────────────────────────────────────────────────────────

// const SECURITY_PEPPER =
//   process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

// const APP_DEBUG = process.env.NODE_ENV !== "production";

// const ALLOWED_ACTOR_ROLES = new Set(["admin", "super_admin", "trainer"]);

// // Defensive bound on identifier inputs (VAPT: reject absurd payloads early).
// const ID_MAX_LENGTH = 64;

// // ─── Generic helpers ─────────────────────────────────────────────────────────

// function normalizeEmail(val) {
//   return typeof val === "string"
//     ? val.trim().toLowerCase()
//     : String(val ?? "").trim().toLowerCase();
// }

// function toInt(val) {
//   const n = Number(val);
//   return Number.isFinite(n) ? Math.trunc(n) : 0;
// }

// /** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS" (matches PHP string output). */
// function toMysqlDateTime(val) {
//   if (val === null || val === undefined) return null;
//   if (val instanceof Date) {
//     if (Number.isNaN(val.getTime())) return null;
//     const pad = (n) => String(n).padStart(2, "0");
//     return (
//       `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
//       `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
//     );
//   }
//   return String(val);
// }

// /** Format a mysql2 DATE as "YYYY-MM-DD". */
// function toMysqlDate(val) {
//   if (val === null || val === undefined) return null;
//   if (val instanceof Date) {
//     if (Number.isNaN(val.getTime())) return null;
//     const pad = (n) => String(n).padStart(2, "0");
//     return `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())}`;
//   }
//   return String(val);
// }

// /** PHP effective code: partner_code, else dietician_id, else null. */
// function getActorEffectiveCode(actor) {
//   if (actor.partner_code !== null && actor.partner_code !== undefined &&
//       String(actor.partner_code).trim() !== "") {
//     return String(actor.partner_code);
//   }
//   if (actor.dietician_id !== null && actor.dietician_id !== undefined &&
//       String(actor.dietician_id).trim() !== "") {
//     return String(actor.dietician_id);
//   }
//   return null;
// }

// function getClientIp(req) {
//   const ip =
//     (typeof req.ip === "string" && req.ip) ||
//     req.socket?.remoteAddress ||
//     req.connection?.remoteAddress ||
//     "0.0.0.0";
//   return String(ip).slice(0, 64);
// }

// function getUserAgent(req) {
//   const ua =
//     (typeof req.get === "function" && req.get("user-agent")) ||
//     req.headers?.["user-agent"] ||
//     "";
//   return String(ua).slice(0, 500);
// }

// function authLogHash(value) {
//   if (value === null || value === undefined) return null;
//   return crypto
//     .createHmac("sha256", SECURITY_PEPPER)
//     .update(String(value).trim().toLowerCase())
//     .digest("hex");
// }

// // ─── Audit log ───────────────────────────────────────────────────────────────

// async function writeAuthLogSafe(req, {
//   eventType,
//   userId,
//   role,
//   partnerCode,
//   identifier,
//   success,
//   failureReason,
// }) {
//   try {
//     const ipHash = authLogHash(getClientIp(req));
//     const userAgentHash = authLogHash(getUserAgent(req));
//     const identifierHash =
//       identifier !== null && identifier !== undefined ? authLogHash(identifier) : null;

//     await pool.execute(
//       `INSERT INTO app_auth_logs (
//          event_type,
//          user_id,
//          role,
//          partner_code,
//          identifier_hash,
//          ip_hash,
//          user_agent_hash,
//          session_id_hash,
//          success,
//          failure_reason
//        )
//        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
//       [
//         String(eventType || "").slice(0, 60),
//         userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
//         role ?? null,
//         partnerCode ?? null,
//         identifierHash,
//         ipHash,
//         userAgentHash,
//         success ? 1 : 0,
//         failureReason !== null && failureReason !== undefined
//           ? String(failureReason).slice(0, 255)
//           : null,
//       ]
//     );
//   } catch (err) {
//     console.error("WEIGHT_TRACKING_AUDIT_FAILED:", err?.code || err?.message);
//   }
// }

// // ─── Actor resolution (token-bound) ──────────────────────────────────────────

// async function resolveActorFromToken(req) {
//   const payload = req.user || {};
//   const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

//   if (!dieticianId || dieticianId.length > ID_MAX_LENGTH) {
//     return { error: { status: 401, body: { status: false, message: "Invalid token user", data: null, error: { code: "UNAUTHENTICATED" } } } };
//   }

//   const [rows] = await pool.execute(
//     `
//       SELECT
//         td.dietician_id,
//         td.name,
//         td.email,
//         aur.role,
//         aur.partner_code,
//         aur.parent_user_id,
//         aur.status
//       FROM table_dietician td
//       INNER JOIN app_user_roles aur
//         ON LOWER(aur.user_id) = LOWER(td.email)
//       WHERE td.dietician_id = ?
//       LIMIT 1
//     `,
//     [dieticianId]
//   );

//   const actor = rows[0];

//   if (!actor) {
//     return { error: { status: 403, body: { status: false, message: "Actor user not found", data: null, error: { code: "FORBIDDEN" } } } };
//   }

//   if (String(actor.status) !== "active") {
//     return { error: { status: 403, body: { status: false, message: "Actor account is not active", data: null, error: { code: "FORBIDDEN" } } } };
//   }

//   if (!ALLOWED_ACTOR_ROLES.has(String(actor.role))) {
//     return { error: { status: 403, body: { status: false, message: "Not allowed to access weight logs", data: null, error: { code: "FORBIDDEN" } } } };
//   }

//   return { actor, actorEmail: normalizeEmail(actor.email) };
// }

// // ─── Authorization: allowed dietician codes ──────────────────────────────────

// /**
//  * Build the set of dietician codes whose clients the actor may view:
//  *   own effective code
//  *   + active trainers parented to the actor (their partner_code)
//  *   + admin-group peers (getAdminGroupPeerCodes, ta_admin_groups).
//  * All UPPER-cased. super_admin does not use this (it bypasses the filter).
//  */
// async function getAllowedCodes(actor, actorEmail) {
//   const codes = new Set();

//   const own = normalizeCode(getActorEffectiveCode(actor));
//   if (own !== "") codes.add(own);

//   // Active child trainers parented to this actor.
//   const [trainerRows] = await pool.execute(
//     `
//       SELECT partner_code
//       FROM app_user_roles
//       WHERE role = 'trainer'
//         AND status = 'active'
//         AND partner_code IS NOT NULL
//         AND partner_code <> ''
//         AND LOWER(parent_user_id) = LOWER(?)
//     `,
//     [actorEmail]
//   );
//   for (const row of trainerRows) {
//     const c = normalizeCode(row.partner_code);
//     if (c !== "") codes.add(c);
//   }

//   // Admin-group peers (shares an active ta_admin_groups group). Always includes
//   // `own`; safe to union in.
//   const peers = await getAdminGroupPeerCodes(own);
//   for (const c of peers) {
//     const nc = normalizeCode(c);
//     if (nc !== "") codes.add(nc);
//   }

//   return codes;
// }

// /**
//  * Confirm the requested (profile_id, dietician_id) pair is a real client owned by
//  * that dietician. Returns true/false. Case-insensitive on dietician_id to match
//  * the rest of the project.
//  */
// async function clientPairExists(profileId, dieticianId) {
//   const [rows] = await pool.execute(
//     `
//       SELECT 1 AS hit
//       FROM table_clients
//       WHERE profile_id = ?
//         AND UPPER(dietician_id) = UPPER(?)
//       LIMIT 1
//     `,
//     [profileId, dieticianId]
//   );
//   return rows.length > 0;
// }

// // ─── Fetch ───────────────────────────────────────────────────────────────────

// async function fetchWeightLogs(profileId) {
//   const [rows] = await pool.execute(
//     `
//       SELECT
//         id,
//         profile_id,
//         weight_kg,
//         weight_change_type,
//         logged_by,
//         log_date,
//         log_time,
//         created_at
//       FROM weight_log
//       WHERE profile_id = ?
//       ORDER BY log_date DESC, log_time DESC, id DESC
//     `,
//     [profileId]
//   );

//   return rows.map((row) => ({
//     id: toInt(row.id),
//     profile_id: row.profile_id,
//     weight_kg: row.weight_kg,
//     weight_change_type: row.weight_change_type,
//     logged_by: row.logged_by,
//     log_date: toMysqlDate(row.log_date),
//     // TIME columns come back as "HH:MM:SS" strings from mysql2; pass through.
//     log_time: row.log_time !== null && row.log_time !== undefined ? String(row.log_time) : null,
//     created_at: toMysqlDateTime(row.created_at),
//   }));
// }

// // ─── Input parsing ───────────────────────────────────────────────────────────

// function parseInputs(req) {
//   const src = req.body && typeof req.body === "object" && !Array.isArray(req.body)
//     ? req.body
//     : null;

//   if (src === null) return { invalidBody: true };

//   const profileId =
//     typeof src.profile_id === "string" ? src.profile_id.trim() : String(src.profile_id ?? "").trim();
//   const dieticianId =
//     typeof src.dietician_id === "string" ? src.dietician_id.trim() : String(src.dietician_id ?? "").trim();
//   const actorUserId = normalizeEmail(src.actor_user_id);

//   return { invalidBody: false, profileId, dieticianId, actorUserId };
// }

// // ─── Controller ──────────────────────────────────────────────────────────────

// /**
//  * POST /dietitian/api/web/weight-tracking
//  *
//  * Headers: Authorization: Bearer <JWT>
//  * Body:
//  *   {
//  *     "profile_id": "PRF10023",       // required
//  *     "dietician_id": "RESPYRD05",     // required; must own the client + be visible to actor
//  *     "actor_user_id": ""              // optional; if set, must match the token email
//  *   }
//  */
// const weightTracking = async (req, res) => {
//   // HIPAA: never let intermediaries cache PHI responses.
//   res.setHeader("Cache-Control", "no-store");
//   res.setHeader("Pragma", "no-cache");

//   // VAPT: method gate (matches the PHP).
//   if (req.method !== "POST") {
//     return res.status(405).json({
//       status: false, message: "Only POST method is allowed", data: null,
//       error: { code: "METHOD_NOT_ALLOWED" },
//     });
//   }

//   const parsed = parseInputs(req);

//   if (parsed.invalidBody) {
//     return res.status(400).json({
//       status: false, message: "Invalid JSON payload", data: null,
//       error: { code: "INVALID_JSON" },
//     });
//   }

//   const { profileId, dieticianId, actorUserId } = parsed;

//   let actorEmail = null;
//   let actorRole = null;
//   let actorCode = null;

//   try {
//     // ── 1. Validate required inputs ─────────────────────────────────────────
//     if (profileId === "" || dieticianId === "") {
//       return res.status(422).json({
//         status: false,
//         message: "profile_id and dietician_id are required",
//         data: null,
//         error: { code: "VALIDATION_ERROR" },
//       });
//     }
//     if (profileId.length > ID_MAX_LENGTH || dieticianId.length > ID_MAX_LENGTH) {
//       return res.status(422).json({
//         status: false,
//         message: "profile_id or dietician_id is too long",
//         data: null,
//         error: { code: "VALIDATION_ERROR" },
//       });
//     }

//     // ── 2. Resolve + authorize actor from JWT ───────────────────────────────
//     const resolved = await resolveActorFromToken(req);

//     if (resolved.error) {
//       await writeAuthLogSafe(req, {
//         eventType: "weight_logs_denied",
//         userId: null,
//         role: null,
//         partnerCode: null,
//         identifier: profileId + "|" + dieticianId,
//         success: false,
//         failureReason: resolved.error.body?.message || "actor resolution failed",
//       });
//       return res.status(resolved.error.status).json(resolved.error.body);
//     }

//     const { actor } = resolved;
//     actorEmail = resolved.actorEmail;
//     actorRole = String(actor.role);
//     actorCode = normalizeCode(getActorEffectiveCode(actor));
//     const isSuperAdmin = actorRole === "super_admin";

//     // ── 2b. Cross-check optional actor_user_id against the token identity ────
//     if (actorUserId !== "" && actorUserId !== actorEmail) {
//       await writeAuthLogSafe(req, {
//         eventType: "weight_logs_denied",
//         userId: actorEmail,
//         role: actorRole,
//         partnerCode: actorCode,
//         identifier: actorUserId,
//         success: false,
//         failureReason: "actor_user_id does not match token identity",
//       });
//       return res.status(403).json({
//         status: false,
//         message: "actor_user_id does not match the authenticated user",
//         data: null,
//         error: { code: "FORBIDDEN" },
//       });
//     }

//     // ── 3. Entitlement: may the actor view this dietician's clients? ─────────
//     if (!isSuperAdmin) {
//       const allowedCodes = await getAllowedCodes(actor, actorEmail);
//       if (!allowedCodes.has(normalizeCode(dieticianId))) {
//         await writeAuthLogSafe(req, {
//           eventType: "weight_logs_denied",
//           userId: actorEmail,
//           role: actorRole,
//           partnerCode: actorCode,
//           identifier: profileId + "|" + dieticianId,
//           success: false,
//           failureReason: "dietician_id outside actor visibility",
//         });
//         return res.status(403).json({
//           status: false,
//           message: "You are not allowed to view this client's weight logs",
//           data: null,
//           error: { code: "FORBIDDEN" },
//         });
//       }
//     }

//     // ── 4. Ownership: the (profile_id, dietician_id) pair must be a real client ─
//     if (!(await clientPairExists(profileId, dieticianId))) {
//       await writeAuthLogSafe(req, {
//         eventType: "weight_logs_denied",
//         userId: actorEmail,
//         role: actorRole,
//         partnerCode: actorCode,
//         identifier: profileId + "|" + dieticianId,
//         success: false,
//         failureReason: "Client not found for dietician",
//       });
//       return res.status(404).json({
//         status: false,
//         message: "Client not found",
//         data: null,
//         error: { code: "NOT_FOUND" },
//       });
//     }

//     // ── 5. Fetch weight logs ────────────────────────────────────────────────
//     const logs = await fetchWeightLogs(profileId);

//     // ── 6. Audit the PHI read (fire-and-forget) ─────────────────────────────
//     writeAuthLogSafe(req, {
//       eventType: "weight_logs_viewed",
//       userId: actorEmail,
//       role: actorRole,
//       partnerCode: actorCode,
//       identifier: profileId + "|" + dieticianId + "|rows:" + logs.length,
//       success: true,
//       failureReason: "Weight logs viewed",
//     });

//     // ── 7. Respond (matches the PHP JSON shape) ─────────────────────────────
//     if (logs.length > 0) {
//       return res.status(200).json({
//         status: true,
//         message: "Weight logs fetched successfully",
//         data: logs,
//         error: null,
//       });
//     }

//     return res.status(404).json({
//       status: false,
//       message: "No weight logs found",
//       data: [],
//       error: { code: "NOT_FOUND" },
//     });
//   } catch (err) {
//     console.error("WEIGHT_TRACKING_ERROR:", {
//       code: err?.code,
//       errno: err?.errno,
//       sqlState: err?.sqlState,
//       message: err?.message,
//     });

//     await writeAuthLogSafe(req, {
//       eventType: "weight_logs_error",
//       userId: actorEmail,
//       role: actorRole,
//       partnerCode: actorCode,
//       identifier: profileId + "|" + dieticianId,
//       success: false,
//       failureReason: err?.code || "internal_error",
//     });

//     return res.status(500).json({
//       status: false,
//       message: "Server error",
//       data: null,
//       error: {
//         code: "SERVER_ERROR",
//         ...(APP_DEBUG && { details: err?.message }),
//       },
//     });
//   }
// };

// module.exports = { weightTracking };
