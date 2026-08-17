"use strict";

/**
 * remove-user.js
 *
 * Platform   : Respyr Dietitian API (api.respyr.ai)
 * Security   : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/remove-user
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 *
 * Permission matrix (Conditions 1–3):
 *  - super_admin → may remove admin, trainer, client
 *  - admin       → may remove trainer, client
 *  - trainer     → may remove client
 *
 * Request body (no target_type — the type is auto-detected server-side):
 *  {
 *    "target_user_id":      "<email>",        // email of the user to remove;
 *                                             // matched against app_user_roles
 *                                             // (admin / trainer) and
 *                                             // table_clients (client) within
 *                                             // the actor's removable scope
 *    "target_profile_id":   "<profile_id>",   // client only — pass instead of
 *                                             // target_user_id, or to break an
 *                                             // email tie between a role user
 *                                             // and a client
 *    "target_dietician_id": "<partner code>", // client only — required when the
 *                                             // profile exists under multiple
 *                                             // codes; forced to the trainer's
 *                                             // own code when actor is trainer
 *    "reason":              "<optional free text, max 255>"
 *  }
 *
 * Target-type detection:
 *  - target_profile_id present → client (profile_ids exist only for clients).
 *  - otherwise the email is searched ONLY among the account types the actor's
 *    role may remove (permission matrix above): app_user_roles for
 *    admin / trainer, table_clients for client. Exactly one type matches →
 *    proceed; zero → 404 (indistinguishable from out-of-scope, so a trainer
 *    cannot probe admin emails); more than one type → 422 asking the caller to
 *    pass target_profile_id to target the client account.
 *
 * Removal semantics:
 *  - admin / trainer  → soft removal. app_user_roles.status is set to
 *    'removed' inside a row-locked transaction. Every access-control query in
 *    this codebase (and resolveActorFromToken in every controller) filters on
 *    status = 'active', so the account is locked out platform-wide instantly.
 *    All rows in dietician_refresh_tokens for that user are deleted, so any
 *    live session dies at the next token refresh (access JWTs expire ≤ 15 min).
 *  - client → archive-then-delete. The table_clients row is copied into
 *    table_clients_removed (with removed_at / removed_by / removed_by_role /
 *    removed_reason appended) and then deleted from table_clients — all inside
 *    one transaction. The client disappears from every existing list endpoint
 *    immediately, while the PHI record is retained (HIPAA record retention)
 *    and the removal is reversible. Historical rows in table_test_data etc.
 *    remain keyed by profile_id and are untouched.
 *
 * Scope enforcement (BOLA/IDOR guards):
 *  - Actor identity comes ONLY from the verified JWT (req.user.sub), re-fetched
 *    from DB and re-checked for role + active status on every call. Nothing is
 *    trusted from the body.
 *  - super_admin removing an admin   → admin.parent_user_id must equal the
 *    super_admin's email.
 *  - super_admin removing a trainer  → trainer.parent_user_id must be the
 *    super_admin's email OR the email of an active admin under that
 *    super_admin (same network model as list-all-trainers-for-super-admin).
 *  - admin removing a trainer        → trainer.parent_user_id must equal the
 *    admin's email.
 *  - trainer removing a client       → client.dietician_id must equal the
 *    trainer's effective partner code.
 *  - admin removing a client         → client.dietician_id must be in the
 *    admin's network codes (own effective code + partner codes of active
 *    trainers parented to the admin) — same model as
 *    trainer-admin-clients-list-dir.
 *  - super_admin removing a client   → any existing client (same global
 *    super_admin visibility precedent as weight-tracking).
 *  - Nobody may remove themselves; a super_admin row can never be removed.
 *
 * VAPT controls applied:
 *  - Token-bound authorization; fully parameterized queries; row-locked
 *    (FOR UPDATE) reads inside transactions; guarded UPDATE/DELETE so a
 *    concurrent removal returns 409 rather than a false success; method gate
 *    (POST only, 405 otherwise); internal error details suppressed in
 *    production; Cache-Control: no-store + Pragma: no-cache on every response.
 *
 * HIPAA controls applied:
 *  - Minimum-necessary columns; PHI in audit logs (identifier, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text;
 *    every attempt (success, denial, error) is recorded in app_auth_logs via
 *    a fail-safe writer that never throws to the client.
 *
 * REQUIRED one-time SQL (run once before deploying — see notes shipped with
 * this file):
 *
 *   CREATE TABLE table_clients_removed LIKE table_clients;
 *   ALTER TABLE table_clients_removed
 *     ADD COLUMN removed_at      DATETIME     NULL,
 *     ADD COLUMN removed_by      VARCHAR(191) NULL,
 *     ADD COLUMN removed_by_role VARCHAR(32)  NULL,
 *     ADD COLUMN removed_reason  VARCHAR(255) NULL;
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

// Condition 1–3 permission matrix: actor role → removable target types.
const PERMISSION_MATRIX = {
  super_admin: new Set(["admin", "trainer", "client"]),
  admin: new Set(["trainer", "client"]),
  trainer: new Set(["client"]),
};

const DEFAULT_REMOVE_REASON = "Removed by administrator";

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return String(val ?? "").trim().toLowerCase();
}

function normalizeCode(val) {
  return String(val ?? "").trim().toUpperCase();
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
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

/** PHP-style effective code: partner_code, else dietician_id, else "". */
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
  return "";
}

function buildInPlaceholders(arr) {
  return arr.map(() => "?").join(",");
}

// ─── Audit log (fail-safe) ───────────────────────────────────────────────────

/**
 * Fail-safe audit writer against app_auth_logs. Never throws — audit failures
 * must not surface to clients. PHI (identifier / IP / UA) is HMAC-hashed.
 */
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

    const truncatedEvent = String(eventType || "").slice(0, 60);
    const truncatedReason =
      failureReason !== null && failureReason !== undefined
        ? String(failureReason).slice(0, 255)
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
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        truncatedEvent,
        userId ?? null,
        role ?? null,
        partnerCode ?? null,
        identifierHash,
        ipHash,
        userAgentHash,
        success ? 1 : 0,
        truncatedReason,
      ]
    );
  } catch (err) {
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound, re-checked in DB) ────────────────────────

async function resolveActorFromToken(req) {
  const payload = req.user || {};

  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return {
      error: { status: 401, message: "Invalid token user" },
    };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.id,
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
    return { error: { status: 401, message: "Token user not found" } };
  }

  if (String(actor.status) !== "active") {
    return { error: { status: 403, message: "Account is not active" } };
  }

  if (!VALID_ACTOR_ROLES.has(actor.role)) {
    return { error: { status: 403, message: "Invalid role configuration" } };
  }

  return {
    actor,
    actorEmail: String(actor.email || "").trim().toLowerCase(),
  };
}

// ─── Network helpers ─────────────────────────────────────────────────────────

/** Emails of ACTIVE admins parented to the given super_admin. */
async function getActiveAdminEmailsUnderSuperAdmin(conn, superAdminEmail) {
  const [rows] = await conn.execute(
    `
      SELECT user_id
      FROM app_user_roles
      WHERE role   = 'admin'
        AND status = 'active'
        AND LOWER(parent_user_id) = LOWER(?)
    `,
    [superAdminEmail]
  );
  return rows
    .map((r) => normalizeEmail(r.user_id))
    .filter((e) => e !== "");
}

/**
 * Admin network codes: actor's own effective code + partner codes of active
 * trainers directly parented to the actor (same model as
 * trainer-admin-clients-list-dir).
 */
async function getAdminNetworkCodes(conn, actor, actorEmail) {
  const codes = new Map();

  const addCode = (code) => {
    const c = normalizeCode(code);
    if (c !== "") codes.set(c, c);
  };

  addCode(getActorEffectiveCode(actor));

  const [rows] = await conn.execute(
    `
      SELECT partner_code
      FROM app_user_roles
      WHERE role   = 'trainer'
        AND status = 'active'
        AND partner_code IS NOT NULL
        AND partner_code <> ''
        AND LOWER(parent_user_id) = LOWER(?)
    `,
    [actorEmail]
  );

  for (const row of rows) addCode(row.partner_code);

  return [...codes.values()];
}

// ─── Refresh-token revocation ────────────────────────────────────────────────

/**
 * Delete every refresh token belonging to the target email so live sessions
 * die at the next refresh. Runs inside the caller's transaction.
 */
async function revokeRefreshTokensByEmail(conn, targetEmail) {
  await conn.execute(
    `
      DELETE rt
      FROM dietician_refresh_tokens rt
      INNER JOIN table_dietician td
        ON td.dietician_id = rt.dietician_id
      WHERE LOWER(td.email) = LOWER(?)
    `,
    [targetEmail]
  );
}

// ─── Removal: admin / trainer (soft removal in app_user_roles) ───────────────

/**
 * Shared soft-removal for admin and trainer targets.
 * `allowedParentEmails` is the list of parent_user_id values the actor is
 * permitted to manage (lower-cased).
 * Returns { status, body } — the caller sends it.
 */
async function removeRoleUser(conn, {
  targetType,          // 'admin' | 'trainer'
  targetEmail,
  allowedParentEmails, // lower-cased emails
}) {
  const [rows] = await conn.execute(
    `
      SELECT id, user_id, role, partner_code, parent_user_id, status
      FROM app_user_roles
      WHERE LOWER(user_id) = LOWER(?)
        AND role = ?
      LIMIT 1
      FOR UPDATE
    `,
    [targetEmail, targetType]
  );

  const target = rows[0];

  if (!target) {
    return {
      status: 404,
      body: {
        ok: false,
        message:
          targetType === "admin" ? "Admin not found" : "Trainer not found",
      },
      failureReason: `${targetType} not found`,
    };
  }

  const targetParent = normalizeEmail(target.parent_user_id);

  if (!allowedParentEmails.includes(targetParent)) {
    return {
      status: 403,
      body: {
        ok: false,
        message: `You are not allowed to remove this ${targetType}`,
      },
      failureReason: `${targetType} outside actor network`,
    };
  }

  const targetStatus = String(target.status || "").toLowerCase();

  if (targetStatus === "removed") {
    return {
      status: 409,
      body: {
        ok: false,
        message:
          targetType === "admin"
            ? "Admin is already removed"
            : "Trainer is already removed",
      },
      failureReason: "already removed",
    };
  }

  if (targetStatus !== "active") {
    return {
      status: 409,
      body: {
        ok: false,
        message: `Only active ${targetType}s can be removed`,
      },
      failureReason: `status is '${targetStatus}'`,
    };
  }

  // Guarded update — a concurrent removal loses cleanly (affectedRows === 0).
  const [result] = await conn.execute(
    `
      UPDATE app_user_roles
      SET status     = 'removed',
          updated_at = UTC_TIMESTAMP()
      WHERE id     = ?
        AND status = 'active'
    `,
    [target.id]
  );

  if (!result || result.affectedRows === 0) {
    return {
      status: 409,
      body: {
        ok: false,
        message: `${targetType === "admin" ? "Admin" : "Trainer"} was modified by another request. Please retry.`,
      },
      failureReason: "concurrent modification",
    };
  }

  // Kill live sessions: access JWTs expire within 15 minutes; refresh dies now.
  await revokeRefreshTokensByEmail(conn, targetEmail);

  return {
    status: 200,
    body: {
      ok: true,
      message:
        targetType === "admin"
          ? "Admin removed successfully"
          : "Trainer removed successfully",
      data: {
        target_type: targetType,
        target_user_id: normalizeEmail(target.user_id),
        partner_code: target.partner_code ?? null,
        previous_status: "active",
        new_status: "removed",
      },
    },
  };
}

// ─── Removal: client (archive-then-delete) ───────────────────────────────────

/**
 * Move the client row from table_clients into table_clients_removed inside the
 * caller's transaction, then delete the original row.
 * Returns { status, body } — the caller sends it.
 */
async function removeClient(conn, {
  actorRole,
  actorEmail,
  actorNetworkCodes, // null for super_admin (global), else array of UPPER codes
  targetProfileId,   // may be "" when the caller identifies the client by email
  targetClientEmail, // may be "" when the caller identifies the client by profile_id
  targetDieticianId, // may be "" — resolved below
  reason,
}) {
  // 1. Find candidate rows. The client may be identified by profile_id or by
  //    email; a profile/email can also exist under multiple partner codes.
  const byProfileId = targetProfileId !== "";

  const [candidates] = await conn.execute(
    byProfileId
      ? `
          SELECT profile_id, dietician_id
          FROM table_clients
          WHERE LOWER(profile_id) = LOWER(?)
          FOR UPDATE
        `
      : `
          SELECT profile_id, dietician_id
          FROM table_clients
          WHERE LOWER(email) = LOWER(?)
          FOR UPDATE
        `,
    [byProfileId ? targetProfileId : targetClientEmail]
  );

  if (!candidates || candidates.length === 0) {
    return {
      status: 404,
      body: { ok: false, message: "Client not found" },
      failureReason: "client not found",
    };
  }

  // 2. Restrict to rows within the actor's scope.
  let inScope = candidates;
  if (Array.isArray(actorNetworkCodes)) {
    inScope = candidates.filter((row) =>
      actorNetworkCodes.includes(normalizeCode(row.dietician_id))
    );
  }

  if (inScope.length === 0) {
    return {
      status: 403,
      body: { ok: false, message: "You are not allowed to remove this client" },
      failureReason: "client outside actor network",
    };
  }

  // 3. Resolve which (profile_id, dietician_id) row is being removed.
  let targetRow = null;

  if (targetDieticianId !== "") {
    targetRow =
      inScope.find(
        (row) => normalizeCode(row.dietician_id) === normalizeCode(targetDieticianId)
      ) || null;

    if (!targetRow) {
      return {
        status: 404,
        body: {
          ok: false,
          message: "Client not found under the specified dietician_id",
        },
        failureReason: "profile/code pair not found in scope",
      };
    }
  } else if (inScope.length === 1) {
    targetRow = inScope[0];
  } else {
    return {
      status: 422,
      body: {
        ok: false,
        message:
          "Client exists under multiple partner codes. Pass target_dietician_id to specify which one to remove.",
        data: {
          candidates: inScope.map((row) => ({
            profile_id: row.profile_id,
            dietician_id: row.dietician_id,
          })),
        },
      },
      failureReason: "ambiguous profile/code pair",
    };
  }

  const profileId = String(targetRow.profile_id);
  const code = String(targetRow.dietician_id);

  // 4. Archive-then-delete. table_clients_removed = table_clients columns
  //    (same order) + removed_at, removed_by, removed_by_role, removed_reason
  //    appended at the end — so `SELECT tc.*, <extras>` lines up exactly.

  // Idempotent replace in the archive (re-added-then-removed-again case).
  await conn.execute(
    `
      DELETE FROM table_clients_removed
      WHERE LOWER(profile_id) = LOWER(?)
        AND UPPER(dietician_id) = UPPER(?)
    `,
    [profileId, code]
  );

  await conn.execute(
    `
      INSERT INTO table_clients_removed
      SELECT tc.*, UTC_TIMESTAMP(), ?, ?, ?
      FROM table_clients tc
      WHERE LOWER(tc.profile_id)  = LOWER(?)
        AND UPPER(tc.dietician_id) = UPPER(?)
    `,
    [actorEmail, actorRole, reason, profileId, code]
  );

  const [del] = await conn.execute(
    `
      DELETE FROM table_clients
      WHERE LOWER(profile_id)  = LOWER(?)
        AND UPPER(dietician_id) = UPPER(?)
    `,
    [profileId, code]
  );

  if (!del || del.affectedRows === 0) {
    return {
      status: 409,
      body: {
        ok: false,
        message: "Client was modified by another request. Please retry.",
      },
      failureReason: "concurrent modification",
    };
  }

  return {
    status: 200,
    body: {
      ok: true,
      message: "Client removed successfully",
      data: {
        target_type: "client",
        target_profile_id: profileId,
        target_dietician_id: code,
      },
    },
  };
}

// ─── Handler ─────────────────────────────────────────────────────────────────

const removeUser = async (req, res) => {
  // HIPAA: never let intermediaries cache these responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate.
  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body)
      ? req.body
      : {};

  const targetEmail = normalizeEmail(body.target_user_id);
  const targetProfileId = String(body.target_profile_id ?? "").trim();
  const targetDieticianId = String(body.target_dietician_id ?? "").trim();

  let reason = String(body.reason ?? "").trim();
  if (reason === "") reason = DEFAULT_REMOVE_REASON;
  reason = reason.slice(0, 255);

  // ── Input validation ───────────────────────────────────────────────────────
  const hasProfileId = targetProfileId !== "" && targetProfileId.length <= 100;
  const hasEmail =
    targetEmail !== "" && targetEmail.length <= 191 && targetEmail.includes("@");

  if (!hasProfileId && !hasEmail) {
    return res.status(422).json({
      ok: false,
      message:
        "Provide target_user_id (email) or target_profile_id (client) to remove a user",
    });
  }

  const auditIdentifier = hasProfileId
    ? `client:${targetProfileId}`
    : targetEmail;

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;
  let conn = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ────────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "user_remove_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: auditIdentifier,
        success: false,
        failureReason: resolved.error.message || "actor resolution failed",
      });
      return res
        .status(resolved.error.status)
        .json({ ok: false, message: resolved.error.message });
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = getActorEffectiveCode(actor) || null;

    // ── 2. Detect target type within the actor's removable scope ─────────────
    // The permission matrix (Conditions 1–3) is applied here implicitly: the
    // identifier is only searched among the account types this actor may
    // remove, so an out-of-scope target is indistinguishable from a
    // nonexistent one (anti-enumeration).
    const allowedTargets = PERMISSION_MATRIX[actorRole] || new Set();

    let targetType;

    if (hasProfileId) {
      // profile_ids exist only for clients.
      targetType = "client";
    } else {
      const matchedTypes = [];

      const roleTypes = ["admin", "trainer"].filter((t) =>
        allowedTargets.has(t)
      );

      if (roleTypes.length > 0) {
        const [roleRows] = await pool.execute(
          `
            SELECT DISTINCT role
            FROM app_user_roles
            WHERE LOWER(user_id) = LOWER(?)
              AND role IN (${buildInPlaceholders(roleTypes)})
          `,
          [targetEmail, ...roleTypes]
        );
        for (const row of roleRows) matchedTypes.push(String(row.role));
      }

      if (allowedTargets.has("client")) {
        const [clientRows] = await pool.execute(
          `SELECT 1 FROM table_clients WHERE LOWER(email) = LOWER(?) LIMIT 1`,
          [targetEmail]
        );
        if (clientRows.length > 0) matchedTypes.push("client");
      }

      if (matchedTypes.length === 0) {
        await writeAuthLogSafe(req, {
          eventType: "user_remove_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: auditIdentifier,
          success: false,
          failureReason: "no removable account found for identifier",
        });
        return res.status(404).json({ ok: false, message: "User not found" });
      }

      if (matchedTypes.length > 1) {
        return res.status(422).json({
          ok: false,
          message: `This email matches multiple account types (${matchedTypes.join(
            ", "
          )}). Pass target_profile_id to remove the client account.`,
          data: { matched_types: matchedTypes },
        });
      }

      targetType = matchedTypes[0];
    }

    // ── 3. Self-protection guards ────────────────────────────────────────────
    if (targetType !== "client" && targetEmail === actorEmail) {
      return res
        .status(403)
        .json({ ok: false, message: "You cannot remove your own account" });
    }

    // ── 4. Transactional removal ─────────────────────────────────────────────
    conn = await pool.getConnection();
    await conn.beginTransaction();

    let outcome;

    if (targetType === "admin") {
      // Condition 1: only super_admin reaches here (matrix), scope = own admins.
      outcome = await removeRoleUser(conn, {
        targetType: "admin",
        targetEmail,
        allowedParentEmails: [actorEmail],
      });
    } else if (targetType === "trainer") {
      // Conditions 1 & 2: super_admin → self + active admins under them;
      // admin → self only.
      let allowedParentEmails = [actorEmail];
      if (actorRole === "super_admin") {
        const adminEmails = await getActiveAdminEmailsUnderSuperAdmin(
          conn,
          actorEmail
        );
        allowedParentEmails = [
          ...new Set([actorEmail, ...adminEmails]),
        ];
      }
      outcome = await removeRoleUser(conn, {
        targetType: "trainer",
        targetEmail,
        allowedParentEmails,
      });
    } else {
      // Conditions 1–3: client removal.
      let actorNetworkCodes = null; // null → global (super_admin)

      if (actorRole === "trainer") {
        const own = normalizeCode(getActorEffectiveCode(actor));
        actorNetworkCodes = own === "" ? [] : [own];
      } else if (actorRole === "admin") {
        actorNetworkCodes = await getAdminNetworkCodes(conn, actor, actorEmail);
      }

      outcome = await removeClient(conn, {
        actorRole,
        actorEmail,
        actorNetworkCodes,
        targetProfileId: hasProfileId ? targetProfileId : "",
        targetClientEmail: hasEmail ? targetEmail : "",
        // Trainer removals are always pinned to the trainer's own code.
        targetDieticianId:
          actorRole === "trainer"
            ? normalizeCode(getActorEffectiveCode(actor))
            : targetDieticianId,
        reason,
      });
    }

    if (outcome.status !== 200) {
      await conn.rollback();
      conn.release();
      conn = null;

      await writeAuthLogSafe(req, {
        eventType: "user_remove_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: auditIdentifier,
        success: false,
        failureReason: outcome.failureReason || `HTTP ${outcome.status}`,
      });

      return res.status(outcome.status).json(outcome.body);
    }

    await conn.commit();
    conn.release();
    conn = null;

    // ── 5. Success audit ─────────────────────────────────────────────────────
    await writeAuthLogSafe(req, {
      eventType:
        actorRole === "super_admin"
          ? `super_admin_${targetType}_removed`
          : `${actorRole}_${targetType}_removed`,
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: auditIdentifier,
      success: true,
      failureReason: reason, // carries the caller-supplied reason for traceability
    });

    return res.status(200).json({
      ...outcome.body,
      meta: {
        removed_by: actorEmail,
        removed_by_role: actorRole,
      },
    });
  } catch (err) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (rollbackErr) {
        console.error("REMOVE_USER_ROLLBACK_FAILED:", rollbackErr?.code || rollbackErr?.message);
      }
      try {
        conn.release();
      } catch (releaseErr) {
        console.error("REMOVE_USER_RELEASE_FAILED:", releaseErr?.code || releaseErr?.message);
      }
      conn = null;
    }

    // Structured server-side log: error metadata only, never row data / PHI.
    console.error("REMOVE_USER_FAILED:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "user_remove_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: auditIdentifier,
      success: false,
      failureReason: err?.code || "internal error",
    });

    return res.status(500).json({
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG ? { debug_error: String(err?.message || err) } : {}),
    });
  }
};

module.exports = { removeUser };