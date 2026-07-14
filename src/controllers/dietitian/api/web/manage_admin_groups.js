"use strict";

/**
 * manage_admin_groups.js
 *
 * Converted from: manage_admin_groups.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/manage-admin-groups
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : admin | super_admin  (writes restricted to super_admin)
 *
 * CRUD for the ta_admin_groups single-table admin-grouping design. One row in
 * ta_admin_groups = one admin's membership in a named group. Admins in the same
 * active group share data visibility (see admin_group_visibility.js).
 *
 * Actions (body.action):
 *   create_group  | list_groups | list_members
 *   add_member    | remove_member | delete_group
 *
 * Behaviour parity with the PHP:
 *  - RBAC: only 'admin' or 'super_admin' may access. WRITE actions
 *    (create_group / add_member / remove_member / delete_group) require
 *    super_admin. READ actions (list_groups / list_members) stay open to any
 *    admin; a normal admin's list_groups is scoped to groups they belong to, and
 *    list_members requires the actor to be a member (super_admin bypasses).
 *  - create_group: only the codes in members[] become members; the creator is
 *    NOT auto-added, only recorded as added_by. 409 if the name already exists.
 *  - upsertMember: idempotent check-then-reactivate-or-insert (the table has no
 *    UNIQUE(group_name, dietician_id) key), UPPER-cased storage.
 *  - Response keys/shape match the PHP (status, message, group_name, members,
 *    groups, actor, removed / removed_rows). `ok` is mirrored alongside `status`
 *    like the sibling Node controllers.
 *  - Same DB tables only: ta_admin_groups, table_dietician, app_user_roles,
 *    app_auth_logs. Nothing added or removed.
 *
 * VAPT hardening (intentional differences from the PHP):
 *  - Token-bound identity. The actor is resolved from the verified JWT
 *    (sub = dietician_id) and re-checked against the DB on every call. The PHP
 *    trusted body.actor_user_id, which let any caller act as another admin
 *    (IDOR / privilege escalation — and here that means CREATING/DELETING groups
 *    as someone else). body.actor_user_id is still accepted for frontend/
 *    back-compat, but it is only cross-checked against the token email
 *    (mismatch → 403); it can never select a different user. role + status are
 *    re-verified server-side.
 *  - Every query is fully parameterized (?, bound params) — no string
 *    interpolation. Codes are UPPER-cased before binding.
 *  - Multi-statement writes (create_group, and the check-then-write in
 *    add_member) run inside a transaction on a dedicated connection so a partial
 *    failure or a concurrent request cannot leave half-written / duplicate rows.
 *    On any error the transaction is rolled back and the connection released.
 *  - Internal error details are suppressed in production (gated behind
 *    APP_DEBUG). The PHP always echoed the raw exception message.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *  - Session time_zone is NOT mutated (shared mysql2 pool — mutating it would
 *    leak into other concurrent requests). DATETIME columns are formatted in JS.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; no SELECT * over identity rows.
 *  - PHI in audit logs (identifier, IP, user-agent) is HMAC-SHA256 hashed with
 *    SECURITY_PEPPER — never stored in clear text.
 *  - Every group mutation and every denial is recorded in app_auth_logs.
 *  - Server logs carry only error metadata (code/errno/sqlState), never row data.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const { normalizeCode } = require("./admin_group_visibility");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTOR_ROLES = new Set(["admin", "super_admin"]);

const ALLOWED_ACTIONS = [
  "create_group",
  "list_groups",
  "list_members",
  "add_member",
  "remove_member",
  "delete_group",
];

const WRITE_ACTIONS = new Set([
  "create_group",
  "add_member",
  "remove_member",
  "delete_group",
]);

const NEEDS_GROUP_ACTIONS = new Set([
  "list_members",
  "add_member",
  "remove_member",
  "delete_group",
]);

// ─── Generic helpers ─────────────────────────────────────────────────────────

function normalizeEmail(val) {
  return typeof val === "string"
    ? val.trim().toLowerCase()
    : String(val ?? "").trim().toLowerCase();
}

function toInt(val) {
  const n = Number(val);
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Format a mysql2 DATETIME as "YYYY-MM-DD HH:MM:SS" (matches PHP string output). */
function toMysqlDateTime(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return (
      `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
      `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
    );
  }
  return String(val);
}

/** PHP getActorEffectiveCode(): partner_code, else dietician_id, else null. */
function getActorEffectiveCode(actor) {
  if (actor.partner_code !== null && actor.partner_code !== undefined &&
      String(actor.partner_code).trim() !== "") {
    return String(actor.partner_code);
  }
  if (actor.dietician_id !== null && actor.dietician_id !== undefined &&
      String(actor.dietician_id).trim() !== "") {
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
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

// ─── Audit log ───────────────────────────────────────────────────────────────

/**
 * Fail-safe audit writer. Never throws — audit failure must not surface to the
 * client. Always writes on the shared pool (not the transaction connection), so
 * a rolled-back transaction still leaves its audit trail.
 *   app_auth_logs(event_type, user_id, role, partner_code, identifier_hash,
 *                 ip_hash, user_agent_hash, session_id_hash, success, failure_reason)
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
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
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
    console.error("ADMIN_GROUPS_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution (token-bound) ──────────────────────────────────────────

/**
 * Resolve the authenticated actor from the JWT (sub = dietician_id) and re-check
 * role/status against the DB. Returns { actor, actorEmail } or
 * { error: { status, body } }. Mirrors PHP getActorForApi(), but keyed off the
 * verified token rather than a body-supplied email.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return { error: { status: 401, body: { status: false, ok: false, message: "Invalid token user" } } };
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
    return { error: { status: 403, body: { status: false, ok: false, message: "Actor user not found" } } };
  }

  if (String(actor.status) !== "active") {
    return { error: { status: 403, body: { status: false, ok: false, message: "Actor account is not active" } } };
  }

  if (!ALLOWED_ACTOR_ROLES.has(String(actor.role))) {
    return {
      error: {
        status: 403,
        body: { status: false, ok: false, message: "Only an admin can access admin groups" },
      },
    };
  }

  return { actor, actorEmail: normalizeEmail(actor.email) };
}

// ─── Group data helpers ──────────────────────────────────────────────────────

/** PHP groupExists(): does the group exist at all (any member, any status)? */
async function groupExists(groupName, executor = pool) {
  const [rows] = await executor.execute(
    `SELECT 1 AS hit FROM ta_admin_groups WHERE group_name = ? LIMIT 1`,
    [groupName]
  );
  return rows.length > 0;
}

/** PHP isMemberOfGroup(): does the code have an active membership row in the group? */
async function isMemberOfGroup(groupName, code, executor = pool) {
  const [rows] = await executor.execute(
    `
      SELECT 1 AS hit
      FROM ta_admin_groups
      WHERE group_name = ?
        AND UPPER(dietician_id) = ?
        AND status = 'active'
      LIMIT 1
    `,
    [groupName, normalizeCode(code)]
  );
  return rows.length > 0;
}

/**
 * PHP upsertMember(): insert (or reactivate) one membership row, UPPER-cased.
 * Idempotent — no duplicate rows even without a composite UNIQUE key. Runs on
 * the passed executor so callers can wrap it in a transaction.
 */
async function upsertMember(groupName, code, addedBy, executor = pool) {
  const normalized = normalizeCode(code);
  const addedByNorm = normalizeCode(addedBy);
  const addedByValue = addedByNorm !== "" ? addedByNorm : null;

  const [existing] = await executor.execute(
    `
      SELECT id
      FROM ta_admin_groups
      WHERE group_name = ?
        AND UPPER(dietician_id) = ?
      LIMIT 1
    `,
    [groupName, normalized]
  );

  if (existing.length > 0) {
    // Row exists → reactivate and refresh added_by.
    await executor.execute(
      `
        UPDATE ta_admin_groups
        SET status = 'active',
            added_by = ?
        WHERE id = ?
      `,
      [addedByValue, toInt(existing[0].id)]
    );
    return;
  }

  // No existing row → insert a fresh membership.
  await executor.execute(
    `
      INSERT INTO ta_admin_groups (group_name, dietician_id, added_by, status)
      VALUES (?, ?, ?, 'active')
    `,
    [groupName, normalized, addedByValue]
  );
}

/** PHP fetchGroupMembers(): all rows for the group with member identity. */
async function fetchGroupMembers(groupName, executor = pool) {
  const [rows] = await executor.execute(
    `
      SELECT
        g.id,
        g.dietician_id,
        g.added_by,
        g.status,
        g.added_at,
        td.name  AS member_name,
        td.email AS member_email
      FROM ta_admin_groups g
      LEFT JOIN table_dietician td
        ON UPPER(td.dietician_id) = UPPER(g.dietician_id)
      WHERE g.group_name = ?
      ORDER BY g.added_at ASC, g.id ASC
    `,
    [groupName]
  );

  return rows.map((row) => ({
    id: toInt(row.id),
    dietician_id: row.dietician_id,
    name: row.member_name ?? null,
    email:
      row.member_email !== null && row.member_email !== undefined
        ? normalizeEmail(row.member_email)
        : null,
    added_by: row.added_by ?? null,
    status: row.status,
    added_at: toMysqlDateTime(row.added_at),
  }));
}

// ─── Input parsing ───────────────────────────────────────────────────────────

function parseInputs(req) {
  const src = req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? req.body
    : null;

  if (src === null) return { invalidBody: true };

  const actorUserId = normalizeEmail(src.actor_user_id);
  const action = typeof src.action === "string" ? src.action.trim().toLowerCase() : "";
  const groupName = typeof src.group_name === "string" ? src.group_name.trim() : "";
  const targetCode =
    src.dietician_id !== undefined && src.dietician_id !== null
      ? normalizeCode(src.dietician_id)
      : "";
  const extraMembers = Array.isArray(src.members) ? src.members : [];

  return { invalidBody: false, actorUserId, action, groupName, targetCode, extraMembers };
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/manage-admin-groups
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "action": "create_group | list_groups | list_members | add_member | remove_member | delete_group",
 *     "group_name": "Group One",          // required for all except list_groups
 *     "dietician_id": "RESPYRD05",         // required for add_member / remove_member
 *     "members": ["RESPYRD05", ...],       // required for create_group
 *     "actor_user_id": ""                  // optional; if set, must match the token email
 *   }
 */
const manageAdminGroups = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const parsed = parseInputs(req);

  if (parsed.invalidBody) {
    return res.status(400).json({ status: false, ok: false, message: "Invalid JSON body" });
  }

  const { actorUserId, action, groupName, targetCode, extraMembers } = parsed;

  // VAPT: validate the action against an allow-list before any DB work.
  if (!ALLOWED_ACTIONS.includes(action)) {
    return res.status(400).json({
      status: false,
      ok: false,
      message: "Invalid action",
      allowed_actions: ALLOWED_ACTIONS,
    });
  }

  let actorEmail = null;
  let actorRole = null;
  let actorCode = null;

  // Held only when a write action opens a transaction; released in finally.
  let conn = null;

  try {
    // ── 1. Resolve + authorize actor from JWT ───────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      await writeAuthLogSafe(req, {
        eventType: "admin_groups_denied",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: action,
        success: false,
        failureReason: resolved.error.body?.message || "actor resolution failed",
      });
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    actorCode = normalizeCode(getActorEffectiveCode(actor));
    const isSuperAdmin = actorRole === "super_admin";

    // ── 1b. Cross-check optional actor_user_id against the token identity ────
    // Accepted for frontend/back-compat; if present it must be a valid email AND
    // equal the token email. It can never select a different user.
    if (actorUserId !== "") {
      if (!EMAIL_REGEX.test(actorUserId) || actorUserId !== actorEmail) {
        await writeAuthLogSafe(req, {
          eventType: "admin_groups_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: actorUserId,
          success: false,
          failureReason: "actor_user_id does not match token identity",
        });
        return res.status(403).json({
          status: false,
          ok: false,
          message: "actor_user_id does not match the authenticated user",
        });
      }
    }

    // ── 1c. Write actions are super_admin-only ──────────────────────────────
    if (WRITE_ACTIONS.has(action) && !isSuperAdmin) {
      await writeAuthLogSafe(req, {
        eventType: "admin_groups_denied",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: action,
        success: false,
        failureReason: "Write action requires super_admin",
      });
      return res.status(403).json({
        status: false,
        ok: false,
        message: "Only a super admin can create groups or manage members",
      });
    }

    // ── 1d. Group-scoped actions: existence + membership checks ─────────────
    if (NEEDS_GROUP_ACTIONS.has(action)) {
      if (groupName === "") {
        return res.status(422).json({ status: false, ok: false, message: "group_name is required" });
      }

      if (!(await groupExists(groupName))) {
        return res.status(404).json({ status: false, ok: false, message: "Group not found" });
      }

      if (action === "list_members" && !isSuperAdmin && !(await isMemberOfGroup(groupName, actorCode))) {
        await writeAuthLogSafe(req, {
          eventType: "admin_groups_denied",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actorCode,
          identifier: action + "|" + groupName,
          success: false,
          failureReason: "Actor not a member of group",
        });
        return res.status(403).json({
          status: false,
          ok: false,
          message: "You are not a member of this group",
        });
      }
    }

    // ── 2. Action handlers ──────────────────────────────────────────────────

    if (action === "create_group") {
      if (groupName === "") {
        return res.status(422).json({ status: false, ok: false, message: "group_name is required" });
      }

      if (await groupExists(groupName)) {
        return res.status(409).json({
          status: false,
          ok: false,
          message: "A group with this name already exists",
        });
      }

      // Only members[] become members; the creator is recorded as added_by only.
      const memberCodes = new Map();
      for (const m of extraMembers) {
        const mc = normalizeCode(m);
        if (mc !== "") memberCodes.set(mc, mc);
      }

      if (memberCodes.size === 0) {
        return res.status(422).json({
          status: false,
          ok: false,
          message: "members is required (at least one dietician_id to add to the group)",
        });
      }

      conn = await pool.getConnection();
      await conn.beginTransaction();
      for (const mc of memberCodes.values()) {
        await upsertMember(groupName, mc, actorCode, conn);
      }
      await conn.commit();
      conn.release();
      conn = null;

      writeAuthLogSafe(req, {
        eventType: "admin_groups_created",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: groupName,
        success: true,
        failureReason: "Group created",
      });

      return res.status(201).json({
        status: true,
        ok: true,
        message: "Group created",
        group_name: groupName,
        members: await fetchGroupMembers(groupName),
      });
    }

    if (action === "list_groups") {
      // super_admin sees all groups; a normal admin sees only groups they belong
      // to. One row per group with member counts.
      let rows;
      if (isSuperAdmin) {
        [rows] = await pool.execute(
          `
            SELECT group_name,
                   SUM(status = 'active') AS active_members,
                   COUNT(*) AS total_members,
                   MIN(added_at) AS created_at
            FROM ta_admin_groups
            GROUP BY group_name
            ORDER BY created_at DESC
          `
        );
      } else {
        [rows] = await pool.execute(
          `
            SELECT g.group_name,
                   SUM(g.status = 'active') AS active_members,
                   COUNT(*) AS total_members,
                   MIN(g.added_at) AS created_at
            FROM ta_admin_groups g
            WHERE g.group_name IN (
              SELECT DISTINCT group_name
              FROM ta_admin_groups
              WHERE UPPER(dietician_id) = ?
                AND status = 'active'
            )
            GROUP BY g.group_name
            ORDER BY created_at DESC
          `,
          [actorCode]
        );
      }

      const groups = rows.map((row) => ({
        group_name: row.group_name,
        active_members: toInt(row.active_members),
        total_members: toInt(row.total_members),
        created_at: toMysqlDateTime(row.created_at),
      }));

      return res.status(200).json({
        status: true,
        ok: true,
        message: "Groups fetched",
        actor: { partner_code: actorCode, role: actorRole },
        groups,
      });
    }

    if (action === "list_members") {
      return res.status(200).json({
        status: true,
        ok: true,
        message: "Members fetched",
        group_name: groupName,
        members: await fetchGroupMembers(groupName),
      });
    }

    if (action === "add_member") {
      if (targetCode === "") {
        return res.status(422).json({ status: false, ok: false, message: "dietician_id is required" });
      }

      // Wrap the check-then-write in a transaction so concurrent add_member
      // calls cannot both insert and create a duplicate membership row.
      conn = await pool.getConnection();
      await conn.beginTransaction();
      await upsertMember(groupName, targetCode, actorCode, conn);
      await conn.commit();
      conn.release();
      conn = null;

      writeAuthLogSafe(req, {
        eventType: "admin_groups_member_added",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: groupName + "|" + targetCode,
        success: true,
        failureReason: "Member added",
      });

      return res.status(200).json({
        status: true,
        ok: true,
        message: "Member added",
        group_name: groupName,
        members: await fetchGroupMembers(groupName),
      });
    }

    if (action === "remove_member") {
      if (targetCode === "") {
        return res.status(422).json({ status: false, ok: false, message: "dietician_id is required" });
      }

      const [result] = await pool.execute(
        `
          DELETE FROM ta_admin_groups
          WHERE group_name = ?
            AND UPPER(dietician_id) = ?
        `,
        [groupName, targetCode]
      );

      writeAuthLogSafe(req, {
        eventType: "admin_groups_member_removed",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: groupName + "|" + targetCode,
        success: true,
        failureReason: "Member removed",
      });

      return res.status(200).json({
        status: true,
        ok: true,
        message: "Member removed",
        group_name: groupName,
        removed: toInt(result.affectedRows),
        members: await fetchGroupMembers(groupName),
      });
    }

    if (action === "delete_group") {
      const [result] = await pool.execute(
        `DELETE FROM ta_admin_groups WHERE group_name = ?`,
        [groupName]
      );

      writeAuthLogSafe(req, {
        eventType: "admin_groups_deleted",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actorCode,
        identifier: groupName,
        success: true,
        failureReason: "Group deleted",
      });

      return res.status(200).json({
        status: true,
        ok: true,
        message: "Group deleted",
        group_name: groupName,
        removed_rows: toInt(result.affectedRows),
      });
    }

    // Unreachable — action was validated against ALLOWED_ACTIONS above.
    return res.status(400).json({ status: false, ok: false, message: "Invalid action" });
  } catch (err) {
    // Roll back + release any open transaction connection before responding.
    if (conn) {
      try {
        await conn.rollback();
      } catch (rbErr) {
        console.error("ADMIN_GROUPS_ROLLBACK_FAILED:", rbErr?.code || rbErr?.message);
      }
      try {
        conn.release();
      } catch (_) {
        /* already released */
      }
      conn = null;
    }

    console.error("MANAGE_ADMIN_GROUPS_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "admin_groups_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: actorCode,
      identifier: action,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  }
};

module.exports = { manageAdminGroups };
