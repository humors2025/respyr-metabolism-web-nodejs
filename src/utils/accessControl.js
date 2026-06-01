"use strict";

/**
 * accessControl.js
 *
 * Centralized authorization for the Respyr Dietitian API.
 *
 * Two families of checks live here so that every PHI controller routes through
 * one audited choke point (HIPAA §164.312(a)(1); satisfies the VAPT "every PHI
 * controller must call a shared access-control helper" rule):
 *
 *  1. SELF / PROFILE access (single-tenant endpoints) — a dietician operating on
 *     their OWN dietician_id and a specific profile_id:
 *       - requireDieticianSelfAccess(req, inputDieticianId)
 *       - requireProfileAccess(req, inputDieticianId, inputProfileId)
 *
 *  2. NETWORK / RBAC access (hierarchical endpoints) — super_admin / admin /
 *     trainer operating across a NETWORK of other dieticians. These return
 *     NEUTRAL, reason-coded results so each controller can map them to its own
 *     historical response shape (some use { ok:false, error }, some
 *     { status:false, ok:false, message }, etc.):
 *       - resolveActorFromToken(req, allowedRoles)   // identity from JWT sub
 *       - resolveActorByEmail(email, allowedRoles)    // identity from an email
 *       - actorCanAccessCode(actor, actorEmail, targetCode)  // one-level RBAC
 *       - requireNetworkAccess(req, targetCode, opts) // resolve + code gate
 *       - getActorCode(actor)
 *
 * The neutral resolvers return one of:
 *   { ok: true,  actor, actorEmail, role, code }
 *   { ok: false, reason, statusCode }
 * where reason ∈ "invalid_token" | "not_found" | "inactive" | "role_not_allowed".
 * Controllers switch on `reason` to reproduce their exact (statusCode, body).
 */

const pool = require("../config/db");

// ─── Role constants ──────────────────────────────────────────────────────────

const ROLE_SUPER_ADMIN = "super_admin";
const ROLE_ADMIN = "admin";
const ROLE_TRAINER = "trainer";
const ALL_NETWORK_ROLES = [ROLE_SUPER_ADMIN, ROLE_ADMIN, ROLE_TRAINER];

// ─── Normalizers ─────────────────────────────────────────────────────────────

const normalizeId = (value) => {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(normalized)) return null;
  return normalized;
};

const normalizeDieticianId = (value) => {
  const id = normalizeId(value);
  return id ? id.toUpperCase() : null;
};

const normalizeEmailLower = (val) => String(val ?? "").trim().toLowerCase();
const normalizeCodeUpper = (val) => String(val ?? "").trim().toUpperCase();

const getTokenDieticianId = (req) => {
  return normalizeDieticianId(
    req.user?.sub || req.user?.dietician?.dietician_id
  );
};

/**
 * Effective code for an actor row: partner_code if non-blank, else dietician_id,
 * else null. Mirrors the per-controller getActorCode/getActorEffectivePartnerCode
 * helpers that were duplicated across the hierarchical controllers.
 */
const getActorCode = (actor) => {
  if (actor &&
      actor.partner_code !== null && actor.partner_code !== undefined &&
      String(actor.partner_code).trim() !== "") {
    return String(actor.partner_code);
  }
  if (actor &&
      actor.dietician_id !== null && actor.dietician_id !== undefined &&
      String(actor.dietician_id).trim() !== "") {
    return String(actor.dietician_id);
  }
  return null;
};

// ─── 1. SELF / PROFILE access (single-tenant) ────────────────────────────────

const requireDieticianSelfAccess = (req, inputDieticianId) => {
  const tokenDieticianId = getTokenDieticianId(req);
  const requestedDieticianId = normalizeDieticianId(inputDieticianId);

  if (!tokenDieticianId || !requestedDieticianId) {
    return {
      allowed: false,
      statusCode: 401,
      message: "Invalid authentication token",
    };
  }

  if (tokenDieticianId !== requestedDieticianId) {
    return {
      allowed: false,
      statusCode: 403,
      message: "Access denied",
    };
  }

  return {
    allowed: true,
    dieticianId: requestedDieticianId,
  };
};

const requireProfileAccess = async (req, inputDieticianId, inputProfileId) => {
  const self = requireDieticianSelfAccess(req, inputDieticianId);

  if (!self.allowed) return self;

  const profileId = normalizeId(inputProfileId);

  if (!profileId) {
    return {
      allowed: false,
      statusCode: 400,
      message: "Invalid profile_id",
    };
  }

  const [rows] = await pool.execute(
    `
      SELECT profile_id
      FROM table_clients
      WHERE UPPER(TRIM(dietician_id)) = ?
        AND profile_id = ?
      LIMIT 1
    `,
    [self.dieticianId, profileId]
  );

  if (!rows.length) {
    return {
      allowed: false,
      statusCode: 403,
      message: "Access denied",
    };
  }

  return {
    allowed: true,
    dieticianId: self.dieticianId,
    profileId,
  };
};

// ─── 2. NETWORK / RBAC access (hierarchical) ─────────────────────────────────

// Superset of the columns any hierarchical controller reads from the actor row.
// Selecting extra columns is harmless; missing ones would break a caller.
const ACTOR_SELECT = `
  SELECT
    td.id,
    td.dietician_id,
    td.name,
    td.phone_no,
    td.email,
    td.location,
    td.is_reset_password,

    aur.role,
    aur.partner_code,
    aur.parent_user_id,
    aur.status,
    aur.email_verified_at,
    aur.created_at,
    aur.updated_at
  FROM table_dietician td
  INNER JOIN app_user_roles aur
    ON LOWER(aur.user_id) = LOWER(td.email)
`;

async function lookupActorByDieticianId(dieticianId) {
  const [rows] = await pool.execute(
    `${ACTOR_SELECT} WHERE td.dietician_id = ? LIMIT 1`,
    [dieticianId]
  );
  return rows[0] || null;
}

async function lookupActorByEmail(email) {
  const [rows] = await pool.execute(
    `${ACTOR_SELECT} WHERE LOWER(td.email) = LOWER(?) LIMIT 1`,
    [email]
  );
  return rows[0] || null;
}

/**
 * Apply the active + allowed-role gates to a fetched actor row and return the
 * neutral result. `allowedRoles` may be a Set or an array; omitted ⇒ all three
 * network roles.
 */
function finalizeActor(actor, allowedRoles) {
  if (!actor) {
    return { ok: false, reason: "not_found", statusCode: 403 };
  }
  if (String(actor.status) !== "active") {
    return { ok: false, reason: "inactive", statusCode: 403 };
  }
  const role = String(actor.role);
  const allowed =
    allowedRoles instanceof Set
      ? allowedRoles
      : new Set(allowedRoles && allowedRoles.length ? allowedRoles : ALL_NETWORK_ROLES);
  if (!allowed.has(role)) {
    return { ok: false, reason: "role_not_allowed", statusCode: 403 };
  }
  return {
    ok: true,
    actor,
    actorEmail: normalizeEmailLower(actor.email),
    role,
    code: getActorCode(actor),
  };
}

/**
 * Resolve the authenticated actor from the verified JWT (sub = dietician_id) and
 * re-check role + status against the DB. Identity is NEVER taken from the
 * request body — this closes the IDOR / privilege-escalation vector the legacy
 * PHP had (it trusted body.actor_user_id).
 */
async function resolveActorFromToken(req, allowedRoles) {
  const payload = req.user || {};
  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return { ok: false, reason: "invalid_token", statusCode: 401 };
  }

  return resolveActorByDieticianId(dieticianId, allowedRoles);
}

/**
 * Resolve by an already-extracted dietician_id WITHOUT the JWT length guard.
 * Used by the dual-source controllers (token sub OR email fallback) that do
 * their own up-front validation and then dispatch by which key is present, so
 * the "id present but unmatched ⇒ not_found" branch must be preserved exactly.
 */
async function resolveActorByDieticianId(dieticianId, allowedRoles) {
  const id = String(dieticianId ?? "").trim();
  if (!id) {
    return { ok: false, reason: "invalid_token", statusCode: 401 };
  }
  const actor = await lookupActorByDieticianId(id);
  return finalizeActor(actor, allowedRoles);
}

/**
 * Resolve an actor by email. Used by the few endpoints whose identity key is an
 * email rather than a dietician_id (e.g. the super-admin invite flow). Callers
 * are responsible for sourcing `email` from a trusted place (the verified token).
 */
async function resolveActorByEmail(email, allowedRoles) {
  const e = normalizeEmailLower(email);
  if (!e || e.length > 191) {
    return { ok: false, reason: "invalid_token", statusCode: 401 };
  }
  const actor = await lookupActorByEmail(e);
  return finalizeActor(actor, allowedRoles);
}

/**
 * One-level hierarchy RBAC: may `actor` view clients whose dietician code is
 * `targetCode`? Faithful port of the duplicated ctd_actor_can_access_code /
 * actorCanAccessDietitianCode helpers — exactly one level of nesting, no extra
 * recursion.
 *
 *   trainer     → own code only
 *   admin       → own code + active trainers parented to the admin
 *   super_admin → own code + self/children + active trainers parented to it or
 *                 to one of its active admins
 */
async function actorCanAccessCode(actor, actorEmail, targetCode) {
  const target = normalizeCodeUpper(targetCode);
  if (target === "") return false;

  const ownCode = getActorCode(actor);
  if (ownCode !== null && normalizeCodeUpper(ownCode) === target) {
    return true;
  }

  const role = String(actor.role);
  const email = normalizeEmailLower(actorEmail);

  if (role === ROLE_TRAINER) {
    return false;
  }

  if (role === ROLE_ADMIN) {
    const [rows] = await pool.execute(
      `
        SELECT aur.id
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer'
          AND aur.status = 'active'
          AND LOWER(aur.parent_user_id) = LOWER(?)
          AND (
                UPPER(aur.partner_code) = UPPER(?)
             OR UPPER(td.dietician_id) = UPPER(?)
          )
        LIMIT 1
      `,
      [email, target, target]
    );
    return rows.length > 0;
  }

  if (role === ROLE_SUPER_ADMIN) {
    const [rows] = await pool.execute(
      `
        SELECT aur.id
        FROM app_user_roles aur
        LEFT JOIN table_dietician td
          ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.status = 'active'
          AND (
                UPPER(aur.partner_code) = UPPER(?)
             OR UPPER(td.dietician_id) = UPPER(?)
          )
          AND (
                LOWER(aur.user_id) = LOWER(?)
             OR LOWER(aur.parent_user_id) = LOWER(?)
             OR LOWER(aur.parent_user_id) IN (
                    SELECT LOWER(user_id)
                    FROM app_user_roles
                    WHERE role = 'admin'
                      AND status = 'active'
                      AND LOWER(parent_user_id) = LOWER(?)
                )
          )
        LIMIT 1
      `,
      [target, target, email, email, email]
    );
    return rows.length > 0;
  }

  return false;
}

/**
 * Convenience: resolve the actor AND gate a specific target code in one call.
 * Returns:
 *   { allowed: true,  actor, actorEmail, role, code, targetCode }
 *   { allowed: false, statusCode, reason, [actor, actorEmail, role, code] }
 *
 * reason for a resolve failure is the resolver reason; for a code-gate failure
 * it is "target_not_in_network".
 *
 * opts:
 *   - allowedRoles : Set|array of permitted roles (default: all network roles)
 *   - byEmail      : true to resolve via opts.email instead of the JWT
 *   - email        : email to resolve when byEmail is true
 */
async function requireNetworkAccess(req, targetCode, opts = {}) {
  const resolved = opts.byEmail
    ? await resolveActorByEmail(opts.email, opts.allowedRoles)
    : await resolveActorFromToken(req, opts.allowedRoles);

  if (!resolved.ok) {
    return {
      allowed: false,
      statusCode: resolved.statusCode,
      reason: resolved.reason,
    };
  }

  const canAccess = await actorCanAccessCode(
    resolved.actor,
    resolved.actorEmail,
    targetCode
  );

  if (!canAccess) {
    return {
      allowed: false,
      statusCode: 403,
      reason: "target_not_in_network",
      actor: resolved.actor,
      actorEmail: resolved.actorEmail,
      role: resolved.role,
      code: resolved.code,
    };
  }

  return {
    allowed: true,
    actor: resolved.actor,
    actorEmail: resolved.actorEmail,
    role: resolved.role,
    code: resolved.code,
    targetCode: normalizeCodeUpper(targetCode),
  };
}

module.exports = {
  // role constants
  ROLE_SUPER_ADMIN,
  ROLE_ADMIN,
  ROLE_TRAINER,
  ALL_NETWORK_ROLES,

  // normalizers / helpers
  normalizeId,
  normalizeDieticianId,
  normalizeEmailLower,
  normalizeCodeUpper,
  getTokenDieticianId,
  getActorCode,

  // self / profile access (single-tenant)
  requireDieticianSelfAccess,
  requireProfileAccess,

  // network / RBAC access (hierarchical)
  lookupActorByDieticianId,
  lookupActorByEmail,
  resolveActorFromToken,
  resolveActorByDieticianId,
  resolveActorByEmail,
  actorCanAccessCode,
  requireNetworkAccess,
};
