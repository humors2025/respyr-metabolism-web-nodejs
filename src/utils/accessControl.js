const pool = require("../config/db");

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

const getTokenDieticianId = (req) => {
  return normalizeDieticianId(
    req.user?.sub || req.user?.dietician?.dietician_id
  );
};

// Roles that are allowed org-wide read access across dietitians.
const SUPER_ADMIN_ROLE = "super_admin";

const getTokenRole = (req) => {
  const role = req.user?.role || req.user?.dietician?.role;
  return typeof role === "string" ? role.trim().toLowerCase() : null;
};

const isSuperAdmin = (req) => getTokenRole(req) === SUPER_ADMIN_ROLE;

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

  // Super-admin: org-wide access. May operate within any dietitian's scope,
  // so the requested dietitian_id is honoured rather than forced to match the
  // token. (HIPAA: this widened PHI access should be audit-logged.)
  if (tokenDieticianId !== requestedDieticianId && isSuperAdmin(req)) {
    console.warn("ACCESS_SUPER_ADMIN_DIETICIAN_SCOPE:", {
      actor: tokenDieticianId,
      requested: requestedDieticianId,
    });
    return {
      allowed: true,
      dieticianId: requestedDieticianId,
      viaSuperAdmin: true,
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
  const profileId = normalizeId(inputProfileId);

  if (!profileId) {
    return {
      allowed: false,
      statusCode: 400,
      message: "Invalid profile_id",
    };
  }

  // Super-admin: org-wide access to any profile, regardless of the dietitian
  // id in the request body. The downstream PHI queries filter by dietitian_id,
  // so we resolve the profile's ACTUAL owning dietitian here and return that —
  // otherwise the bypass would authorize the call but return an empty result.
  if (isSuperAdmin(req)) {
    const actor = getTokenDieticianId(req);

    if (!actor) {
      return {
        allowed: false,
        statusCode: 401,
        message: "Invalid authentication token",
      };
    }

    const [ownerRows] = await pool.execute(
      `
        SELECT dietician_id
        FROM table_clients
        WHERE profile_id = ?
        LIMIT 1
      `,
      [profileId]
    );

    // Unknown profile → deny (no client row to own this PHI).
    if (!ownerRows.length) {
      return {
        allowed: false,
        statusCode: 403,
        message: "Access denied",
      };
    }

    const ownerDieticianId = normalizeDieticianId(ownerRows[0].dietician_id);

    // HIPAA: log cross-dietitian PHI access by a super-admin.
    console.warn("ACCESS_SUPER_ADMIN_PROFILE:", {
      actor,
      profile_id: profileId,
      owner: ownerDieticianId,
    });

    return {
      allowed: true,
      dieticianId: ownerDieticianId,
      profileId,
      viaSuperAdmin: true,
    };
  }

  const self = requireDieticianSelfAccess(req, inputDieticianId);

  if (!self.allowed) return self;

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

module.exports = {
  normalizeId,
  normalizeDieticianId,
  getTokenDieticianId,
  requireDieticianSelfAccess,
  requireProfileAccess,
};