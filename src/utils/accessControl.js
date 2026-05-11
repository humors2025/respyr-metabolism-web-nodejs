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

module.exports = {
  normalizeId,
  normalizeDieticianId,
  getTokenDieticianId,
  requireDieticianSelfAccess,
  requireProfileAccess,
};