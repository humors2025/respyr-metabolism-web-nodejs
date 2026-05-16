// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const crypto = require('crypto');

// exports.refreshToken = async (req, res) => {
//   try {
//     const { refresh_token } = req.body;

//     if (!refresh_token) {
//       return res.status(400).json({
//         ok: false,
//         message: 'refresh_token is required',
//       });
//     }

//     // 🔍 Verify refresh token
//     jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);

//     // 🔒 Hash refresh token
//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refresh_token)
//       .digest('hex');

//     // 🔍 Check token in DB
//     const [rows] = await pool.query(
//       `SELECT dietician_id, name, email, phone_no, location
//        FROM table_dietician
//        WHERE refresh_token_hash = ?
//        AND refresh_token_expires_at > NOW()`,
//       [hashedToken]
//     );

//     if (rows.length === 0) {
//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid or expired refresh token',
//       });
//     }

//     const dietician = rows[0];

//     // 🔑 New access token
//     const accessToken = jwt.sign(
//       {
//         sub: dietician.dietician_id,
//         role: 'dietician',
//         dietician: {
//           dietician_id: dietician.dietician_id,
//           name: dietician.name,
//           email: dietician.email,
//           phone_no: dietician.phone_no,
//           location: dietician.location,
//         },
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: '15m' }
//     );

//     return res.json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       expires_in: 900,
//     });

//   } catch (error) {
//     console.error('Refresh Token Error:', error);
//     return res.status(401).json({
//       ok: false,
//       message: 'Invalid or expired refresh token',
//     });
//   }
// };








const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_DAYS = 7;

const JWT_ALGORITHM = 'HS256';
const JWT_ISSUER = process.env.JWT_ISSUER || 'dietician-api';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'dietician-app';

const isProduction =
  process.env.NODE_ENV === 'production' ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function getClientIp(req) {
  const ip =
    req.ip ||
    req.headers?.['x-forwarded-for']?.split(',')?.[0]?.trim() ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    null;

  return ip ? String(ip).substring(0, 45) : null;
}

function getUserAgent(req) {
  const ua =
    typeof req.get === 'function'
      ? req.get('user-agent')
      : req.headers?.['user-agent'];

  return ua ? String(ua).substring(0, 255) : null;
}

function getRefreshTokenFromRequest(req) {
  return (
    req.cookies?.refresh_token ||
    req.body?.refresh_token ||
    req.headers?.['x-refresh-token'] ||
    null
  );
}

function clearRefreshCookie(res) {
  res.clearCookie('refresh_token', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: process.env.REFRESH_COOKIE_PATH || '/auth',
  });
}

function setRefreshCookie(res, refreshToken) {
  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
    path: process.env.REFRESH_COOKIE_PATH || '/auth',
  });
}

function ensureAuthSecretsConfigured() {
  if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
    return false;
  }

  if (
    process.env.JWT_SECRET.length < 32 ||
    process.env.JWT_REFRESH_SECRET.length < 32
  ) {
    return false;
  }

  return true;
}

function ensureProductionSecurityConfigured() {
  if (!ensureAuthSecretsConfigured()) {
    return {
      ok: false,
      reason: 'JWT secrets missing or too short',
    };
  }

  if (isProduction && process.env.ENABLE_DB_AUDIT_LOGS !== 'true') {
    return {
      ok: false,
      reason: 'Audit logs must be enabled in production',
    };
  }

  return { ok: true };
}

async function recordAuthEvent({
  req,
  action = 'REFRESH_TOKEN',
  status,
  dieticianId = null,
  failureReason = null,
}) {
  try {
    if (process.env.ENABLE_DB_AUDIT_LOGS !== 'true') return;

    await pool.query(
      `INSERT INTO api_audit_logs
         (actor_id, actor_role, action, resource_type, resource_id,
          ip_address, user_agent, status, failure_reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        dieticianId,
        'dietician',
        action,
        'auth_session',
        dieticianId,
        getClientIp(req),
        getUserAgent(req),
        status,
        failureReason,
      ]
    );
  } catch (error) {
    console.warn('[AUTH] audit_log_failed', {
      message: error?.message || null,
      code: error?.code || null,
    });
  }
}

function signAccessToken(dieticianId) {
  return jwt.sign(
    {
      sub: String(dieticianId),
      role: 'dietician',
    },
    process.env.JWT_SECRET,
    {
      expiresIn: ACCESS_TOKEN_TTL_SECONDS,
      algorithm: JWT_ALGORITHM,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      jwtid: crypto.randomBytes(16).toString('hex'),
    }
  );
}

function signRefreshToken(dieticianId) {
  return jwt.sign(
    {
      sub: String(dieticianId),
      role: 'dietician',
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
      algorithm: JWT_ALGORITHM,
      issuer: JWT_ISSUER,
      audience: JWT_AUDIENCE,
      jwtid: crypto.randomBytes(16).toString('hex'),
    }
  );
}

exports.refreshToken = async (req, res) => {
  let connection;

  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    if (typeof req.body === 'string') {
      try {
        req.body = JSON.parse(req.body);
      } catch {
        return res.status(400).json({
          ok: false,
          message: 'Invalid JSON body',
        });
      }
    }

    const securityConfig = ensureProductionSecurityConfigured();

    if (!securityConfig.ok) {
      console.error('[AUTH] Security config error:', securityConfig.reason);

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    const oldRefreshToken = getRefreshTokenFromRequest(req);

    if (!oldRefreshToken || typeof oldRefreshToken !== 'string') {
      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId: null,
        failureReason: 'missing_refresh_token',
      });

      return res.status(400).json({
        ok: false,
        message: 'refresh_token is required',
      });
    }

    let decoded;

    try {
      decoded = jwt.verify(oldRefreshToken, process.env.JWT_REFRESH_SECRET, {
        algorithms: [JWT_ALGORITHM],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });
    } catch {
      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId: null,
        failureReason: 'jwt_invalid_or_expired',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    const dieticianId = String(decoded.sub || '');

    if (!dieticianId || decoded.role !== 'dietician') {
      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId: dieticianId || null,
        failureReason: 'invalid_token_claims',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    const oldTokenHash = sha256(oldRefreshToken);

    connection = await pool.getConnection();
    await connection.beginTransaction();

    /*
    |--------------------------------------------------------------------------
    | Check Refresh Token From dietician_refresh_tokens Only
    |--------------------------------------------------------------------------
    */

    const [tokenRows] = await connection.query(
      `SELECT
         id,
         dietician_id,
         token_hash,
         expires_at,
         revoked_at
       FROM dietician_refresh_tokens
       WHERE token_hash = ?
       LIMIT 1
       FOR UPDATE`,
      [oldTokenHash]
    );

    const storedToken = tokenRows?.[0] || null;

    if (!storedToken) {
      await connection.rollback();

      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId,
        failureReason: 'token_not_found',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Reuse Detection
    |--------------------------------------------------------------------------
    */

    if (storedToken.revoked_at) {
      await connection.query(
        `UPDATE dietician_refresh_tokens
         SET revoked_at = COALESCE(revoked_at, NOW())
         WHERE dietician_id = ?`,
        [storedToken.dietician_id]
      );

      await connection.commit();

      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN_REUSE_DETECTED',
        status: 'failure',
        dieticianId: storedToken.dietician_id,
        failureReason: 'revoked_token_reused',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    if (String(storedToken.dietician_id) !== dieticianId) {
      await connection.rollback();

      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId,
        failureReason: 'subject_mismatch',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | DB Expiry Check
    |--------------------------------------------------------------------------
    */

    const expiresAtMs = new Date(storedToken.expires_at).getTime();

    if (!expiresAtMs || expiresAtMs <= Date.now()) {
      await connection.query(
        `UPDATE dietician_refresh_tokens
         SET revoked_at = NOW()
         WHERE id = ?`,
        [storedToken.id]
      );

      await connection.commit();

      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId,
        failureReason: 'token_expired',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Check Dietician Account Is Still Active
    | Requires table_dietician columns:
    | status, is_blocked, deleted_at
    |--------------------------------------------------------------------------
    */

    const [dieticianRows] = await connection.query(
      `SELECT dietician_id
       FROM table_dietician
       WHERE dietician_id = ?
         AND COALESCE(is_blocked, 0) = 0
         AND COALESCE(status, 'active') = 'active'
         AND deleted_at IS NULL
       LIMIT 1`,
      [dieticianId]
    );

    if (dieticianRows.length === 0) {
      await connection.rollback();

      await recordAuthEvent({
        req,
        action: 'REFRESH_TOKEN',
        status: 'failure',
        dieticianId,
        failureReason: 'account_not_found_or_inactive',
      });

      clearRefreshCookie(res);

      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Generate New Tokens
    |--------------------------------------------------------------------------
    */

    const newAccessToken = signAccessToken(dieticianId);
    const newRefreshToken = signRefreshToken(dieticianId);
    const newRefreshTokenHash = sha256(newRefreshToken);

    const newRefreshExpiresAt = new Date(
      Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
    );

    /*
    |--------------------------------------------------------------------------
    | Rotate Refresh Token
    |--------------------------------------------------------------------------
    */

    await connection.query(
      `UPDATE dietician_refresh_tokens
       SET revoked_at = NOW(),
           replaced_by_token_hash = ?,
           last_used_at = NOW()
       WHERE id = ?`,
      [newRefreshTokenHash, storedToken.id]
    );

    await connection.query(
      `INSERT INTO dietician_refresh_tokens
         (dietician_id, token_hash, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        dieticianId,
        newRefreshTokenHash,
        newRefreshExpiresAt,
        getClientIp(req),
        getUserAgent(req),
      ]
    );

    await connection.query(
      `DELETE FROM dietician_refresh_tokens
       WHERE dietician_id = ?
         AND expires_at < NOW()`,
      [dieticianId]
    );

    await connection.commit();

    await recordAuthEvent({
      req,
      action: 'REFRESH_TOKEN',
      status: 'success',
      dieticianId,
      failureReason: null,
    });

    /*
    |--------------------------------------------------------------------------
    | Cookie Mode
    |--------------------------------------------------------------------------
    */

    if (process.env.USE_REFRESH_COOKIE === 'true') {
      setRefreshCookie(res, newRefreshToken);

      return res.status(200).json({
        ok: true,
        token_type: 'Bearer',
        access_token: newAccessToken,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
      });
    }

    /*
    |--------------------------------------------------------------------------
    | JSON Fallback For Mobile/Native Clients
    |--------------------------------------------------------------------------
    */

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: newAccessToken,
      refresh_token: newRefreshToken,
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    });
  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch (_) {}
    }

    console.error('[AUTH] Refresh token error:', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      sqlMessage: isProduction ? undefined : error?.sqlMessage,
      stack: isProduction ? undefined : error?.stack,
    });

    clearRefreshCookie(res);

    return res.status(401).json({
      ok: false,
      message: 'Invalid or expired refresh token',
    });
  } finally {
    if (connection) connection.release();
  }
};







// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const crypto = require('crypto');

// exports.refreshToken = async (req, res) => {
//   try {
//     const { refresh_token } = req.body;

//     if (!refresh_token) {
//       return res.status(400).json({
//         ok: false,
//         message: 'refresh_token is required',
//       });
//     }

//     // Verify JWT signature & expiry
//     const decoded = jwt.verify(
//       refresh_token,
//       process.env.JWT_REFRESH_SECRET
//     );

//     // 🔐 Hash incoming refresh token
//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refresh_token)
//       .digest('hex');

//     // Check token exists & not revoked
//     const [rows] = await pool.query(
//       `SELECT * FROM refresh_tokens
//        WHERE token = ? AND revoked = 0`,
//       [hashedToken]
//     );

//     if (rows.length === 0) {
//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid refresh token',
//       });
//     }

//     // 🔹 Issue new access token
//     const accessToken = jwt.sign(
//       {
//         sub: decoded.sub,
//         role: decoded.role,
//         email: decoded.email,
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: process.env.JWT_EXPIRES_IN }
//     );

//     return res.json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       expires_in: 3600,
//     });

//   } catch (error) {
//     console.error('Refresh Token Error:', error);
//     return res.status(401).json({
//       ok: false,
//       message: 'Invalid or expired refresh token',
//     });
//   }
// };


