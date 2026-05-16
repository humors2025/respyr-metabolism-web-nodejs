const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/*
|--------------------------------------------------------------------------
| Constants
|--------------------------------------------------------------------------
*/

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_DAYS = 7;

const JWT_ALGORITHM = 'HS256';
const JWT_ISSUER = process.env.JWT_ISSUER || 'dietician-api';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'dietician-app';

const isProduction =
  process.env.NODE_ENV === 'production' ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
*/

exports.refreshToken = async (req, res) => {
  try {
    /*
    |--------------------------------------------------------------------------
    | Security headers for token response
    |--------------------------------------------------------------------------
    */

    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    /*
    |--------------------------------------------------------------------------
    | Lambda/API Gateway raw body handling
    |--------------------------------------------------------------------------
    */

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

    /*
    |--------------------------------------------------------------------------
    | Input extraction
    |--------------------------------------------------------------------------
    |
    | Accepts refresh token from request body or, if enabled,
    | from an httpOnly cookie.
    |
    */

    const refreshToken =
      req.body?.refresh_token || req.cookies?.refresh_token;

    if (typeof refreshToken !== 'string' || !refreshToken) {
      return res.status(400).json({
        ok: false,
        message: 'refresh_token is required',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Environment validation
    |--------------------------------------------------------------------------
    */

    if (!ensureAuthSecretsConfigured()) {
      console.error('[AUTH] JWT secrets missing or too short');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Verify JWT signature, expiry, issuer and audience
    |--------------------------------------------------------------------------
    */

    let decoded;

    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, {
        algorithms: [JWT_ALGORITHM],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
      });
    } catch {
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    if (!decoded?.sub) {
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Database lookup
    |--------------------------------------------------------------------------
    |
    | Hash the incoming token and match it against the stored hash.
    | We never store raw refresh tokens.
    |
    */

    const hashedToken = sha256(refreshToken);

    const [rows] = await pool.query(
      `SELECT
         id,
         dietician_id,
         expires_at
       FROM dietician_refresh_tokens
       WHERE token_hash = ?
         AND dietician_id = ?
         AND expires_at > NOW()
       LIMIT 1`,
      [hashedToken, decoded.sub]
    );

    const storedToken = rows?.[0] || null;

    if (!storedToken) {
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Token rotation
    |--------------------------------------------------------------------------
    |
    | The presented refresh token is single-use. We delete it before
    | issuing a new pair so a token cannot be replayed.
    |
    */

    await pool.query(
      `DELETE FROM dietician_refresh_tokens
       WHERE id = ?`,
      [storedToken.id]
    );

    /*
    |--------------------------------------------------------------------------
    | Generate new access token
    |--------------------------------------------------------------------------
    */

    const accessToken = jwt.sign(
      {
        sub: String(decoded.sub),
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

    /*
    |--------------------------------------------------------------------------
    | Generate new refresh token
    |--------------------------------------------------------------------------
    */

    const newRefreshToken = jwt.sign(
      {
        sub: String(decoded.sub),
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

    const hashedNewRefreshToken = sha256(newRefreshToken);

    const expiresAt = new Date(
      Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
    );

    /*
    |--------------------------------------------------------------------------
    | Store new refresh token
    |--------------------------------------------------------------------------
    */

    await pool.query(
      `INSERT INTO dietician_refresh_tokens
         (dietician_id, token_hash, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        decoded.sub,
        hashedNewRefreshToken,
        expiresAt,
        getClientIp(req),
        getUserAgent(req),
      ]
    );

    /*
    |--------------------------------------------------------------------------
    | Optional refresh token cookie
    |--------------------------------------------------------------------------
    */

    if (process.env.USE_REFRESH_COOKIE === 'true') {
      res.cookie('refresh_token', newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
        path: process.env.REFRESH_COOKIE_PATH || '/auth',
      });

      return res.status(200).json({
        ok: true,
        token_type: 'Bearer',
        access_token: accessToken,
        expires_in: ACCESS_TOKEN_TTL_SECONDS,
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Response
    |--------------------------------------------------------------------------
    */

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: newRefreshToken,
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    });
  } catch (error) {
    console.error('[AUTH] Refresh token error:', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      sqlMessage: isProduction ? undefined : error?.sqlMessage,
      stack: isProduction ? undefined : error?.stack,
    });

    return res.status(401).json({
      ok: false,
      message: 'Invalid or expired refresh token',
    });
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


