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






const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/* ===============================
   Constants
================================ */

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_DAYS = 7;

const JWT_ALGORITHM = 'HS256';
const JWT_ISSUER = process.env.JWT_ISSUER || 'dietician-api';
const JWT_AUDIENCE = process.env.JWT_AUDIENCE || 'dietician-app';

const isProduction =
  process.env.NODE_ENV === 'production' ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

const useRefreshCookie = process.env.USE_REFRESH_COOKIE === 'true';

const REFRESH_COOKIE_NAME =
  process.env.REFRESH_COOKIE_NAME || 'refresh_token';

const REFRESH_COOKIE_PATH =
  process.env.REFRESH_COOKIE_PATH || '/auth';

const REFRESH_COOKIE_SAME_SITE =
  process.env.REFRESH_COOKIE_SAME_SITE || 'strict';

/* ===============================
   Helpers
================================ */

function shouldWriteAuditLogs() {
  return process.env.ENABLE_DB_AUDIT_LOGS === 'true';
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

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sendInvalidRefresh(res) {
  clearRefreshCookieIfUsed(res);

  return res.status(401).json({
    ok: false,
    message: 'Invalid or expired refresh token',
  });
}

function clearRefreshCookieIfUsed(res) {
  if (!useRefreshCookie) return;

  res.clearCookie(REFRESH_COOKIE_NAME, {
    httpOnly: true,
    secure: true,
    sameSite: REFRESH_COOKIE_SAME_SITE,
    path: REFRESH_COOKIE_PATH,
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

/* ===============================
   Audit helpers
================================ */

async function recordAuthEvent({
  req,
  status,
  dieticianId = null,
  failureReason = null,
}) {
  try {
    if (!shouldWriteAuditLogs()) return;

    await pool.query(
      `INSERT INTO api_audit_logs
         (actor_id, actor_role, action, resource_type, resource_id,
          ip_address, user_agent, status, failure_reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        dieticianId,
        'dietician',
        'TOKEN_REFRESH',
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

/**
 * Refresh-token reuse response:
 * If a token that was already rotated is presented again,
 * revoke all active sessions for that dietitian.
 */
async function revokeAllSessionsFor(dieticianId, reason) {
  try {
    await pool.query(
      `UPDATE dietician_refresh_tokens
          SET revoked_at = NOW()
        WHERE dietician_id = ?
          AND revoked_at IS NULL`,
      [dieticianId]
    );

    console.warn('[AUTH] all_sessions_revoked', {
      dietician_id: dieticianId,
      reason,
    });
  } catch (error) {
    console.error('[AUTH] revoke_all_failed', {
      message: error?.message || null,
      code: error?.code || null,
    });
  }
}

/* ===============================
   Controller
================================ */

exports.refreshToken = async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');

  let decoded = null;
  let dieticianIdForAudit = null;
  let reuseDetectedDieticianId = null;

  try {
    /**
     * AWS Lambda/API Gateway raw body handling.
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

    const fromBody = req.body?.refresh_token;
    const fromCookie = req.cookies?.[REFRESH_COOKIE_NAME];

    const refreshToken =
      typeof fromBody === 'string' && fromBody.length > 0
        ? fromBody
        : typeof fromCookie === 'string' && fromCookie.length > 0
        ? fromCookie
        : null;

    if (!refreshToken) {
      clearRefreshCookieIfUsed(res);

      return res.status(400).json({
        ok: false,
        message: 'refresh_token is required',
      });
    }

    if (refreshToken.length > 4096) {
      await recordAuthEvent({
        req,
        status: 'failure',
        dieticianId: null,
        failureReason: 'token_too_large',
      });

      return sendInvalidRefresh(res);
    }

    if (!ensureAuthSecretsConfigured()) {
      console.error('[AUTH] jwt_secrets_invalid_or_missing');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    /**
     * Verify JWT first:
     * - signature
     * - expiry
     * - algorithm
     * - issuer
     * - audience
     */
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, {
        algorithms: [JWT_ALGORITHM],
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        clockTolerance: 5,
      });
    } catch {
      await recordAuthEvent({
        req,
        status: 'failure',
        dieticianId: null,
        failureReason: 'jwt_verify_failed',
      });

      return sendInvalidRefresh(res);
    }

    if (
      !decoded ||
      decoded.role !== 'dietician' ||
      !decoded.sub ||
      typeof decoded.sub !== 'string'
    ) {
      await recordAuthEvent({
        req,
        status: 'failure',
        dieticianId: null,
        failureReason: 'bad_claims',
      });

      return sendInvalidRefresh(res);
    }

    dieticianIdForAudit = decoded.sub;

    const presentedTokenHash = sha256(refreshToken);

    /**
     * Generate new tokens before transaction.
     * They will only become valid after DB commit.
     */
    const newAccessJti = crypto.randomBytes(16).toString('hex');
    const newRefreshJti = crypto.randomBytes(16).toString('hex');

    const newAccessToken = jwt.sign(
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
        jwtid: newAccessJti,
      }
    );

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
        jwtid: newRefreshJti,
      }
    );

    const newRefreshHash = sha256(newRefreshToken);

    const newExpiresAt = new Date(
      Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
    );

    let finalDieticianId = null;

    /**
     * Critical VAPT fix:
     * SELECT ... FOR UPDATE prevents two simultaneous refresh requests
     * from rotating the same old refresh token into two valid new tokens.
     */
    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      const [lockedRows] = await conn.execute(
        `SELECT
           id,
           dietician_id,
           expires_at,
           revoked_at,
           last_used_at
         FROM dietician_refresh_tokens
         WHERE token_hash = ?
         LIMIT 1
         FOR UPDATE`,
        [presentedTokenHash]
      );

      if (lockedRows.length === 0) {
        await conn.rollback();

        await recordAuthEvent({
          req,
          status: 'failure',
          dieticianId: decoded.sub,
          failureReason: 'token_not_found',
        });

        return sendInvalidRefresh(res);
      }

      const row = lockedRows[0];

      finalDieticianId = row.dietician_id;

      /**
       * If row is revoked:
       * - If last_used_at is present, it was previously rotated.
       *   Presenting it again means likely token reuse/theft.
       * - If last_used_at is null, it may be logout/session-cap revocation.
       */
      if (row.revoked_at !== null) {
        await conn.rollback();

        if (row.last_used_at !== null) {
          reuseDetectedDieticianId = row.dietician_id;
        }

        await recordAuthEvent({
          req,
          status: 'failure',
          dieticianId: row.dietician_id,
          failureReason:
            row.last_used_at !== null
              ? 'refresh_reuse_detected'
              : 'token_revoked',
        });

        if (reuseDetectedDieticianId) {
          await revokeAllSessionsFor(
            reuseDetectedDieticianId,
            'refresh_reuse_detected'
          );
        }

        return sendInvalidRefresh(res);
      }

      if (new Date(row.expires_at).getTime() <= Date.now()) {
        await conn.rollback();

        await recordAuthEvent({
          req,
          status: 'failure',
          dieticianId: row.dietician_id,
          failureReason: 'token_expired_db',
        });

        return sendInvalidRefresh(res);
      }

      if (String(row.dietician_id) !== String(decoded.sub)) {
        await conn.rollback();

        await recordAuthEvent({
          req,
          status: 'failure',
          dieticianId: row.dietician_id,
          failureReason: 'sub_mismatch',
        });

        return sendInvalidRefresh(res);
      }

      const [updateResult] = await conn.execute(
        `UPDATE dietician_refresh_tokens
            SET revoked_at = NOW(),
                last_used_at = NOW()
          WHERE id = ?
            AND revoked_at IS NULL`,
        [row.id]
      );

      /**
       * Defense-in-depth:
       * If affectedRows is not 1, another request modified the row.
       */
      if (updateResult.affectedRows !== 1) {
        await conn.rollback();

        await recordAuthEvent({
          req,
          status: 'failure',
          dieticianId: row.dietician_id,
          failureReason: 'token_rotation_race_detected',
        });

        return sendInvalidRefresh(res);
      }

      await conn.execute(
        `INSERT INTO dietician_refresh_tokens
           (dietician_id, token_hash, expires_at, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?)`,
        [
          row.dietician_id,
          newRefreshHash,
          newExpiresAt,
          getClientIp(req),
          getUserAgent(req),
        ]
      );

      /**
       * Cleanup only expired revoked rows.
       * Do not delete unexpired revoked rows because they help detect reuse.
       */
      await conn.execute(
        `DELETE FROM dietician_refresh_tokens
          WHERE dietician_id = ?
            AND revoked_at IS NOT NULL
            AND expires_at < NOW()`,
        [row.dietician_id]
      );

      await conn.commit();
    } catch (txError) {
      try {
        await conn.rollback();
      } catch (_) {
        // Ignore rollback failure.
      }

      throw txError;
    } finally {
      conn.release();
    }

    await recordAuthEvent({
      req,
      status: 'success',
      dieticianId: finalDieticianId,
      failureReason: null,
    });

    if (useRefreshCookie) {
      res.cookie(REFRESH_COOKIE_NAME, newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: REFRESH_COOKIE_SAME_SITE,
        maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
        path: REFRESH_COOKIE_PATH,
      });
    }

    const responseBody = {
      ok: true,
      token_type: 'Bearer',
      access_token: newAccessToken,
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    };

    if (!useRefreshCookie) {
      responseBody.refresh_token = newRefreshToken;
    }

    return res.status(200).json(responseBody);
  } catch (error) {
    console.error('[AUTH] refresh_token_error', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      sqlMessage: isProduction ? undefined : error?.sqlMessage,
      stack: isProduction ? undefined : error?.stack,
    });

    await recordAuthEvent({
      req,
      status: 'failure',
      dieticianId: dieticianIdForAudit,
      failureReason: 'server_error',
    });

    return sendInvalidRefresh(res);
  }
};