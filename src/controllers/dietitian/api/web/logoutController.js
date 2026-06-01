// controllers/dietitian/api/web/logoutController.js

'use strict';

const crypto = require('crypto');
const pool = require('../../../../config/db');

/*
|--------------------------------------------------------------------------
| Config
|--------------------------------------------------------------------------
*/

const JWT_SECRET = process.env.JWT_SECRET;
const SECURITY_PEPPER = process.env.SECURITY_PEPPER || JWT_SECRET;

const JWT_REFRESH_TTL_DAYS = parseInt(process.env.JWT_REFRESH_TTL_DAYS, 10) || 30;
const JWT_REFRESH_TTL_SECONDS = JWT_REFRESH_TTL_DAYS * 24 * 60 * 60;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function hashRefreshToken(refreshToken) {
  return crypto.createHash('sha256').update(refreshToken).digest('hex');
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || '0.0.0.0').substring(0, 45);
}

function getUserAgent(req) {
  const ua = req.headers?.['user-agent'] || '';
  return String(ua).substring(0, 255);
}

function authLogHash(value) {
  return crypto
    .createHmac('sha256', SECURITY_PEPPER)
    .update(String(value == null ? '' : value).trim().toLowerCase())
    .digest('hex');
}

function getCookieValue(req, cookieName) {
  const cookieHeader = req.headers?.cookie;

  if (!cookieHeader || typeof cookieHeader !== 'string') return null;

  const cookies = cookieHeader.split(';').map((item) => item.trim());

  for (const cookie of cookies) {
    const index = cookie.indexOf('=');
    if (index === -1) continue;

    const name = cookie.substring(0, index);
    const value = cookie.substring(index + 1);

    if (name === cookieName) {
      return decodeURIComponent(value);
    }
  }

  return null;
}

function clearRefreshCookieIfEnabled(res) {
  if (process.env.USE_REFRESH_COOKIE !== 'true') return;

  res.clearCookie('refresh_token', {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    path: process.env.REFRESH_COOKIE_PATH || '/v1/auth/refresh-token',
  });
}

async function writeAuthLogSafe(conn, req, eventType, dieticianId, success, failureReason) {
  try {
    const safeEventType = String(eventType).substring(0, 60);

    const safeFailureReason =
      failureReason !== null && failureReason !== undefined
        ? String(failureReason).substring(0, 255)
        : null;

    await conn.execute(
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
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        safeEventType,
        dieticianId,
        null,
        null,
        null,
        authLogHash(getClientIp(req)),
        authLogHash(getUserAgent(req)),
        null,
        success ? 1 : 0,
        safeFailureReason,
      ]
    );
  } catch (error) {
    console.error('AUTH_LOG_WRITE_FAILED: ' + error.message);
  }
}

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
| Logout is identified solely by the presented refresh token (same as the
| refresh endpoint). We revoke by deleting the matching row from
| dietician_refresh_tokens — the table login/refresh actually use.
|
| The response is intentionally idempotent: we return success whether or
| not a row matched, so an attacker cannot probe which tokens exist.
|--------------------------------------------------------------------------
*/

exports.logout = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      message: 'Method not allowed',
    });
  }

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

  const inBody = req.body && typeof req.body === 'object' ? req.body : {};

  const refreshToken =
    (typeof inBody.refresh_token === 'string' && inBody.refresh_token.trim()) ||
    getCookieValue(req, 'refresh_token');

  if (!refreshToken) {
    return res.status(400).json({
      ok: false,
      message: 'refresh_token is required',
    });
  }

  const refreshTokenHash = hashRefreshToken(refreshToken);

  let conn;

  try {
    conn = await pool.getConnection();

    // Capture the owner (for the audit log) before we delete the row.
    const [rows] = await conn.execute(
      `SELECT dietician_id
         FROM dietician_refresh_tokens
        WHERE token_hash = ?
        LIMIT 1`,
      [refreshTokenHash]
    );

    const dieticianId =
      rows && rows.length ? String(rows[0].dietician_id) : null;

    // Revoke: one-time delete of the matching refresh token.
    await conn.execute(
      `DELETE FROM dietician_refresh_tokens
        WHERE token_hash = ?`,
      [refreshTokenHash]
    );

    await writeAuthLogSafe(conn, req, 'logout', dieticianId, 1, null);

    clearRefreshCookieIfEnabled(res);

    return res.status(200).json({
      ok: true,
      message: 'Logged out successfully',
    });
  } catch (error) {
    console.error('LOGOUT_ERROR:', {
      message: error?.message || null,
      code: error?.code || null,
      sqlState: error?.sqlState || null,
      sqlMessage:
        process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
    });

    return res.status(500).json({
      ok: false,
      message: 'Internal server error',
    });
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (_) {
        // noop
      }
    }
  }
};
