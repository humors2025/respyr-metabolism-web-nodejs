// controllers/dietitian/api/web/refreshTokenController.js

'use strict';

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const pool = require('../../../../config/db');

/*
|--------------------------------------------------------------------------
| Config
|--------------------------------------------------------------------------
*/

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISS = process.env.JWT_ISS || process.env.JWT_ISSUER || 'api.respyr.ai';
const JWT_AUD = process.env.JWT_AUD || process.env.JWT_AUDIENCE || 'respyr-dietitian-app';

const JWT_TTL = parseInt(process.env.JWT_TTL, 10) || 900;

const JWT_REFRESH_TTL_DAYS =
  parseInt(process.env.JWT_REFRESH_TTL_DAYS, 10) || 30;

const JWT_REFRESH_TTL_SECONDS = JWT_REFRESH_TTL_DAYS * 24 * 60 * 60;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function makeJwt(payload) {
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
  });
}

function createRefreshToken() {
  return crypto.randomBytes(64).toString('hex');
}

function hashRefreshToken(refreshToken) {
  return crypto.createHash('sha256').update(refreshToken).digest('hex');
}

function getRefreshExpiresAt() {
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + JWT_REFRESH_TTL_DAYS);
  return expiresAt;
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || '0.0.0.0').substring(0, 45);
}

function getUserAgent(req) {
  const ua = req.headers?.['user-agent'] || '';
  return String(ua).substring(0, 255);
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

function setRefreshCookieIfEnabled(res, refreshToken) {
  if (process.env.USE_REFRESH_COOKIE !== 'true') return;

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict',
    maxAge: JWT_REFRESH_TTL_SECONDS * 1000,
    path: process.env.REFRESH_COOKIE_PATH || '/v1/auth/refresh-token',
  });
}

function buildDashboardRoute(role) {
  if (role === 'super_admin') return '/super-admin/overview';
  if (role === 'admin') return '/trainer-admin/overview';
  if (role === 'trainer') return '/trainer/clients';
  return '/login';
}

function buildLogoUrl(dieticianId) {
  return (
    'https://humorstech.com/humors_app/app_final/dieticianapp/api/get_dietician_logo.php?dietician_id=' +
    encodeURIComponent(dieticianId)
  );
}

function sendInvalidRefreshToken(res) {
  return res.status(401).json({
    ok: false,
    message: 'Invalid or expired refresh token',
  });
}

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
*/

exports.refreshToken = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      message: 'Method not allowed',
    });
  }

  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('[AUTH] JWT_SECRET missing or too short');
    return res.status(500).json({
      ok: false,
      message: 'Server configuration error',
    });
  }

  let conn;

  try {
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

    const incomingRefreshTokenHash = hashRefreshToken(refreshToken);

    conn = await pool.getConnection();
    await conn.beginTransaction();

    /*
    |--------------------------------------------------------------------------
    | Find active refresh token
    |--------------------------------------------------------------------------
    | We do not store plain refresh token.
    | We compare SHA-256 hash and rotate token one-time-use.
    |--------------------------------------------------------------------------
    */

    const [rows] = await conn.query(
      `SELECT
         rt.id AS token_id,
         rt.dietician_id AS refresh_dietician_id,
         rt.expires_at,

         td.id,
         td.dietician_id,
         td.is_reset_password,
         td.name,
         td.phone_no,
         td.email,
         td.location,

         aur.role,
         aur.partner_code,
         aur.parent_user_id,
         aur.status,
         aur.email_verified_at
       FROM dietician_refresh_tokens rt
       INNER JOIN table_dietician td
         ON td.dietician_id = rt.dietician_id
       INNER JOIN app_user_roles aur
         ON LOWER(aur.user_id) = LOWER(td.email)
       WHERE rt.token_hash = ?
         AND rt.expires_at > NOW()
       LIMIT 1
       FOR UPDATE`,
      [incomingRefreshTokenHash]
    );

    if (!rows || rows.length === 0) {
      await conn.rollback();
      return sendInvalidRefreshToken(res);
    }

    const user = rows[0];
    const role = String(user.role);

    if (String(user.status) !== 'active') {
      await conn.rollback();
      return res.status(403).json({
        ok: false,
        message: 'Account is not active',
      });
    }

    if (role !== 'super_admin' && role !== 'admin' && role !== 'trainer') {
      await conn.rollback();
      return res.status(403).json({
        ok: false,
        message: 'Invalid role configuration',
      });
    }

    if (
      (role === 'admin' || role === 'trainer') &&
      String(user.partner_code == null ? '' : user.partner_code).trim() === ''
    ) {
      await conn.rollback();
      return res.status(403).json({
        ok: false,
        message: 'Partner code missing for this account',
      });
    }

    if (
      (role === 'admin' || role === 'trainer') &&
      String(user.parent_user_id == null ? '' : user.parent_user_id).trim() === ''
    ) {
      await conn.rollback();
      return res.status(403).json({
        ok: false,
        message: 'Parent user missing for this account',
      });
    }

    if ((role === 'admin' || role === 'trainer') && !user.email_verified_at) {
      await conn.rollback();
      return res.status(403).json({
        ok: false,
        message: 'Email is not verified',
      });
    }

    const partnerCode =
      user.partner_code !== null && user.partner_code !== undefined
        ? String(user.partner_code)
        : null;

    const parentUserId =
      user.parent_user_id !== null && user.parent_user_id !== undefined
        ? String(user.parent_user_id).toLowerCase()
        : null;

    const dashboardRoute = buildDashboardRoute(role);
    const logoUrl = buildLogoUrl(user.dietician_id);

    const dieticianPayload = {
      dietician_id: String(user.dietician_id),
      name: user.name,
      email: String(user.email).toLowerCase(),
      phone_no: user.phone_no,
      location: user.location,
      logo: logoUrl,
      is_reset_password: parseInt(user.is_reset_password, 10) || 0,

      role,
      partner_code: partnerCode,
      parent_user_id: parentUserId,
    };

    const now = Math.floor(Date.now() / 1000);

    const accessPayload = {
      iss: JWT_ISS,
      aud: JWT_AUD,
      iat: now,
      nbf: now,
      exp: now + JWT_TTL,

      sub: String(user.dietician_id),
      dietician_id: String(user.dietician_id),

      role,
      partner_code: partnerCode,
      parent_user_id: parentUserId,
      dashboard_route: dashboardRoute,

      dietician: dieticianPayload,
    };

    const newAccessToken = makeJwt(accessPayload);

    /*
    |--------------------------------------------------------------------------
    | Rotate refresh token
    |--------------------------------------------------------------------------
    | Delete old refresh token and create a new one.
    |--------------------------------------------------------------------------
    */

    const newRefreshToken = createRefreshToken();
    const newRefreshTokenHash = hashRefreshToken(newRefreshToken);
    const newRefreshExpiresAt = getRefreshExpiresAt();

    await conn.query(
      `DELETE FROM dietician_refresh_tokens
       WHERE id = ?`,
      [user.token_id]
    );

    await conn.query(
      `INSERT INTO dietician_refresh_tokens
         (dietician_id, token_hash, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        String(user.dietician_id),
        newRefreshTokenHash,
        newRefreshExpiresAt,
        getClientIp(req),
        getUserAgent(req),
      ]
    );

    await conn.commit();

    setRefreshCookieIfEnabled(res, newRefreshToken);

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: newAccessToken,
      expires_in: JWT_TTL,
      refresh_token: newRefreshToken,
      refresh_expires_in: JWT_REFRESH_TTL_SECONDS,
    });
  } catch (error) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (_) {
        // noop
      }
    }

    console.error('[AUTH] Refresh token error:', {
      message: error?.message || null,
      code: error?.code || null,
      sqlState: error?.sqlState || null,
      sqlMessage: process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
    });

    return res.status(500).json({
      ok: false,
      message: 'Token refresh failed. Please try again later.',
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