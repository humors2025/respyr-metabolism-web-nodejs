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

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;   // 15 min
const REFRESH_TOKEN_TTL_DAYS = 7;

// Use the SAME env var names + defaults as loginController + authMiddleware
// so tokens issued here verify cleanly on protected routes.
const JWT_ISS = process.env.JWT_ISS || 'api.respyr.ai';
const JWT_AUD = process.env.JWT_AUD || 'respyr-dietitian-app';

exports.refreshToken = async (req, res) => {
  // Connection used for the rotation transaction
  let conn;
  try {
    // Lambda/API Gateway raw body handling (consistent with login controller)
    if (typeof req.body === 'string') {
      try {
        req.body = JSON.parse(req.body);
      } catch {
        return res.status(400).json({ ok: false, message: 'Invalid JSON body' });
      }
    }

    // Accept refresh token from body or httpOnly cookie (login can set either)
    const refreshToken =
      (typeof req.body?.refresh_token === 'string' && req.body.refresh_token) ||
      req.cookies?.refresh_token ||
      null;

    if (!refreshToken) {
      return res.status(400).json({
        ok: false,
        message: 'refresh_token is required',
      });
    }

    // Server config check before any work
    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
      console.error('[AUTH] JWT secrets missing in environment');
      return res.status(500).json({ ok: false, message: 'Server configuration error' });
    }

    // Verify signature, expiry, issuer and audience — must match how login signed it
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, {
        algorithms: ['HS256'],
        issuer: JWT_ISS,
        audience: JWT_AUD,
      });
    } catch {
      // Signature/expiry/claim failure — genuinely an invalid token
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    const hashedToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    // Transaction: look up the stored token, then rotate it atomically
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // Join to table_dietician to fetch profile data in one query.
    // FOR UPDATE locks the row so a concurrent refresh can't reuse it.
    const [rows] = await conn.query(
      `SELECT
         rt.id            AS token_id,
         rt.dietician_id  AS dietician_id,
         td.name,
         td.email,
         td.phone_no,
         td.location,
         (
           SELECT tc.profile_id
           FROM table_clients tc
           WHERE tc.dietician_id = td.dietician_id
           ORDER BY tc.profile_id ASC
           LIMIT 1
         ) AS profile_id
       FROM dietician_refresh_tokens rt
       JOIN table_dietician td ON td.dietician_id = rt.dietician_id
       WHERE rt.token_hash = ? AND rt.expires_at > NOW()
       LIMIT 1
       FOR UPDATE`,
      [hashedToken]
    );

    if (rows.length === 0) {
      await conn.rollback();
      // Token not in DB or expired. If it passed jwt.verify() but isn't in the
      // DB, it may have already been rotated/revoked — possible token reuse.
      console.warn('[AUTH] Refresh token not found or expired', {
        sub: decoded?.sub || null,
      });
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    const dietician = rows[0];

    // Cross-check: token's `sub` claim must match the DB row's owner
    if (String(decoded.sub) !== String(dietician.dietician_id)) {
      await conn.rollback();
      console.warn('[AUTH] Refresh token sub mismatch', {
        token_sub: decoded.sub,
        row_owner: dietician.dietician_id,
      });
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    const baseUrl = process.env.BASE_URL;
    const logoUrl = baseUrl
      ? `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`
      : null;
    const profileUrl = baseUrl && dietician.profile_id
      ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`
      : null;

    // New access token — minimal claims only. PII (name/phone/email/location)
    // is NOT embedded in the JWT; it's returned in the response body so the
    // client can populate UI. This matches the hardened loginController.
    const accessToken = jwt.sign(
      {
        sub: String(dietician.dietician_id),
        role: 'dietician',
        scope: 'full',
      },
      process.env.JWT_SECRET,
      {
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        algorithm: 'HS256',
        issuer: JWT_ISS,
        audience: JWT_AUD,
        jwtid: crypto.randomBytes(16).toString('hex'),
      }
    );

    // --- Refresh token rotation ---
    // Issue a brand-new refresh token and delete the old one so it can't be reused.
    const newRefreshToken = jwt.sign(
      {
        sub: String(dietician.dietician_id),
        role: 'dietician',
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
        algorithm: 'HS256',
        issuer: JWT_ISS,
        audience: JWT_AUD,
        jwtid: crypto.randomBytes(16).toString('hex'),
      }
    );

    const newHashedRefreshToken = crypto
      .createHash('sha256')
      .update(newRefreshToken)
      .digest('hex');

    const newExpiresAt = new Date();
    newExpiresAt.setDate(newExpiresAt.getDate() + REFRESH_TOKEN_TTL_DAYS);

    // Delete the consumed token (one-time use)
    await conn.query(
      `DELETE FROM dietician_refresh_tokens WHERE id = ?`,
      [dietician.token_id]
    );

    // Insert the replacement
    await conn.query(
      `INSERT INTO dietician_refresh_tokens
         (dietician_id, token_hash, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        dietician.dietician_id,
        newHashedRefreshToken,
        newExpiresAt,
        (req.ip || req.socket?.remoteAddress || null)?.toString().substring(0, 45) || null,
        (typeof req.get === 'function' ? req.get('user-agent') : null)?.toString().substring(0, 255) || null,
      ]
    );

    await conn.commit();

    // Match the login controller's cookie behaviour
    if (process.env.USE_REFRESH_COOKIE === 'true') {
      res.cookie('refresh_token', newRefreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
        path: '/dietitian/api/web/auth',
      });
    }

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: newRefreshToken,   // rotated — old one is now invalid
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    });
  } catch (error) {
    if (conn) {
      try { await conn.rollback(); } catch { /* ignore rollback failure */ }
    }
    console.error('[AUTH] Refresh token error:', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      sqlState: error?.sqlState || null,
      sqlMessage: process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
      stack: process.env.NODE_ENV !== 'production' ? error?.stack : undefined,
    });
    // Real server/DB error — 500, not a misleading 401
    return res.status(500).json({
      ok: false,
      message: 'Token refresh failed. Please try again later.',
    });
  } finally {
    if (conn) conn.release();
  }
};