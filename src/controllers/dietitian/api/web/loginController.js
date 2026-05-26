// controllers/dietitian/api/web/loginController.js

'use strict';

const { getRounds, compare, hash } = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../../../../config/db');

// ─── Helpers ────────────────────────────────────────────────────────────────

const normalizeEmail = (email) =>
  typeof email === 'string' ? email.trim().toLowerCase() : '';

const buildDashboardRoute = (role) => {
  switch (role) {
    case 'super_admin': return '/super-admin/dashboard';
    case 'admin':       return '/admin/dashboard';
    case 'trainer':     return '/trainer/dashboard';
    default:            return '/dashboard';
  }
};

/**
 * Writes an audit log entry to app_auth_logs.
 * Silently swallows errors — audit failure must never break login.
 * Never logs passwords, tokens, or session IDs.
 */
const safeWriteAuthLog = async (conn, {
  event,
  userEmail = null,
  role = null,
  partnerCode = null,
  attemptedIdentifier = null,
  success = false,
  failReason = null,
}) => {
  try {
    await conn.execute(
      `INSERT INTO app_auth_logs
         (event, user_email, role, partner_code, attempted_identifier, success, fail_reason, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
      [event, userEmail, role, partnerCode, attemptedIdentifier, success ? 1 : 0, failReason]
    );
  } catch (err) {
    // Never propagate — audit errors must not surface to clients
    console.error('AUTH_LOG_WRITE_ERROR:', err.message);
  }
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// ─── Controller ─────────────────────────────────────────────────────────────

exports.login = async (req, res) => {
  let conn;

  try {
    // ── 1. Parse & validate input ──────────────────────────────────────────

    // Support both `identifier` and `email` for backward compat with PHP API
    let identifier = normalizeEmail(
      req.body?.identifier || req.body?.email || ''
    );
    const password = typeof req.body?.password === 'string'
      ? req.body.password
      : '';

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        message: 'Email and password are required',
      });
    }

    // Basic format gate — avoids hitting DB with obviously invalid input
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(identifier)) {
      return res.status(400).json({
        ok: false,
        message: 'Invalid email format',
      });
    }

    conn = await pool.getConnection();

    // ── 2. Look up user ────────────────────────────────────────────────────
    // JOIN ensures only users with a valid role entry can log in.
    // LOWER() on both sides prevents case-sensitivity bypasses.

    const [rows] = await conn.execute(
      `SELECT
         td.id,
         td.dietician_id,
         td.name,
         td.phone_no,
         td.email,
         td.location,
         td.password,
         td.is_reset_password,
         aur.role,
         aur.partner_code,
         aur.parent_user_id,
         aur.status,
         aur.email_verified_at
       FROM table_dietician td
       INNER JOIN app_user_roles aur
         ON LOWER(aur.user_id) = LOWER(td.email)
       WHERE LOWER(td.email) = LOWER(?)
       LIMIT 1`,
      [identifier]
    );

    const user = rows[0] || null;

    // ── 3. User not found — generic message (no email enumeration) ─────────

    if (!user) {
      await safeWriteAuthLog(conn, {
        event: 'login_failed',
        attemptedIdentifier: identifier,
        success: false,
        failReason: 'User not found',
      });

      await sleep(400); // Constant-time response to prevent timing attacks
      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    // ── 4. Account status & role gates ────────────────────────────────────

    if (user.status !== 'active') {
      return res.status(403).json({
        ok: false,
        message: 'Account is not active',
      });
    }

    const role = String(user.role);
    const VALID_ROLES = ['super_admin', 'admin', 'trainer'];

    if (!VALID_ROLES.includes(role)) {
      return res.status(403).json({
        ok: false,
        message: 'Invalid role configuration',
      });
    }

    if (['admin', 'trainer'].includes(role)) {
      if (!user.partner_code) {
        return res.status(403).json({
          ok: false,
          message: 'Partner code missing for this account',
        });
      }
      if (!user.parent_user_id) {
        return res.status(403).json({
          ok: false,
          message: 'Parent user missing for this account',
        });
      }
      if (!user.email_verified_at) {
        return res.status(403).json({
          ok: false,
          message: 'Email is not verified',
        });
      }
    }

    // ── 5. Password verification ───────────────────────────────────────────

    const passwordMatch = await compare(password, String(user.password));

    if (!passwordMatch) {
      await safeWriteAuthLog(conn, {
        event: 'login_failed',
        userEmail: normalizeEmail(user.email),
        role: user.role,
        partnerCode: user.partner_code || null,
        attemptedIdentifier: identifier,
        success: false,
        failReason: 'Invalid password',
      });

      await sleep(400);
      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    // ── 6. Rehash if bcrypt cost factor is outdated ────────────────────────
    // Keeps stored hashes current without forcing a password reset.

    const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

    try {
      const currentRounds = getRounds(String(user.password));
      if (currentRounds < BCRYPT_ROUNDS) {
        const newHash = await hash(password, BCRYPT_ROUNDS);
        await conn.execute(
          'UPDATE table_dietician SET password = ? WHERE id = ? LIMIT 1',
          [newHash, user.id]
        );
      }
    } catch (rehashErr) {
      // Non-fatal — log and continue, do not fail login
      console.error('REHASH_ERROR:', rehashErr.message);
    }

    // ── 7. Issue JWT ───────────────────────────────────────────────────────
    // PHP used sessions; Node.js uses stateless JWT to match your existing
    // authMiddleware and refreshTokenController patterns.

    const userEmail = normalizeEmail(user.email);

    const tokenPayload = {
      user_id:        userEmail,
      dietician_id:   String(user.dietician_id),  // canonical spelling
      dietician_id:   String(user.dietician_id),  // backward-compat alias
      name:           String(user.name),
      email:          userEmail,
      role,
      partner_code:   user.partner_code   || null,
      parent_user_id: user.parent_user_id || null,
    };

    const accessToken = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_EXPIRES_IN || '15m',
        issuer:    'api.respyr.ai',
        audience:  'respyr-dietitian-app',
      }
    );

    const refreshToken = jwt.sign(
      { user_id: userEmail, type: 'refresh' },
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
      {
        expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
        issuer:    'api.respyr.ai',
        audience:  'respyr-dietitian-app',
      }
    );

    // ── 8. Audit log — success ─────────────────────────────────────────────

    await safeWriteAuthLog(conn, {
      event:               'login_success',
      userEmail,
      role,
      partnerCode:         user.partner_code || null,
      attemptedIdentifier: userEmail,
      success:             true,
    });

    // ── 9. Respond ─────────────────────────────────────────────────────────

    return res.status(200).json({
      ok:              true,
      message:         'Login successful',
      access_token:    accessToken,
      refresh_token:   refreshToken,
      dashboard_route: buildDashboardRoute(role),
      user: {
        user_id:           userEmail,
        dietician_id:      String(user.dietician_id),
        name:              String(user.name),
        email:             userEmail,
        phone_no:          String(user.phone_no  || ''),
        location:          String(user.location  || ''),
        role,
        partner_code:      user.partner_code     || null,
        parent_user_id:    user.parent_user_id   || null,
        is_reset_password: Number(user.is_reset_password),
      },
    });

  } catch (err) {
    console.error('LOGIN_ERROR:', err.message);

    return res.status(500).json({
      ok:      false,
      message: 'Internal server error',
      ...(process.env.NODE_ENV !== 'production' && {
        debug_error: err.message,
      }),
    });

  } finally {
    if (conn) conn.release();
  }
};





// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');

// // Dummy bcrypt hash used to equalize timing when user is not found.
// // Real $2b$ hash of a random string — never matches any real password.
// const DUMMY_BCRYPT_HASH =
//   '$2b$10$CwTycUXWue0Thq9StjUM0uJ8.LJ3pP0NRmI8r1mB6q1RZ5lOq8eqW';

// const MAX_IDENTIFIER_LENGTH = 254;
// const MAX_PASSWORD_LENGTH = 128;
// const MIN_PASSWORD_LENGTH = 12;

// const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;        // 15 min
// const REFRESH_TOKEN_TTL_DAYS = 7;

// function getClientIp(req) {
//   // Trust the first value only if Express trust proxy is configured correctly
//   // at the app level: app.set('trust proxy', 1) (or appropriate number).
//   const ip = req.ip || req.connection?.remoteAddress || req.socket?.remoteAddress || null;
//   return ip ? String(ip).substring(0, 45) : null;
// }

// function getUserAgent(req) {
//   const ua = typeof req.get === 'function'
//     ? req.get('user-agent')
//     : req.headers?.['user-agent'];
//   return ua ? String(ua).substring(0, 255) : null;
// }

// function isValidIdentifier(identifier) {
//   if (!identifier || identifier.length > MAX_IDENTIFIER_LENGTH) return false;
//   // Accept email-like OR digits-only phone (7–15 digits, optional leading +)
//   const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//   const phoneRe = /^\+?\d{7,15}$/;
//   return emailRe.test(identifier) || phoneRe.test(identifier);
// }

// function sendInvalidCredentials(res) {
//   return res.status(401).json({
//     ok: false,
//     message: 'Invalid email or password',
//   });
// }

// exports.login = async (req, res) => {
//   try {
//     // Lambda/API Gateway raw body handling
//     if (typeof req.body === 'string') {
//       try {
//         req.body = JSON.parse(req.body);
//       } catch {
//         return res.status(400).json({ ok: false, message: 'Invalid JSON body' });
//       }
//     }

//     const rawIdentifier = req.body?.identifier;
//     const rawPassword = req.body?.password;

//     if (typeof rawIdentifier !== 'string' || typeof rawPassword !== 'string') {
//       return res.status(400).json({
//         ok: false,
//         message: 'Email and password are required',
//       });
//     }

//     const identifier = rawIdentifier.trim().toLowerCase();
//     const password = rawPassword;

//     // Input validation
//     if (
//       !identifier ||
//       !password ||
//       password.length < MIN_PASSWORD_LENGTH ||
//       password.length > MAX_PASSWORD_LENGTH ||
//       !isValidIdentifier(identifier)
//     ) {
//       // Still burn time so attackers can't distinguish "bad format" from "bad creds"
//       await bcrypt.compare(password || 'x', DUMMY_BCRYPT_HASH);
//       return sendInvalidCredentials(res);
//     }

//     // Server config check (do this early, before any DB work on invalid setups)
//     if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
//       console.error('[AUTH] JWT secrets missing in environment');
//       return res.status(500).json({
//         ok: false,
//         message: 'Server configuration error',
//       });
//     }

//     // Fetch dietician (use UNION to avoid LEFT JOIN row multiplication)
//     const [rows] = await pool.query(
//       `SELECT
//          td.dietician_id,
//          td.name,
//          td.email,
//          td.phone_no,
//          td.location,
//          td.password,
//          (
//            SELECT tc.profile_id
//            FROM table_clients tc
//            WHERE tc.dietician_id = td.dietician_id
//            ORDER BY tc.profile_id ASC
//            LIMIT 1
//          ) AS profile_id
//        FROM table_dietician td
//        WHERE LOWER(td.email) = ? OR td.phone_no = ?
//        LIMIT 1`,
//       [identifier, identifier]
//     );

//     const dietician = rows[0];

//     // Constant-time-ish path: always run bcrypt.compare, with dummy hash if no user
//     const hashToCompare =
//       dietician && dietician.password ? dietician.password : DUMMY_BCRYPT_HASH;

//     let isPasswordValid = false;
//     try {
//       isPasswordValid = await bcrypt.compare(password, hashToCompare);
//     } catch {
//       isPasswordValid = false;
//     }

//     if (!dietician || !dietician.password || !isPasswordValid) {
//       // Server-side log only — never expose details to client
//       console.warn('[AUTH] Login failed', {
//         identifier_hash: crypto.createHash('sha256').update(identifier).digest('hex').slice(0, 12),
//         ip: getClientIp(req),
//         reason: !dietician
//           ? 'user_not_found'
//           : !dietician.password
//           ? 'no_password_set'
//           : 'bad_password',
//       });
//       return sendInvalidCredentials(res);
//     }

//     // Build absolute URLs from a trusted env var only (don't trust Host header)
//     const baseUrl = process.env.BASE_URL;
//     if (!baseUrl) {
//       console.error('[AUTH] BASE_URL not configured');
//       return res.status(500).json({
//         ok: false,
//         message: 'Server configuration error',
//       });
//     }

//     const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;
//     const profileUrl = dietician.profile_id
//       ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`
//       : null;

//     // Generate a unique JWT id so we can revoke this specific token if needed
//     const jti = crypto.randomBytes(16).toString('hex');

//     const accessToken = jwt.sign(
//       {
//         sub: String(dietician.dietician_id),
//         role: 'dietician',
//         dietician: {
//           dietician_id: dietician.dietician_id,
//           name: dietician.name,
//           email: dietician.email,
//           phone_no: dietician.phone_no,
//           location: dietician.location,
//           logo_url: logoUrl,
//           profile_url: profileUrl,
//         },
//       },
//       process.env.JWT_SECRET,
//       {
//         expiresIn: ACCESS_TOKEN_TTL_SECONDS,
//         algorithm: 'HS256',
//         issuer: process.env.JWT_ISSUER || 'dietician-api',
//         audience: process.env.JWT_AUDIENCE || 'dietician-app',
//         jwtid: jti,
//       }
//     );

//     const refreshToken = jwt.sign(
//       {
//         sub: String(dietician.dietician_id),
//         role: 'dietician',
//       },
//       process.env.JWT_REFRESH_SECRET,
//       {
//         expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
//         algorithm: 'HS256',
//         issuer: process.env.JWT_ISSUER || 'dietician-api',
//         audience: process.env.JWT_AUDIENCE || 'dietician-app',
//         jwtid: crypto.randomBytes(16).toString('hex'),
//       }
//     );

//     const hashedRefreshToken = crypto
//       .createHash('sha256')
//       .update(refreshToken)
//       .digest('hex');

//     const expiresAt = new Date();
//     expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_TTL_DAYS);

//     const ipAddress = getClientIp(req);
//     const userAgent = getUserAgent(req);

//     // Housekeeping: delete expired refresh tokens for this user (keeps table small)
//     await pool.query(
//       `DELETE FROM dietician_refresh_tokens
//        WHERE dietician_id = ? AND expires_at < NOW()`,
//       [dietician.dietician_id]
//     );

//     // Store the new refresh token
//     await pool.query(
//       `INSERT INTO dietician_refresh_tokens
//          (dietician_id, token_hash, expires_at, ip_address, user_agent)
//        VALUES (?, ?, ?, ?, ?)`,
//       [dietician.dietician_id, hashedRefreshToken, expiresAt, ipAddress, userAgent]
//     );

//     // Optionally also set refresh token as httpOnly cookie (recommended for browser clients)
//     if (process.env.USE_REFRESH_COOKIE === 'true') {
//       res.cookie('refresh_token', refreshToken, {
//         httpOnly: true,
//         secure: true,
//         sameSite: 'strict',
//         maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
//         path: '/dietitian/api/web/auth',
//       });
//     }

//     return res.status(200).json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       refresh_token: refreshToken, // remove this line if you switch fully to cookie-based
//       expires_in: ACCESS_TOKEN_TTL_SECONDS,
//     });
//   } catch (error) {
//     // Log full details server-side
//     console.error('[AUTH] Login error:', {
//       message: error?.message || null,
//       name: error?.name || null,
//       code: error?.code || null,
//       errno: error?.errno || null,
//       sqlState: error?.sqlState || null,
//       // do NOT log sqlMessage in prod if it contains query fragments; keep for dev only
//       sqlMessage: process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
//       stack: process.env.NODE_ENV !== 'production' ? error?.stack : undefined,
//     });

//     // Never leak internals to client
//     return res.status(500).json({
//       ok: false,
//       message: 'Login failed. Please try again later.',
//     });
//   }
// };