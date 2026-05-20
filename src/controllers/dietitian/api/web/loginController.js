const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

/**
 * Role-based login controller converted from role-login.php.
 *
 * This version:
 * - Reuses existing /auth/login route
 * - Reuses existing loginRateLimiter.js
 * - Reuses existing refreshTokenController.js table flow
 * - Reuses existing authMiddleware JWT flow
 * - Does not expose user object openly in API response
 * - Does not return dashboard_route
 * - Keeps only required identity/role data inside access_token
 */

const DUMMY_BCRYPT_HASH =
  '$2b$10$CwTycUXWue0Thq9StjUM0uJ8.LJ3pP0NRmI8r1mB6q1RZ5lOq8eqW';

const MAX_EMAIL_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;

const ACCESS_TOKEN_TTL_SECONDS = Number(
  process.env.ACCESS_TOKEN_TTL_SECONDS || 15 * 60
);

const REFRESH_TOKEN_TTL_DAYS = Number(
  process.env.REFRESH_TOKEN_TTL_DAYS || 7
);

const JWT_ALGORITHM = process.env.JWT_ALGORITHM || 'HS256';

const ALLOWED_ROLES = new Set(['super_admin', 'admin', 'trainer']);

function parseBodyIfNeeded(req) {
  if (typeof req.body === 'string') {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      return {
        ok: false,
        error: 'Invalid JSON body',
      };
    }
  }

  return {
    ok: true,
    body: req.body || {},
  };
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isValidEmail(email) {
  if (!email || email.length > MAX_EMAIL_LENGTH) return false;

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizePhpBcryptHash(hash) {
  const value = String(hash || '');

  /**
   * PHP password_hash() with bcrypt may create $2y$ hashes.
   * bcryptjs expects $2a$ or $2b$.
   */
  if (value.startsWith('$2y$')) {
    return `$2b$${value.slice(4)}`;
  }

  return value;
}

async function safePasswordCompare(password, storedHash) {
  try {
    return await bcrypt.compare(password, normalizePhpBcryptHash(storedHash));
  } catch {
    return false;
  }
}

function passwordNeedsRehash(storedHash) {
  const hash = String(storedHash || '');

  if (!hash) return false;

  if (hash.startsWith('$2y$')) {
    return true;
  }

  try {
    const existingRounds = bcrypt.getRounds(normalizePhpBcryptHash(hash));
    const requiredRounds = Number(process.env.BCRYPT_ROUNDS || 12);

    return existingRounds < requiredRounds;
  } catch {
    return false;
  }
}

function getClientIp(req) {
  const forwardedFor = req.headers?.['x-forwarded-for'];

  if (typeof forwardedFor === 'string' && forwardedFor.trim()) {
    return forwardedFor.split(',')[0].trim().substring(0, 45);
  }

  const ip =
    req.ip ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    null;

  return ip ? String(ip).substring(0, 45) : null;
}

function getUserAgent(req) {
  const userAgent =
    typeof req.get === 'function'
      ? req.get('user-agent')
      : req.headers?.['user-agent'];

  return userAgent ? String(userAgent).substring(0, 255) : null;
}

function hashForAudit(value) {
  if (!value) return null;

  const secret =
    process.env.AUDIT_HASH_SECRET ||
    process.env.JWT_SECRET ||
    'fallback-audit-secret';

  return crypto
    .createHmac('sha256', secret)
    .update(String(value).trim().toLowerCase())
    .digest('hex');
}

async function safeWriteAuthLog(req, payload) {
  /**
   * Optional DB audit logging.
   *
   * Keep ENABLE_DB_AUDIT_LOGS=false unless auth_audit_logs table exists.
   */
  if (process.env.ENABLE_DB_AUDIT_LOGS !== 'true') return;

  try {
    await pool.query(
      `
        INSERT INTO auth_audit_logs
          (
            event_type,
            user_id,
            role,
            partner_code,
            attempted_identifier_hash,
            success,
            failure_reason,
            ip_hash,
            user_agent_hash,
            created_at
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `,
      [
        payload.event_type,
        payload.user_id || null,
        payload.role || null,
        payload.partner_code || null,
        hashForAudit(payload.attempted_identifier),
        payload.success ? 1 : 0,
        payload.failure_reason || null,
        hashForAudit(getClientIp(req)),
        hashForAudit(getUserAgent(req)),
      ]
    );
  } catch (error) {
    console.warn('[AUTH] Audit log failed', {
      event_type: payload.event_type,
      message: error.message,
    });

    if (process.env.AUTH_AUDIT_FAIL_CLOSED === 'true') {
      throw error;
    }
  }
}

function createAccessToken(user) {
  /**
   * Keep token payload minimal.
   *
   * Do not put phone_no/location/profile data inside token.
   * JWT is signed, not encrypted, so frontend/users can decode it.
   */
  return jwt.sign(
    {
      sub: String(user.dietician_id),

      user_id: normalizeEmail(user.email),
      dietician_id: String(user.dietician_id),
      role: String(user.role),
      partner_code: user.partner_code || null,
      parent_user_id: user.parent_user_id || null,
      email: normalizeEmail(user.email),
      is_reset_password: Number(user.is_reset_password || 0),
    },
    process.env.JWT_SECRET,
    {
      expiresIn: ACCESS_TOKEN_TTL_SECONDS,
      algorithm: JWT_ALGORITHM,
      issuer: process.env.JWT_ISSUER || 'dietician-api',
      audience: process.env.JWT_AUDIENCE || 'dietician-app',
      jwtid: crypto.randomBytes(16).toString('hex'),
    }
  );
}

function createRefreshToken(user) {
  /**
   * Keep refresh token compatible with existing refreshTokenController.js.
   * Existing refresh controller usually depends on sub = dietician_id.
   */
  return jwt.sign(
    {
      sub: String(user.dietician_id),
      role: 'dietician',
      token_use: 'refresh',
    },
    process.env.JWT_REFRESH_SECRET,
    {
      expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
      algorithm: JWT_ALGORITHM,
      issuer: process.env.JWT_ISSUER || 'dietician-api',
      audience: process.env.JWT_AUDIENCE || 'dietician-app',
      jwtid: crypto.randomBytes(16).toString('hex'),
    }
  );
}

async function storeRefreshToken(req, dieticianId, refreshToken) {
  const hashedRefreshToken = crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_TTL_DAYS);

  /**
   * Cleanup expired refresh tokens for this user.
   */
  await pool.query(
    `
      DELETE FROM dietician_refresh_tokens
      WHERE dietician_id = ?
        AND expires_at < NOW()
    `,
    [dieticianId]
  );

  /**
   * This must match your existing refreshTokenController.js table structure.
   */
  await pool.query(
    `
      INSERT INTO dietician_refresh_tokens
        (
          dietician_id,
          token_hash,
          expires_at,
          ip_address,
          user_agent
        )
      VALUES (?, ?, ?, ?, ?)
    `,
    [
      dieticianId,
      hashedRefreshToken,
      expiresAt,
      getClientIp(req),
      getUserAgent(req),
    ]
  );
}

function maybeSetRefreshCookie(res, refreshToken) {
  /**
   * By default, refresh token is returned in JSON because your existing
   * frontend/API flow may already expect it.
   *
   * If later you want cookie-based refresh flow, set:
   * USE_REFRESH_COOKIE=true
   */
  if (process.env.USE_REFRESH_COOKIE !== 'true') return;

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure:
      process.env.NODE_ENV === 'production' ||
      Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME),
    sameSite: 'strict',
    maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
    path: '/',
  });
}

function sendInvalidCredentials(res) {
  return res.status(401).json({
    ok: false,
    message: 'Invalid email or password',
  });
}

exports.login = async (req, res) => {
  try {
    const parsed = parseBodyIfNeeded(req);

    if (!parsed.ok) {
      return res.status(400).json({
        ok: false,
        message: parsed.error,
      });
    }

    const body = parsed.body;

    let identifier = normalizeEmail(body.identifier);

    if (!identifier && body.email) {
      identifier = normalizeEmail(body.email);
    }

    const password = typeof body.password === 'string' ? body.password : '';

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        message: 'Email and password are required',
      });
    }

    if (!isValidEmail(identifier)) {
      return res.status(400).json({
        ok: false,
        message: 'Invalid email format',
      });
    }

    if (password.length > MAX_PASSWORD_LENGTH) {
      await bcrypt.compare('x', DUMMY_BCRYPT_HASH);
      return sendInvalidCredentials(res);
    }

    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
      console.error('[AUTH] JWT secrets missing in environment');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    const [rows] = await pool.query(
      `
        SELECT
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
        LIMIT 1
      `,
      [identifier]
    );

    const user = rows[0] || null;

    /**
     * Always run bcrypt compare.
     * If user does not exist, compare with dummy hash.
     * This reduces timing difference between valid and invalid emails.
     */
    const hashToCompare = user?.password || DUMMY_BCRYPT_HASH;

    const isPasswordValid = await safePasswordCompare(
      password,
      hashToCompare
    );

    if (!user || !user.password || !isPasswordValid) {
      await safeWriteAuthLog(req, {
        event_type: 'login_failed',
        user_id: user ? normalizeEmail(user.email) : null,
        role: user?.role || null,
        partner_code: user?.partner_code || null,
        attempted_identifier: identifier,
        success: false,
        failure_reason: 'Invalid email or password',
      });

      return sendInvalidCredentials(res);
    }

    /**
     * Important VAPT fix:
     * Password is checked before account status/role checks.
     * This avoids exposing whether an email exists, is inactive, or unverified.
     */
    const role = String(user.role || '').trim().toLowerCase();

    if (String(user.status || '').trim().toLowerCase() !== 'active') {
      await safeWriteAuthLog(req, {
        event_type: 'login_blocked',
        user_id: normalizeEmail(user.email),
        role,
        partner_code: user.partner_code || null,
        attempted_identifier: identifier,
        success: false,
        failure_reason: 'Account is not active',
      });

      return res.status(403).json({
        ok: false,
        message: 'Account is not active',
      });
    }

    if (!ALLOWED_ROLES.has(role)) {
      await safeWriteAuthLog(req, {
        event_type: 'login_blocked',
        user_id: normalizeEmail(user.email),
        role,
        partner_code: user.partner_code || null,
        attempted_identifier: identifier,
        success: false,
        failure_reason: 'Invalid role configuration',
      });

      return res.status(403).json({
        ok: false,
        message: 'Invalid role configuration',
      });
    }

    if ((role === 'admin' || role === 'trainer') && !user.partner_code) {
      return res.status(403).json({
        ok: false,
        message: 'Partner code missing for this account',
      });
    }

    if ((role === 'admin' || role === 'trainer') && !user.parent_user_id) {
      return res.status(403).json({
        ok: false,
        message: 'Parent user missing for this account',
      });
    }

    if ((role === 'admin' || role === 'trainer') && !user.email_verified_at) {
      return res.status(403).json({
        ok: false,
        message: 'Email is not verified',
      });
    }

    /**
     * Upgrade old PHP bcrypt hash if needed.
     */
    if (passwordNeedsRehash(user.password)) {
      const newHash = await bcrypt.hash(
        password,
        Number(process.env.BCRYPT_ROUNDS || 12)
      );

      await pool.query(
        `
          UPDATE table_dietician
          SET password = ?
          WHERE id = ?
          LIMIT 1
        `,
        [newHash, Number(user.id)]
      );
    }

    const accessToken = createAccessToken({
      ...user,
      role,
    });

    const refreshToken = createRefreshToken(user);

    await storeRefreshToken(req, user.dietician_id, refreshToken);

    maybeSetRefreshCookie(res, refreshToken);

    await safeWriteAuthLog(req, {
      event_type: 'login_success',
      user_id: normalizeEmail(user.email),
      role,
      partner_code: user.partner_code || null,
      attempted_identifier: normalizeEmail(user.email),
      success: true,
      failure_reason: null,
    });

    /**
     * Final response:
     * No open user object.
     * No dashboard_route.
     * Frontend should decode access_token for role-based routing.
     */
    return res.status(200).json({
      ok: true,
      message: 'Login successful',
      session: true,
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    });
  } catch (error) {
    console.error('[AUTH] Role login error:', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      sqlMessage:
        process.env.NODE_ENV !== 'production'
          ? error?.sqlMessage
          : undefined,
      stack:
        process.env.NODE_ENV !== 'production'
          ? error?.stack
          : undefined,
    });

    return res.status(500).json({
      ok: false,
      message: 'Login failed. Please try again later.',
    });
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