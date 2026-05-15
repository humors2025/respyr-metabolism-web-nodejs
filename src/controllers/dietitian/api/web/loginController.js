// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');

// exports.login = async (req, res) => {
//   try {
//     // Handle Lambda body string
//     if (typeof req.body === 'string') {
//       try {
//         req.body = JSON.parse(req.body);
//       } catch (parseError) {
//         return res.status(400).json({
//           ok: false,
//           message: 'Invalid JSON body',
//         });
//       }
//     }

//     const identifier = String(req.body?.identifier || '').trim().toLowerCase();
//     const password = String(req.body?.password || '');

//     if (!identifier || !password) {
//       return res.status(400).json({
//         ok: false,
//         message: 'Email and password are required',
//       });
//     }

//     /**
//      * ROOT FIX:
//      * Login should check table_dietician email/phone,
//      * not table_clients email.
//      */
//     const [rows] = await pool.query(
//       `SELECT 
//          td.dietician_id,
//          td.name,
//          td.email,
//          td.phone_no,
//          td.location,
//          td.password,
//          tc.profile_id
//        FROM table_dietician td
//        LEFT JOIN table_clients tc 
//          ON td.dietician_id = tc.dietician_id
//        WHERE LOWER(td.email) = ?
//           OR td.phone_no = ?
//        LIMIT 1`,
//       [identifier, identifier]
//     );

//     if (!rows.length) {
//       console.log('LOGIN FAILED: dietician not found', {
//         identifier,
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     const dietician = rows[0];

//     if (!dietician.password) {
//       console.log('LOGIN FAILED: password missing in DB', {
//         dietician_id: dietician.dietician_id,
//         email: dietician.email,
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     /**
//      * bcrypt.compare works only if DB password is bcrypt hashed.
//      * Example hash starts with:
//      * $2a$, $2b$, or $2y$
//      */
//     const isPasswordValid = await bcrypt.compare(password, dietician.password);

//     if (!isPasswordValid) {
//       console.log('LOGIN FAILED: invalid password', {
//         dietician_id: dietician.dietician_id,
//         email: dietician.email,
//         password_hash_prefix: String(dietician.password).substring(0, 4),
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     const baseUrl =
//       process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

//     const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;

//     const profileUrl = dietician.profile_id
//       ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`
//       : null;

//     if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
//       console.error('JWT secrets missing');

//       return res.status(500).json({
//         ok: false,
//         message: 'Server configuration error',
//       });
//     }

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
//           logo_url: logoUrl,
//           profile_url: profileUrl,
//         },
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: '15m' }
//     );

//     const refreshToken = jwt.sign(
//       {
//         sub: dietician.dietician_id,
//         role: 'dietician',
//       },
//       process.env.JWT_REFRESH_SECRET,
//       { expiresIn: '7d' }
//     );

//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refreshToken)
//       .digest('hex');

//     const expiresAt = new Date();
//     expiresAt.setDate(expiresAt.getDate() + 7);

//     await pool.query(
//       `UPDATE table_dietician
//        SET refresh_token_hash = ?, refresh_token_exp = ?
//        WHERE dietician_id = ?`,
//       [hashedToken, expiresAt, dietician.dietician_id]
//     );

//     return res.status(200).json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       refresh_token: refreshToken,
//       expires_in: 900,
//     });
//   } catch (error) {
//     console.error('LOGIN ERROR 🔥:', {
//       message: error.message,
//       code: error.code,
//       errno: error.errno,
//       sqlState: error.sqlState,
//       stack: error.stack,
//     });

//     return res.status(500).json({
//       ok: false,
//       error: error.message,
//     });
//   }
// };






// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');

// function getClientIp(req) {
//   const forwardedFor = req.headers?.['x-forwarded-for'];

//   if (forwardedFor) {
//     return String(forwardedFor).split(',')[0].trim().substring(0, 45);
//   }

//   return (
//     req.ip ||
//     req.connection?.remoteAddress ||
//     req.socket?.remoteAddress ||
//     null
//   );
// }

// function getUserAgent(req) {
//   const userAgent =
//     typeof req.get === 'function'
//       ? req.get('user-agent')
//       : req.headers?.['user-agent'];

//   return userAgent ? String(userAgent).substring(0, 255) : null;
// }

// exports.login = async (req, res) => {
//   try {
//     /**
//      * Handle Lambda/API Gateway body string
//      */
//     if (typeof req.body === 'string') {
//       try {
//         req.body = JSON.parse(req.body);
//       } catch (parseError) {
//         return res.status(400).json({
//           ok: false,
//           message: 'Invalid JSON body',
//         });
//       }
//     }

//     const identifier = String(req.body?.identifier || '')
//       .trim()
//       .toLowerCase();

//     const password = String(req.body?.password || '');

//     if (!identifier || !password) {
//       return res.status(400).json({
//         ok: false,
//         message: 'Email and password are required',
//       });
//     }

//     /**
//      * Check dietician table using email or phone.
//      */
//     const [rows] = await pool.query(
//       `SELECT 
//          td.dietician_id,
//          td.name,
//          td.email,
//          td.phone_no,
//          td.location,
//          td.password,
//          tc.profile_id
//        FROM table_dietician td
//        LEFT JOIN table_clients tc 
//          ON td.dietician_id = tc.dietician_id
//        WHERE LOWER(td.email) = ?
//           OR td.phone_no = ?
//        LIMIT 1`,
//       [identifier, identifier]
//     );

//     if (!rows.length) {
//       console.log('LOGIN FAILED: dietician not found', {
//         identifier,
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     const dietician = rows[0];

//     if (!dietician.password) {
//       console.log('LOGIN FAILED: password missing in DB', {
//         dietician_id: dietician.dietician_id,
//         email: dietician.email,
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     /**
//      * bcrypt.compare works only if DB password is bcrypt hashed.
//      * Valid bcrypt hashes usually start with $2a$, $2b$, or $2y$.
//      */
//     const isPasswordValid = await bcrypt.compare(
//       password,
//       dietician.password
//     );

//     if (!isPasswordValid) {
//       console.log('LOGIN FAILED: invalid password', {
//         dietician_id: dietician.dietician_id,
//         email: dietician.email,
//         password_hash_prefix: String(dietician.password).substring(0, 4),
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
//       console.error('JWT secrets missing');

//       return res.status(500).json({
//         ok: false,
//         message: 'Server configuration error',
//       });
//     }

//     const baseUrl =
//       process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

//     const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;

//     const profileUrl = dietician.profile_id
//       ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`
//       : null;

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
//           logo_url: logoUrl,
//           profile_url: profileUrl,
//         },
//       },
//       process.env.JWT_SECRET,
//       {
//         expiresIn: '15m',
//       }
//     );

//     const refreshToken = jwt.sign(
//       {
//         sub: dietician.dietician_id,
//         role: 'dietician',
//       },
//       process.env.JWT_REFRESH_SECRET,
//       {
//         expiresIn: '7d',
//       }
//     );

//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refreshToken)
//       .digest('hex');

//     const expiresAt = new Date();
//     expiresAt.setDate(expiresAt.getDate() + 7);

//     const ipAddress = getClientIp(req);
//     const userAgent = getUserAgent(req);

//     /**
//      * Store refresh token in separate table.
//      * Do NOT update table_dietician with refresh_token_hash.
//      */
//     await pool.query(
//       `INSERT INTO dietician_refresh_tokens
//        (
//          dietician_id,
//          token_hash,
//          expires_at,
//          ip_address,
//          user_agent
//        )
//        VALUES (?, ?, ?, ?, ?)`,
//       [
//         dietician.dietician_id,
//         hashedToken,
//         expiresAt,
//         ipAddress,
//         userAgent,
//       ]
//     );

//     return res.status(200).json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       refresh_token: refreshToken,
//       expires_in: 900,
//     });
//   } catch (error) {
//     console.error('LOGIN ERROR 🔥 FULL:', error);

//     console.error('LOGIN ERROR DETAILS:', {
//       message: error?.message || null,
//       name: error?.name || null,
//       code: error?.code || null,
//       errno: error?.errno || null,
//       sqlMessage: error?.sqlMessage || null,
//       sqlState: error?.sqlState || null,
//       stack: error?.stack || null,
//     });

//     return res.status(500).json({
//       ok: false,
//       message: 'Login failed due to server error',
//       error:
//         error?.message ||
//         error?.sqlMessage ||
//         'Unknown server error',
//     });
//   }
// };










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
// const MIN_PASSWORD_LENGTH = 6;

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










const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const https = require('https');

/* ===============================
   Constants
================================ */

const DUMMY_BCRYPT_HASH =
  process.env.DUMMY_BCRYPT_HASH ||
  '$2b$10$CwTycUXWue0Thq9StjUM0uJ8.LJ3pP0NRmI8r1mB6q1RZ5lOq8eqW';

const MAX_IDENTIFIER_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;
const MIN_PASSWORD_LENGTH = 12;

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_DAYS = 7;

const MAX_CONCURRENT_SESSIONS = Number(
  process.env.MAX_CONCURRENT_SESSIONS || 5
);

const ACCOUNT_LOCKOUT_THRESHOLD = Number(
  process.env.ACCOUNT_LOCKOUT_THRESHOLD || 10
);

const ACCOUNT_LOCKOUT_WINDOW_MIN = Number(
  process.env.ACCOUNT_LOCKOUT_WINDOW_MIN || 60
);

const ACCOUNT_LOCKOUT_DURATION_MIN = Number(
  process.env.ACCOUNT_LOCKOUT_DURATION_MIN || 30
);

const BCRYPT_COST = Number(process.env.BCRYPT_COST || 12);

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

/**
 * For VAPT/HIPAA-aligned readiness, audit logs should be enabled in production.
 * Set ENABLE_DB_AUDIT_LOGS=true in Lambda/prod env.
 */
function shouldWriteAuditLogs() {
  return process.env.ENABLE_DB_AUDIT_LOGS === 'true';
}

/* ===============================
   Startup validation
================================ */

(function validateSecretsOnLoad() {
  const minLen = 32;

  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < minLen) {
    console.error('[AUTH] JWT_SECRET is shorter than 32 characters');
  }

  if (
    process.env.JWT_REFRESH_SECRET &&
    process.env.JWT_REFRESH_SECRET.length < minLen
  ) {
    console.error('[AUTH] JWT_REFRESH_SECRET is shorter than 32 characters');
  }

  if (isProduction && process.env.ENABLE_DB_AUDIT_LOGS !== 'true') {
    console.warn(
      '[AUTH] ENABLE_DB_AUDIT_LOGS is not true in production. Account lockout/audit trail may be weakened.'
    );
  }
})();

/* ===============================
   Helpers
================================ */

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

function isValidIdentifier(identifier) {
  if (!identifier || identifier.length > MAX_IDENTIFIER_LENGTH) return false;

  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRe = /^\+?\d{7,15}$/;

  return emailRe.test(identifier) || phoneRe.test(identifier);
}

/**
 * bcrypt has a 72-byte input limit.
 * SHA-256 pre-hash normalizes long/multibyte passwords before bcrypt.
 */
function normalizePasswordForBcrypt(password) {
  return crypto.createHash('sha256').update(password, 'utf8').digest('base64');
}

function hashIdentifierForAudit(identifier) {
  const pepper = process.env.AUDIT_HASH_PEPPER;

  if (pepper) {
    return crypto
      .createHmac('sha256', pepper)
      .update(identifier)
      .digest('hex');
  }

  return crypto.createHash('sha256').update(identifier).digest('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function sendInvalidCredentials(res) {
  return res.status(401).json({
    ok: false,
    message: 'Invalid email or password',
  });
}

function sendAccountLocked(res) {
  return res.status(423).json({
    ok: false,
    message:
      'This account is temporarily locked due to too many failed attempts. Please try again later.',
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

/**
 * Optional HaveIBeenPwned password check.
 * Do not use in login flow. Use only in signup/change-password flows.
 */
async function isPasswordBreached(password) {
  if (process.env.ENABLE_HIBP_CHECK !== 'true') return false;

  const sha1 = crypto
    .createHash('sha1')
    .update(password, 'utf8')
    .digest('hex')
    .toUpperCase();

  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  return new Promise((resolve) => {
    const hibpReq = https.request(
      {
        host: 'api.pwnedpasswords.com',
        path: `/range/${prefix}`,
        method: 'GET',
        headers: {
          'Add-Padding': 'true',
          'User-Agent': 'dietician-api',
        },
        timeout: 2000,
      },
      (hibpRes) => {
        let body = '';

        hibpRes.on('data', (chunk) => {
          body += chunk;
        });

        hibpRes.on('end', () => {
          const lines = body.split('\n');

          for (const line of lines) {
            const [hashSuffix] = line.trim().split(':');

            if (hashSuffix === suffix) {
              return resolve(true);
            }
          }

          return resolve(false);
        });
      }
    );

    hibpReq.on('error', () => resolve(false));

    hibpReq.on('timeout', () => {
      hibpReq.destroy();
      resolve(false);
    });

    hibpReq.end();
  });
}

/* ===============================
   Audit helpers
================================ */

async function recordAuthEvent({
  req,
  action = 'LOGIN',
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

async function isAccountLocked(dieticianId) {
  try {
    if (!shouldWriteAuditLogs()) return false;

    const [rows] = await pool.query(
      `SELECT COUNT(*) AS failed_count
         FROM api_audit_logs
        WHERE actor_id = ?
          AND action = 'LOGIN'
          AND status = 'failure'
          AND created_at >= DATE_SUB(NOW(), INTERVAL ? MINUTE)`,
      [dieticianId, ACCOUNT_LOCKOUT_WINDOW_MIN]
    );

    const failedCount = Number(rows?.[0]?.failed_count || 0);

    if (failedCount < ACCOUNT_LOCKOUT_THRESHOLD) {
      return false;
    }

    const [latestRows] = await pool.query(
      `SELECT created_at
         FROM api_audit_logs
        WHERE actor_id = ?
          AND action = 'LOGIN'
          AND status = 'failure'
        ORDER BY created_at DESC
        LIMIT 1`,
      [dieticianId]
    );

    if (!latestRows.length) return false;

    const lastFailureTime = new Date(latestRows[0].created_at).getTime();
    const unlockAt =
      lastFailureTime + ACCOUNT_LOCKOUT_DURATION_MIN * 60 * 1000;

    return Date.now() < unlockAt;
  } catch (error) {
    /**
     * Fail-open to avoid locking every user out if audit table has a problem.
     * But log it so production monitoring catches it.
     */
    console.warn('[AUTH] lockout_check_failed', {
      message: error?.message || null,
      code: error?.code || null,
    });

    return false;
  }
}

/**
 * Revoke oldest active sessions instead of deleting them.
 * This preserves evidence and allows refresh-token reuse detection.
 */
async function revokeOldestActiveSessionsIfNeeded(conn, dieticianId) {
  const [activeRows] = await conn.execute(
    `SELECT id
       FROM dietician_refresh_tokens
      WHERE dietician_id = ?
        AND revoked_at IS NULL
        AND expires_at > NOW()
      ORDER BY expires_at ASC
      FOR UPDATE`,
    [dieticianId]
  );

  if (activeRows.length < MAX_CONCURRENT_SESSIONS) {
    return;
  }

  const revokeCount = activeRows.length - MAX_CONCURRENT_SESSIONS + 1;
  const idsToRevoke = activeRows.slice(0, revokeCount).map((row) => row.id);

  if (!idsToRevoke.length) return;

  const placeholders = idsToRevoke.map(() => '?').join(',');

  await conn.execute(
    `UPDATE dietician_refresh_tokens
        SET revoked_at = NOW()
      WHERE id IN (${placeholders})`,
    idsToRevoke
  );
}

/* ===============================
   Controller
================================ */

exports.login = async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');

    /**
     * AWS Lambda/API Gateway can sometimes pass raw body as string.
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

    const rawIdentifier = req.body?.identifier;
    const rawPassword = req.body?.password;

    if (
      typeof rawIdentifier !== 'string' ||
      typeof rawPassword !== 'string'
    ) {
      return res.status(400).json({
        ok: false,
        message: 'Email and password are required',
      });
    }

    const identifier = rawIdentifier.trim().toLowerCase();
    const password = rawPassword;

    /**
     * Basic input validation.
     * We still burn bcrypt time on invalid input to reduce timing clues.
     */
    if (
      !identifier ||
      !password ||
      password.length < MIN_PASSWORD_LENGTH ||
      password.length > MAX_PASSWORD_LENGTH ||
      !isValidIdentifier(identifier)
    ) {
      await bcrypt.compare(
        normalizePasswordForBcrypt(password || 'x'),
        DUMMY_BCRYPT_HASH
      );

      return sendInvalidCredentials(res);
    }

    if (!ensureAuthSecretsConfigured()) {
      console.error('[AUTH] jwt_secrets_invalid_or_missing');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    const [rows] = await pool.query(
      `SELECT
         td.dietician_id,
         td.password
       FROM table_dietician td
       WHERE LOWER(td.email) = ?
          OR td.phone_no = ?
       LIMIT 1`,
      [identifier, identifier]
    );

    const dietician = rows?.[0] || null;

    if (dietician && (await isAccountLocked(dietician.dietician_id))) {
      await recordAuthEvent({
        req,
        action: 'LOGIN',
        status: 'failure',
        dieticianId: dietician.dietician_id,
        failureReason: 'account_locked',
      });

      return sendAccountLocked(res);
    }

    const hashToCompare =
      dietician && dietician.password
        ? dietician.password
        : DUMMY_BCRYPT_HASH;

    let isPasswordValid = false;
    let usedLegacyPasswordHash = false;

    /**
     * First try secure normalized bcrypt password.
     * Then fallback to legacy raw bcrypt check to avoid breaking existing users.
     * If legacy works, we upgrade hash after successful login.
     */
    try {
      isPasswordValid = await bcrypt.compare(
        normalizePasswordForBcrypt(password),
        hashToCompare
      );

      if (!isPasswordValid && dietician?.password) {
        const legacyValid = await bcrypt.compare(password, hashToCompare);

        if (legacyValid) {
          isPasswordValid = true;
          usedLegacyPasswordHash = true;
        }
      }
    } catch {
      isPasswordValid = false;
    }

    if (!dietician || !dietician.password || !isPasswordValid) {
      console.warn('[AUTH] login_failed', {
        identifier_hash: hashIdentifierForAudit(identifier),
        ip: getClientIp(req),
      });

      await recordAuthEvent({
        req,
        action: 'LOGIN',
        status: 'failure',
        dieticianId: dietician ? dietician.dietician_id : null,
        failureReason: 'auth_failed',
      });

      return sendInvalidCredentials(res);
    }

    /**
     * Upgrade old raw bcrypt password hash to normalized bcrypt hash.
     */
    if (usedLegacyPasswordHash) {
      try {
        const upgradedHash = await bcrypt.hash(
          normalizePasswordForBcrypt(password),
          BCRYPT_COST
        );

        await pool.query(
          `UPDATE table_dietician
              SET password = ?
            WHERE dietician_id = ?`,
          [upgradedHash, dietician.dietician_id]
        );
      } catch (upgradeError) {
        console.warn('[AUTH] password_hash_upgrade_failed', {
          dietician_id: dietician.dietician_id,
          message: upgradeError?.message || null,
        });
      }
    }

    const accessJti = crypto.randomBytes(16).toString('hex');
    const refreshJti = crypto.randomBytes(16).toString('hex');

    const accessToken = jwt.sign(
      {
        sub: String(dietician.dietician_id),
        role: 'dietician',
      },
      process.env.JWT_SECRET,
      {
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        algorithm: JWT_ALGORITHM,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        jwtid: accessJti,
      }
    );

    const refreshToken = jwt.sign(
      {
        sub: String(dietician.dietician_id),
        role: 'dietician',
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
        algorithm: JWT_ALGORITHM,
        issuer: JWT_ISSUER,
        audience: JWT_AUDIENCE,
        jwtid: refreshJti,
      }
    );

    const hashedRefreshToken = sha256(refreshToken);

    const expiresAt = new Date(
      Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000
    );

    const ipAddress = getClientIp(req);
    const userAgent = getUserAgent(req);

    /**
     * Store refresh token inside transaction.
     * This safely caps active sessions and inserts the new token.
     */
    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      /**
       * Remove expired tokens for this user.
       * Active or revoked but expired rows are no longer useful.
       */
      await conn.execute(
        `DELETE FROM dietician_refresh_tokens
          WHERE dietician_id = ?
            AND expires_at < NOW()`,
        [dietician.dietician_id]
      );

      await revokeOldestActiveSessionsIfNeeded(conn, dietician.dietician_id);

      await conn.execute(
        `INSERT INTO dietician_refresh_tokens
           (dietician_id, token_hash, expires_at, ip_address, user_agent)
         VALUES (?, ?, ?, ?, ?)`,
        [
          dietician.dietician_id,
          hashedRefreshToken,
          expiresAt,
          ipAddress,
          userAgent,
        ]
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
      action: 'LOGIN',
      status: 'success',
      dieticianId: dietician.dietician_id,
      failureReason: null,
    });

    if (useRefreshCookie) {
      res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
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
      access_token: accessToken,
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    };

    if (!useRefreshCookie) {
      responseBody.refresh_token = refreshToken;
    }

    return res.status(200).json(responseBody);
  } catch (error) {
    console.error('[AUTH] login_error', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      sqlMessage: isProduction ? undefined : error?.sqlMessage,
      stack: isProduction ? undefined : error?.stack,
    });

    return res.status(500).json({
      ok: false,
      message: 'Login failed. Please try again later.',
    });
  }
};

exports._internal = {
  isPasswordBreached,
  normalizePasswordForBcrypt,
  hashIdentifierForAudit,
};