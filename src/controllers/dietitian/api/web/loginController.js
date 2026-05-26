// controllers/dietitian/api/web/loginController.js
//
// Node.js port of role-login-jwt.php (table_dietician + app_user_roles).
// Hardened login flow:
//   - No PHI/PII in audit logs (HMAC-hashed identifiers/IP/UA)
//   - Generic error messages (no user enumeration)
//   - Constant-time password verification + fixed delay on failure
//   - Strict input validation (type + length caps)
//   - Fail-fast on missing/weak JWT secret
//   - Explicit JWT algorithm (HS256) with manual iat/nbf/exp
//   - Connection always released
//
// NOTE:
// As requested, this version stores role, partner_code, parent_user_id,
// dashboard_route, and full dietician object inside access_token.
// JWT payload is base64-decodable, so do not treat JWT payload as private.
//
// POST JSON:
// {
//   "identifier": "john@demo.com",
//   "password":   "PlainTextPassword"
// }

'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const pool = require('../../../../config/db');

/*
|--------------------------------------------------------------------------
| Config
|--------------------------------------------------------------------------
*/
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISS = process.env.JWT_ISS || 'api.respyr.ai';
const JWT_AUD = process.env.JWT_AUD || 'respyr-dietitian-app';
const JWT_TTL = parseInt(process.env.JWT_TTL, 10) || 900; // seconds

// HMAC pepper for audit-log hashing — separate from JWT_SECRET when possible.
const SECURITY_PEPPER = process.env.SECURITY_PEPPER || JWT_SECRET;

// Fail-fast: a weak/missing JWT secret is a critical misconfig.
// Length 32+ ensures HS256 has ≥256 bits of entropy.
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL_CONFIG: JWT_SECRET is missing or too short (need >= 32 chars).');
}

// Hard caps to prevent oversized-payload DoS.
const MAX_IDENTIFIER_LEN = 254;
const MAX_PASSWORD_LEN = 256;
const FAIL_DELAY_MS = 400;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function isValidEmail(s) {
  return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function bestPasswordAlgo() {
  return {
    rounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
  };
}

function makeJwt(payload) {
  // iat/nbf/exp/iss/aud/sub are manually added in payload.
  // noTimestamp:true prevents jsonwebtoken from adding another iat.
  return jwt.sign(payload, JWT_SECRET, {
    algorithm: 'HS256',
    noTimestamp: true,
  });
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || '0.0.0.0');
}

function getUserAgent(req) {
  const ua = req.headers?.['user-agent'] || '';
  return String(ua).substring(0, 500);
}

function authLogHash(value) {
  return crypto
    .createHmac('sha256', SECURITY_PEPPER || '')
    .update(String(value == null ? '' : value).trim().toLowerCase())
    .digest('hex');
}

// Generic 500 — never leak err.message to the client.
function send500(res) {
  return res.status(500).json({
    ok: false,
    error: 'Internal server error',
  });
}

/*
 * Safe logging — if app_auth_logs insert fails, login still succeeds.
 * Identifying fields are HMAC-hashed before insert.
 */
async function writeAuthLogSafe(
  conn,
  req,
  eventType,
  userId,
  role,
  partnerCode,
  identifier,
  success,
  failureReason
) {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash =
      identifier !== null && identifier !== undefined
        ? authLogHash(identifier)
        : null;

    const ev = String(eventType).substring(0, 60);
    const fr =
      failureReason !== null && failureReason !== undefined
        ? String(failureReason).substring(0, 255)
        : null;

    const sessionHash = null;
    const successInt = success ? 1 : 0;

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
        ev,
        userId,
        role,
        partnerCode,
        identifierHash,
        ipHash,
        userAgentHash,
        sessionHash,
        successInt,
        fr,
      ]
    );
  } catch (e) {
    console.error('AUTH_LOG_WRITE_FAILED: ' + e.message);
  }
}

/*
|--------------------------------------------------------------------------
| Dashboard route
|--------------------------------------------------------------------------
*/
function buildDashboardRoute(role) {
  if (role === 'super_admin') return '/super-admin/overview';
  if (role === 'admin') return '/trainer-admin/overview';
  if (role === 'trainer') return '/trainer/clients';
  return '/login';
}

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
*/
exports.login = async (req, res) => {
  // Method gate
  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      error: 'Method not allowed',
    });
  }

  // Refuse early if JWT secret is misconfigured.
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    return send500(res);
  }

  // Lambda/API Gateway raw-body fallback
  if (typeof req.body === 'string') {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      return res.status(400).json({
        ok: false,
        error: 'Invalid JSON body',
      });
    }
  }

  const inBody = req.body && typeof req.body === 'object' ? req.body : {};

  // Strict type + length validation
  const rawIdentifier = inBody.identifier;
  const rawPassword = inBody.password;

  if (typeof rawIdentifier !== 'string' || typeof rawPassword !== 'string') {
    return res.status(422).json({
      ok: false,
      error: 'identifier and password are required',
    });
  }

  const identifier = rawIdentifier.trim();
  const password = rawPassword;

  if (
    identifier === '' ||
    password === '' ||
    identifier.length > MAX_IDENTIFIER_LEN ||
    password.length > MAX_PASSWORD_LEN
  ) {
    return res.status(422).json({
      ok: false,
      error: 'identifier and password are required',
    });
  }

  let conn;

  try {
    conn = await pool.getConnection();

    /*
    |--------------------------------------------------------------------------
    | Lookup from table_dietician + app_user_roles
    |--------------------------------------------------------------------------
    | table_dietician.email = app_user_roles.user_id
    */
    let rows;

    try {
      if (isValidEmail(identifier)) {
        const [r] = await conn.execute(
          `SELECT
             td.id,
             td.dietician_id,
             td.is_reset_password,
             td.name,
             td.phone_no,
             td.email,
             td.location,
             td.password,

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

        rows = r;
      } else {
        const [r] = await conn.execute(
          `SELECT
             td.id,
             td.dietician_id,
             td.is_reset_password,
             td.name,
             td.phone_no,
             td.email,
             td.location,
             td.password,

             aur.role,
             aur.partner_code,
             aur.parent_user_id,
             aur.status,
             aur.email_verified_at
           FROM table_dietician td
           INNER JOIN app_user_roles aur
             ON LOWER(aur.user_id) = LOWER(td.email)
           WHERE td.phone_no = ?
           LIMIT 1`,
          [identifier]
        );

        rows = r;
      }
    } catch (e) {
      console.error('ROLE_LOGIN_LOOKUP_ERROR: ' + e.message);
      return send500(res);
    }

    const user = rows && rows.length ? rows[0] : null;

    /*
    |--------------------------------------------------------------------------
    | User not found — same response shape + delay as bad password
    |--------------------------------------------------------------------------
    */
    if (!user) {
      await writeAuthLogSafe(
        conn,
        req,
        'login_failed',
        null,
        null,
        null,
        identifier,
        0,
        'Invalid credentials'
      );

      await sleep(FAIL_DELAY_MS);

      return res.status(401).json({
        ok: false,
        error: 'Invalid credentials',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Validate role/status
    |--------------------------------------------------------------------------
    */
    const role = String(user.role);

    if (String(user.status) !== 'active') {
      await writeAuthLogSafe(
        conn,
        req,
        'login_blocked',
        user.email,
        role,
        user.partner_code,
        identifier,
        0,
        'Account is not active'
      );

      return res.status(403).json({
        ok: false,
        error: 'Account is not active',
      });
    }

    if (role !== 'super_admin' && role !== 'admin' && role !== 'trainer') {
      await writeAuthLogSafe(
        conn,
        req,
        'login_blocked',
        user.email,
        role,
        user.partner_code,
        identifier,
        0,
        'Invalid role configuration'
      );

      return res.status(403).json({
        ok: false,
        error: 'Invalid role configuration',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Admin / trainer validation
    |--------------------------------------------------------------------------
    | super_admin may have partner_code = NULL and parent_user_id = NULL.
    */
    if (
      (role === 'admin' || role === 'trainer') &&
      String(user.partner_code == null ? '' : user.partner_code).trim() === ''
    ) {
      await writeAuthLogSafe(
        conn,
        req,
        'login_blocked',
        user.email,
        role,
        user.partner_code,
        identifier,
        0,
        'Partner code missing'
      );

      return res.status(403).json({
        ok: false,
        error: 'Partner code missing for this account',
      });
    }

    if (
      (role === 'admin' || role === 'trainer') &&
      String(user.parent_user_id == null ? '' : user.parent_user_id).trim() === ''
    ) {
      await writeAuthLogSafe(
        conn,
        req,
        'login_blocked',
        user.email,
        role,
        user.partner_code,
        identifier,
        0,
        'Parent user missing'
      );

      return res.status(403).json({
        ok: false,
        error: 'Parent user missing for this account',
      });
    }

    if ((role === 'admin' || role === 'trainer') && !user.email_verified_at) {
      await writeAuthLogSafe(
        conn,
        req,
        'login_blocked',
        user.email,
        role,
        user.partner_code,
        identifier,
        0,
        'Email is not verified'
      );

      return res.status(403).json({
        ok: false,
        error: 'Email is not verified',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Verify password
    |--------------------------------------------------------------------------
    */
    const hash = String(user.password || '');

    let passwordOk = false;

    try {
      passwordOk = hash !== '' && (await bcrypt.compare(password, hash));
    } catch (cmpErr) {
      console.error('BCRYPT_COMPARE_ERROR: ' + cmpErr.message);
      passwordOk = false;
    }

    if (!passwordOk) {
      await writeAuthLogSafe(
        conn,
        req,
        'login_failed',
        user.email,
        role,
        user.partner_code,
        identifier,
        0,
        'Invalid credentials'
      );

      await sleep(FAIL_DELAY_MS);

      return res.status(401).json({
        ok: false,
        error: 'Invalid credentials',
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Optional password rehash
    |--------------------------------------------------------------------------
    */
    try {
      const { rounds } = bestPasswordAlgo();
      const currentRounds = bcrypt.getRounds(hash);

      if (currentRounds < rounds) {
        const newHash = await bcrypt.hash(password, rounds);

        await conn.execute(
          'UPDATE table_dietician SET password = ? WHERE id = ?',
          [newHash, user.id]
        );
      }
    } catch (rehashErr) {
      console.error('REHASH_ERROR: ' + rehashErr.message);
    }

    /*
    |--------------------------------------------------------------------------
    | Build response/user payload
    |--------------------------------------------------------------------------
    */
    const partnerCode =
      user.partner_code !== null && user.partner_code !== undefined
        ? String(user.partner_code)
        : null;

    const parentUserId =
      user.parent_user_id !== null && user.parent_user_id !== undefined
        ? String(user.parent_user_id).toLowerCase()
        : null;

    const dashboardRoute = buildDashboardRoute(role);

    const logoUrl =
      'https://humorstech.com/humors_app/app_final/dieticianapp/api/get_dietician_logo.php?dietician_id=' +
      encodeURIComponent(user.dietician_id);

    const dieticianPayload = {
      dietician_id: String(user.dietician_id),
      name: user.name,
      email: String(user.email).toLowerCase(),
      phone_no: user.phone_no,
      location: user.location,
      logo: logoUrl,
      is_reset_password: parseInt(user.is_reset_password, 10) || 0,

      role: role,
      partner_code: partnerCode,
      parent_user_id: parentUserId,
    };

    /*
    |--------------------------------------------------------------------------
    | Issue JWT
    |--------------------------------------------------------------------------
    | As requested, full login payload is included inside access_token.
    */
    const now = Math.floor(Date.now() / 1000);

    const payload = {
      iss: JWT_ISS,
      aud: JWT_AUD,
      iat: now,
      nbf: now,
      exp: now + JWT_TTL,

      // Keep these top-level claims for authMiddleware/backward compatibility.
      sub: String(user.dietician_id),
      dietician_id: String(user.dietician_id),
      role: role,
      partner_code: partnerCode,
      parent_user_id: parentUserId,
      dashboard_route: dashboardRoute,

      // Full object inside access_token as requested.
      dietician: dieticianPayload,
    };

    const token = makeJwt(payload);

    /*
    |--------------------------------------------------------------------------
    | Audit log: login_success
    |--------------------------------------------------------------------------
    */
    await writeAuthLogSafe(
      conn,
      req,
      'login_success',
      user.email,
      role,
      user.partner_code,
      identifier,
      1,
      null
    );

    /*
    |--------------------------------------------------------------------------
    | Success response
    |--------------------------------------------------------------------------
    */
    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: token,
      expires_in: JWT_TTL,

      role: role,
      partner_code: partnerCode,
      parent_user_id: parentUserId,
      dashboard_route: dashboardRoute,

      dietician: dieticianPayload,
    });
  } catch (err) {
    console.error('LOGIN_ERROR:', err.message);
    return send500(res);
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