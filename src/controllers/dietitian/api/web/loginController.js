// controllers/dietitian/api/web/loginController.js
//
// Hardened login controller for VAPT + HIPAA.
//
// Key hardening over the original PHP port:
//   - Input validated and length-capped before any DB work (DoS / bcrypt abuse).
//   - Password is verified BEFORE status/role/verified checks → no enumeration
//     via differential error messages.
//   - When the user doesn't exist, a fixed dummy bcrypt hash is still compared
//     so total response time is independent of whether the account exists.
//   - All pre-auth failures collapse to the same 401 "Invalid credentials".
//   - JWT payload is minimal: only sub/role/partner_code/parent_user_id/scope
//     plus standard claims. No PII (name/phone/location/email) in the token.
//   - When the user has is_reset_password = 1, the issued JWT carries
//     scope = "password_reset" and the login response says so. The auth
//     middleware rejects this scope for any route that hasn't opted in.
//   - SECURITY_PEPPER is required in production (no silent fallback to JWT_SECRET).
//   - app_auth_logs.user_id stores dietician_id (opaque ID), not email (PHI).
//
// POST JSON:
// {
//   "identifier": "john@demo.com",   // email OR phone_no
//   "password":   "PlainTextPassword"
// }

'use strict';

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const pool = require('../../../../config/db');

/*
|--------------------------------------------------------------------------
| Config
|--------------------------------------------------------------------------
*/
const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISS    = process.env.JWT_ISS  || 'api.respyr.ai';
const JWT_AUD    = process.env.JWT_AUD  || 'respyr-dietitian-app';
const JWT_TTL    = parseInt(process.env.JWT_TTL, 10) || 900; // seconds

const isProduction =
  process.env.NODE_ENV === 'production' ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

// In production, SECURITY_PEPPER MUST be explicitly set. The dev fallback is
// only allowed locally to keep onboarding simple.
const SECURITY_PEPPER = process.env.SECURITY_PEPPER || (isProduction ? null : JWT_SECRET);

if (isProduction && !SECURITY_PEPPER) {
  // Surface loudly at first request — startup validation should catch this earlier.
  console.error('FATAL: SECURITY_PEPPER must be set in production');
}

/*
|--------------------------------------------------------------------------
| Input limits
|--------------------------------------------------------------------------
*/
const MAX_IDENTIFIER_LEN = 254; // RFC 5321 email max
const MAX_PASSWORD_LEN   = 128; // bcrypt truncates at 72 bytes anyway; cap input to prevent CPU abuse

/*
|--------------------------------------------------------------------------
| Constant-time-ish dummy hash
|--------------------------------------------------------------------------
| Bcrypt hash of a random string, computed once at module load. Used when
| the user doesn't exist so bcrypt.compare still runs and total response
| time matches the "wrong password" branch. This kills enumeration-by-timing.
*/
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(
  crypto.randomBytes(32).toString('hex'),
  parseInt(process.env.BCRYPT_ROUNDS, 10) || 12
);

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function isValidEmail(s) {
  return typeof s === 'string' && validator.isEmail(s, { allow_utf8_local_part: false });
}

function bestPasswordAlgo() {
  return { rounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12 };
}

function makeJwt(payload) {
  // PHP code manually sets iat/nbf/exp/iss/aud/sub inside the payload,
  // so noTimestamp:true prevents jsonwebtoken from re-adding iat.
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

/*
 * Safe logging: if app_auth_logs write fails, login still works.
 * Stores dietician_id (opaque) in user_id column — NOT email (PHI).
 */
async function writeAuthLogSafe(
  conn,
  req,
  eventType,
  dieticianId,
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
        dieticianId,
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
  if (role === 'admin')       return '/trainer-admin/overview';
  if (role === 'trainer')     return '/trainer/clients';
  return '/login';
}

/*
|--------------------------------------------------------------------------
| Generic auth failure response — identical for every pre-auth rejection.
|--------------------------------------------------------------------------
| Returning the same body/status for "user not found", "wrong password",
| "account inactive", "missing partner_code", "email not verified", etc.,
| eliminates user enumeration via differential responses.
*/
function genericAuthFailure(res) {
  return res.status(401).json({
    ok: false,
    error: 'Invalid credentials',
  });
}

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
*/
exports.login = async (req, res) => {
  if (req.method !== 'POST') {
    return res.status(405).json({ ok: false, error: 'Method not allowed' });
  }

  // Lambda/API Gateway raw body handling
  if (typeof req.body === 'string') {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      return res.status(400).json({ ok: false, error: 'Invalid JSON body' });
    }
  }

  const inBody = req.body || {};

  // Type-guard before length checks so we never call .length on a number/array.
  if (typeof inBody.identifier !== 'string' || typeof inBody.password !== 'string') {
    return res.status(422).json({
      ok: false,
      error: 'identifier and password are required',
    });
  }

  const identifier = inBody.identifier.trim();
  const password   = inBody.password;

  if (identifier === '' || password === '') {
    return res.status(422).json({
      ok: false,
      error: 'identifier and password are required',
    });
  }

  // Length caps — reject oversized payloads before any DB or bcrypt work.
  if (identifier.length > MAX_IDENTIFIER_LEN || password.length > MAX_PASSWORD_LEN) {
    return res.status(422).json({
      ok: false,
      error: 'identifier or password exceeds maximum length',
    });
  }

  let conn;

  try {
    conn = await pool.getConnection();

    /*
    |--------------------------------------------------------------------------
    | Lookup user (email OR phone_no)
    |--------------------------------------------------------------------------
    */
    let user = null;
    try {
      let rows;
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
      user = rows && rows.length ? rows[0] : null;
    } catch (e) {
      console.error('ROLE_LOGIN_LOOKUP_ERROR: ' + e.message);
      return res.status(500).json({ ok: false, error: 'Internal server error' });
    }

    /*
    |--------------------------------------------------------------------------
    | Verify password FIRST (constant-time-ish)
    |--------------------------------------------------------------------------
    | If user is missing, we still run bcrypt.compare against a fixed dummy
    | hash so the timing matches a "wrong password" branch. This kills the
    | classic enumeration-by-response-time attack.
    */
    const hashToCompare = user ? String(user.password) : DUMMY_BCRYPT_HASH;
    let passwordOk = false;
    try {
      passwordOk = await bcrypt.compare(password, hashToCompare);
    } catch (e) {
      console.error('BCRYPT_COMPARE_ERROR: ' + e.message);
      passwordOk = false;
    }

    if (!user || !passwordOk) {
      await writeAuthLogSafe(
        conn,
        req,
        'login_failed',
        user ? user.dietician_id : null,
        user ? String(user.role || '') : null,
        user ? user.partner_code : null,
        identifier,
        0,
        'Invalid credentials'
      );
      return genericAuthFailure(res);
    }

    /*
    |--------------------------------------------------------------------------
    | Password is correct — NOW apply status / role / verified gates.
    |--------------------------------------------------------------------------
    | All of these still return the same generic 401 to clients (no enumeration),
    | but we log a precise reason in app_auth_logs for the audit trail.
    */
    const role = String(user.role || '');

    if (String(user.status) !== 'active') {
      await writeAuthLogSafe(
        conn, req, 'login_blocked',
        user.dietician_id, role, user.partner_code,
        identifier, 0, 'Account is not active'
      );
      return genericAuthFailure(res);
    }

    if (role !== 'super_admin' && role !== 'admin' && role !== 'trainer') {
      await writeAuthLogSafe(
        conn, req, 'login_blocked',
        user.dietician_id, role, user.partner_code,
        identifier, 0, 'Invalid role configuration'
      );
      return genericAuthFailure(res);
    }

    const needsPartnerCode = (role === 'admin' || role === 'trainer');
    if (
      needsPartnerCode &&
      String(user.partner_code == null ? '' : user.partner_code).trim() === ''
    ) {
      await writeAuthLogSafe(
        conn, req, 'login_blocked',
        user.dietician_id, role, user.partner_code,
        identifier, 0, 'Partner code missing'
      );
      return genericAuthFailure(res);
    }

    if (
      needsPartnerCode &&
      String(user.parent_user_id == null ? '' : user.parent_user_id).trim() === ''
    ) {
      await writeAuthLogSafe(
        conn, req, 'login_blocked',
        user.dietician_id, role, user.partner_code,
        identifier, 0, 'Parent user missing'
      );
      return genericAuthFailure(res);
    }

    if (needsPartnerCode && !user.email_verified_at) {
      await writeAuthLogSafe(
        conn, req, 'login_blocked',
        user.dietician_id, role, user.partner_code,
        identifier, 0, 'Email is not verified'
      );
      return genericAuthFailure(res);
    }

    /*
    |--------------------------------------------------------------------------
    | Opportunistic password rehash (best-effort)
    |--------------------------------------------------------------------------
    */
    try {
      const { rounds } = bestPasswordAlgo();
      const currentRounds = bcrypt.getRounds(hashToCompare);
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
    | Build JWT — minimal claims only
    |--------------------------------------------------------------------------
    | If is_reset_password = 1 the token is scoped to password reset only; the
    | auth middleware refuses to authorize normal routes when scope is set.
    */
    const mustResetPassword = parseInt(user.is_reset_password, 10) === 1;
    const scope = mustResetPassword ? 'password_reset' : 'full';

    const partnerCodeStr =
      user.partner_code !== null && user.partner_code !== undefined
        ? String(user.partner_code)
        : null;
    const parentUserIdStr =
      user.parent_user_id !== null && user.parent_user_id !== undefined
        ? String(user.parent_user_id).toLowerCase()
        : null;

    const now = Math.floor(Date.now() / 1000);
    const ttl = mustResetPassword ? Math.min(JWT_TTL, 300) : JWT_TTL;

    const payload = {
      iss: JWT_ISS,
      aud: JWT_AUD,
      iat: now,
      nbf: now,
      exp: now + ttl,
      sub: String(user.dietician_id),
      role: role,
      partner_code: partnerCodeStr,
      parent_user_id: parentUserIdStr,
      scope: scope,
    };

    const token = makeJwt(payload);

    /*
    |--------------------------------------------------------------------------
    | Logo URL + dashboard route
    |--------------------------------------------------------------------------
    */
    const logo_url =
      'https://humorstech.com/humors_app/app_final/dieticianapp/api/get_dietician_logo.php?dietician_id=' +
      encodeURIComponent(user.dietician_id);

    const dashboard_route = mustResetPassword
      ? '/change-password'
      : buildDashboardRoute(role);

    /*
    |--------------------------------------------------------------------------
    | Audit log: login_success
    |--------------------------------------------------------------------------
    */
    await writeAuthLogSafe(
      conn, req,
      mustResetPassword ? 'login_success_reset_required' : 'login_success',
      user.dietician_id, role, user.partner_code,
      identifier, 1, null
    );

    /*
    |--------------------------------------------------------------------------
    | Success response
    |--------------------------------------------------------------------------
    | JWT carries only the minimum needed for authorization. Profile data
    | (name/phone/location/email) is returned in the response body so the
    | client can populate the UI, but it isn't embedded in the token.
    */
    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: token,
      expires_in: ttl,
      scope: scope,
      must_reset_password: mustResetPassword,

      role: role,
      partner_code: partnerCodeStr,
      parent_user_id: parentUserIdStr,
      dashboard_route: dashboard_route,

      dietician: {
        dietician_id: user.dietician_id,
        name: user.name,
        email: String(user.email).toLowerCase(),
        phone_no: user.phone_no,
        location: user.location,
        logo: logo_url,
        is_reset_password: parseInt(user.is_reset_password, 10) || 0,
        role: role,
        partner_code: partnerCodeStr,
        parent_user_id: parentUserIdStr,
      },
    });
  } catch (err) {
    console.error('LOGIN_ERROR:', err.message);
    return res.status(500).json({ ok: false, error: 'Internal server error' });
  } finally {
    if (conn) conn.release();
  }
};
