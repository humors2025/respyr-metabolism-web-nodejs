'use strict';

const jwt = require('jsonwebtoken');
const pool = require('../config/db');

const JWT_ALGORITHM = process.env.JWT_ALGORITHM || 'HS256';

/*
|--------------------------------------------------------------------------
| Get cookie value
|--------------------------------------------------------------------------
*/

const getCookieValue = (req, cookieName) => {
  const cookieHeader = req.headers?.cookie;

  if (!cookieHeader || typeof cookieHeader !== 'string') {
    return null;
  }

  const cookies = cookieHeader.split(';').map((item) => item.trim());

  for (const cookie of cookies) {
    const index = cookie.indexOf('=');

    if (index === -1) continue;

    const name = cookie.substring(0, index);
    const value = cookie.substring(index + 1);

    if (name === cookieName) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
};

/*
|--------------------------------------------------------------------------
| Extract access token
|--------------------------------------------------------------------------
*/

const extractToken = (req) => {
  const authHeader = req.headers?.authorization;

  /*
  |--------------------------------------------------------------------------
  | Normal API request
  | Authorization: Bearer <access_token>
  |--------------------------------------------------------------------------
  */

  if (authHeader && typeof authHeader === 'string') {
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);

    if (bearerMatch?.[1]) {
      return bearerMatch[1].trim();
    }
  }

  /*
  |--------------------------------------------------------------------------
  | Some browser requests such as <img src=""> cannot send Authorization
  | header, so access token may be read from cookie.
  |--------------------------------------------------------------------------
  */

  return getCookieValue(req, 'access_token');
};

/*
|--------------------------------------------------------------------------
| Authentication middleware
|--------------------------------------------------------------------------
*/

module.exports = async (req, res, next) => {
  /*
  |--------------------------------------------------------------------------
  | Allow CORS preflight
  |--------------------------------------------------------------------------
  */

  if (req.method === 'OPTIONS') {
    return next();
  }

  const jwtSecret = process.env.JWT_SECRET;

  if (!jwtSecret) {
    console.error('JWT_SECRET_MISSING');

    return res.status(500).json({
      status: false,
      ok: false,
      message: 'Server configuration error',
    });
  }

  /*
  |--------------------------------------------------------------------------
  | Extract token
  |--------------------------------------------------------------------------
  */

  const token = extractToken(req);

  if (!token || typeof token !== 'string' || token.length > 4096) {
    return res.status(401).json({
      status: false,
      ok: false,
      message: 'Authorization token required',
    });
  }

  let decoded;

  /*
  |--------------------------------------------------------------------------
  | Step 1: Verify JWT signature and expiry
  |--------------------------------------------------------------------------
  */

  try {
    decoded = jwt.verify(token, jwtSecret, {
      algorithms: [JWT_ALGORITHM],
      clockTolerance: 5,
    });
  } catch (error) {
    if (process.env.NODE_ENV !== 'production') {
      console.error('JWT_VERIFY_FAILED:', error.message);
    }

    return res.status(401).json({
      status: false,
      ok: false,
      message: 'Invalid or expired token',
    });
  }

  /*
  |--------------------------------------------------------------------------
  | Step 2: Read server-side session ID from JWT
  |--------------------------------------------------------------------------
  */

  const sessionId = String(decoded?.sid || '').trim();

  const dieticianId = String(
    decoded?.dietician_id || decoded?.sub || ''
  ).trim();

  /*
  |--------------------------------------------------------------------------
  | Validate sid
  |
  | dietician_refresh_tokens.id is BIGINT UNSIGNED.
  | sid must therefore contain only positive numeric characters.
  |--------------------------------------------------------------------------
  */

  if (
    !sessionId ||
    !/^[1-9]\d{0,19}$/.test(sessionId) ||
    !dieticianId
  ) {
    return res.status(401).json({
      status: false,
      ok: false,
      message: 'Invalid session',
    });
  }

  /*
  |--------------------------------------------------------------------------
  | Step 3: Verify session in database
  |--------------------------------------------------------------------------
  |
  | Session is valid only when:
  |
  | 1. Session ID exists
  | 2. Session belongs to the same dietician
  | 3. Session has NOT been revoked
  | 4. Session has NOT expired
  |--------------------------------------------------------------------------
  */

  try {
    const [sessionRows] = await pool.execute(
      `SELECT id
         FROM dietician_refresh_tokens
        WHERE id = ?
          AND dietician_id = ?
          AND revoked_at IS NULL
          AND expires_at > NOW()
        LIMIT 1`,
      [
        sessionId,
        dieticianId,
      ]
    );

    /*
    |--------------------------------------------------------------------------
    | Session missing / revoked / expired
    |--------------------------------------------------------------------------
    */

    if (!Array.isArray(sessionRows) || sessionRows.length === 0) {
      return res.status(401).json({
        status: false,
        ok: false,
        message: 'Session expired or logged out',
      });
    }
  } catch (error) {
    console.error('SESSION_VALIDATION_DB_ERROR:', {
      message: error?.message || null,
      code: error?.code || null,
    });

    /*
    |--------------------------------------------------------------------------
    | Fail closed
    |--------------------------------------------------------------------------
    |
    | If session status cannot be verified, never allow the protected request.
    |--------------------------------------------------------------------------
    */

    return res.status(500).json({
      status: false,
      ok: false,
      message: 'Unable to validate session',
    });
  }

  /*
  |--------------------------------------------------------------------------
  | Step 4: View-only (super-admin "View as") sessions may not mutate
  |--------------------------------------------------------------------------
  |
  | Tokens minted by super-admin-view-as carry view_only: true. They read
  | everything the impersonated user reads, but any endpoint that writes is
  | refused. Matching is by path keyword — every mutating route in
  | apiRoutes.js contains one of these fragments, while the read routes
  | (get_*, list-*, *-status, weight-tracking, habits/tracking-data, …)
  | contain none. /auth/logout stays allowed so the view session can be
  | revoked. False positives only ever block a read inside a view-as
  | session, never a real user.
  |--------------------------------------------------------------------------
  */

  if (decoded.view_only === true) {
    const path = String(req.originalUrl || req.path || '').split('?')[0];

    const WRITE_PATTERN = new RegExp(
      [
        'update', 'delete', 'remove', 'revoke', 'resend', 'cancel',
        'approve', 'extend', 'assign', 'setup', 'generate', 'create',
        'store', 'reset', 'save', 'upload', 'redeem', 'simulate',
        'restore', 'change', 'password', 'mfa', 'checkout', 'custom-meal',
        'complete1', 'invite-trainer', 'invite-admin', 'invite-facility',
        'send_trainer_client_invite', 'send_diatitian_otp',
        'lock-request', 'lock-verify',
        'run-payouts', 'run-breath-credits',
        'set-pricing', 'set-commission-rate', 'set-trainer-commission-split',
        'habits/add', 'habits/track-batch', 'selected-habits/track',
        'selected-habits/save', 'level-type',
        // Stripe Connect links act on the target's Stripe account (onboarding
        // writes state; the dashboard link logs into their Express account).
        'stripe-connect-onboarding-link', 'stripe-connect-dashboard-link',
        'qr-link',
      ].join('|'),
      'i'
    );

    if (WRITE_PATTERN.test(path) && !path.endsWith('/auth/logout')) {
      return res.status(403).json({
        status: false,
        ok: false,
        view_only: true,
        message: 'This is a view-only session — changes are disabled',
      });
    }
  }

  /*
  |--------------------------------------------------------------------------
  | Step 5: Authentication successful
  |--------------------------------------------------------------------------
  */

  req.user = decoded;

  return next();
};











// const jwt = require("jsonwebtoken");

// const JWT_ALGORITHM = process.env.JWT_ALGORITHM || "HS256";

// const getCookieValue = (req, cookieName) => {
//   const cookieHeader = req.headers?.cookie;
//   if (!cookieHeader || typeof cookieHeader !== "string") return null;

//   const cookies = cookieHeader.split(";").map((item) => item.trim());

//   for (const cookie of cookies) {
//     const index = cookie.indexOf("=");
//     if (index === -1) continue;

//     const name = cookie.substring(0, index);
//     const value = cookie.substring(index + 1);

//     if (name === cookieName) {
//       try {
//         return decodeURIComponent(value);
//       } catch {
//         return value;
//       }
//     }
//   }

//   return null;
// };

// const extractToken = (req) => {
//   const authHeader = req.headers.authorization;

//   // Normal API calls: Authorization: Bearer <access_token>
//   if (authHeader && typeof authHeader === "string") {
//     const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
//     if (bearerMatch?.[1]) {
//       return bearerMatch[1].trim();
//     }
//   }

//   // Image request like <img src=""> cannot send Authorization header.
//   // So token is taken from cookie.
//   return getCookieValue(req, "access_token");
// };

// module.exports = (req, res, next) => {
//   if (req.method === "OPTIONS") {
//     return next();
//   }

//   try {
//     const jwtSecret = process.env.JWT_SECRET;

//     if (!jwtSecret) {
//       console.error("JWT_SECRET_MISSING");

//       return res.status(500).json({
//         status: false,
//         ok: false,
//         message: "Server configuration error",
//       });
//     }

//     const token = extractToken(req);

//     if (!token || typeof token !== "string" || token.length > 4096) {
//       return res.status(401).json({
//         status: false,
//         ok: false,
//         message: "Authorization token required",
//       });
//     }

//     const decoded = jwt.verify(token, jwtSecret, {
//       algorithms: [JWT_ALGORITHM],
//       clockTolerance: 5,
//     });

//     req.user = decoded;

//     return next();
//   } catch (error) {
//     return res.status(401).json({
//       status: false,
//       ok: false,
//       message: "Invalid or expired token",
//     });
//   }
// };