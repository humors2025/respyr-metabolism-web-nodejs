// controllers/dietitian/api/web/logoutController.js

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
const JWT_ALGORITHM = 'HS256';

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || JWT_SECRET;

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function hashRefreshToken(refreshToken) {
  return crypto
    .createHash('sha256')
    .update(refreshToken)
    .digest('hex');
}

function getClientIp(req) {
  return String(
    req.ip ||
    req.socket?.remoteAddress ||
    '0.0.0.0'
  ).substring(0, 45);
}

function getUserAgent(req) {
  const ua = req.headers?.['user-agent'] || '';

  return String(ua).substring(0, 255);
}

function authLogHash(value) {
  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {
    return null;
  }

  return crypto
    .createHmac(
      'sha256',
      SECURITY_PEPPER || 'fallback'
    )
    .update(
      String(value)
        .trim()
        .toLowerCase()
    )
    .digest('hex');
}

/*
|--------------------------------------------------------------------------
| Read cookie
|--------------------------------------------------------------------------
*/

function getCookieValue(req, cookieName) {
  const cookieHeader = req.headers?.cookie;

  if (
    !cookieHeader ||
    typeof cookieHeader !== 'string'
  ) {
    return null;
  }

  const cookies = cookieHeader
    .split(';')
    .map((item) => item.trim());

  for (const cookie of cookies) {
    const index = cookie.indexOf('=');

    if (index === -1) {
      continue;
    }

    const name =
      cookie.substring(0, index);

    const value =
      cookie.substring(index + 1);

    if (name === cookieName) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

/*
|--------------------------------------------------------------------------
| Extract access token
|--------------------------------------------------------------------------
*/

function extractAccessToken(req) {
  const authHeader =
    req.headers?.authorization;

  /*
  |--------------------------------------------------------------------------
  | Authorization: Bearer <access token>
  |--------------------------------------------------------------------------
  */

  if (
    authHeader &&
    typeof authHeader === 'string'
  ) {
    const bearerMatch =
      authHeader.match(
        /^Bearer\s+(.+)$/i
      );

    if (bearerMatch?.[1]) {
      return bearerMatch[1].trim();
    }
  }

  /*
  |--------------------------------------------------------------------------
  | Fallback to access_token cookie
  |--------------------------------------------------------------------------
  */

  return getCookieValue(
    req,
    'access_token'
  );
}

/*
|--------------------------------------------------------------------------
| Clear refresh cookie
|--------------------------------------------------------------------------
*/

function clearRefreshCookieIfEnabled(res) {
  if (
    process.env.USE_REFRESH_COOKIE !== 'true'
  ) {
    return;
  }

  res.clearCookie(
    'refresh_token',
    {
      httpOnly: true,
      secure: true,

      sameSite:
        process.env.REFRESH_COOKIE_SAMESITE ||
        'none',

      path:
        process.env.REFRESH_COOKIE_PATH ||
        '/v1/auth',
    }
  );
}

/*
|--------------------------------------------------------------------------
| Write authentication audit log
|--------------------------------------------------------------------------
*/

async function writeAuthLogSafe(
  conn,
  req,
  eventType,
  dieticianId,
  sessionId,
  success,
  failureReason
) {
  try {
    const safeEventType =
      String(eventType)
        .substring(0, 60);

    const safeFailureReason =
      failureReason !== null &&
      failureReason !== undefined
        ? String(failureReason)
            .substring(0, 255)
        : null;

    const sessionIdHash =
      sessionId
        ? authLogHash(sessionId)
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

        authLogHash(
          getClientIp(req)
        ),

        authLogHash(
          getUserAgent(req)
        ),

        sessionIdHash,

        success ? 1 : 0,

        safeFailureReason,
      ]
    );
  } catch (error) {
    console.error(
      'AUTH_LOG_WRITE_FAILED: ' +
      error.message
    );
  }
}

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
|
| Logout must invalidate the server-side session immediately.
|
| The session is identified using:
|
| 1. sid from the access JWT
| 2. refresh-token cookie
|
| dietician_refresh_tokens.id is our session ID.
|
| We DO NOT delete the row.
| We set:
|
| revoked_at = NOW()
|
| authMiddleware will then reject the old access JWT immediately.
|--------------------------------------------------------------------------
*/

exports.logout = async (req, res) => {
  /*
  |--------------------------------------------------------------------------
  | Method validation
  |--------------------------------------------------------------------------
  */

  if (req.method !== 'POST') {
    return res.status(405).json({
      ok: false,
      message: 'Method not allowed',
    });
  }

  /*
  |--------------------------------------------------------------------------
  | Get access token + refresh token
  |--------------------------------------------------------------------------
  */

  const accessToken =
    extractAccessToken(req);

  const refreshToken =
    getCookieValue(
      req,
      'refresh_token'
    );

  /*
  |--------------------------------------------------------------------------
  | Read sid from access token
  |--------------------------------------------------------------------------
  |
  | We intentionally do NOT return an error here if the JWT is expired.
  |
  | A user must still be able to logout using their refresh token even when
  | the access token has expired.
  |--------------------------------------------------------------------------
  */

  let accessSessionId = null;
  let accessDieticianId = null;

  if (
    accessToken &&
    JWT_SECRET
  ) {
    try {
      const decoded =
        jwt.verify(
          accessToken,
          JWT_SECRET,
          {
            algorithms: [
              JWT_ALGORITHM,
            ],

            clockTolerance: 5,
          }
        );

      const sid =
        String(
          decoded?.sid || ''
        ).trim();

      const dieticianId =
        String(
          decoded?.dietician_id ||
          decoded?.sub ||
          ''
        ).trim();

      /*
      |--------------------------------------------------------------------------
      | Validate sid format
      |--------------------------------------------------------------------------
      */

      if (
        /^[1-9]\d{0,19}$/.test(sid) &&
        dieticianId
      ) {
        accessSessionId = sid;
        accessDieticianId =
          dieticianId;
      }
    } catch (_) {
      /*
      |--------------------------------------------------------------------------
      | Ignore invalid/expired access JWT
      |--------------------------------------------------------------------------
      |
      | Refresh token can still identify the session.
      |--------------------------------------------------------------------------
      */
    }
  }

  /*
  |--------------------------------------------------------------------------
  | Hash refresh token if present
  |--------------------------------------------------------------------------
  */

  const refreshTokenHash =
    refreshToken
      ? hashRefreshToken(refreshToken)
      : null;

  /*
  |--------------------------------------------------------------------------
  | No credentials presented
  |--------------------------------------------------------------------------
  |
  | Logout remains idempotent.
  |--------------------------------------------------------------------------
  */

  if (
    !accessSessionId &&
    !refreshTokenHash
  ) {
    clearRefreshCookieIfEnabled(
      res
    );

    return res.status(200).json({
      ok: true,
      message:
        'Logged out successfully',
    });
  }

  let conn;

  try {
    conn =
      await pool.getConnection();

    await conn.beginTransaction();

    /*
    |--------------------------------------------------------------------------
    | Sessions to revoke
    |--------------------------------------------------------------------------
    |
    | Normally the access JWT sid and refresh-token row point to exactly
    | the same session.
    |
    | We collect both so logout still works safely if browser state becomes
    | inconsistent.
    |--------------------------------------------------------------------------
    */

    const sessionsToRevoke =
      new Map();

    /*
    |--------------------------------------------------------------------------
    | Step 1: Find session using access JWT sid
    |--------------------------------------------------------------------------
    */

    if (
      accessSessionId &&
      accessDieticianId
    ) {
      const [accessRows] =
        await conn.query(
          `SELECT
             id,
             dietician_id,
             revoked_at
           FROM dietician_refresh_tokens
           WHERE id = ?
             AND dietician_id = ?
           LIMIT 1
           FOR UPDATE`,
          [
            accessSessionId,
            accessDieticianId,
          ]
        );

      if (
        Array.isArray(accessRows) &&
        accessRows.length > 0
      ) {
        const row =
          accessRows[0];

        sessionsToRevoke.set(
          String(row.id),
          {
            id: String(row.id),
            dieticianId:
              String(
                row.dietician_id
              ),
          }
        );
      }
    }

    /*
    |--------------------------------------------------------------------------
    | Step 2: Find session using refresh token
    |--------------------------------------------------------------------------
    */

    if (refreshTokenHash) {
      const [refreshRows] =
        await conn.query(
          `SELECT
             id,
             dietician_id,
             revoked_at
           FROM dietician_refresh_tokens
           WHERE token_hash = ?
           LIMIT 1
           FOR UPDATE`,
          [
            refreshTokenHash,
          ]
        );

      if (
        Array.isArray(refreshRows) &&
        refreshRows.length > 0
      ) {
        const row =
          refreshRows[0];

        sessionsToRevoke.set(
          String(row.id),
          {
            id: String(row.id),
            dieticianId:
              String(
                row.dietician_id
              ),
          }
        );
      }
    }

    /*
    |--------------------------------------------------------------------------
    | Step 3: Revoke server-side session
    |--------------------------------------------------------------------------
    |
    | IMPORTANT:
    |
    | DO NOT DELETE the session row.
    |
    | Setting revoked_at preserves session history and allows authMiddleware
    | to immediately reject previously issued access JWTs.
    |--------------------------------------------------------------------------
    */

    for (
      const session
      of sessionsToRevoke.values()
    ) {
      await conn.execute(
        `UPDATE dietician_refresh_tokens
            SET revoked_at =
              COALESCE(
                revoked_at,
                NOW()
              )
          WHERE id = ?
            AND dietician_id = ?`,
        [
          session.id,
          session.dieticianId,
        ]
      );
    }

    /*
    |--------------------------------------------------------------------------
    | Audit information
    |--------------------------------------------------------------------------
    */

    let auditDieticianId =
      accessDieticianId;

    let auditSessionId =
      accessSessionId;

    /*
    |--------------------------------------------------------------------------
    | If access token was unavailable/expired, use refresh-token session
    |--------------------------------------------------------------------------
    */

    if (
      sessionsToRevoke.size > 0
    ) {
      const firstSession =
        sessionsToRevoke
          .values()
          .next()
          .value;

      if (!auditDieticianId) {
        auditDieticianId =
          firstSession.dieticianId;
      }

      if (!auditSessionId) {
        auditSessionId =
          firstSession.id;
      }
    }

    /*
    |--------------------------------------------------------------------------
    | Write logout audit log
    |--------------------------------------------------------------------------
    */

    await writeAuthLogSafe(
      conn,
      req,
      'logout',
      auditDieticianId,
      auditSessionId,
      1,
      null
    );

    /*
    |--------------------------------------------------------------------------
    | Commit
    |--------------------------------------------------------------------------
    */

    await conn.commit();

    /*
    |--------------------------------------------------------------------------
    | Delete HttpOnly refresh cookie from browser
    |--------------------------------------------------------------------------
    */

    clearRefreshCookieIfEnabled(
      res
    );

    /*
    |--------------------------------------------------------------------------
    | Idempotent response
    |--------------------------------------------------------------------------
    |
    | We intentionally return success even when the session was already
    | revoked or did not exist.
    |
    | This prevents session/token enumeration.
    |--------------------------------------------------------------------------
    */

    return res.status(200).json({
      ok: true,
      message:
        'Logged out successfully',
    });
  } catch (error) {
    /*
    |--------------------------------------------------------------------------
    | Rollback
    |--------------------------------------------------------------------------
    */

    if (conn) {
      try {
        await conn.rollback();
      } catch (_) {
        // noop
      }
    }

    console.error(
      'LOGOUT_ERROR:',
      {
        message:
          error?.message ||
          null,

        code:
          error?.code ||
          null,

        sqlState:
          error?.sqlState ||
          null,

        sqlMessage:
          process.env.NODE_ENV !==
          'production'
            ? error?.sqlMessage
            : undefined,
      }
    );

    return res.status(500).json({
      ok: false,
      message:
        'Internal server error',
    });
  } finally {
    /*
    |--------------------------------------------------------------------------
    | Release DB connection
    |--------------------------------------------------------------------------
    */

    if (conn) {
      try {
        conn.release();
      } catch (_) {
        // noop
      }
    }
  }
};












// // controllers/dietitian/api/web/logoutController.js

// 'use strict';

// const crypto = require('crypto');
// const pool = require('../../../../config/db');

// /*
// |--------------------------------------------------------------------------
// | Config
// |--------------------------------------------------------------------------
// */

// const JWT_SECRET = process.env.JWT_SECRET;
// const SECURITY_PEPPER = process.env.SECURITY_PEPPER || JWT_SECRET;

// const JWT_REFRESH_TTL_DAYS = parseInt(process.env.JWT_REFRESH_TTL_DAYS, 10) || 30;
// const JWT_REFRESH_TTL_SECONDS = JWT_REFRESH_TTL_DAYS * 24 * 60 * 60;

// /*
// |--------------------------------------------------------------------------
// | Helpers
// |--------------------------------------------------------------------------
// */

// function hashRefreshToken(refreshToken) {
//   return crypto.createHash('sha256').update(refreshToken).digest('hex');
// }

// function getClientIp(req) {
//   return String(req.ip || req.socket?.remoteAddress || '0.0.0.0').substring(0, 45);
// }

// function getUserAgent(req) {
//   const ua = req.headers?.['user-agent'] || '';
//   return String(ua).substring(0, 255);
// }

// function authLogHash(value) {
//   return crypto
//     .createHmac('sha256', SECURITY_PEPPER)
//     .update(String(value == null ? '' : value).trim().toLowerCase())
//     .digest('hex');
// }

// function getCookieValue(req, cookieName) {
//   const cookieHeader = req.headers?.cookie;

//   if (!cookieHeader || typeof cookieHeader !== 'string') return null;

//   const cookies = cookieHeader.split(';').map((item) => item.trim());

//   for (const cookie of cookies) {
//     const index = cookie.indexOf('=');
//     if (index === -1) continue;

//     const name = cookie.substring(0, index);
//     const value = cookie.substring(index + 1);

//     if (name === cookieName) {
//       return decodeURIComponent(value);
//     }
//   }

//   return null;
// }

// // function clearRefreshCookieIfEnabled(res) {
// //   if (process.env.USE_REFRESH_COOKIE !== 'true') return;

// //   res.clearCookie('refresh_token', {
// //     httpOnly: true,
// //     secure: true,
// //     sameSite: 'strict',
// //     path: process.env.REFRESH_COOKIE_PATH || '/v1/auth/refresh-token',
// //   });
// // }


// function clearRefreshCookieIfEnabled(res) {
//   if (process.env.USE_REFRESH_COOKIE !== 'true') return;

//   res.clearCookie('refresh_token', {
//     httpOnly: true,
//     secure: true,
//     sameSite: process.env.REFRESH_COOKIE_SAMESITE || 'none',
//     path: process.env.REFRESH_COOKIE_PATH || '/v1/auth',
//   });
// }


// async function writeAuthLogSafe(conn, req, eventType, dieticianId, success, failureReason) {
//   try {
//     const safeEventType = String(eventType).substring(0, 60);

//     const safeFailureReason =
//       failureReason !== null && failureReason !== undefined
//         ? String(failureReason).substring(0, 255)
//         : null;

//     await conn.execute(
//       `INSERT INTO app_auth_logs (
//          event_type,
//          user_id,
//          role,
//          partner_code,
//          identifier_hash,
//          ip_hash,
//          user_agent_hash,
//          session_id_hash,
//          success,
//          failure_reason
//        )
//        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
//       [
//         safeEventType,
//         dieticianId,
//         null,
//         null,
//         null,
//         authLogHash(getClientIp(req)),
//         authLogHash(getUserAgent(req)),
//         null,
//         success ? 1 : 0,
//         safeFailureReason,
//       ]
//     );
//   } catch (error) {
//     console.error('AUTH_LOG_WRITE_FAILED: ' + error.message);
//   }
// }

// /*
// |--------------------------------------------------------------------------
// | Controller
// |--------------------------------------------------------------------------
// | Logout is identified solely by the presented refresh token (same as the
// | refresh endpoint). We revoke by deleting the matching row from
// | dietician_refresh_tokens — the table login/refresh actually use.
// |
// | The response is intentionally idempotent: we return success whether or
// | not a row matched, so an attacker cannot probe which tokens exist.
// |--------------------------------------------------------------------------
// */

// exports.logout = async (req, res) => {
//   if (req.method !== 'POST') {
//     return res.status(405).json({
//       ok: false,
//       message: 'Method not allowed',
//     });
//   }

//   // if (typeof req.body === 'string') {
//   //   try {
//   //     req.body = JSON.parse(req.body);
//   //   } catch {
//   //     return res.status(400).json({
//   //       ok: false,
//   //       message: 'Invalid JSON body',
//   //     });
//   //   }
//   // }

//   // const inBody = req.body && typeof req.body === 'object' ? req.body : {};

//   // const refreshToken =
//   //   (typeof inBody.refresh_token === 'string' && inBody.refresh_token.trim()) ||
//   //   getCookieValue(req, 'refresh_token');

//   const refreshToken = getCookieValue(req, 'refresh_token');

//   if (!refreshToken) {
//     // return res.status(400).json({
//     //   ok: false,
//     //   message: 'refresh_token is required',
//     // });

//      clearRefreshCookieIfEnabled(res);

//   return res.status(200).json({
//     ok: true,
//     message: 'Logged out successfully',
//   });
//   }

//   const refreshTokenHash = hashRefreshToken(refreshToken);

//   let conn;

//   try {
//     conn = await pool.getConnection();

//     // Capture the owner (for the audit log) before we delete the row.
//     const [rows] = await conn.execute(
//       `SELECT dietician_id
//          FROM dietician_refresh_tokens
//         WHERE token_hash = ?
//         LIMIT 1`,
//       [refreshTokenHash]
//     );

//     const dieticianId =
//       rows && rows.length ? String(rows[0].dietician_id) : null;

//     // Revoke: one-time delete of the matching refresh token.
//     await conn.execute(
//       `DELETE FROM dietician_refresh_tokens
//         WHERE token_hash = ?`,
//       [refreshTokenHash]
//     );

//     await writeAuthLogSafe(conn, req, 'logout', dieticianId, 1, null);

//     clearRefreshCookieIfEnabled(res);

//     return res.status(200).json({
//       ok: true,
//       message: 'Logged out successfully',
//     });
//   } catch (error) {
//     console.error('LOGOUT_ERROR:', {
//       message: error?.message || null,
//       code: error?.code || null,
//       sqlState: error?.sqlState || null,
//       sqlMessage:
//         process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
//     });

//     return res.status(500).json({
//       ok: false,
//       message: 'Internal server error',
//     });
//   } finally {
//     if (conn) {
//       try {
//         conn.release();
//       } catch (_) {
//         // noop
//       }
//     }
//   }
// };
