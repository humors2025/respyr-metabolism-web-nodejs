// controllers/dietitian/api/web/loginController.js

'use strict';

const crypto = require('crypto');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../../../../config/db');

const {
  validateEmailAddress,
  validatePhoneNumber,
} = require('../../../../utils/securityValidation');

/*
|--------------------------------------------------------------------------
| Config
|--------------------------------------------------------------------------
*/

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISS =
  process.env.JWT_ISS ||
  process.env.JWT_ISSUER ||
  'api.respyr.ai';

const JWT_AUD =
  process.env.JWT_AUD ||
  process.env.JWT_AUDIENCE ||
  'respyr-dietitian-app';

const JWT_TTL =
  parseInt(
    process.env.JWT_TTL,
    10
  ) || 900;

const JWT_REFRESH_TTL_DAYS =
  parseInt(
    process.env.JWT_REFRESH_TTL_DAYS,
    10
  ) || 30;

const JWT_REFRESH_TTL_SECONDS =
  JWT_REFRESH_TTL_DAYS *
  24 *
  60 *
  60;

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER ||
  JWT_SECRET;

const MAX_IDENTIFIER_LEN = 254;
const MAX_PASSWORD_LEN = 256;
const FAIL_DELAY_MS = 400;

if (
  !JWT_SECRET ||
  JWT_SECRET.length < 32
) {
  console.error(
    'FATAL_CONFIG: JWT_SECRET is missing or too short. Need >= 32 chars.'
  );
}

/*
|--------------------------------------------------------------------------
| Login Identifier Validation
|--------------------------------------------------------------------------
|
| Login supports:
|
| - Email
| - Phone
|
| Email-like values containing @ must pass strict email validation.
|
| Everything else must pass strict phone validation.
|
| This prevents malicious values such as:
|
| <script>alert(1)</script>
| <script>@example.com
| {{7*7}}
| +91<script>9876543210
|
| from reaching database lookup.
|--------------------------------------------------------------------------
*/

function classifyIdentifier(
  value
) {
  if (
    typeof value !==
    'string'
  ) {
    return {
      ok: false,
      type: null,
      value: '',
      message:
        'Invalid login identifier',
    };
  }

  const identifier =
    value.trim();

  /*
  |--------------------------------------------------------------------------
  | Required / length
  |--------------------------------------------------------------------------
  */

  if (
    identifier === '' ||
    identifier.length >
      MAX_IDENTIFIER_LEN
  ) {
    return {
      ok: false,
      type: null,
      value: '',
      message:
        'Invalid login identifier',
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Email Login
  |--------------------------------------------------------------------------
  |
  | If @ is present, the value MUST be a valid email.
  |
  | We do not allow malformed email-like input to fall through into phone
  | handling.
  |--------------------------------------------------------------------------
  */

  if (
    identifier.includes(
      '@'
    )
  ) {
    const result =
      validateEmailAddress(
        identifier,
        'identifier'
      );

    if (
      !result.ok
    ) {
      return {
        ok: false,
        type: null,
        value: '',
        message:
          'Invalid login identifier',
      };
    }

    return {
      ok: true,
      type: 'email',
      value:
        result.value,
      message: null,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Phone Login
  |--------------------------------------------------------------------------
  |
  | Unexpected characters are rejected BEFORE normalization.
  |
  | Example:
  |
  | +91<script>alert(1)</script>9876543210
  |
  | must be rejected, not converted to:
  |
  | +919876543210
  |--------------------------------------------------------------------------
  */

  const result =
    validatePhoneNumber(
      identifier,
      'identifier',
      {
        required: true,
      }
    );

  if (
    !result.ok
  ) {
    return {
      ok: false,
      type: null,
      value: '',
      message:
        'Invalid login identifier',
    };
  }

  return {
    ok: true,
    type: 'phone',
    value:
      result.value,
    message: null,
  };
}

/*
|--------------------------------------------------------------------------
| Sleep
|--------------------------------------------------------------------------
*/

function sleep(
  ms
) {
  return new Promise(
    (resolve) =>
      setTimeout(
        resolve,
        ms
      )
  );
}

/*
|--------------------------------------------------------------------------
| Password algorithm
|--------------------------------------------------------------------------
*/

function bestPasswordAlgo() {
  return {
    rounds:
      parseInt(
        process.env.BCRYPT_ROUNDS,
        10
      ) || 12,
  };
}

/*
|--------------------------------------------------------------------------
| JWT
|--------------------------------------------------------------------------
*/

function makeJwt(
  payload
) {
  return jwt.sign(
    payload,
    JWT_SECRET,
    {
      algorithm:
        'HS256',
    }
  );
}

/*
|--------------------------------------------------------------------------
| Refresh Token
|--------------------------------------------------------------------------
*/

function createRefreshToken() {
  return crypto
    .randomBytes(64)
    .toString(
      'hex'
    );
}

function hashRefreshToken(
  refreshToken
) {
  return crypto
    .createHash(
      'sha256'
    )
    .update(
      refreshToken
    )
    .digest(
      'hex'
    );
}

function getRefreshExpiresAt() {
  const expiresAt =
    new Date();

  expiresAt.setDate(
    expiresAt.getDate() +
      JWT_REFRESH_TTL_DAYS
  );

  return expiresAt;
}

/*
|--------------------------------------------------------------------------
| Request Metadata
|--------------------------------------------------------------------------
*/

function getClientIp(
  req
) {
  return String(
    req.ip ||
      req.socket
        ?.remoteAddress ||
      '0.0.0.0'
  ).substring(
    0,
    45
  );
}

function getUserAgent(
  req
) {
  const ua =
    req.headers?.[
      'user-agent'
    ] || '';

  return String(
    ua
  ).substring(
    0,
    255
  );
}

/*
|--------------------------------------------------------------------------
| Audit Hash
|--------------------------------------------------------------------------
*/

function authLogHash(
  value
) {
  return crypto
    .createHmac(
      'sha256',
      SECURITY_PEPPER
    )
    .update(
      String(
        value == null
          ? ''
          : value
      )
        .trim()
        .toLowerCase()
    )
    .digest(
      'hex'
    );
}

/*
|--------------------------------------------------------------------------
| Generic 500
|--------------------------------------------------------------------------
*/

function send500(
  res
) {
  return res
    .status(500)
    .json({
      ok: false,
      error:
        'Internal server error',
    });
}

/*
|--------------------------------------------------------------------------
| Refresh Cookie
|--------------------------------------------------------------------------
*/

function setRefreshCookieIfEnabled(
  res,
  refreshToken
) {
  if (
    process.env
      .USE_REFRESH_COOKIE !==
    'true'
  ) {
    return;
  }

  res.cookie(
    'refresh_token',
    refreshToken,
    {
      httpOnly: true,

      secure: true,

      sameSite:
        process.env
          .REFRESH_COOKIE_SAMESITE ||
        'none',

      maxAge:
        JWT_REFRESH_TTL_SECONDS *
        1000,

      path:
        process.env
          .REFRESH_COOKIE_PATH ||
        '/v1/auth',
    }
  );
}

/*
|--------------------------------------------------------------------------
| Audit Logging
|--------------------------------------------------------------------------
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
    const ipHash =
      authLogHash(
        getClientIp(
          req
        )
      );

    const userAgentHash =
      authLogHash(
        getUserAgent(
          req
        )
      );

    const identifierHash =
      identifier !==
        null &&
      identifier !==
        undefined
        ? authLogHash(
            identifier
          )
        : null;

    const safeEventType =
      String(
        eventType
      ).substring(
        0,
        60
      );

    const safeFailureReason =
      failureReason !==
        null &&
      failureReason !==
        undefined
        ? String(
            failureReason
          ).substring(
            0,
            255
          )
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

        userId,

        role,

        partnerCode,

        identifierHash,

        ipHash,

        userAgentHash,

        null,

        success
          ? 1
          : 0,

        safeFailureReason,
      ]
    );
  } catch (
    error
  ) {
    console.error(
      'AUTH_LOG_WRITE_FAILED: ' +
        error.message
    );
  }
}

/*
|--------------------------------------------------------------------------
| Dashboard Route
|--------------------------------------------------------------------------
*/

function buildDashboardRoute(
  role
) {
  if (
    role ===
    'super_admin'
  ) {
    return '/super-admin/overview';
  }

  if (
    role ===
    'admin'
  ) {
    return '/trainer-admin/overview';
  }

  if (
    role ===
    'trainer'
  ) {
    return '/trainer/clients';
  }

  return '/login';
}

/*
|--------------------------------------------------------------------------
| Logo URL
|--------------------------------------------------------------------------
*/

const LOGO_BASE_URL =
  (
    process.env
      .PUBLIC_API_BASE_URL ||
    'https://api.respyr.ai'
  ).replace(
    /\/+$/,
    ''
  );

function buildLogoUrl(
  dieticianId
) {
  return (
    LOGO_BASE_URL +
    '/v1/dietitian/api/web/get_dietician_logo?dietician_id=' +
    encodeURIComponent(
      dieticianId
    )
  );
}

/*
|--------------------------------------------------------------------------
| Login Controller
|--------------------------------------------------------------------------
*/

exports.login =
  async (
    req,
    res
  ) => {
    /*
    |--------------------------------------------------------------------------
    | Prevent caching
    |--------------------------------------------------------------------------
    */

    res.setHeader(
      'Cache-Control',
      'no-store'
    );

    res.setHeader(
      'Pragma',
      'no-cache'
    );

    /*
    |--------------------------------------------------------------------------
    | POST only
    |--------------------------------------------------------------------------
    */

    if (
      req.method !==
      'POST'
    ) {
      return res
        .status(405)
        .json({
          ok: false,

          error:
            'Method not allowed',
        });
    }

    /*
    |--------------------------------------------------------------------------
    | JWT config
    |--------------------------------------------------------------------------
    */

    if (
      !JWT_SECRET ||
      JWT_SECRET.length <
        32
    ) {
      return send500(
        res
      );
    }

    /*
    |--------------------------------------------------------------------------
    | Parse JSON body if needed
    |--------------------------------------------------------------------------
    */

    if (
      typeof req.body ===
      'string'
    ) {
      try {
        req.body =
          JSON.parse(
            req.body
          );
      } catch {
        return res
          .status(400)
          .json({
            ok: false,

            error:
              'Invalid JSON body',
          });
      }
    }

    /*
    |--------------------------------------------------------------------------
    | Body must be an object
    |--------------------------------------------------------------------------
    */

    const inBody =
      req.body &&
      typeof req.body ===
        'object' &&
      !Array.isArray(
        req.body
      )
        ? req.body
        : {};

    const rawIdentifier =
      inBody.identifier;

    const rawPassword =
      inBody.password;

    /*
    |--------------------------------------------------------------------------
    | Type validation
    |--------------------------------------------------------------------------
    */

    if (
      typeof rawIdentifier !==
        'string' ||
      typeof rawPassword !==
        'string'
    ) {
      return res
        .status(422)
        .json({
          ok: false,

          error:
            'identifier and password are required',
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Password validation
    |--------------------------------------------------------------------------
    |
    | Password is treated as an opaque secret.
    |
    | Do NOT strip HTML/special characters from passwords.
    |
    | Only type, presence and maximum length are checked here.
    |--------------------------------------------------------------------------
    */

    const password =
      rawPassword;

    if (
      password === '' ||
      password.length >
        MAX_PASSWORD_LEN
    ) {
      return res
        .status(422)
        .json({
          ok: false,

          error:
            'identifier and password are required',
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Identifier validation
    |--------------------------------------------------------------------------
    */

    const identifierResult =
      classifyIdentifier(
        rawIdentifier
      );

    if (
      !identifierResult.ok
    ) {
      return res
        .status(422)
        .json({
          ok: false,

          error:
            'Invalid login identifier',
        });
    }

    const identifier =
      identifierResult.value;

    const identifierType =
      identifierResult.type;

    let conn;

    try {
      /*
      |--------------------------------------------------------------------------
      | Database connection
      |--------------------------------------------------------------------------
      */

      conn =
        await pool
          .getConnection();

      let rows;

      /*
      |--------------------------------------------------------------------------
      | User Lookup
      |--------------------------------------------------------------------------
      |
      | All SQL is parameterized.
      |--------------------------------------------------------------------------
      */

      try {
        /*
        |--------------------------------------------------------------------------
        | Email Login
        |--------------------------------------------------------------------------
        */

        if (
          identifierType ===
          'email'
        ) {
          const [
            result,
          ] =
            await conn.execute(
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
                 ON LOWER(aur.user_id) =
                    LOWER(td.email)

               WHERE LOWER(td.email) =
                     LOWER(?)

               LIMIT 1`,
              [
                identifier,
              ]
            );

          rows =
            result;
        } else {
          /*
          |--------------------------------------------------------------------------
          | Phone Login
          |--------------------------------------------------------------------------
          */

          const [
            result,
          ] =
            await conn.execute(
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
                 ON LOWER(aur.user_id) =
                    LOWER(td.email)

               WHERE td.phone_no = ?

               LIMIT 1`,
              [
                identifier,
              ]
            );

          rows =
            result;
        }
      } catch (
        error
      ) {
        console.error(
          'ROLE_LOGIN_LOOKUP_ERROR: ' +
            error.message
        );

        return send500(
          res
        );
      }

      /*
      |--------------------------------------------------------------------------
      | User not found
      |--------------------------------------------------------------------------
      */

      const user =
        rows &&
        rows.length
          ? rows[0]
          : null;

      if (
        !user
      ) {
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

        await sleep(
          FAIL_DELAY_MS
        );

        return res
          .status(401)
          .json({
            ok: false,

            error:
              'Invalid credentials',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Role
      |--------------------------------------------------------------------------
      */

      const role =
        String(
          user.role
        );

      /*
      |--------------------------------------------------------------------------
      | Account Status
      |--------------------------------------------------------------------------
      */

      if (
        String(
          user.status
        ) !==
        'active'
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

          'Account is not active'
        );

        return res
          .status(403)
          .json({
            ok: false,

            error:
              'Account is not active',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Role Validation
      |--------------------------------------------------------------------------
      */

      if (
        role !==
          'super_admin' &&
        role !==
          'admin' &&
        role !==
          'trainer'
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

          'Invalid role configuration'
        );

        return res
          .status(403)
          .json({
            ok: false,

            error:
              'Invalid role configuration',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Partner Code
      |--------------------------------------------------------------------------
      */

      if (
        (
          role ===
            'admin' ||
          role ===
            'trainer'
        ) &&
        String(
          user.partner_code ==
            null
            ? ''
            : user.partner_code
        ).trim() ===
          ''
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

        return res
          .status(403)
          .json({
            ok: false,

            error:
              'Partner code missing for this account',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Parent User
      |--------------------------------------------------------------------------
      */

      if (
        (
          role ===
            'admin' ||
          role ===
            'trainer'
        ) &&
        String(
          user.parent_user_id ==
            null
            ? ''
            : user.parent_user_id
        ).trim() ===
          ''
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

        return res
          .status(403)
          .json({
            ok: false,

            error:
              'Parent user missing for this account',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Email Verification
      |--------------------------------------------------------------------------
      */

      if (
        (
          role ===
            'admin' ||
          role ===
            'trainer'
        ) &&
        !user
          .email_verified_at
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

          'Email is not verified'
        );

        return res
          .status(403)
          .json({
            ok: false,

            error:
              'Email is not verified',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Password Verification
      |--------------------------------------------------------------------------
      |
      | Convert PHP $2y$ bcrypt prefix to Node-compatible $2b$.
      |--------------------------------------------------------------------------
      */

      const hash =
        String(
          user.password ||
            ''
        ).replace(
          /^\$2y\$/,
          '$2b$'
        );

      let passwordOk =
        false;

      try {
        passwordOk =
          hash !== '' &&
          await bcrypt.compare(
            password,
            hash
          );
      } catch (
        error
      ) {
        console.error(
          'BCRYPT_COMPARE_ERROR: ' +
            error.message
        );

        passwordOk =
          false;
      }

      /*
      |--------------------------------------------------------------------------
      | Invalid Password
      |--------------------------------------------------------------------------
      */

      if (
        !passwordOk
      ) {
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

        await sleep(
          FAIL_DELAY_MS
        );

        return res
          .status(401)
          .json({
            ok: false,

            error:
              'Invalid credentials',
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Upgrade bcrypt rounds if needed
      |--------------------------------------------------------------------------
      */

      try {
        const {
          rounds,
        } =
          bestPasswordAlgo();

        const currentRounds =
          bcrypt.getRounds(
            hash
          );

        if (
          currentRounds <
          rounds
        ) {
          const newHash =
            await bcrypt.hash(
              password,
              rounds
            );

          await conn.execute(
            `UPDATE table_dietician
             SET password = ?
             WHERE id = ?`,
            [
              newHash,
              user.id,
            ]
          );
        }
      } catch (
        error
      ) {
        console.error(
          'REHASH_ERROR: ' +
            error.message
        );
      }

      /*
      |--------------------------------------------------------------------------
      | Role Metadata
      |--------------------------------------------------------------------------
      */

      const partnerCode =
        user.partner_code !==
          null &&
        user.partner_code !==
          undefined
          ? String(
              user.partner_code
            )
          : null;

      const parentUserId =
        user.parent_user_id !==
          null &&
        user.parent_user_id !==
          undefined
          ? String(
              user.parent_user_id
            ).toLowerCase()
          : null;

      const dashboardRoute =
        buildDashboardRoute(
          role
        );

      const logoUrl =
        buildLogoUrl(
          user.dietician_id
        );

      /*
      |--------------------------------------------------------------------------
      | Dietician JWT payload
      |--------------------------------------------------------------------------
      */

      const dieticianPayload =
        {
          dietician_id:
            String(
              user.dietician_id
            ),

          user_id:
            String(
              user.email
            ).toLowerCase(),

          name:
            user.name,

          email:
            String(
              user.email
            ).toLowerCase(),

          phone_no:
            user.phone_no,

          location:
            user.location,

          logo:
            logoUrl,

          is_reset_password:
            parseInt(
              user.is_reset_password,
              10
            ) || 0,

          role,

          partner_code:
            partnerCode,

          parent_user_id:
            parentUserId,
        };

      const now =
        Math.floor(
          Date.now() /
          1000
        );

      /*
      |--------------------------------------------------------------------------
      | Create Refresh Token / Server-side Session
      |--------------------------------------------------------------------------
      |
      | Refresh token is opaque/random.
      |
      | Database stores only SHA-256 hash.
      |
      | dietician_refresh_tokens.id becomes the session ID (`sid`) used by
      | the access token.
      |--------------------------------------------------------------------------
      */

      const refreshToken =
        createRefreshToken();

      const refreshTokenHash =
        hashRefreshToken(
          refreshToken
        );

      const refreshExpiresAt =
        getRefreshExpiresAt();

      const [
        refreshInsertResult,
      ] =
        await conn.execute(
          `INSERT INTO dietician_refresh_tokens (
             dietician_id,
             token_hash,
             expires_at,
             ip_address,
             user_agent
           )

           VALUES (?, ?, ?, ?, ?)`,
          [
            String(
              user.dietician_id
            ),

            refreshTokenHash,

            refreshExpiresAt,

            getClientIp(
              req
            ),

            getUserAgent(
              req
            ),
          ]
        );

      /*
      |--------------------------------------------------------------------------
      | Validate Session ID
      |--------------------------------------------------------------------------
      */

      const sessionId =
        String(
          refreshInsertResult
            .insertId
        );

      if (
        !refreshInsertResult
          .insertId ||
        !Number.isSafeInteger(
          Number(
            refreshInsertResult
              .insertId
          )
        ) ||
        Number(
          refreshInsertResult
            .insertId
        ) <= 0
      ) {
        console.error(
          'SESSION_CREATION_FAILED: Invalid refresh token row id'
        );

        return send500(
          res
        );
      }

      /*
      |--------------------------------------------------------------------------
      | Access JWT
      |--------------------------------------------------------------------------
      */

      const accessPayload =
        {
          iss:
            JWT_ISS,

          aud:
            JWT_AUD,

          iat:
            now,

          nbf:
            now,

          exp:
            now +
            JWT_TTL,

          sub:
            String(
              user.dietician_id
            ),

          /*
          |--------------------------------------------------------------------------
          | Server-side Session ID
          |--------------------------------------------------------------------------
          */

          sid:
            sessionId,

          dietician_id:
            String(
              user.dietician_id
            ),

          user_id:
            String(
              user.email
            ).toLowerCase(),

          role,

          partner_code:
            partnerCode,

          parent_user_id:
            parentUserId,

          dashboard_route:
            dashboardRoute,

          dietician:
            dieticianPayload,
        };

      const accessToken =
        makeJwt(
          accessPayload
        );

      /*
      |--------------------------------------------------------------------------
      | Audit Success
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
      | Refresh Cookie
      |--------------------------------------------------------------------------
      */

      setRefreshCookieIfEnabled(
        res,
        refreshToken
      );

      /*
      |--------------------------------------------------------------------------
      | Response
      |--------------------------------------------------------------------------
      */

      return res
        .status(200)
        .json({
          ok:
            true,

          token_type:
            'Bearer',

          access_token:
            accessToken,

          expires_in:
            JWT_TTL,

          refresh_expires_in:
            JWT_REFRESH_TTL_SECONDS,
        });
    } catch (
      error
    ) {
      console.error(
        'LOGIN_ERROR:',
        {
          message:
            error
              ?.message ||
            null,

          code:
            error
              ?.code ||
            null,

          sqlState:
            error
              ?.sqlState ||
            null,

          sqlMessage:
            process.env
              .NODE_ENV !==
            'production'
              ? error
                  ?.sqlMessage
              : undefined,
        }
      );

      return send500(
        res
      );
    } finally {
      if (
        conn
      ) {
        try {
          conn.release();
        } catch (_) {
          // noop
        }
      }
    }
  };















// // controllers/dietitian/api/web/loginController.js

// 'use strict';

// const crypto = require('crypto');
// // const bcrypt = require('bcryptjs');
// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
// const pool = require('../../../../config/db');

// /*
// |--------------------------------------------------------------------------
// | Config
// |--------------------------------------------------------------------------
// */

// const JWT_SECRET = process.env.JWT_SECRET;
// const JWT_ISS = process.env.JWT_ISS || process.env.JWT_ISSUER || 'api.respyr.ai';
// const JWT_AUD = process.env.JWT_AUD || process.env.JWT_AUDIENCE || 'respyr-dietitian-app';
// const JWT_TTL = parseInt(process.env.JWT_TTL, 10) || 900; // 15 minutes

// const JWT_REFRESH_TTL_DAYS =
//   parseInt(process.env.JWT_REFRESH_TTL_DAYS, 10) || 30;

// const JWT_REFRESH_TTL_SECONDS = JWT_REFRESH_TTL_DAYS * 24 * 60 * 60;

// const SECURITY_PEPPER = process.env.SECURITY_PEPPER || JWT_SECRET;

// const MAX_IDENTIFIER_LEN = 254;
// const MAX_PASSWORD_LEN = 256;
// const FAIL_DELAY_MS = 400;

// if (!JWT_SECRET || JWT_SECRET.length < 32) {
//   console.error('FATAL_CONFIG: JWT_SECRET is missing or too short. Need >= 32 chars.');
// }

// /*
// |--------------------------------------------------------------------------
// | Helpers
// |--------------------------------------------------------------------------
// */

// function isValidEmail(value) {
//   return typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
// }

// function sleep(ms) {
//   return new Promise((resolve) => setTimeout(resolve, ms));
// }

// function bestPasswordAlgo() {
//   return {
//     rounds: parseInt(process.env.BCRYPT_ROUNDS, 10) || 12,
//   };
// }

// function makeJwt(payload) {
//   return jwt.sign(payload, JWT_SECRET, {
//     algorithm: 'HS256',
//   });
// }

// function createRefreshToken() {
//   return crypto.randomBytes(64).toString('hex');
// }

// function hashRefreshToken(refreshToken) {
//   return crypto.createHash('sha256').update(refreshToken).digest('hex');
// }

// function getRefreshExpiresAt() {
//   const expiresAt = new Date();
//   expiresAt.setDate(expiresAt.getDate() + JWT_REFRESH_TTL_DAYS);
//   return expiresAt;
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

// function send500(res) {
//   return res.status(500).json({
//     ok: false,
//     error: 'Internal server error',
//   });
// }

// // function setRefreshCookieIfEnabled(res, refreshToken) {
// //   if (process.env.USE_REFRESH_COOKIE !== 'true') return;

// //   res.cookie('refresh_token', refreshToken, {
// //     httpOnly: true,
// //     secure: true,
// //     sameSite: 'strict',
// //     maxAge: JWT_REFRESH_TTL_SECONDS * 1000,
// //     path: process.env.REFRESH_COOKIE_PATH || '/v1/auth/refresh-token',
// //   });
// // }


// function setRefreshCookieIfEnabled(res, refreshToken) {
//   if (process.env.USE_REFRESH_COOKIE !== "true") return;

//   res.cookie("refresh_token", refreshToken, {
//     httpOnly: true,
//     secure: true,
//     sameSite:
//       process.env.REFRESH_COOKIE_SAMESITE || "none",
//     maxAge: JWT_REFRESH_TTL_SECONDS * 1000,
//     path: process.env.REFRESH_COOKIE_PATH || "/v1/auth",
//   });
// }



// async function writeAuthLogSafe(
//   conn,
//   req,
//   eventType,
//   userId,
//   role,
//   partnerCode,
//   identifier,
//   success,
//   failureReason
// ) {
//   try {
//     const ipHash = authLogHash(getClientIp(req));
//     const userAgentHash = authLogHash(getUserAgent(req));

//     const identifierHash =
//       identifier !== null && identifier !== undefined
//         ? authLogHash(identifier)
//         : null;

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
//         userId,
//         role,
//         partnerCode,
//         identifierHash,
//         ipHash,
//         userAgentHash,
//         null,
//         success ? 1 : 0,
//         safeFailureReason,
//       ]
//     );
//   } catch (error) {
//     console.error('AUTH_LOG_WRITE_FAILED: ' + error.message);
//   }
// }

// function buildDashboardRoute(role) {
//   if (role === 'super_admin') return '/super-admin/overview';
//   if (role === 'admin') return '/trainer-admin/overview';
//   if (role === 'trainer') return '/trainer/clients';
//   return '/login';
// }

// // Points at the Node logo endpoint (src/controllers/.../get_dietician_logo.js),
// // mounted at /dietitian/api/web/get_dietician_logo and exposed publicly under
// // the /v1 prefix. Base host is configurable; defaults to the API host.
// const LOGO_BASE_URL = (
//   process.env.PUBLIC_API_BASE_URL || 'https://api.respyr.ai'
// ).replace(/\/+$/, '');

// function buildLogoUrl(dieticianId) {
//   return (
//     LOGO_BASE_URL +
//     '/v1/dietitian/api/web/get_dietician_logo?dietician_id=' +
//     encodeURIComponent(dieticianId)
//   );
// }

// /*
// |--------------------------------------------------------------------------
// | Controller
// |--------------------------------------------------------------------------
// */

// exports.login = async (req, res) => {
//   if (req.method !== 'POST') {
//     return res.status(405).json({
//       ok: false,
//       error: 'Method not allowed',
//     });
//   }

//   if (!JWT_SECRET || JWT_SECRET.length < 32) {
//     return send500(res);
//   }

//   if (typeof req.body === 'string') {
//     try {
//       req.body = JSON.parse(req.body);
//     } catch {
//       return res.status(400).json({
//         ok: false,
//         error: 'Invalid JSON body',
//       });
//     }
//   }

//   const inBody = req.body && typeof req.body === 'object' ? req.body : {};

//   const rawIdentifier = inBody.identifier;
//   const rawPassword = inBody.password;

//   if (typeof rawIdentifier !== 'string' || typeof rawPassword !== 'string') {
//     return res.status(422).json({
//       ok: false,
//       error: 'identifier and password are required',
//     });
//   }

//   const identifier = rawIdentifier.trim();
//   const password = rawPassword;

//   if (
//     identifier === '' ||
//     password === '' ||
//     identifier.length > MAX_IDENTIFIER_LEN ||
//     password.length > MAX_PASSWORD_LEN
//   ) {
//     return res.status(422).json({
//       ok: false,
//       error: 'identifier and password are required',
//     });
//   }

//   let conn;

//   try {
//     conn = await pool.getConnection();

//     let rows;

//     try {
//       if (isValidEmail(identifier)) {
//         const [result] = await conn.execute(
//           `SELECT
//              td.id,
//              td.dietician_id,
//              td.is_reset_password,
//              td.name,
//              td.phone_no,
//              td.email,
//              td.location,
//              td.password,

//              aur.role,
//              aur.partner_code,
//              aur.parent_user_id,
//              aur.status,
//              aur.email_verified_at
//            FROM table_dietician td
//            INNER JOIN app_user_roles aur
//              ON LOWER(aur.user_id) = LOWER(td.email)
//            WHERE LOWER(td.email) = LOWER(?)
//            LIMIT 1`,
//           [identifier]
//         );

//         rows = result;
//       } else {
//         const [result] = await conn.execute(
//           `SELECT
//              td.id,
//              td.dietician_id,
//              td.is_reset_password,
//              td.name,
//              td.phone_no,
//              td.email,
//              td.location,
//              td.password,

//              aur.role,
//              aur.partner_code,
//              aur.parent_user_id,
//              aur.status,
//              aur.email_verified_at
//            FROM table_dietician td
//            INNER JOIN app_user_roles aur
//              ON LOWER(aur.user_id) = LOWER(td.email)
//            WHERE td.phone_no = ?
//            LIMIT 1`,
//           [identifier]
//         );

//         rows = result;
//       }
//     } catch (error) {
//       console.error('ROLE_LOGIN_LOOKUP_ERROR: ' + error.message);
//       return send500(res);
//     }

//     const user = rows && rows.length ? rows[0] : null;

//     if (!user) {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_failed',
//         null,
//         null,
//         null,
//         identifier,
//         0,
//         'Invalid credentials'
//       );

//       await sleep(FAIL_DELAY_MS);

//       return res.status(401).json({
//         ok: false,
//         error: 'Invalid credentials',
//       });
//     }

//     const role = String(user.role);

//     if (String(user.status) !== 'active') {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_blocked',
//         user.email,
//         role,
//         user.partner_code,
//         identifier,
//         0,
//         'Account is not active'
//       );

//       return res.status(403).json({
//         ok: false,
//         error: 'Account is not active',
//       });
//     }

//     if (role !== 'super_admin' && role !== 'admin' && role !== 'trainer') {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_blocked',
//         user.email,
//         role,
//         user.partner_code,
//         identifier,
//         0,
//         'Invalid role configuration'
//       );

//       return res.status(403).json({
//         ok: false,
//         error: 'Invalid role configuration',
//       });
//     }

//     if (
//       (role === 'admin' || role === 'trainer') &&
//       String(user.partner_code == null ? '' : user.partner_code).trim() === ''
//     ) {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_blocked',
//         user.email,
//         role,
//         user.partner_code,
//         identifier,
//         0,
//         'Partner code missing'
//       );

//       return res.status(403).json({
//         ok: false,
//         error: 'Partner code missing for this account',
//       });
//     }

//     if (
//       (role === 'admin' || role === 'trainer') &&
//       String(user.parent_user_id == null ? '' : user.parent_user_id).trim() === ''
//     ) {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_blocked',
//         user.email,
//         role,
//         user.partner_code,
//         identifier,
//         0,
//         'Parent user missing'
//       );

//       return res.status(403).json({
//         ok: false,
//         error: 'Parent user missing for this account',
//       });
//     }

//     if ((role === 'admin' || role === 'trainer') && !user.email_verified_at) {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_blocked',
//         user.email,
//         role,
//         user.partner_code,
//         identifier,
//         0,
//         'Email is not verified'
//       );

//       return res.status(403).json({
//         ok: false,
//         error: 'Email is not verified',
//       });
//     }

//     // const hash = String(user.password || '');
//      const hash = String(user.password || '').replace(/^\$2y\$/, '$2b$');

//     let passwordOk = false;

//     try {
//       passwordOk = hash !== '' && (await bcrypt.compare(password, hash));
//     } catch (error) {
//       console.error('BCRYPT_COMPARE_ERROR: ' + error.message);
//       passwordOk = false;
//     }

//     if (!passwordOk) {
//       await writeAuthLogSafe(
//         conn,
//         req,
//         'login_failed',
//         user.email,
//         role,
//         user.partner_code,
//         identifier,
//         0,
//         'Invalid credentials'
//       );

//       await sleep(FAIL_DELAY_MS);

//       return res.status(401).json({
//         ok: false,
//         error: 'Invalid credentials',
//       });
//     }

//     try {
//       const { rounds } = bestPasswordAlgo();
//       const currentRounds = bcrypt.getRounds(hash);

//       if (currentRounds < rounds) {
//         const newHash = await bcrypt.hash(password, rounds);

//         await conn.execute(
//           `UPDATE table_dietician
//            SET password = ?
//            WHERE id = ?`,
//           [newHash, user.id]
//         );
//       }
//     } catch (error) {
//       console.error('REHASH_ERROR: ' + error.message);
//     }

//     const partnerCode =
//       user.partner_code !== null && user.partner_code !== undefined
//         ? String(user.partner_code)
//         : null;

//     const parentUserId =
//       user.parent_user_id !== null && user.parent_user_id !== undefined
//         ? String(user.parent_user_id).toLowerCase()
//         : null;

//     const dashboardRoute = buildDashboardRoute(role);
//     const logoUrl = buildLogoUrl(user.dietician_id);

//     const dieticianPayload = {
//       dietician_id: String(user.dietician_id),
//       user_id: String(user.email).toLowerCase(),
//       name: user.name,
//       email: String(user.email).toLowerCase(),
//       phone_no: user.phone_no,
//       location: user.location,
//       logo: logoUrl,
//       is_reset_password: parseInt(user.is_reset_password, 10) || 0,

//       role,
//       partner_code: partnerCode,
//       parent_user_id: parentUserId,
//     };

//     // const now = Math.floor(Date.now() / 1000);

//     // const accessPayload = { 
//     //   iss: JWT_ISS,
//     //   aud: JWT_AUD,
//     //   iat: now,
//     //   nbf: now,
//     //   exp: now + JWT_TTL,

//     //   sub: String(user.dietician_id),
//     //   dietician_id: String(user.dietician_id),
//     //   user_id: String(user.email).toLowerCase(),

//     //   role,
//     //   partner_code: partnerCode,
//     //   parent_user_id: parentUserId,
//     //   dashboard_route: dashboardRoute,

//     //   dietician: dieticianPayload,
//     // };

//     // const accessToken = makeJwt(accessPayload);

//     // /*
//     // |--------------------------------------------------------------------------
//     // | Create refresh token
//     // |--------------------------------------------------------------------------
//     // | Refresh token is opaque/random.
//     // | DB stores only SHA-256 hash, never plain token.
//     // |--------------------------------------------------------------------------
//     // */

//     // const refreshToken = createRefreshToken();
//     // const refreshTokenHash = hashRefreshToken(refreshToken);
//     // const refreshExpiresAt = getRefreshExpiresAt();

//     // await conn.execute(
//     //   `INSERT INTO dietician_refresh_tokens
//     //      (dietician_id, token_hash, expires_at, ip_address, user_agent)
//     //    VALUES (?, ?, ?, ?, ?)`,
//     //   [
//     //     String(user.dietician_id),
//     //     refreshTokenHash,
//     //     refreshExpiresAt,
//     //     getClientIp(req),
//     //     getUserAgent(req),
//     //   ]
//     // );



// const now = Math.floor(Date.now() / 1000);

// /*
// |--------------------------------------------------------------------------
// | Create refresh token / server-side session
// |--------------------------------------------------------------------------
// | Refresh token is opaque/random.
// | DB stores only SHA-256 hash, never plain token.
// |
// | IMPORTANT:
// | dietician_refresh_tokens.id is used as the server-side
// | session identifier (sid) for the access JWT.
// |--------------------------------------------------------------------------
// */

// const refreshToken = createRefreshToken();
// const refreshTokenHash = hashRefreshToken(refreshToken);
// const refreshExpiresAt = getRefreshExpiresAt();

// const [refreshInsertResult] = await conn.execute(
//   `INSERT INTO dietician_refresh_tokens
//      (
//        dietician_id,
//        token_hash,
//        expires_at,
//        ip_address,
//        user_agent
//      )
//    VALUES (?, ?, ?, ?, ?)`,
//   [
//     String(user.dietician_id),
//     refreshTokenHash,
//     refreshExpiresAt,
//     getClientIp(req),
//     getUserAgent(req),
//   ]
// );

// /*
// |--------------------------------------------------------------------------
// | Get server-side session ID
// |--------------------------------------------------------------------------
// */

// const sessionId = String(refreshInsertResult.insertId);

// if (
//   !refreshInsertResult.insertId ||
//   !Number.isSafeInteger(Number(refreshInsertResult.insertId)) ||
//   Number(refreshInsertResult.insertId) <= 0
// ) {
//   console.error('SESSION_CREATION_FAILED: Invalid refresh token row id');

//   return send500(res);
// }

// /*
// |--------------------------------------------------------------------------
// | Create access token
// |--------------------------------------------------------------------------
// | The JWT is now linked to the server-side session using sid.
// |--------------------------------------------------------------------------
// */

// const accessPayload = {
//   iss: JWT_ISS,
//   aud: JWT_AUD,
//   iat: now,
//   nbf: now,
//   exp: now + JWT_TTL,

//   sub: String(user.dietician_id),

//   /*
//   |--------------------------------------------------------------------------
//   | Server-side session identifier
//   |--------------------------------------------------------------------------
//   */

//   sid: sessionId,

//   dietician_id: String(user.dietician_id),
//   user_id: String(user.email).toLowerCase(),

//   role,
//   partner_code: partnerCode,
//   parent_user_id: parentUserId,
//   dashboard_route: dashboardRoute,

//   dietician: dieticianPayload,
// };

// const accessToken = makeJwt(accessPayload);




//     await writeAuthLogSafe(
//       conn,
//       req,
//       'login_success',
//       user.email,
//       role,
//       user.partner_code,
//       identifier,
//       1,
//       null
//     );

//     setRefreshCookieIfEnabled(res, refreshToken);

//     return res.status(200).json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       expires_in: JWT_TTL,
//       // refresh_token: refreshToken,
//       refresh_expires_in: JWT_REFRESH_TTL_SECONDS,
//     });
//   } catch (error) {
//     console.error('LOGIN_ERROR:', {
//       message: error?.message || null,
//       code: error?.code || null,
//       sqlState: error?.sqlState || null,
//       sqlMessage: process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
//     });

//     return send500(res);
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