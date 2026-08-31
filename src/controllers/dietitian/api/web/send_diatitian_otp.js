"use strict";

/**
 * send_diatitian_otp.js
 *
 * Converted from: send_diatitian_otp.php
 * Endpoint : POST /auth/send_diatitian_otp   (PUBLIC, rate-limited)
 * Purpose  : Step 1 of the dietitian "forgot password" flow — email a 6-digit OTP.
 *
 * Behaviour vs. the PHP (and WHY it changed for VAPT / HIPAA):
 *  - PHP generated a 4-digit OTP → now 6 digits (crypto.randomInt, not rand()).
 *  - PHP echoed the OTP in the JSON response → REMOVED. Returning the OTP makes
 *    the whole flow pointless. (Dev-only escape hatch: OTP_DEBUG_RETURN=true.)
 *  - PHP stored the OTP in a PHP session with NO expiry → now bcrypt-hashed in
 *    Redis with a hard TTL (see dietitianOtpStore.js).
 *  - PHP returned 404 "Email not found" → that is account enumeration. We now
 *    ALWAYS return the same generic 200, doing equal work (dummy bcrypt) whether
 *    or not the account exists, so timing/response cannot reveal membership.
 *  - Resend cooldown prevents email-bombing a victim.
 *  - Email is sent via the Resend "email-verification" template (NOT inline HTML).
 *    The template must be PUBLISHED and use the {{{OTP}}} variable (uppercase).
 *
 * Input Validation hardening:
 *  - Request email is strictly validated server-side.
 *  - Injection-like/malformed emails are rejected before DB lookup.
 *  - Stored DB email is validated again before sending.
 *
 * HTML Injection hardening:
 *  - table_dietician.name is treated as untrusted legacy DB data.
 *  - NAME is HTML-escaped before entering the Resend template.
 *
 * No DB tables added/removed — reads table_dietician only; audits app_auth_logs.
 */

const crypto = require("crypto");
const axios = require("axios");
const pool = require("../../../../config/db");
const otpStore = require("../../../../services/dietitianOtpStore");

const {
  validateEmailAddress,
  escapeHtml,
} = require("../../../../utils/securityValidation");

// ─── Config ───────────────────────────────────────────────────────────────────

const APP_DEBUG =
  process.env.NODE_ENV !== "production";

const OTP_DEBUG_RETURN =
  String(
    process.env.OTP_DEBUG_RETURN || ""
  ).toLowerCase() === "true";

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER ||
  process.env.JWT_SECRET ||
  "";

const RESEND_API_KEY =
  process.env.RESEND_API_KEY ||
  "";

const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL ||
  "Respyr <no-reply@respyr.ai>";

const RESEND_OTP_TEMPLATE_ID =
  process.env.RESEND_OTP_TEMPLATE_ID ||
  "email-verification";

const GENERIC_MESSAGE =
  "Verification code has been sent to your email.";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getClientIp(req) {
  return String(
    req.ip ||
    req.socket?.remoteAddress ||
    "0.0.0.0"
  ).substring(
    0,
    45
  );
}

function getUserAgent(req) {
  return String(
    req.headers?.["user-agent"] ||
    ""
  ).substring(
    0,
    255
  );
}

function authLogHash(value) {
  return crypto
    .createHmac(
      "sha256",
      SECURITY_PEPPER
    )
    .update(
      String(
        value == null
          ? ""
          : value
      )
        .trim()
        .toLowerCase()
    )
    .digest("hex");
}

async function writeAuthLogSafe(
  req,
  {
    eventType,
    userId,
    identifier,
    success,
    failureReason,
  }
) {
  try {
    const identifierHash =
      identifier !== null &&
      identifier !== undefined
        ? authLogHash(
            identifier
          )
        : null;

    await pool.execute(
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
       VALUES (
         ?,
         ?,
         NULL,
         NULL,
         ?,
         ?,
         ?,
         NULL,
         ?,
         ?
       )`,
      [
        String(
          eventType || ""
        ).substring(
          0,
          60
        ),

        userId !== null &&
        userId !== undefined
          ? String(
              userId
            ).substring(
              0,
              191
            )
          : null,

        identifierHash,

        authLogHash(
          getClientIp(req)
        ),

        authLogHash(
          getUserAgent(req)
        ),

        success
          ? 1
          : 0,

        failureReason !== null &&
        failureReason !== undefined
          ? String(
              failureReason
            ).substring(
              0,
              255
            )
          : null,
      ]
    );
  } catch (err) {
    console.error(
      "OTP_SEND_AUDIT_FAILED:",
      err?.code ||
      err?.message
    );
  }
}

/**
 * Send the OTP email through the Resend template.
 */
async function sendOtpEmail(
  toEmail,
  name,
  otp,
  ttlMinutes
) {
  /*
  |--------------------------------------------------------------------------
  | Validate destination email again
  |--------------------------------------------------------------------------
  */

  const emailValidation =
    validateEmailAddress(
      toEmail,
      "email"
    );

  if (
    !emailValidation.ok
  ) {
    return {
      ok: false,

      status: 0,

      error:
        "Invalid destination email",
    };
  }

  const validatedEmail =
    emailValidation.value;

  /*
  |--------------------------------------------------------------------------
  | Resend configuration
  |--------------------------------------------------------------------------
  */

  if (
    !RESEND_API_KEY
  ) {
    return {
      ok: false,
      status: 0,
      error:
        "RESEND_API_KEY not configured",
    };
  }

  try {
    const response =
      await axios.post(
        "https://api.resend.com/emails",

        {
          from:
            RESEND_FROM_EMAIL,

          to: [
            validatedEmail,
          ],

          subject:
            "Your Respyr verification code",

          template: {
            id:
              RESEND_OTP_TEMPLATE_ID,

            variables: {
              OTP:
                String(
                  otp
                ),

              /*
              |--------------------------------------------------------------------------
              | HTML Injection protection
              |--------------------------------------------------------------------------
              |
              | user.name is read from table_dietician and may contain legacy
              | untrusted content. Escape it before it enters the HTML template.
              |--------------------------------------------------------------------------
              */

              NAME:
                escapeHtml(
                  name ||
                  "there"
                ),

              TTL_MINUTES:
                String(
                  ttlMinutes
                ),
            },
          },

          tags: [
            {
              name:
                "kind",

              value:
                "password_reset_otp",
            },
          ],
        },

        {
          timeout:
            10_000,

          headers: {
            Authorization:
              `Bearer ${RESEND_API_KEY}`,

            "Content-Type":
              "application/json",
          },

          validateStatus:
            () => true,
        }
      );

    if (
      response.status >= 200 &&
      response.status < 300
    ) {
      return {
        ok: true,

        status:
          response.status,
      };
    }

    return {
      ok: false,

      status:
        response.status,

      error:
        response.data ??
        "Resend non-2xx",
    };
  } catch (err) {
    return {
      ok: false,

      status: 0,

      error:
        err?.code ||
        err?.message ||
        "Resend request failed",
    };
  }
}

// ─── Controller ───────────────────────────────────────────────────────────────

exports.sendDietitianOtp =
  async (req, res) => {
    /*
    |--------------------------------------------------------------------------
    | Prevent caching
    |--------------------------------------------------------------------------
    */

    res.setHeader(
      "Cache-Control",
      "no-store"
    );

    res.setHeader(
      "Pragma",
      "no-cache"
    );

    /*
    |--------------------------------------------------------------------------
    | POST only
    |--------------------------------------------------------------------------
    */

    if (
      req.method !==
      "POST"
    ) {
      return res
        .status(405)
        .json({
          success:
            false,

          message:
            "Method not allowed",
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Parse JSON body if necessary
    |--------------------------------------------------------------------------
    */

    if (
      typeof req.body ===
      "string"
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
            success:
              false,

            message:
              "Invalid JSON body",
          });
      }
    }

    /*
    |--------------------------------------------------------------------------
    | Request body object validation
    |--------------------------------------------------------------------------
    */

    const body =
      req.body &&
      typeof req.body ===
        "object" &&
      !Array.isArray(
        req.body
      )
        ? req.body
        : {};

    /*
    |--------------------------------------------------------------------------
    | Strict server-side email validation
    |--------------------------------------------------------------------------
    |
    | Do not use the old permissive regex.
    |
    | Examples rejected:
    |
    | <script>@example.com
    | {{7*7}}@example.com
    | test<>@example.com
    | test user@example.com
    |--------------------------------------------------------------------------
    */

    const emailValidation =
      validateEmailAddress(
        body.email,
        "email"
      );

    if (
      !emailValidation.ok
    ) {
      return res
        .status(400)
        .json({
          success:
            false,

          message:
            "A valid email is required.",
        });
    }

    /*
    |--------------------------------------------------------------------------
    | Use only normalized validated email from this point
    |--------------------------------------------------------------------------
    */

    const email =
      emailValidation.value;

    const ttlMinutes =
      Math.ceil(
        otpStore.OTP_TTL_SECONDS /
          60
      );

    try {
      /*
      |--------------------------------------------------------------------------
      | Find dietitian
      |--------------------------------------------------------------------------
      |
      | SQL is parameterized.
      |--------------------------------------------------------------------------
      */

      const [rows] =
        await pool.execute(
          `SELECT
             id,
             dietician_id,
             name,
             email

           FROM table_dietician

           WHERE LOWER(email) =
                 LOWER(?)

           LIMIT 1`,
          [
            email,
          ]
        );

      const user =
        rows &&
        rows.length
          ? rows[0]
          : null;

      /*
      |--------------------------------------------------------------------------
      | Account enumeration protection
      |--------------------------------------------------------------------------
      |
      | Unknown accounts receive exactly the same public response as real ones.
      |--------------------------------------------------------------------------
      */

      if (
        !user
      ) {
        /*
        |--------------------------------------------------------------------------
        | Equalize work
        |--------------------------------------------------------------------------
        */

        await otpStore
          .dummyHashWork();

        /*
        |--------------------------------------------------------------------------
        | Audit
        |--------------------------------------------------------------------------
        */

        await writeAuthLogSafe(
          req,
          {
            eventType:
              "otp_request_no_account",

            userId:
              null,

            identifier:
              email,

            success:
              false,

            failureReason:
              "No account for email",
          }
        );

        return res
          .status(200)
          .json({
            success:
              true,

            message:
              GENERIC_MESSAGE,
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Resend cooldown
      |--------------------------------------------------------------------------
      */

      const cooldown =
        await otpStore
          .getResendCooldown(
            email
          );

      if (
        cooldown > 0
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              "otp_request_cooldown",

            userId:
              user.dietician_id,

            identifier:
              email,

            success:
              false,

            failureReason:
              `Resend cooldown ${cooldown}s`,
          }
        );

        /*
        |--------------------------------------------------------------------------
        | Keep response identical
        |--------------------------------------------------------------------------
        */

        return res
          .status(200)
          .json({
            success:
              true,

            message:
              GENERIC_MESSAGE,
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Generate and store OTP
      |--------------------------------------------------------------------------
      |
      | dietitianOtpStore stores the OTP securely with TTL.
      |--------------------------------------------------------------------------
      */

      const {
        otp,
      } =
        await otpStore
          .setOtp(
            email,
            user.dietician_id
          );

      /*
      |--------------------------------------------------------------------------
      | Validate legacy DB email before outbound email
      |--------------------------------------------------------------------------
      |
      | Even though this row was found using the validated request email,
      | database values are treated as untrusted defense-in-depth.
      |--------------------------------------------------------------------------
      */

      const storedEmailValidation =
        validateEmailAddress(
          user.email,
          "email"
        );

      /*
      |--------------------------------------------------------------------------
      | Send OTP email
      |--------------------------------------------------------------------------
      */

      const emailResult =
        storedEmailValidation.ok
          ? await sendOtpEmail(
              storedEmailValidation.value,
              user.name,
              otp,
              ttlMinutes
            )
          : {
              ok:
                false,

              status:
                0,

              error:
                "Invalid stored email",
            };

      /*
      |--------------------------------------------------------------------------
      | Audit result
      |--------------------------------------------------------------------------
      */

      await writeAuthLogSafe(
        req,
        {
          eventType:
            emailResult.ok
              ? "otp_requested"
              : "otp_send_failed",

          userId:
            user.dietician_id,

          identifier:
            email,

          success:
            emailResult.ok,

          failureReason:
            emailResult.ok
              ? null
              : "OTP email send failed",
        }
      );

      /*
      |--------------------------------------------------------------------------
      | Development error log
      |--------------------------------------------------------------------------
      */

      if (
        !emailResult.ok &&
        APP_DEBUG
      ) {
        console.error(
          "OTP_EMAIL_FAILED:",
          emailResult.status,
          emailResult.error
        );
      }

      /*
      |--------------------------------------------------------------------------
      | Always generic public response
      |--------------------------------------------------------------------------
      */

      const response = {
        success:
          true,

        message:
          GENERIC_MESSAGE,
      };

      /*
      |--------------------------------------------------------------------------
      | Development-only OTP response
      |--------------------------------------------------------------------------
      |
      | Never enable OTP_DEBUG_RETURN in production.
      |--------------------------------------------------------------------------
      */

      if (
        OTP_DEBUG_RETURN &&
        APP_DEBUG
      ) {
        response.debug_otp =
          otp;

        response.debug_email_sent =
          emailResult.ok;
      }

      return res
        .status(200)
        .json(
          response
        );
    } catch (error) {
      /*
      |--------------------------------------------------------------------------
      | Internal error
      |--------------------------------------------------------------------------
      */

      console.error(
        "SEND_OTP_ERROR:",
        {
          code:
            error?.code,

          message:
            error?.message,
        }
      );

      return res
        .status(500)
        .json({
          success:
            false,

          message:
            "Internal server error",

          ...(APP_DEBUG && {
            debug_error:
              error?.message,
          }),
        });
    }
  };











// "use strict";

// /**
//  * send_diatitian_otp.js
//  *
//  * Converted from: send_diatitian_otp.php
//  * Endpoint : POST /auth/send_diatitian_otp   (PUBLIC, rate-limited)
//  * Purpose  : Step 1 of the dietitian "forgot password" flow — email a 6-digit OTP.
//  *
//  * Behaviour vs. the PHP (and WHY it changed for VAPT / HIPAA):
//  *  - PHP generated a 4-digit OTP → now 6 digits (crypto.randomInt, not rand()).
//  *  - PHP echoed the OTP in the JSON response → REMOVED. Returning the OTP makes
//  *    the whole flow pointless. (Dev-only escape hatch: OTP_DEBUG_RETURN=true.)
//  *  - PHP stored the OTP in a PHP session with NO expiry → now bcrypt-hashed in
//  *    Redis with a hard TTL (see dietitianOtpStore.js).
//  *  - PHP returned 404 "Email not found" → that is account enumeration. We now
//  *    ALWAYS return the same generic 200, doing equal work (dummy bcrypt) whether
//  *    or not the account exists, so timing/response cannot reveal membership.
//  *  - Resend cooldown prevents email-bombing a victim.
//  *  - Email is sent via the Resend "email-verification" template (NOT inline HTML).
//  *    The template must be PUBLISHED and use the {{{OTP}}} variable (uppercase).
//  *
//  * HTML Injection hardening:
//  *  - table_dietician.name is treated as untrusted legacy DB data.
//  *  - NAME is HTML-escaped before entering the Resend template.
//  *
//  * No DB tables added/removed — reads table_dietician only; audits app_auth_logs.
//  */

// const crypto = require("crypto");
// const axios = require("axios");
// const pool = require("../../../../config/db");
// const otpStore = require("../../../../services/dietitianOtpStore");

// const {
//   escapeHtml,
// } = require("../../../../utils/securityValidation");

// // ─── Config ───────────────────────────────────────────────────────────────────

// const APP_DEBUG =
//   process.env.NODE_ENV !== "production";

// const OTP_DEBUG_RETURN =
//   String(
//     process.env.OTP_DEBUG_RETURN || ""
//   ).toLowerCase() === "true";

// const SECURITY_PEPPER =
//   process.env.SECURITY_PEPPER ||
//   process.env.JWT_SECRET ||
//   "";

// const RESEND_API_KEY =
//   process.env.RESEND_API_KEY ||
//   "";

// const RESEND_FROM_EMAIL =
//   process.env.RESEND_FROM_EMAIL ||
//   "Respyr <no-reply@respyr.ai>";

// const RESEND_OTP_TEMPLATE_ID =
//   process.env.RESEND_OTP_TEMPLATE_ID ||
//   "email-verification";

// const GENERIC_MESSAGE =
//   "Verification code has been sent to your email.";

// // ─── Helpers ──────────────────────────────────────────────────────────────────

// function isValidEmail(value) {
//   return (
//     typeof value === "string" &&
//     /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) &&
//     value.length <= 254
//   );
// }

// function getClientIp(req) {
//   return String(
//     req.ip ||
//     req.socket?.remoteAddress ||
//     "0.0.0.0"
//   ).substring(
//     0,
//     45
//   );
// }

// function getUserAgent(req) {
//   return String(
//     req.headers?.["user-agent"] ||
//     ""
//   ).substring(
//     0,
//     255
//   );
// }

// function authLogHash(value) {
//   return crypto
//     .createHmac(
//       "sha256",
//       SECURITY_PEPPER
//     )
//     .update(
//       String(
//         value == null
//           ? ""
//           : value
//       )
//         .trim()
//         .toLowerCase()
//     )
//     .digest("hex");
// }

// async function writeAuthLogSafe(
//   req,
//   {
//     eventType,
//     userId,
//     identifier,
//     success,
//     failureReason,
//   }
// ) {
//   try {
//     const identifierHash =
//       identifier !== null &&
//       identifier !== undefined
//         ? authLogHash(
//             identifier
//           )
//         : null;

//     await pool.execute(
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
//        VALUES (
//          ?,
//          ?,
//          NULL,
//          NULL,
//          ?,
//          ?,
//          ?,
//          NULL,
//          ?,
//          ?
//        )`,
//       [
//         String(
//           eventType || ""
//         ).substring(
//           0,
//           60
//         ),

//         userId !== null &&
//         userId !== undefined
//           ? String(
//               userId
//             ).substring(
//               0,
//               191
//             )
//           : null,

//         identifierHash,

//         authLogHash(
//           getClientIp(req)
//         ),

//         authLogHash(
//           getUserAgent(req)
//         ),

//         success
//           ? 1
//           : 0,

//         failureReason !== null &&
//         failureReason !== undefined
//           ? String(
//               failureReason
//             ).substring(
//               0,
//               255
//             )
//           : null,
//       ]
//     );
//   } catch (err) {
//     console.error(
//       "OTP_SEND_AUDIT_FAILED:",
//       err?.code ||
//       err?.message
//     );
//   }
// }

// /**
//  * Send the OTP email through the Resend template.
//  */
// async function sendOtpEmail(
//   toEmail,
//   name,
//   otp,
//   ttlMinutes
// ) {
//   if (
//     !RESEND_API_KEY
//   ) {
//     return {
//       ok: false,
//       status: 0,
//       error:
//         "RESEND_API_KEY not configured",
//     };
//   }

//   try {
//     const response =
//       await axios.post(
//         "https://api.resend.com/emails",

//         {
//           from:
//             RESEND_FROM_EMAIL,

//           to: [
//             toEmail,
//           ],

//           subject:
//             "Your Respyr verification code",

//           template: {
//             id:
//               RESEND_OTP_TEMPLATE_ID,

//             variables: {
//               OTP:
//                 String(
//                   otp
//                 ),

//               /*
//               |--------------------------------------------------------------------------
//               | HTML Injection protection
//               |--------------------------------------------------------------------------
//               |
//               | user.name is read from table_dietician and may contain legacy
//               | untrusted content. Escape it before it enters the HTML template.
//               |--------------------------------------------------------------------------
//               */

//               NAME:
//                 escapeHtml(
//                   name ||
//                   "there"
//                 ),

//               TTL_MINUTES:
//                 String(
//                   ttlMinutes
//                 ),
//             },
//           },

//           tags: [
//             {
//               name:
//                 "kind",

//               value:
//                 "password_reset_otp",
//             },
//           ],
//         },

//         {
//           timeout:
//             10_000,

//           headers: {
//             Authorization:
//               `Bearer ${RESEND_API_KEY}`,

//             "Content-Type":
//               "application/json",
//           },

//           validateStatus:
//             () => true,
//         }
//       );

//     if (
//       response.status >= 200 &&
//       response.status < 300
//     ) {
//       return {
//         ok: true,
//         status:
//           response.status,
//       };
//     }

//     return {
//       ok: false,

//       status:
//         response.status,

//       error:
//         response.data ??
//         "Resend non-2xx",
//     };
//   } catch (err) {
//     return {
//       ok: false,

//       status: 0,

//       error:
//         err?.code ||
//         err?.message ||
//         "Resend request failed",
//     };
//   }
// }

// // ─── Controller ───────────────────────────────────────────────────────────────

// exports.sendDietitianOtp =
//   async (req, res) => {
//     res.setHeader(
//       "Cache-Control",
//       "no-store"
//     );

//     res.setHeader(
//       "Pragma",
//       "no-cache"
//     );

//     /*
//     |--------------------------------------------------------------------------
//     | POST only
//     |--------------------------------------------------------------------------
//     */

//     if (
//       req.method !==
//       "POST"
//     ) {
//       return res
//         .status(405)
//         .json({
//           success:
//             false,

//           message:
//             "Method not allowed",
//         });
//     }

//     /*
//     |--------------------------------------------------------------------------
//     | Parse JSON body if necessary
//     |--------------------------------------------------------------------------
//     */

//     if (
//       typeof req.body ===
//       "string"
//     ) {
//       try {
//         req.body =
//           JSON.parse(
//             req.body
//           );
//       } catch {
//         return res
//           .status(400)
//           .json({
//             success:
//               false,

//             message:
//               "Invalid JSON body",
//           });
//       }
//     }

//     const body =
//       req.body &&
//       typeof req.body ===
//         "object" &&
//       !Array.isArray(
//         req.body
//       )
//         ? req.body
//         : {};

//     const email =
//       otpStore.normalizeEmail(
//         body.email
//       );

//     /*
//     |--------------------------------------------------------------------------
//     | Email validation
//     |--------------------------------------------------------------------------
//     */

//     if (
//       !isValidEmail(
//         email
//       )
//     ) {
//       return res
//         .status(400)
//         .json({
//           success:
//             false,

//           message:
//             "A valid email is required.",
//         });
//     }

//     const ttlMinutes =
//       Math.ceil(
//         otpStore.OTP_TTL_SECONDS /
//           60
//       );

//     try {
//       /*
//       |--------------------------------------------------------------------------
//       | Find dietitian
//       |--------------------------------------------------------------------------
//       */

//       const [rows] =
//         await pool.execute(
//           `SELECT
//              id,
//              dietician_id,
//              name,
//              email

//            FROM table_dietician

//            WHERE LOWER(email) =
//                  LOWER(?)

//            LIMIT 1`,
//           [
//             email,
//           ]
//         );

//       const user =
//         rows &&
//         rows.length
//           ? rows[0]
//           : null;

//       /*
//       |--------------------------------------------------------------------------
//       | Account enumeration protection
//       |--------------------------------------------------------------------------
//       */

//       if (
//         !user
//       ) {
//         await otpStore
//           .dummyHashWork();

//         await writeAuthLogSafe(
//           req,
//           {
//             eventType:
//               "otp_request_no_account",

//             userId:
//               null,

//             identifier:
//               email,

//             success:
//               false,

//             failureReason:
//               "No account for email",
//           }
//         );

//         return res
//           .status(200)
//           .json({
//             success:
//               true,

//             message:
//               GENERIC_MESSAGE,
//           });
//       }

//       /*
//       |--------------------------------------------------------------------------
//       | Resend cooldown
//       |--------------------------------------------------------------------------
//       */

//       const cooldown =
//         await otpStore
//           .getResendCooldown(
//             email
//           );

//       if (
//         cooldown > 0
//       ) {
//         await writeAuthLogSafe(
//           req,
//           {
//             eventType:
//               "otp_request_cooldown",

//             userId:
//               user.dietician_id,

//             identifier:
//               email,

//             success:
//               false,

//             failureReason:
//               `Resend cooldown ${cooldown}s`,
//           }
//         );

//         return res
//           .status(200)
//           .json({
//             success:
//               true,

//             message:
//               GENERIC_MESSAGE,
//           });
//       }

//       /*
//       |--------------------------------------------------------------------------
//       | Generate/store OTP
//       |--------------------------------------------------------------------------
//       */

//       const {
//         otp,
//       } =
//         await otpStore
//           .setOtp(
//             email,
//             user.dietician_id
//           );

//       /*
//       |--------------------------------------------------------------------------
//       | Send email
//       |--------------------------------------------------------------------------
//       */

//       const emailResult =
//         await sendOtpEmail(
//           user.email,
//           user.name,
//           otp,
//           ttlMinutes
//         );

//       /*
//       |--------------------------------------------------------------------------
//       | Audit
//       |--------------------------------------------------------------------------
//       */

//       await writeAuthLogSafe(
//         req,
//         {
//           eventType:
//             emailResult.ok
//               ? "otp_requested"
//               : "otp_send_failed",

//           userId:
//             user.dietician_id,

//           identifier:
//             email,

//           success:
//             emailResult.ok,

//           failureReason:
//             emailResult.ok
//               ? null
//               : "OTP email send failed",
//         }
//       );

//       if (
//         !emailResult.ok &&
//         APP_DEBUG
//       ) {
//         console.error(
//           "OTP_EMAIL_FAILED:",
//           emailResult.status,
//           emailResult.error
//         );
//       }

//       const response = {
//         success:
//           true,

//         message:
//           GENERIC_MESSAGE,
//       };

//       /*
//       |--------------------------------------------------------------------------
//       | Development-only OTP
//       |--------------------------------------------------------------------------
//       */

//       if (
//         OTP_DEBUG_RETURN &&
//         APP_DEBUG
//       ) {
//         response.debug_otp =
//           otp;

//         response.debug_email_sent =
//           emailResult.ok;
//       }

//       return res
//         .status(200)
//         .json(
//           response
//         );
//     } catch (error) {
//       console.error(
//         "SEND_OTP_ERROR:",
//         {
//           code:
//             error?.code,

//           message:
//             error?.message,
//         }
//       );

//       return res
//         .status(500)
//         .json({
//           success:
//             false,

//           message:
//             "Internal server error",

//           ...(APP_DEBUG && {
//             debug_error:
//               error?.message,
//           }),
//         });
//     }
//   };












// "use strict";

// /**
//  * send_diatitian_otp.js
//  *
//  * Converted from: send_diatitian_otp.php
//  * Endpoint : POST /auth/send_diatitian_otp   (PUBLIC, rate-limited)
//  * Purpose  : Step 1 of the dietitian "forgot password" flow — email a 6-digit OTP.
//  *
//  * Behaviour vs. the PHP (and WHY it changed for VAPT / HIPAA):
//  *  - PHP generated a 4-digit OTP → now 6 digits (crypto.randomInt, not rand()).
//  *  - PHP echoed the OTP in the JSON response → REMOVED. Returning the OTP makes
//  *    the whole flow pointless. (Dev-only escape hatch: OTP_DEBUG_RETURN=true.)
//  *  - PHP stored the OTP in a PHP session with NO expiry → now bcrypt-hashed in
//  *    Redis with a hard TTL (see dietitianOtpStore.js).
//  *  - PHP returned 404 "Email not found" → that is account enumeration. We now
//  *    ALWAYS return the same generic 200, doing equal work (dummy bcrypt) whether
//  *    or not the account exists, so timing/response cannot reveal membership.
//  *  - Resend cooldown prevents email-bombing a victim.
//  *  - Email is sent via the Resend "email-verification" template (NOT inline HTML).
//  *    The template must be PUBLISHED and use the {{{OTP}}} variable (uppercase).
//  *
//  * No DB tables added/removed — reads table_dietician only; audits app_auth_logs.
//  */

// const crypto = require("crypto");
// const axios = require("axios");
// const pool = require("../../../../config/db");
// const otpStore = require("../../../../services/dietitianOtpStore");

// // ─── Config ───────────────────────────────────────────────────────────────────

// const APP_DEBUG = process.env.NODE_ENV !== "production";
// const OTP_DEBUG_RETURN =
//   String(process.env.OTP_DEBUG_RETURN || "").toLowerCase() === "true";

// const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

// const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
// const RESEND_FROM_EMAIL =
//   process.env.RESEND_FROM_EMAIL || "Respyr <no-reply@respyr.ai>";

// // Resend template alias for the OTP email. Defaults to the published
// // "email-verification" template so a missing env var can't send an empty
// // template id (the same 422 that hit the invites_client flow).
// const RESEND_OTP_TEMPLATE_ID =
//   process.env.RESEND_OTP_TEMPLATE_ID || "email-verification";

// const GENERIC_MESSAGE =
//   "Verification code has been sent to your email.";

// // ─── Helpers ──────────────────────────────────────────────────────────────────

// function isValidEmail(value) {
//   return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) &&
//     value.length <= 254;
// }

// function getClientIp(req) {
//   return String(req.ip || req.socket?.remoteAddress || "0.0.0.0").substring(0, 45);
// }

// function getUserAgent(req) {
//   return String(req.headers?.["user-agent"] || "").substring(0, 255);
// }

// function authLogHash(value) {
//   return crypto
//     .createHmac("sha256", SECURITY_PEPPER)
//     .update(String(value == null ? "" : value).trim().toLowerCase())
//     .digest("hex");
// }

// async function writeAuthLogSafe(req, { eventType, userId, identifier, success, failureReason }) {
//   try {
//     const identifierHash =
//       identifier !== null && identifier !== undefined ? authLogHash(identifier) : null;
//     await pool.execute(
//       `INSERT INTO app_auth_logs (
//          event_type, user_id, role, partner_code,
//          identifier_hash, ip_hash, user_agent_hash, session_id_hash,
//          success, failure_reason
//        ) VALUES (?, ?, NULL, NULL, ?, ?, ?, NULL, ?, ?)`,
//       [
//         String(eventType || "").substring(0, 60),
//         userId !== null && userId !== undefined ? String(userId).substring(0, 191) : null,
//         identifierHash,
//         authLogHash(getClientIp(req)),
//         authLogHash(getUserAgent(req)),
//         success ? 1 : 0,
//         failureReason !== null && failureReason !== undefined
//           ? String(failureReason).substring(0, 255)
//           : null,
//       ]
//     );
//   } catch (err) {
//     console.error("OTP_SEND_AUDIT_FAILED:", err?.code || err?.message);
//   }
// }

// /** Send the OTP email via the Resend "email-verification" template. Returns { ok, status?, error? }. */
// async function sendOtpEmail(toEmail, name, otp, ttlMinutes) {
//   if (!RESEND_API_KEY) {
//     return { ok: false, status: 0, error: "RESEND_API_KEY not configured" };
//   }
//   try {
//     const response = await axios.post(
//       "https://api.resend.com/emails",
//       {
//         from: RESEND_FROM_EMAIL,
//         to: [toEmail],
//         // When a template is used you must NOT also send html/text/react —
//         // Resend rejects that combination. subject/from here override the
//         // template's own defaults; delete `subject` to use the template's.
//         subject: "Your Respyr verification code",
//         template: {
//           id: RESEND_OTP_TEMPLATE_ID,
//           variables: {
//             // Names must match the {{{...}}} variables in the Resend template.
//             // The published email-verification template only uses OTP; NAME and
//             // TTL_MINUTES are sent for forward-compatibility and are ignored if
//             // the template does not reference them (extra variables are safe).
//             OTP: String(otp),
//             NAME: name || "there",
//             TTL_MINUTES: String(ttlMinutes),
//           },
//         },
//         tags: [{ name: "kind", value: "password_reset_otp" }],
//       },
//       {
//         timeout: 10_000,
//         headers: {
//           Authorization: `Bearer ${RESEND_API_KEY}`,
//           "Content-Type": "application/json",
//         },
//         validateStatus: () => true,
//       }
//     );
//     if (response.status >= 200 && response.status < 300) {
//       return { ok: true, status: response.status };
//     }
//     return { ok: false, status: response.status, error: response.data ?? "Resend non-2xx" };
//   } catch (err) {
//     return { ok: false, status: 0, error: err?.code || err?.message || "Resend request failed" };
//   }
// }

// // ─── Controller ───────────────────────────────────────────────────────────────

// exports.sendDietitianOtp = async (req, res) => {
//   res.setHeader("Cache-Control", "no-store");
//   res.setHeader("Pragma", "no-cache");

//   if (req.method !== "POST") {
//     return res.status(405).json({ success: false, message: "Method not allowed" });
//   }

//   if (typeof req.body === "string") {
//     try {
//       req.body = JSON.parse(req.body);
//     } catch {
//       return res.status(400).json({ success: false, message: "Invalid JSON body" });
//     }
//   }

//   const body = req.body && typeof req.body === "object" && !Array.isArray(req.body)
//     ? req.body
//     : {};

//   const email = otpStore.normalizeEmail(body.email);

//   // A malformed email is a client error, not an enumeration vector.
//   if (!isValidEmail(email)) {
//     return res.status(400).json({ success: false, message: "A valid email is required." });
//   }

//   const ttlMinutes = Math.ceil(otpStore.OTP_TTL_SECONDS / 60);

//   try {
//     // Look up the dietician. We deliberately DO NOT branch the response on this.
//     const [rows] = await pool.execute(
//       `SELECT id, dietician_id, name, email
//          FROM table_dietician
//         WHERE LOWER(email) = LOWER(?)
//         LIMIT 1`,
//       [email]
//     );
//     const user = rows && rows.length ? rows[0] : null;

//     if (!user) {
//       // Equalise work, log, and return the SAME generic response.
//       await otpStore.dummyHashWork();
//       await writeAuthLogSafe(req, {
//         eventType: "otp_request_no_account",
//         userId: null,
//         identifier: email,
//         success: false,
//         failureReason: "No account for email",
//       });
//       return res.status(200).json({ success: true, message: GENERIC_MESSAGE });
//     }

//     // Resend cooldown — silently skip resending (does not leak existence because
//     // the response is identical to the no-account path).
//     const cooldown = await otpStore.getResendCooldown(email);
//     if (cooldown > 0) {
//       await writeAuthLogSafe(req, {
//         eventType: "otp_request_cooldown",
//         userId: user.dietician_id,
//         identifier: email,
//         success: false,
//         failureReason: `Resend cooldown ${cooldown}s`,
//       });
//       return res.status(200).json({ success: true, message: GENERIC_MESSAGE });
//     }

//     // Issue + store the OTP (bcrypt-hashed, TTL'd in Redis).
//     const { otp } = await otpStore.setOtp(email, user.dietician_id);

//     // Email it.
//     const emailResult = await sendOtpEmail(user.email, user.name, otp, ttlMinutes);

//     await writeAuthLogSafe(req, {
//       eventType: emailResult.ok ? "otp_requested" : "otp_send_failed",
//       userId: user.dietician_id,
//       identifier: email,
//       success: emailResult.ok,
//       failureReason: emailResult.ok ? null : "OTP email send failed",
//     });

//     if (!emailResult.ok && APP_DEBUG) {
//       console.error("OTP_EMAIL_FAILED:", emailResult.status, emailResult.error);
//     }

//     const response = { success: true, message: GENERIC_MESSAGE };

//     // DEV ONLY — never enable in production. Lets you test without a mailbox.
//     if (OTP_DEBUG_RETURN && APP_DEBUG) {
//       response.debug_otp = otp;
//       response.debug_email_sent = emailResult.ok;
//     }

//     return res.status(200).json(response);
//   } catch (error) {
//     console.error("SEND_OTP_ERROR:", {
//       code: error?.code,
//       message: error?.message,
//     });
//     return res.status(500).json({
//       success: false,
//       message: "Internal server error",
//       ...(APP_DEBUG && { debug_error: error?.message }),
//     });
//   }
// };