"use strict";

/**
 * POST /dietitian/api/web/super-admin-invite-trainer
 * Auth: Bearer JWT
 * Authorized role: super_admin
 *
 * VAPT controls:
 * - Actor comes from the verified JWT and is re-checked in DB.
 * - actor_user_id can only be cross-checked; it cannot select another actor.
 * - All SQL is parameterized.
 * - Human names, email and phone are validated on the server.
 * - Malicious input is rejected, not silently cleaned.
 * - User-controlled text is HTML-escaped before entering HTML email templates.
 * - Invite tokens are securely random and stored only as HMAC hashes.
 */

const crypto = require("crypto");
const axios = require("axios");
const pool = require("../../../../config/db");

const {
  validateHumanName,
  validateEmailAddress,
  validatePhoneNumber,
  escapeHtml,
} = require("../../../../utils/securityValidation");

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const INVITE_EXPIRY_HOURS = Math.max(
  1,
  parseInt(process.env.INVITE_EXPIRY_HOURS, 10) || 24
);

const FRONTEND_ACCEPT_INVITE_URL =
  process.env.FRONTEND_ACCEPT_INVITE_URL ||
  "https://api.rysflo.com/signup";

const RESEND_API_KEY =
  process.env.RESEND_API_KEY || "";

const RESEND_INVITE_TEMPLATE_ID =
  process.env.RESEND_INVITE_TEMPLATE_ID ||
  "admin_trainer_invitation";

const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL ||
  "Respyr <no-reply@respyr.ai>";

const APP_DEBUG =
  process.env.NODE_ENV !== "production";

const RETURN_INVITE_LINK_FOR_TESTING =
  String(
    process.env.RETURN_INVITE_LINK_FOR_TESTING || ""
  ).toLowerCase() === "true";

const PARTNER_CODE_PREFIX = "TRN";
const PARTNER_CODE_RANDOM_LEN = 7;
const PARTNER_CODE_MAX_ATTEMPTS = 10;

const PARTNER_CODE_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function normalizeEmail(value) {
  return typeof value === "string"
    ? value.trim().toLowerCase()
    : "";
}

function getClientIp(req) {
  const ip =
    (typeof req.ip === "string" && req.ip) ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "0.0.0.0";

  return String(ip).slice(0, 64);
}

function getUserAgent(req) {
  const ua =
    (typeof req.get === "function" &&
      req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";

  return String(ua).slice(0, 500);
}

function authLogHash(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return null;
  }

  return crypto
    .createHmac(
      "sha256",
      SECURITY_PEPPER
    )
    .update(
      String(value)
        .trim()
        .toLowerCase()
    )
    .digest("hex");
}

function secureHash(value) {
  return crypto
    .createHmac(
      "sha256",
      SECURITY_PEPPER
    )
    .update(String(value))
    .digest("hex");
}

function toUtcMysqlDateTime(date) {
  const pad = (number) =>
    String(number).padStart(2, "0");

  return (
    `${date.getUTCFullYear()}-` +
    `${pad(date.getUTCMonth() + 1)}-` +
    `${pad(date.getUTCDate())} ` +
    `${pad(date.getUTCHours())}:` +
    `${pad(date.getUTCMinutes())}:` +
    `${pad(date.getUTCSeconds())}`
  );
}

async function writeAuthLogSafe(
  req,
  {
    eventType,
    userId,
    role,
    partnerCode,
    identifier,
    success,
    failureReason,
  }
) {
  try {
    const ipHash =
      authLogHash(
        getClientIp(req)
      );

    const userAgentHash =
      authLogHash(
        getUserAgent(req)
      );

    const identifierHash =
      identifier !== null &&
      identifier !== undefined
        ? authLogHash(identifier)
        : null;

    const truncatedEvent =
      String(
        eventType || ""
      ).slice(0, 60);

    const truncatedReason =
      failureReason !== null &&
      failureReason !== undefined
        ? String(
            failureReason
          ).slice(0, 255)
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
       VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
      [
        truncatedEvent,
        userId ?? null,
        role ?? null,
        partnerCode ?? null,
        identifierHash,
        ipHash,
        userAgentHash,
        success ? 1 : 0,
        truncatedReason,
      ]
    );
  } catch (error) {
    console.error(
      "AUTH_LOG_WRITE_FAILED:",
      error?.code ||
        error?.message
    );
  }
}

async function resolveActorFromToken(
  req,
  requiredRole = "super_admin"
) {
  const payload =
    req.user || {};

  const dieticianId =
    String(
      payload.sub ||
        payload.dietician_id ||
        ""
    ).trim();

  const tokenEmail =
    normalizeEmail(
      payload.email ||
        payload.user_id ||
        payload?.dietician?.email ||
        ""
    );

  if (
    (
      !dieticianId ||
      dieticianId.length > 64
    ) &&
    tokenEmail === ""
  ) {
    return {
      error: {
        status: 401,

        body: {
          ok: false,

          message:
            "Invalid token user",
        },
      },
    };
  }

  let rows;

  if (dieticianId) {
    const [result] =
      await pool.execute(
        `
          SELECT
            td.id,
            td.dietician_id,
            td.email,

            aur.user_id,
            aur.role,
            aur.partner_code,
            aur.parent_user_id,
            aur.status

          FROM table_dietician td

          INNER JOIN app_user_roles aur
            ON LOWER(aur.user_id) =
               LOWER(td.email)

          WHERE td.dietician_id = ?

          LIMIT 1
        `,
        [
          dieticianId,
        ]
      );

    rows = result;
  } else {
    const [result] =
      await pool.execute(
        `
          SELECT
            td.id,
            td.dietician_id,
            td.email,

            aur.user_id,
            aur.role,
            aur.partner_code,
            aur.parent_user_id,
            aur.status

          FROM table_dietician td

          INNER JOIN app_user_roles aur
            ON LOWER(aur.user_id) =
               LOWER(td.email)

          WHERE LOWER(td.email) =
                LOWER(?)

          LIMIT 1
        `,
        [
          tokenEmail,
        ]
      );

    rows = result;
  }

  const actor =
    rows && rows.length
      ? rows[0]
      : null;

  if (!actor) {
    return {
      error: {
        status: 401,

        body: {
          ok: false,

          message:
            "Token user not found",
        },
      },
    };
  }

  if (
    String(actor.status) !==
    "active"
  ) {
    return {
      error: {
        status: 403,

        body: {
          ok: false,

          message:
            "Account is not active",
        },
      },
    };
  }

  if (
    String(actor.role) !==
    requiredRole
  ) {
    return {
      error: {
        status: 403,

        body: {
          ok: false,

          message:
            "You are not allowed to perform this action",
        },
      },
    };
  }

  return {
    actor,

    actorEmail:
      normalizeEmail(
        actor.user_id ||
          actor.email
      ),
  };
}

function validateInviteInput(body) {
  if (
    !body ||
    typeof body !== "object" ||
    Array.isArray(body)
  ) {
    return {
      ok: false,

      status: 400,

      message:
        "Invalid request body",
    };
  }

  /*
  |--------------------------------------------------------------------------
  | First name
  |--------------------------------------------------------------------------
  */

  const firstNameResult =
    validateHumanName(
      body.first_name,
      "first_name"
    );

  if (
    !firstNameResult.ok
  ) {
    return {
      ok: false,

      status: 400,

      message:
        firstNameResult.message,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Last name
  |--------------------------------------------------------------------------
  */

  const lastNameResult =
    validateHumanName(
      body.last_name,
      "last_name"
    );

  if (
    !lastNameResult.ok
  ) {
    return {
      ok: false,

      status: 400,

      message:
        lastNameResult.message,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Email
  |--------------------------------------------------------------------------
  |
  | Important:
  |
  | Do not use the old loose regex:
  |
  | /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  |
  | because values such as:
  |
  | <script>@example.com
  | {{7*7}}@example.com
  |
  | can pass loose validation.
  |--------------------------------------------------------------------------
  */

  const emailResult =
    validateEmailAddress(
      body.email,
      "email"
    );

  if (
    !emailResult.ok
  ) {
    return {
      ok: false,

      status: 400,

      message:
        emailResult.message,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Phone
  |--------------------------------------------------------------------------
  |
  | Validate BEFORE normalization.
  |
  | Never do:
  |
  | phone.replace(/[^\d+]/g, "")
  |
  | because malicious input could get silently cleaned and accepted.
  |--------------------------------------------------------------------------
  */

  const phoneResult =
    validatePhoneNumber(
      body.phone,
      "phone",
      {
        required: false,
      }
    );

  if (
    !phoneResult.ok
  ) {
    return {
      ok: false,

      status: 400,

      message:
        phoneResult.message,
    };
  }

  return {
    ok: true,

    value: {
      first_name:
        firstNameResult.value,

      last_name:
        lastNameResult.value,

      email:
        emailResult.value,

      phone:
        phoneResult.value,
    },
  };
}

async function ensureInviteCanBeCreated(
  email
) {
  /*
  |--------------------------------------------------------------------------
  | Existing user
  |--------------------------------------------------------------------------
  */

  const [roleRows] =
    await pool.execute(
      `
        SELECT id

        FROM app_user_roles

        WHERE LOWER(user_id) =
              LOWER(?)

        LIMIT 1
      `,
      [
        email,
      ]
    );

  if (
    roleRows.length > 0
  ) {
    return {
      ok: false,

      status: 409,

      message:
        "A user with this email already exists",
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Existing pending invitation
  |--------------------------------------------------------------------------
  */

  const [inviteRows] =
    await pool.execute(
      `
        SELECT id

        FROM app_user_invitations

        WHERE LOWER(invited_email) =
              LOWER(?)

          AND status =
              'pending'

          AND expires_at >
              UTC_TIMESTAMP()

        LIMIT 1
      `,
      [
        email,
      ]
    );

  if (
    inviteRows.length > 0
  ) {
    return {
      ok: false,

      status: 409,

      message:
        "A pending invitation already exists for this email",
    };
  }

  return {
    ok: true,
  };
}

function randomPartnerCodeSuffix() {
  let output = "";

  for (
    let i = 0;
    i <
    PARTNER_CODE_RANDOM_LEN;
    i++
  ) {
    const index =
      crypto.randomInt(
        0,
        PARTNER_CODE_ALPHABET.length
      );

    output +=
      PARTNER_CODE_ALPHABET[
        index
      ];
  }

  return output;
}

async function generateUniquePartnerCode() {
  for (
    let attempt = 0;
    attempt <
    PARTNER_CODE_MAX_ATTEMPTS;
    attempt++
  ) {
    const candidate =
      PARTNER_CODE_PREFIX +
      randomPartnerCodeSuffix();

    const [hits] =
      await pool.execute(
        `
          SELECT 1 AS hit

          FROM app_user_roles

          WHERE UPPER(partner_code) =
                UPPER(?)

          UNION ALL

          SELECT 1 AS hit

          FROM app_user_invitations

          WHERE UPPER(partner_code) =
                UPPER(?)

          LIMIT 1
        `,
        [
          candidate,
          candidate,
        ]
      );

    if (
      hits.length === 0
    ) {
      return candidate;
    }
  }

  throw new Error(
    "Failed to generate a unique partner code"
  );
}

async function createPendingInvite({
  email,
  firstName,
  lastName,
  phone,
  invitedRole,
  partnerCode,
  invitedByUserId,
  parentUserId,
  tokenHash,
  expiresAt,
}) {
  const invitedEmailHash =
    secureHash(email);

  const [result] =
    await pool.execute(
      `
        INSERT INTO app_user_invitations (
          invited_email,
          invited_email_hash,
          invited_first_name,
          invited_last_name,
          invited_phone,
          invited_role,
          partner_code,
          invited_by_user_id,
          parent_user_id,
          token_hash,
          status,
          expires_at,
          created_at,
          updated_at
        )

        VALUES (
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          'pending',
          ?,
          UTC_TIMESTAMP(),
          UTC_TIMESTAMP()
        )
      `,
      [
        email,
        invitedEmailHash,
        firstName,
        lastName,
        phone,
        invitedRole,
        partnerCode,
        invitedByUserId,
        parentUserId,
        tokenHash,
        expiresAt,
      ]
    );

  return Number(
    result.insertId
  );
}

async function markInviteRevoked(
  invitationId
) {
  try {
    await pool.execute(
      `
        UPDATE app_user_invitations

        SET
          status =
            'revoked',

          updated_at =
            UTC_TIMESTAMP()

        WHERE id = ?

        LIMIT 1
      `,
      [
        invitationId,
      ]
    );
  } catch (error) {
    console.error(
      "MARK_INVITE_REVOKED_FAILED:",
      error?.code ||
        error?.message
    );
  }
}

async function markInviteSent(
  invitationId
) {
  await pool.execute(
    `
      UPDATE app_user_invitations

      SET
        status =
          'pending',

        sent_at =
          UTC_TIMESTAMP(),

        updated_at =
          UTC_TIMESTAMP()

      WHERE id = ?

      LIMIT 1
    `,
    [
      invitationId,
    ]
  );
}

async function sendResendTemplateEmail(
  toEmail,
  subject,
  templateId,
  variables
) {
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
            toEmail,
          ],

          subject,

          template: {
            id:
              templateId,

            variables,
          },

          headers: {
            "X-Entity-Ref-ID":
              `invite-${variables.PARTNER_CODE}`,
          },

          tags: [
            {
              name:
                "kind",

              value:
                "invite",
            },

            {
              name:
                "invited_role",

              value:
                String(
                  variables.INVITED_ROLE ||
                    ""
                ),
            },

            {
              name:
                "template_id",

              value:
                String(
                  templateId ||
                    "inline"
                ),
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

        id:
          response.data?.id ??
          null,
      };
    }

    return {
      ok: false,

      status:
        response.status,

      error:
        response.data ??
        "Resend non-2xx response",
    };
  } catch (error) {
    return {
      ok: false,

      status: 0,

      error:
        error?.code ||
        error?.message ||
        "Resend request failed",
    };
  }
}

const superAdminInviteTrainer =
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
      req.method !== "POST"
    ) {
      return res
        .status(405)
        .json({
          ok: false,

          message:
            "Method not allowed",
        });
    }

    let invitationId =
      null;

    let actorEmail =
      null;

    let actorCode =
      null;

    try {
      /*
      |--------------------------------------------------------------------------
      | Resolve authenticated super admin
      |--------------------------------------------------------------------------
      */

      const resolved =
        await resolveActorFromToken(
          req,
          "super_admin"
        );

      if (
        resolved.error
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              "super_admin_invite_trainer_denied",

            userId:
              null,

            role:
              null,

            partnerCode:
              null,

            identifier:
              normalizeEmail(
                req.user?.email ||
                  req.user?.user_id ||
                  req.user?.dietician
                    ?.email ||
                  req.user?.sub ||
                  ""
              ),

            success:
              false,

            failureReason:
              resolved.error.body
                ?.message ||
              "actor resolution failed",
          }
        );

        return res
          .status(
            resolved.error.status
          )
          .json(
            resolved.error.body
          );
      }

      const {
        actor,
      } = resolved;

      actorEmail =
        resolved.actorEmail;

      /*
      |--------------------------------------------------------------------------
      | Cross-check actor_user_id
      |--------------------------------------------------------------------------
      |
      | The request body cannot choose another super admin.
      |--------------------------------------------------------------------------
      */

      const bodyActorUserId =
        normalizeEmail(
          req.body &&
          typeof req.body ===
            "object"
            ? req.body
                .actor_user_id
            : ""
        );

      if (
        bodyActorUserId !==
          "" &&
        bodyActorUserId !==
          actorEmail
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              "super_admin_invite_trainer_denied",

            userId:
              actorEmail,

            role:
              "super_admin",

            partnerCode:
              actor.partner_code ??
              null,

            identifier:
              actorEmail,

            success:
              false,

            failureReason:
              "actor_user_id does not match token identity",
          }
        );

        return res
          .status(403)
          .json({
            ok: false,

            message:
              "actor_user_id does not match the authenticated user",
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Super admin may legitimately have partner_code = null
      |--------------------------------------------------------------------------
      */

      actorCode =
        actor.partner_code !==
          null &&
        actor.partner_code !==
          undefined
          ? String(
              actor.partner_code
            )
          : null;

      /*
      |--------------------------------------------------------------------------
      | Server-side input validation
      |--------------------------------------------------------------------------
      |
      | This is the important CWE-20 remediation.
      |--------------------------------------------------------------------------
      */

      const validation =
        validateInviteInput(
          req.body
        );

      if (
        !validation.ok
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              "super_admin_invite_trainer_validation_failed",

            userId:
              actorEmail,

            role:
              "super_admin",

            partnerCode:
              actorCode,

            identifier:
              actorEmail,

            success:
              false,

            failureReason:
              validation.message,
          }
        );

        return res
          .status(
            validation.status
          )
          .json({
            ok: false,

            message:
              validation.message,
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Only validated values are used after this point
      |--------------------------------------------------------------------------
      */

      const {
        first_name:
          firstName,

        last_name:
          lastName,

        email,

        phone,
      } =
        validation.value;

      const phoneOrNull =
        phone !== ""
          ? phone
          : null;

      /*
      |--------------------------------------------------------------------------
      | Duplicate check
      |--------------------------------------------------------------------------
      */

      const canCreate =
        await ensureInviteCanBeCreated(
          email
        );

      if (
        !canCreate.ok
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              "super_admin_invite_trainer_duplicate",

            userId:
              actorEmail,

            role:
              "super_admin",

            partnerCode:
              actorCode,

            identifier:
              email,

            success:
              false,

            failureReason:
              canCreate.message,
          }
        );

        return res
          .status(
            canCreate.status
          )
          .json({
            ok: false,

            message:
              canCreate.message,
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Generate trainer partner code
      |--------------------------------------------------------------------------
      */

      const partnerCode =
        await generateUniquePartnerCode();

      /*
      |--------------------------------------------------------------------------
      | Generate secure invitation token
      |--------------------------------------------------------------------------
      */

      const rawToken =
        crypto
          .randomBytes(32)
          .toString("hex");

      const tokenHash =
        secureHash(
          rawToken
        );

      const inviteLink =
        `${FRONTEND_ACCEPT_INVITE_URL}?token=${encodeURIComponent(
          rawToken
        )}`;

      /*
      |--------------------------------------------------------------------------
      | Invitation expiry
      |--------------------------------------------------------------------------
      */

      const expiresAtDate =
        new Date(
          Date.now() +
            INVITE_EXPIRY_HOURS *
              60 *
              60 *
              1000
        );

      const expiresAt =
        toUtcMysqlDateTime(
          expiresAtDate
        );

      /*
      |--------------------------------------------------------------------------
      | Create pending invitation
      |--------------------------------------------------------------------------
      */

      invitationId =
        await createPendingInvite(
          {
            email,

            firstName,

            lastName,

            phone:
              phoneOrNull,

            invitedRole:
              "trainer",

            partnerCode,

            invitedByUserId:
              actorEmail,

            parentUserId:
              actorEmail,

            tokenHash,

            expiresAt,
          }
        );

      const fullName =
        `${firstName} ${lastName}`.trim();

      /*
      |--------------------------------------------------------------------------
      | Send invitation email
      |--------------------------------------------------------------------------
      |
      | User-controlled text is escaped before entering HTML templates.
      |--------------------------------------------------------------------------
      */

      const emailResult =
        await sendResendTemplateEmail(
          email,

          "You have been invited to Respyr",

          RESEND_INVITE_TEMPLATE_ID,

          {
            INVITED_NAME:
              escapeHtml(
                fullName
              ),

            INVITER_EMAIL:
              escapeHtml(
                actorEmail
              ),

            INVITED_EMAIL:
              escapeHtml(
                email
              ),

            INVITED_ROLE:
              "trainer",

            PARTNER_CODE:
              escapeHtml(
                partnerCode
              ),

            EXPIRES_IN:
              escapeHtml(
                `${INVITE_EXPIRY_HOURS} hours`
              ),

            /*
            |--------------------------------------------------------------------------
            | Server-generated URL
            |--------------------------------------------------------------------------
            */

            INVITE_LINK:
              inviteLink,
          }
        );

      /*
      |--------------------------------------------------------------------------
      | Email failure
      |--------------------------------------------------------------------------
      */

      if (
        !emailResult.ok
      ) {
        await markInviteRevoked(
          invitationId
        );

        console.error(
          "SUPER_ADMIN_TRAINER_INVITE_FAILED:",
          {
            invitation_id:
              invitationId,

            status:
              emailResult.status,

            error:
              APP_DEBUG
                ? emailResult.error
                : undefined,
          }
        );

        await writeAuthLogSafe(
          req,
          {
            eventType:
              "super_admin_invite_trainer_email_failed",

            userId:
              actorEmail,

            role:
              "super_admin",

            partnerCode:
              actorCode,

            identifier:
              email,

            success:
              false,

            failureReason:
              "resend_failed",
          }
        );

        return res
          .status(502)
          .json({
            ok: false,

            message:
              "Invitation email could not be sent",

            ...(APP_DEBUG && {
              debug_resend_error:
                emailResult,
            }),
          });
      }

      /*
      |--------------------------------------------------------------------------
      | Mark invite sent
      |--------------------------------------------------------------------------
      */

      await markInviteSent(
        invitationId
      );

      /*
      |--------------------------------------------------------------------------
      | Audit success
      |--------------------------------------------------------------------------
      */

      await writeAuthLogSafe(
        req,
        {
          eventType:
            "super_admin_trainer_invite_sent",

          userId:
            actorEmail,

          role:
            "super_admin",

          partnerCode:
            actorCode,

          identifier:
            email,

          success:
            true,

          failureReason:
            `Super admin sent trainer invite to ${email}`,
        }
      );

      /*
      |--------------------------------------------------------------------------
      | Response
      |--------------------------------------------------------------------------
      */

      const response = {
        ok: true,

        message:
          "Trainer invitation sent successfully",

        data: {
          invitation_id:
            invitationId,

          invited_first_name:
            firstName,

          invited_last_name:
            lastName,

          invited_name:
            fullName,

          invited_email:
            email,

          invited_phone:
            phoneOrNull,

          invited_role:
            "trainer",

          partner_code:
            partnerCode,

          invited_by_user_id:
            actorEmail,

          parent_user_id:
            actorEmail,

          status:
            "pending",

          expires_at:
            expiresAt,

          email_sent:
            true,
        },
      };

      /*
      |--------------------------------------------------------------------------
      | Testing only
      |--------------------------------------------------------------------------
      |
      | Keep RETURN_INVITE_LINK_FOR_TESTING=false in production.
      |--------------------------------------------------------------------------
      */

      if (
        RETURN_INVITE_LINK_FOR_TESTING
      ) {
        response.debug_invite_link =
          inviteLink;
      }

      return res
        .status(201)
        .json(response);
    } catch (error) {
      /*
      |--------------------------------------------------------------------------
      | Revoke partially-created invitation
      |--------------------------------------------------------------------------
      */

      if (
        invitationId !==
        null
      ) {
        await markInviteRevoked(
          invitationId
        );
      }

      console.error(
        "SUPER_ADMIN_INVITE_TRAINER_ERROR:",
        {
          code:
            error?.code,

          errno:
            error?.errno,

          sqlState:
            error?.sqlState,

          message:
            error?.message,
        }
      );

      await writeAuthLogSafe(
        req,
        {
          eventType:
            "super_admin_invite_trainer_error",

          userId:
            actorEmail,

          role:
            "super_admin",

          partnerCode:
            actorCode,

          identifier:
            actorEmail,

          success:
            false,

          failureReason:
            error?.code ||
            "internal_error",
        }
      );

      return res
        .status(500)
        .json({
          ok: false,

          message:
            "Internal server error",

          ...(APP_DEBUG && {
            debug_error:
              error?.message,

            debug_file:
              error?.stack
                ?.split("\n")[1]
                ?.trim(),
          }),
        });
    }
  };

module.exports = {
  superAdminInviteTrainer,
};








// "use strict";

// /**
//  * super-admin-invite-trainer.js
//  *
//  * Converted from: super-admin-invite-trainer.php
//  * Platform      : Respyr Dietitian API (api.respyr.ai)
//  * Security      : VAPT-hardened, HIPAA-aligned
//  *
//  * Endpoint   : POST /dietitian/api/web/super-admin-invite-trainer
//  * Auth       : Bearer JWT (authMiddleware must run before this handler)
//  * Authorized : super_admin only
//  *
//  * Behaviour parity with PHP:
//  *  - The super admin invites a trainer DIRECTLY under themselves
//  *    (invited_by_user_id = parent_user_id = super admin email).
//  *  - super_admin is NOT blocked when partner_code is null. In this system a
//  *    super_admin can have partner_code = null but still invites trainers.
//  *  - Creates a `pending` row in app_user_invitations with a hashed token, a
//  *    unique trainer partner_code (TRN + 7 chars), and a UTC expiry.
//  *  - Sends a templated invite email via Resend.
//  *  - On email failure, marks the invitation revoked and returns 502.
//  *  - On success, marks the invitation as sent and returns 201 with the same
//  *    JSON shape as the PHP file.
//  *
//  * Hardening differences from PHP (intentional):
//  *  - Actor identity is taken from the verified JWT (sub = dietician_id) — never
//  *    from req.body.actor_user_id. The PHP version trusted a body-supplied
//  *    `actor_user_id`, which is a privilege-escalation / IDOR vector.
//  *    actor_user_id is still accepted for frontend back-compat, but it is only
//  *    cross-checked against the token identity (mismatch → 403) and can never
//  *    select a different super_admin.
//  *  - Token is generated with crypto.randomBytes(32) and stored as a SHA-256
//  *    HMAC keyed by SECURITY_PEPPER (falling back to JWT_SECRET). The raw
//  *    token never touches the database.
//  *  - Partner code uniqueness check uses a parameterized query and retries
//  *    a bounded number of times before failing closed.
//  *  - All audit log writes use a fail-safe wrapper that hashes PHI/PII.
//  *
//  * VAPT Controls applied:
//  *  - Token-bound authorization (JWT → DB re-check on every call). A stale or
//  *    demoted super_admin cannot invite.
//  *  - Fully parameterized queries — zero string interpolation.
//  *  - Strict input validation: email RFC-like regex + length cap, name length
//  *    cap, phone digit/length cap, control-char rejection in names.
//  *  - Cache-Control: no-store, Pragma: no-cache on every response.
//  *  - Internal error details suppressed in production responses.
//  *  - Email-sending uses HTTPS to Resend, with a hard timeout and no body
//  *    echoed back to the client on success.
//  *
//  * HIPAA Controls applied:
//  *  - Minimum-necessary data: only the columns needed are selected/inserted.
//  *  - PHI (email, IP, UA) in audit logs is HMAC-SHA256 hashed with
//  *    SECURITY_PEPPER. Raw PHI never lands in app_auth_logs.
//  *  - Structured server-side logs contain only error metadata, never row data.
//  *  - Access is bound to an authenticated super_admin JWT, verified against
//  *    app_user_roles before any invite is created or any email is sent.
//  *
//  * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
//  * app_user_roles, app_user_invitations, app_auth_logs.
//  */

// const crypto = require("crypto");
// const axios  = require("axios");
// const pool   = require("../../../../config/db");
// const {
//   validateHumanName,
//   escapeHtml,
// } = require("../../../../utils/securityValidation");

// // ─── Constants ───────────────────────────────────────────────────────────────

// const SECURITY_PEPPER =
//   process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

// const INVITE_EXPIRY_HOURS = Math.max(
//   1,
//   parseInt(process.env.INVITE_EXPIRY_HOURS, 10) || 24
// );

// const FRONTEND_ACCEPT_INVITE_URL =
//   process.env.FRONTEND_ACCEPT_INVITE_URL ||
//   "https://api.rysflo.com/signup";
//   // "https://api.respyr.ai/dietitian/api/web/accept-invite";
//   // "https://app.respyr.ai/accept-invite";

// const RESEND_API_KEY            = process.env.RESEND_API_KEY            || "";
// const RESEND_INVITE_TEMPLATE_ID = process.env.RESEND_INVITE_TEMPLATE_ID || "admin_trainer_invitation";
// const RESEND_FROM_EMAIL         = process.env.RESEND_FROM_EMAIL         || "Respyr <no-reply@respyr.ai>";

// const APP_DEBUG = process.env.NODE_ENV !== "production";

// const RETURN_INVITE_LINK_FOR_TESTING =
//   String(process.env.RETURN_INVITE_LINK_FOR_TESTING || "").toLowerCase() === "true";

// // Trainer partner codes are prefixed TRN (e.g. TRN8M4P6XA) — matches the PHP
// // generateUniquePartnerCode($pdo, 'trainer') example.
// const PARTNER_CODE_PREFIX        = "TRN";
// const PARTNER_CODE_RANDOM_LEN    = 7;
// const PARTNER_CODE_MAX_ATTEMPTS  = 10;
// const PARTNER_CODE_ALPHABET      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

// const EMAIL_MAX_LENGTH = 254;
// const NAME_MAX_LENGTH  = 100;
// const PHONE_MAX_LENGTH = 20;

// // ─── Helpers ─────────────────────────────────────────────────────────────────

// function normalizeEmail(val) {
//   return typeof val === "string" ? val.trim().toLowerCase() : "";
// }

// function getClientIp(req) {
//   const ip =
//     (typeof req.ip === "string" && req.ip) ||
//     req.socket?.remoteAddress ||
//     req.connection?.remoteAddress ||
//     "0.0.0.0";
//   return String(ip).slice(0, 64);
// }

// function getUserAgent(req) {
//   const ua =
//     (typeof req.get === "function" && req.get("user-agent")) ||
//     req.headers?.["user-agent"] ||
//     "";
//   return String(ua).slice(0, 500);
// }

// function authLogHash(value) {
//   if (value === null || value === undefined) return null;
//   return crypto
//     .createHmac("sha256", SECURITY_PEPPER)
//     .update(String(value).trim().toLowerCase())
//     .digest("hex");
// }

// /**
//  * SHA-256 HMAC keyed by SECURITY_PEPPER. Used to hash invite tokens before
//  * storing them. Reversing the hash without the pepper is computationally
//  * infeasible — a DB dump alone cannot be used to accept an invite.
//  */
// function secureHash(value) {
//   return crypto
//     .createHmac("sha256", SECURITY_PEPPER)
//     .update(String(value))
//     .digest("hex");
// }

// /**
//  * Format a Date (UTC) as "YYYY-MM-DD HH:MM:SS" — matches PHP gmdate() output
//  * and the response shape expected by the frontend.
//  */
// function toUtcMysqlDateTime(date) {
//   const pad = (n) => String(n).padStart(2, "0");
//   return (
//     `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ` +
//     `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`
//   );
// }

// /**
//  * Fail-safe audit log writer. Schema mirrors writeAuthLogSafe() in the rest of
//  * this codebase. Never throws.
//  */
// async function writeAuthLogSafe(req, {
//   eventType,
//   userId,
//   role,
//   partnerCode,
//   identifier,
//   success,
//   failureReason,
// }) {
//   try {
//     const ipHash         = authLogHash(getClientIp(req));
//     const userAgentHash  = authLogHash(getUserAgent(req));
//     const identifierHash = identifier !== null && identifier !== undefined
//       ? authLogHash(identifier)
//       : null;

//     const truncatedEvent = String(eventType || "").slice(0, 60);
//     const truncatedReason =
//       failureReason !== null && failureReason !== undefined
//         ? String(failureReason).slice(0, 255)
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
//        VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
//       [
//         truncatedEvent,
//         userId ?? null,
//         role ?? null,
//         partnerCode ?? null,
//         identifierHash,
//         ipHash,
//         userAgentHash,
//         success ? 1 : 0,
//         truncatedReason,
//       ]
//     );
//   } catch (err) {
//     console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
//   }
// }

// // ─── Actor resolution ────────────────────────────────────────────────────────

// /**
//  * Re-fetch the authenticated actor from DB using the JWT subject
//  * (sub = dietician_id, with email fallback). Enforces active + super_admin.
//  * Returns { actor, actorEmail } on success or { error: { status, body } }.
//  *
//  * IMPORTANT: unlike admin-invite-trainer, this does NOT require a partner_code.
//  * In this system a super_admin can legitimately have partner_code = null and
//  * still has permission to invite trainers (PHP parity).
//  */
// async function resolveActorFromToken(req, requiredRole = "super_admin") {
//   const payload = req.user || {};

//   // This codebase's JWTs carry the dietician_id as `sub` (and `dietician_id`),
//   // with the email nested under `dietician.email` — there is NO top-level email
//   // claim. Resolve both, prefer the dietician_id (token subject), fall back to
//   // email. Mirrors resolveActorFromToken() in admin-invite-trainer.js.
//   const dieticianId = String(payload.sub || payload.dietician_id || "").trim();
//   const tokenEmail  = normalizeEmail(
//     payload.email || payload.user_id || payload?.dietician?.email || ""
//   );

//   if ((!dieticianId || dieticianId.length > 64) && tokenEmail === "") {
//     return {
//       error: {
//         status: 401,
//         body: { ok: false, message: "Invalid token user" },
//       },
//     };
//   }

//   // Prefer dietician_id (token subject); fall back to email.
//   const [rows] = dieticianId
//     ? await pool.execute(
//         `
//           SELECT
//             td.id,
//             td.dietician_id,
//             td.email,
//             aur.user_id,
//             aur.role,
//             aur.partner_code,
//             aur.parent_user_id,
//             aur.status
//           FROM table_dietician td
//           INNER JOIN app_user_roles aur
//             ON LOWER(aur.user_id) = LOWER(td.email)
//           WHERE td.dietician_id = ?
//           LIMIT 1
//         `,
//         [dieticianId]
//       )
//     : await pool.execute(
//         `
//           SELECT
//             td.id,
//             td.dietician_id,
//             td.email,
//             aur.user_id,
//             aur.role,
//             aur.partner_code,
//             aur.parent_user_id,
//             aur.status
//           FROM table_dietician td
//           INNER JOIN app_user_roles aur
//             ON LOWER(aur.user_id) = LOWER(td.email)
//           WHERE LOWER(td.email) = LOWER(?)
//           LIMIT 1
//         `,
//         [tokenEmail]
//       );

//   const actor = rows[0];

//   if (!actor) {
//     return {
//       error: {
//         status: 401,
//         body: { ok: false, message: "Token user not found" },
//       },
//     };
//   }

//   if (String(actor.status) !== "active") {
//     return {
//       error: {
//         status: 403,
//         body: { ok: false, message: "Account is not active" },
//       },
//     };
//   }

//   if (String(actor.role) !== requiredRole) {
//     return {
//       error: {
//         status: 403,
//         body: { ok: false, message: "You are not allowed to perform this action" },
//       },
//     };
//   }

//   return { actor, actorEmail: normalizeEmail(actor.user_id || actor.email) };
// }

// // ─── Input validation ────────────────────────────────────────────────────────

// /**
//  * Mirrors PHP validateInviteInput(). Returns { ok: true, value } or
//  * { ok: false, status, message }.
//  */
// function validateInviteInput(body) {
//   if (!body || typeof body !== "object") {
//     return { ok: false, status: 400, message: "Invalid request body" };
//   }

//   // const firstName = typeof body.first_name === "string"
//   //   ? body.first_name.trim()
//   //   : "";
//   // const lastName = typeof body.last_name === "string"
//   //   ? body.last_name.trim()
//   //   : "";


//   const firstNameResult =
//   validateHumanName(
//     body.first_name,
//     "first_name"
//   );

// if (!firstNameResult.ok) {
//   return {
//     ok: false,
//     status: 400,
//     message: firstNameResult.message,
//   };
// }

// const lastNameResult =
//   validateHumanName(
//     body.last_name,
//     "last_name"
//   );

// if (!lastNameResult.ok) {
//   return {
//     ok: false,
//     status: 400,
//     message: lastNameResult.message,
//   };
// }

// const firstName =
//   firstNameResult.value;

// const lastName =
//   lastNameResult.value;


//   /*
//   |--------------------------------------------------------------------------
//   | Email
//   |--------------------------------------------------------------------------
//   */


//   const email = normalizeEmail(body.email);
//   const phoneRaw = body.phone === null || body.phone === undefined
//     ? ""
//     : String(body.phone).trim();

//   if (!firstName || firstName.length > NAME_MAX_LENGTH) {
//     return { ok: false, status: 400, message: "first_name is required" };
//   }
//   if (!lastName || lastName.length > NAME_MAX_LENGTH) {
//     return { ok: false, status: 400, message: "last_name is required" };
//   }

//   // Disallow control chars in names — defends against CRLF injection
//   // and bidi-override smuggling into downstream email templates.
//   // eslint-disable-next-line no-control-regex
//   const nameSafeRegex = /^[^\x00-\x1f\x7f]+$/;
//   if (!nameSafeRegex.test(firstName) || !nameSafeRegex.test(lastName)) {
//     return { ok: false, status: 400, message: "Names contain invalid characters" };
//   }

//   if (!email || email.length > EMAIL_MAX_LENGTH) {
//     return { ok: false, status: 400, message: "email is required" };
//   }
//   const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
//   if (!emailRegex.test(email)) {
//     return { ok: false, status: 400, message: "Invalid email format" };
//   }

//   let phone = "";
//   if (phoneRaw !== "") {
//     // Strip everything except + and digits, then enforce length cap.
//     phone = phoneRaw.replace(/[^\d+]/g, "");
//     if (phone.length === 0 || phone.length > PHONE_MAX_LENGTH) {
//       return { ok: false, status: 400, message: "Invalid phone number" };
//     }
//   }

//   return {
//     ok: true,
//     value: { first_name: firstName, last_name: lastName, email, phone },
//   };
// }

// // ─── Pre-flight checks ───────────────────────────────────────────────────────

// /**
//  * Mirrors PHP ensureInviteCanBeCreated(). Refuses if the email already maps
//  * to an active role OR has an outstanding pending invite that has not
//  * expired.
//  */
// async function ensureInviteCanBeCreated(email) {
//   const [roleRows] = await pool.execute(
//     `
//       SELECT id
//       FROM app_user_roles
//       WHERE LOWER(user_id) = LOWER(?)
//       LIMIT 1
//     `,
//     [email]
//   );

//   if (roleRows.length > 0) {
//     return {
//       ok: false,
//       status: 409,
//       message: "A user with this email already exists",
//     };
//   }

//   const [inviteRows] = await pool.execute(
//     `
//       SELECT id
//       FROM app_user_invitations
//       WHERE LOWER(invited_email) = LOWER(?)
//         AND status     = 'pending'
//         AND expires_at > UTC_TIMESTAMP()
//       LIMIT 1
//     `,
//     [email]
//   );

//   if (inviteRows.length > 0) {
//     return {
//       ok: false,
//       status: 409,
//       message: "A pending invitation already exists for this email",
//     };
//   }

//   return { ok: true };
// }

// // ─── Partner code generation ─────────────────────────────────────────────────

// function randomPartnerCodeSuffix() {
//   // Use crypto.randomInt for unbiased selection over PARTNER_CODE_ALPHABET.
//   let out = "";
//   for (let i = 0; i < PARTNER_CODE_RANDOM_LEN; i++) {
//     const idx = crypto.randomInt(0, PARTNER_CODE_ALPHABET.length);
//     out += PARTNER_CODE_ALPHABET[idx];
//   }
//   return out;
// }

// /**
//  * Returns a partner_code that does not collide with any existing row in
//  * app_user_roles or app_user_invitations. Bounded retry — fails closed
//  * after PARTNER_CODE_MAX_ATTEMPTS rather than looping forever.
//  */
// async function generateUniquePartnerCode() {
//   for (let attempt = 0; attempt < PARTNER_CODE_MAX_ATTEMPTS; attempt++) {
//     const candidate = PARTNER_CODE_PREFIX + randomPartnerCodeSuffix();

//     const [hits] = await pool.execute(
//       `
//         SELECT 1 AS hit
//         FROM app_user_roles
//         WHERE UPPER(partner_code) = UPPER(?)
//         UNION ALL
//         SELECT 1 AS hit
//         FROM app_user_invitations
//         WHERE UPPER(partner_code) = UPPER(?)
//         LIMIT 1
//       `,
//       [candidate, candidate]
//     );

//     if (hits.length === 0) {
//       return candidate;
//     }
//   }

//   throw new Error("Failed to generate a unique partner code");
// }

// // ─── Invitation row helpers ──────────────────────────────────────────────────

// async function createPendingInvite({
//   email,
//   firstName,
//   lastName,
//   phone,
//   invitedRole,
//   partnerCode,
//   invitedByUserId,
//   parentUserId,
//   tokenHash,
//   expiresAt,
// }) {
//   // invited_email_hash is a NOT-NULL column on app_user_invitations. Store a
//   // deterministic keyed hash of the email (same HMAC the token uses) so it is
//   // consistent and non-reversible without the pepper.
//   const invitedEmailHash = secureHash(email);

//   const [result] = await pool.execute(
//     `
//       INSERT INTO app_user_invitations (
//         invited_email,
//         invited_email_hash,
//         invited_first_name,
//         invited_last_name,
//         invited_phone,
//         invited_role,
//         partner_code,
//         invited_by_user_id,
//         parent_user_id,
//         token_hash,
//         status,
//         expires_at,
//         created_at,
//         updated_at
//       )
//       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, UTC_TIMESTAMP(), UTC_TIMESTAMP())
//     `,
//     [
//       email,
//       invitedEmailHash,
//       firstName,
//       lastName,
//       phone,
//       invitedRole,
//       partnerCode,
//       invitedByUserId,
//       parentUserId,
//       tokenHash,
//       expiresAt,
//     ]
//   );

//   return Number(result.insertId);
// }

// async function markInviteRevoked(invitationId) {
//   try {
//     await pool.execute(
//       `
//         UPDATE app_user_invitations
//         SET status     = 'revoked',
//             updated_at = UTC_TIMESTAMP()
//         WHERE id = ?
//         LIMIT 1
//       `,
//       [invitationId]
//     );
//   } catch (err) {
//     console.error("MARK_INVITE_REVOKED_FAILED:", err?.code || err?.message);
//   }
// }

// async function markInviteSent(invitationId) {
//   await pool.execute(
//     `
//       UPDATE app_user_invitations
//       SET status     = 'pending',
//           sent_at    = UTC_TIMESTAMP(),
//           updated_at = UTC_TIMESTAMP()
//       WHERE id = ?
//       LIMIT 1
//     `,
//     [invitationId]
//   );
// }

// // ─── Email via Resend ────────────────────────────────────────────────────────

// /**
//  * Sends the invite email via Resend's /emails endpoint. Returns
//  * { ok: boolean, status?: number, error?: any }.
//  *
//  * Sends via the published Resend "admin_trainer_invitation" template
//  * (template id + variables). Resend substitutes the {{{VAR}}} placeholders
//  * server-side, so no HTML is rendered in this service.
//  */
// async function sendResendTemplateEmail(toEmail, subject, templateId, vars) {
//   if (!RESEND_API_KEY) {
//     return { ok: false, status: 0, error: "RESEND_API_KEY not configured" };
//   }

//   try {

//     const response = await axios.post(
//       "https://api.resend.com/emails",
//       {
//         from:    RESEND_FROM_EMAIL,
//         to:      [toEmail],
//         subject: subject,
//         // Send via the published Resend "admin_trainer_invitation" template.
//         // Resend rejects html/text/react when a template is supplied; every
//         // {{VAR}} the template uses must be present in `vars` or Resend
//         // returns 422 (extra variables are ignored). from/subject here
//         // override the template's own defaults.
//         template: {
//           id: templateId,
//           variables: vars,
//         },
//         headers: {
//           // Aids deliverability / threading in the recipient's client.
//           "X-Entity-Ref-ID": `invite-${vars.PARTNER_CODE}`,
//         },
//         tags: [
//           { name: "kind",         value: "invite" },
//           { name: "invited_role", value: String(vars.INVITED_ROLE || "") },
//           { name: "template_id",  value: String(templateId || "inline") },
//         ],
//       },
//       {
//         timeout: 10_000,
//         headers: {
//           Authorization: `Bearer ${RESEND_API_KEY}`,
//           "Content-Type": "application/json",
//         },
//         // Treat any non-2xx as a failure here; don't throw on 4xx.
//         validateStatus: () => true,
//       }
//     );

//     if (response.status >= 200 && response.status < 300) {
//       return { ok: true, status: response.status, id: response.data?.id ?? null };
//     }

//     return {
//       ok: false,
//       status: response.status,
//       error: response.data ?? "Resend non-2xx response",
//     };
//   } catch (err) {
//     return {
//       ok: false,
//       status: 0,
//       error: err?.code || err?.message || "Resend request failed",
//     };
//   }
// }

// // ─── Controller ──────────────────────────────────────────────────────────────

// /**
//  * POST /dietitian/api/web/super-admin-invite-trainer
//  *
//  * Body:
//  *   {
//  *     "first_name": "poornesh",
//  *     "last_name":  "kumar",
//  *     "email":      "poornesh@respyr.ai",
//  *     "phone":      "8520046632589"   // optional
//  *   }
//  *
//  * Auth: Bearer JWT with role=super_admin
//  */
// const superAdminInviteTrainer = async (req, res) => {
//   // HIPAA: never let intermediaries cache PHI-adjacent responses.
//   res.setHeader("Cache-Control", "no-store");
//   res.setHeader("Pragma", "no-cache");

//   // VAPT: method gate (matches PHP behavior).
//   if (req.method !== "POST") {
//     return res.status(405).json({
//       ok:      false,
//       message: "Method not allowed",
//     });
//   }

//   let invitationId = null;
//   let actorEmail   = null;
//   let actorCode    = null;

//   try {
//     // ── 1. Resolve actor from JWT + DB (super_admin only) ──────────────────
//     const resolved = await resolveActorFromToken(req, "super_admin");

//     if (resolved.error) {
//       await writeAuthLogSafe(req, {
//         eventType:     "super_admin_invite_trainer_denied",
//         userId:        null,
//         role:          null,
//         partnerCode:   null,
//         identifier:    normalizeEmail(
//           req.user?.email ||
//           req.user?.user_id ||
//           req.user?.dietician?.email ||
//           req.user?.sub ||
//           ""
//         ),
//         success:       false,
//         failureReason: resolved.error.body?.message || "actor resolution failed",
//       });

//       return res.status(resolved.error.status).json(resolved.error.body);
//     }

//     const { actor } = resolved;
//     actorEmail = resolved.actorEmail;

//     // ── 1b. Cross-check optional actor_user_id against the token identity ──
//     // The PHP took the actor FROM the body. We keep `actor_user_id` in the
//     // payload for frontend back-compat, but it is only ever cross-checked
//     // against the JWT — it can never select a different super_admin (privilege
//     // escalation / IDOR). Mismatch → 403.
//     const bodyActorUserId = normalizeEmail(
//       req.body && typeof req.body === "object" ? req.body.actor_user_id : ""
//     );

//     if (bodyActorUserId !== "" && bodyActorUserId !== actorEmail) {
//       await writeAuthLogSafe(req, {
//         eventType:     "super_admin_invite_trainer_denied",
//         userId:        actorEmail,
//         role:          "super_admin",
//         partnerCode:   actor.partner_code ?? null,
//         identifier:    actorEmail,
//         success:       false,
//         failureReason: "actor_user_id does not match token identity",
//       });

//       return res.status(403).json({
//         ok:      false,
//         message: "actor_user_id does not match the authenticated user",
//       });
//     }

//     // ── 1c. PHP parity: do NOT block super_admin when partner_code is null ──
//     // A super_admin may legitimately have partner_code = null and still invite
//     // trainers. We capture it (may be null) for the audit log only.
//     actorCode = actor.partner_code !== null && actor.partner_code !== undefined
//       ? String(actor.partner_code)
//       : null;

//     // ── 2. Validate input ──────────────────────────────────────────────────
//     const validation = validateInviteInput(req.body);

//     if (!validation.ok) {
//       await writeAuthLogSafe(req, {
//         eventType:     "super_admin_invite_trainer_validation_failed",
//         userId:        actorEmail,
//         role:          "super_admin",
//         partnerCode:   actorCode,
//         identifier:    actorEmail,
//         success:       false,
//         failureReason: validation.message,
//       });

//       return res.status(validation.status).json({
//         ok:      false,
//         message: validation.message,
//       });
//     }

//     const { first_name: firstName, last_name: lastName, email, phone } =
//       validation.value;
//     const phoneOrNull = phone !== "" ? phone : null;

//     // ── 3. Pre-flight: no duplicate / no live pending invite ───────────────
//     const canCreate = await ensureInviteCanBeCreated(email);

//     if (!canCreate.ok) {
//       await writeAuthLogSafe(req, {
//         eventType:     "super_admin_invite_trainer_duplicate",
//         userId:        actorEmail,
//         role:          "super_admin",
//         partnerCode:   actorCode,
//         identifier:    email,
//         success:       false,
//         failureReason: canCreate.message,
//       });

//       return res.status(canCreate.status).json({
//         ok:      false,
//         message: canCreate.message,
//       });
//     }

//     // ── 4. Generate trainer partner code + invite token ────────────────────
//     const partnerCode = await generateUniquePartnerCode();

//     const rawToken  = crypto.randomBytes(32).toString("hex");
//     const tokenHash = secureHash(rawToken);

//     const inviteLink =
//       `${FRONTEND_ACCEPT_INVITE_URL}?token=${encodeURIComponent(rawToken)}`;

//     const expiresAtDate = new Date(
//       Date.now() + INVITE_EXPIRY_HOURS * 60 * 60 * 1000
//     );
//     const expiresAt = toUtcMysqlDateTime(expiresAtDate);

//     // ── 5. Insert pending invite row ───────────────────────────────────────
//     // Trainer is directly under the super admin:
//     //   invited_by_user_id = parent_user_id = super admin email.
//     invitationId = await createPendingInvite({
//       email,
//       firstName,
//       lastName,
//       phone: phoneOrNull,
//       invitedRole:     "trainer",
//       partnerCode,
//       invitedByUserId: actorEmail,
//       parentUserId:    actorEmail,
//       tokenHash,
//       expiresAt,
//     });

//     // const fullName = `${firstName} ${lastName}`.trim();

//     const fullName =
//   `${firstName} ${lastName}`.trim();

// const safeFullName =
//   escapeHtml(fullName);

// const safeInviterEmail =
//   escapeHtml(actorEmail);

// const safeInvitedEmail =
//   escapeHtml(email);

//     // ── 6. Send the email ──────────────────────────────────────────────────
//     // const emailResult = await sendResendTemplateEmail(
//     //   email,
//     //   "You have been invited to Respyr",
//     //   RESEND_INVITE_TEMPLATE_ID,
//     //   {
//     //     INVITED_NAME:   fullName,
//     //     INVITER_EMAIL:  actorEmail,
//     //     INVITED_EMAIL:  email,
//     //     INVITED_ROLE:   "trainer",
//     //     PARTNER_CODE:   partnerCode,
//     //     EXPIRES_IN:     `${INVITE_EXPIRY_HOURS} hours`,
//     //     INVITE_LINK:    inviteLink,
//     //   }
//     // );


//     const emailResult =
//   await sendResendTemplateEmail(
//     email,
//     "You have been invited to Respyr",
//     RESEND_INVITE_TEMPLATE_ID,
//     {
//       INVITED_NAME:
//         safeFullName,

//       INVITER_EMAIL:
//         safeInviterEmail,

//       INVITED_EMAIL:
//         safeInvitedEmail,

//       INVITED_ROLE:
//         "trainer",

//       PARTNER_CODE:
//         escapeHtml(partnerCode),

//       EXPIRES_IN:
//         escapeHtml(
//           `${INVITE_EXPIRY_HOURS} hours`
//         ),

//       /*
//       |--------------------------------------------------------------------------
//       | Invite link
//       |--------------------------------------------------------------------------
//       |
//       | Don't run a URL through generic human-name validation.
//       | This URL is server-generated, not user-controlled.
//       |--------------------------------------------------------------------------
//       */

//       INVITE_LINK:
//         inviteLink,
//     }
//   );



//     if (!emailResult.ok) {
//       await markInviteRevoked(invitationId);

//       console.error("SUPER_ADMIN_TRAINER_INVITE_FAILED:", {
//         invitation_id: invitationId,
//         status:        emailResult.status,
//         error:         APP_DEBUG ? emailResult.error : undefined,
//       });

//       await writeAuthLogSafe(req, {
//         eventType:     "super_admin_invite_trainer_email_failed",
//         userId:        actorEmail,
//         role:          "super_admin",
//         partnerCode:   actorCode,
//         identifier:    email,
//         success:       false,
//         failureReason: "resend_failed",
//       });

//       return res.status(502).json({
//         ok:      false,
//         message: "Invitation email could not be sent",
//         ...(APP_DEBUG && { debug_resend_error: emailResult }),
//       });
//     }

//     // ── 7. Mark invite as sent ─────────────────────────────────────────────
//     await markInviteSent(invitationId);

//     // ── 8. Audit — success ────────────────────────────────────────────────
//     await writeAuthLogSafe(req, {
//       eventType:     "super_admin_trainer_invite_sent",
//       userId:        actorEmail,
//       role:          "super_admin",
//       partnerCode:   actorCode,
//       identifier:    email,
//       success:       true,
//       failureReason: `Super admin sent trainer invite to ${email}`,
//     });

//     // ── 9. Respond (matches PHP JSON shape exactly) ────────────────────────
//     const response = {
//       ok:      true,
//       message: "Trainer invitation sent successfully",
//       data: {
//         invitation_id:       invitationId,
//         invited_first_name:  firstName,
//         invited_last_name:   lastName,
//         invited_name:        fullName,
//         invited_email:       email,
//         invited_phone:       phoneOrNull,
//         invited_role:        "trainer",

//         // This is the new trainer's generated code.
//         partner_code:        partnerCode,

//         // Super admin is inviter and parent.
//         invited_by_user_id:  actorEmail,
//         parent_user_id:      actorEmail,

//         status:              "pending",
//         expires_at:          expiresAt,
//         email_sent:          true,
//       },
//     };

//     if (RETURN_INVITE_LINK_FOR_TESTING) {
//       response.debug_invite_link = inviteLink;
//     }

//     return res.status(201).json(response);

//   } catch (err) {
//     // Defense in depth: if we created an invite row before crashing, revoke it
//     // so a half-finished invite cannot be silently activated later.
//     if (invitationId !== null) {
//       await markInviteRevoked(invitationId);
//     }

//     console.error("SUPER_ADMIN_INVITE_TRAINER_ERROR:", {
//       code:     err?.code,
//       errno:    err?.errno,
//       sqlState: err?.sqlState,
//       message:  err?.message,
//     });

//     await writeAuthLogSafe(req, {
//       eventType:     "super_admin_invite_trainer_error",
//       userId:        actorEmail,
//       role:          "super_admin",
//       partnerCode:   actorCode,
//       identifier:    actorEmail,
//       success:       false,
//       failureReason: err?.code || "internal_error",
//     });

//     return res.status(500).json({
//       ok:      false,
//       message: "Internal server error",
//       ...(APP_DEBUG && {
//         debug_error: err?.message,
//         debug_file:  err?.stack?.split("\n")[1]?.trim(),
//       }),
//     });
//   }
// };

// module.exports = { superAdminInviteTrainer };