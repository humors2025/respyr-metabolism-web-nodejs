"use strict";

/**
 * accept-invite.js
 *
 * Endpoint   : POST /dietitian/api/web/accept-invite
 * Auth       : NONE
 *
 * Updated flow with S3 agreement PDF:
 *   1. Frontend uploads agreement PDF to S3 using signed upload URL.
 *   2. Frontend sends agreement_s3_key + agreement_pdf_name to this API.
 *   3. Backend checks that PDF exists in S3.
 *   4. Backend accepts invite.
 *   5. Backend inserts PDF reference into agreement_terms_conditions table.
 */

const bcrypt = require("bcryptjs");
const pool = require("../../../../config/db");

const { HeadObjectCommand } = require("@aws-sdk/client-s3");
const { s3, AGREEMENT_S3_BUCKET } = require("../../../../config/s3");

const {
  APP_DEBUG,
  applySecurityHeaders,
  sendJson,
  ensurePostOrReject,
  getJsonBody,
  validateServerConfig,
  normalizeEmail,
  cleanName,
  cleanPhone,
  secureHash,
  writeAuthLogSafe,
} = require("./auth_common");

const BCRYPT_ROUNDS = 12;
const PASSWORD_MAX_BYTES = 72;

const EMAIL_MAX_LENGTH = 150;
const PHONE_MAX_LENGTH = 15;
const PARTNER_CODE_MAX_LENGTH = 10;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateInvitePassword(password) {
  if (typeof password !== "string" || password.length < 10) {
    return {
      ok: false,
      status: 400,
      message: "Password must be at least 10 characters",
    };
  }

  if (Buffer.byteLength(password, "utf8") > PASSWORD_MAX_BYTES) {
    return {
      ok: false,
      status: 400,
      message: "Password is too long (max 72 bytes)",
    };
  }

  if (!/[A-Z]/.test(password)) {
    return {
      ok: false,
      status: 400,
      message: "Password must contain at least one uppercase letter",
    };
  }

  if (!/[a-z]/.test(password)) {
    return {
      ok: false,
      status: 400,
      message: "Password must contain at least one lowercase letter",
    };
  }

  if (!/[0-9]/.test(password)) {
    return {
      ok: false,
      status: 400,
      message: "Password must contain at least one number",
    };
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    return {
      ok: false,
      status: 400,
      message: "Password must contain at least one special character",
    };
  }

  return { ok: true };
}

async function ensureFeaturesAllowForDietician(conn, dieticianIdRaw) {
  const dieticianId = String(dieticianIdRaw || "").trim().toUpperCase();

  if (dieticianId === "") {
    return {
      ok: false,
      status: 409,
      message: "Invalid dietician_id for features_allow",
    };
  }

  const [existing] = await conn.execute(
    `
      SELECT id
      FROM features_allow
      WHERE UPPER(dietician_id) = UPPER(?)
      LIMIT 1
      FOR UPDATE
    `,
    [dieticianId]
  );

  if (existing.length > 0) {
    await conn.execute(
      `
        UPDATE features_allow
        SET test_allow = 1,
            multiple_reading = 1,
            practice_test_allow = 1,
            detailed_scores = 1
        WHERE UPPER(dietician_id) = UPPER(?)
      `,
      [dieticianId]
    );

    return { ok: true };
  }

  await conn.execute(
    `
      INSERT INTO features_allow (
        dietician_id,
        test_allow,
        multiple_reading,
        practice_test_allow,
        detailed_scores
      )
      VALUES (?, 1, 1, 1, 1)
    `,
    [dieticianId]
  );

  return { ok: true };
}

const acceptInvite = async (req, res) => {
  applySecurityHeaders(res);

  if (ensurePostOrReject(req, res)) return;

  const cfg = validateServerConfig();

  if (!cfg.ok) {
    return sendJson(res, cfg.status, {
      ok: false,
      message: cfg.message,
      ...(cfg.missing && cfg.missing.length ? { missing: cfg.missing } : {}),
    });
  }

  const parsed = getJsonBody(req);

  if (!parsed.ok) {
    return sendJson(res, parsed.status, {
      ok: false,
      message: parsed.message,
    });
  }

  const body = parsed.body;

  const token = typeof body.token === "string" ? body.token.trim() : "";

  const password =
    body.password === null || body.password === undefined
      ? ""
      : String(body.password);

  const confirmPassword =
    body.confirm_password === null || body.confirm_password === undefined
      ? ""
      : String(body.confirm_password);

  const agreementS3Key =
    typeof body.agreement_s3_key === "string"
      ? body.agreement_s3_key.trim()
      : "";

  const agreementPdfName =
    typeof body.agreement_pdf_name === "string"
      ? body.agreement_pdf_name.trim().slice(0, 255)
      : "";

  if (token === "") {
    return sendJson(res, 400, {
      ok: false,
      message: "Invite token is required",
    });
  }

  if (password === "" || confirmPassword === "") {
    return sendJson(res, 400, {
      ok: false,
      message: "Password and confirm password are required",
    });
  }

  if (password !== confirmPassword) {
    return sendJson(res, 400, {
      ok: false,
      message: "Password and confirm password do not match",
    });
  }

  const pwCheck = validateInvitePassword(password);

  if (!pwCheck.ok) {
    return sendJson(res, pwCheck.status, {
      ok: false,
      message: pwCheck.message,
    });
  }

  const tokenHash = secureHash(token);

  let conn = null;

  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [inviteRows] = await conn.execute(
      `
        SELECT
          id,
          invited_email,
          invited_first_name,
          invited_last_name,
          invited_phone,
          invited_role,
          partner_code,
          parent_user_id,
          status,
          (expires_at <= UTC_TIMESTAMP()) AS is_expired
        FROM app_user_invitations
        WHERE token_hash = ?
        LIMIT 1
        FOR UPDATE
      `,
      [tokenHash]
    );

    const invite = inviteRows[0];

    if (!invite) {
      await conn.rollback();
      conn.release();
      conn = null;

      await writeAuthLogSafe(req, {
        eventType: "invite_accept_failed",
        userId: null,
        role: null,
        partnerCode: null,
        identifier: null,
        success: false,
        failureReason: "invalid_token",
      });

      return sendJson(res, 404, {
        ok: false,
        message: "Invalid invitation link",
      });
    }

    if (String(invite.status) !== "pending") {
      await conn.rollback();
      conn.release();
      conn = null;

      await writeAuthLogSafe(req, {
        eventType: "invite_accept_failed",
        userId: null,
        role: String(invite.invited_role || ""),
        partnerCode: invite.partner_code ?? null,
        identifier: invite.invited_email ?? null,
        success: false,
        failureReason: `status_${invite.status}`,
      });

      return sendJson(res, 409, {
        ok: false,
        message: "Invitation is already used or no longer valid",
      });
    }

    if (Number(invite.is_expired) === 1) {
      await conn.execute(
        `
          UPDATE app_user_invitations
          SET status = 'expired',
              updated_at = UTC_TIMESTAMP()
          WHERE id = ?
          LIMIT 1
        `,
        [invite.id]
      );

      await conn.commit();
      conn.release();
      conn = null;

      await writeAuthLogSafe(req, {
        eventType: "invite_accept_failed",
        userId: null,
        role: String(invite.invited_role || ""),
        partnerCode: invite.partner_code ?? null,
        identifier: invite.invited_email ?? null,
        success: false,
        failureReason: "expired",
      });

      return sendJson(res, 410, {
        ok: false,
        message: "Invitation link has expired",
      });
    }

    /**
     * Agreement PDF validation.
     *
     * This API now requires frontend to upload PDF to S3 first,
     * then send agreement_s3_key to this accept-invite API.
     */
    if (!AGREEMENT_S3_BUCKET) {
      await conn.rollback();
      conn.release();
      conn = null;

      return sendJson(res, 500, {
        ok: false,
        message: "Agreement S3 bucket is not configured",
      });
    }

    if (!agreementS3Key) {
      await conn.rollback();
      conn.release();
      conn = null;

      return sendJson(res, 400, {
        ok: false,
        message: "Agreement PDF is required",
      });
    }

    const expectedAgreementPrefix = `agreements/pending/${invite.id}/`;

    if (
      !agreementS3Key.startsWith(expectedAgreementPrefix) ||
      !agreementS3Key.endsWith(".pdf")
    ) {
      await conn.rollback();
      conn.release();
      conn = null;

      return sendJson(res, 400, {
        ok: false,
        message: "Invalid agreement PDF reference",
      });
    }

    let agreementObjectInfo;

    try {
      agreementObjectInfo = await s3.send(
        new HeadObjectCommand({
          Bucket: AGREEMENT_S3_BUCKET,
          Key: agreementS3Key,
        })
      );
    } catch (s3Err) {
      await conn.rollback();
      conn.release();
      conn = null;

      console.error("AGREEMENT_S3_HEAD_ERROR:", {
        code: s3Err?.code,
        name: s3Err?.name,
        message: s3Err?.message,
      });

      return sendJson(res, 400, {
        ok: false,
        message: "Agreement PDF was not uploaded",
      });
    }

    const email = normalizeEmail(invite.invited_email);
    const role = String(invite.invited_role || "");
    const partnerCode = String(invite.partner_code || "").toUpperCase();
    const parentUserId = normalizeEmail(invite.parent_user_id);

    const firstName = cleanName(invite.invited_first_name);
    const lastName = cleanName(invite.invited_last_name);

    const phoneResult = cleanPhone(invite.invited_phone);
    const phone = phoneResult.ok ? phoneResult.value : "";

    let fullName = `${firstName} ${lastName}`.trim();
    if (fullName === "") fullName = "User";

    const fail409 = async (message, reason) => {
      await conn.rollback();
      conn.release();
      conn = null;

      await writeAuthLogSafe(req, {
        eventType: "invite_accept_failed",
        userId: null,
        role,
        partnerCode,
        identifier: email,
        success: false,
        failureReason: reason,
      });

      return sendJson(res, 409, {
        ok: false,
        message,
      });
    };

    if (email === "" || !EMAIL_REGEX.test(email)) {
      return await fail409("Invalid invitation email", "invalid_email");
    }

    if (email.length > EMAIL_MAX_LENGTH) {
      await conn.rollback();
      conn.release();
      conn = null;

      return sendJson(res, 400, {
        ok: false,
        message: "Email must be maximum 150 characters",
      });
    }

    if (phone !== "" && phone.length > PHONE_MAX_LENGTH) {
      await conn.rollback();
      conn.release();
      conn = null;

      return sendJson(res, 400, {
        ok: false,
        message: "Phone number must be maximum 15 characters",
      });
    }

    if (role !== "admin" && role !== "trainer") {
      return await fail409("Invalid invitation role", "invalid_role");
    }

    if (partnerCode === "" || partnerCode.length > PARTNER_CODE_MAX_LENGTH) {
      return await fail409("Invalid partner code", "invalid_partner_code");
    }

    if (parentUserId === "") {
      return await fail409("Invalid parent user", "invalid_parent_user");
    }

    const [roleExists] = await conn.execute(
      `
        SELECT id
        FROM app_user_roles
        WHERE LOWER(user_id) = LOWER(?)
        LIMIT 1
        FOR UPDATE
      `,
      [email]
    );

    if (roleExists.length > 0) {
      return await fail409("This account is already active", "role_exists");
    }

    const [codeExists] = await conn.execute(
      `
        SELECT id
        FROM app_user_roles
        WHERE UPPER(partner_code) = UPPER(?)
        LIMIT 1
        FOR UPDATE
      `,
      [partnerCode]
    );

    if (codeExists.length > 0) {
      return await fail409("Partner code is already active", "partner_code_active");
    }

    const [dieticianByCode] = await conn.execute(
      `
        SELECT id, email
        FROM table_dietician
        WHERE UPPER(dietician_id) = UPPER(?)
        LIMIT 1
        FOR UPDATE
      `,
      [partnerCode]
    );

    if (
      dieticianByCode.length > 0 &&
      normalizeEmail(dieticianByCode[0].email) !== email
    ) {
      return await fail409(
        "Partner code already exists with another email",
        "code_email_conflict"
      );
    }

    const dieticianId = partnerCode;
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const phoneOrNa = phone !== "" ? phone : "NA";

    const [existingDietRows] = await conn.execute(
      `
        SELECT id, dietician_id, email
        FROM table_dietician
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
        FOR UPDATE
      `,
      [email]
    );

    const existingDietician = existingDietRows[0];

    if (existingDietician) {
      if (
        String(existingDietician.dietician_id || "").toUpperCase() !==
        dieticianId.toUpperCase()
      ) {
        return await fail409(
          "Email already exists with different partner code",
          "email_code_conflict"
        );
      }

      await conn.execute(
        `
          UPDATE table_dietician
          SET name = ?,
              phone_no = ?,
              email = ?,
              password = ?,
              is_reset_password = 1
          WHERE id = ?
          LIMIT 1
        `,
        [fullName, phoneOrNa, email, passwordHash, existingDietician.id]
      );
    } else {
      await conn.execute(
        `
          INSERT INTO table_dietician (
            dietician_id,
            name,
            phone_no,
            email,
            location,
            logo,
            dttm,
            password,
            is_reset_password
          )
          VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP(), ?, 1)
        `,
        [dieticianId, fullName, phoneOrNa, email, "NA", "", passwordHash]
      );
    }

    const featuresResult = await ensureFeaturesAllowForDietician(conn, dieticianId);

    if (!featuresResult.ok) {
      await conn.rollback();
      conn.release();
      conn = null;

      return sendJson(res, featuresResult.status, {
        ok: false,
        message: featuresResult.message,
      });
    }

    await conn.execute(
      `
        INSERT INTO app_user_roles (
          user_id,
          role,
          partner_code,
          parent_user_id,
          status,
          email_verified_at,
          created_at,
          updated_at
        )
        VALUES (?, ?, ?, ?, 'active', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())
      `,
      [email, role, partnerCode, parentUserId]
    );

    await conn.execute(
      `
        UPDATE app_user_invitations
        SET status = 'accepted',
            accepted_at = UTC_TIMESTAMP(),
            updated_at = UTC_TIMESTAMP()
        WHERE id = ?
        LIMIT 1
      `,
      [invite.id]
    );

    /**
     * Save agreement PDF reference in new table.
     *
     * Actual PDF file is stored in S3.
     * MySQL stores only the S3 bucket/key and related metadata.
     */
    await conn.execute(
      `
        INSERT INTO agreement_terms_conditions (
          invitation_id,
          agreement_type,
          s3_bucket,
          s3_key,
          pdf_name,
          mime_type,
          file_size_bytes,
          status,
          uploaded_at,
          accepted_at,
          created_at,
          updated_at
        )
        VALUES (
          ?,
          'terms_conditions_agreement',
          ?,
          ?,
          ?,
          'application/pdf',
          ?,
          'accepted',
          UTC_TIMESTAMP(),
          UTC_TIMESTAMP(),
          UTC_TIMESTAMP(),
          UTC_TIMESTAMP()
        )
        ON DUPLICATE KEY UPDATE
          s3_bucket = VALUES(s3_bucket),
          s3_key = VALUES(s3_key),
          pdf_name = VALUES(pdf_name),
          mime_type = VALUES(mime_type),
          file_size_bytes = VALUES(file_size_bytes),
          status = 'accepted',
          uploaded_at = VALUES(uploaded_at),
          accepted_at = VALUES(accepted_at),
          updated_at = UTC_TIMESTAMP()
      `,
      [
        invite.id,
        AGREEMENT_S3_BUCKET,
        agreementS3Key,
        agreementPdfName || "device-evaluation-agreement.pdf",
        agreementObjectInfo?.ContentLength || null,
      ]
    );

    await conn.commit();
    conn.release();
    conn = null;

    await writeAuthLogSafe(req, {
      eventType: "invite_accepted",
      userId: email,
      role,
      partnerCode,
      identifier: email,
      success: true,
      failureReason: `Invite accepted for ${role}`,
    });

    return sendJson(res, 200, {
      ok: true,
      message: "Invitation accepted successfully. You can now login.",
      data: {
        user_id: email,
        dietician_id: dieticianId,
        name: fullName,
        phone_no: phoneOrNa,
        role,
        partner_code: partnerCode,
        parent_user_id: parentUserId,
        status: "active",
        email_verified: true,
        agreement: {
          s3_bucket: AGREEMENT_S3_BUCKET,
          s3_key: agreementS3Key,
          pdf_name: agreementPdfName || "device-evaluation-agreement.pdf",
          file_size_bytes: agreementObjectInfo?.ContentLength || null,
          status: "accepted",
        },
        features_allow: {
          dietician_id: dieticianId,
          test_allow: 1,
          multiple_reading: 1,
          practice_test_allow: 1,
          detailed_scores: 1,
        },
      },
    });
  } catch (err) {
    if (conn) {
      try {
        await conn.rollback();
      } catch (_) {
        /* ignore rollback error */
      }

      try {
        conn.release();
      } catch (_) {
        /* ignore release error */
      }

      conn = null;
    }

    console.error("ACCEPT_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await writeAuthLogSafe(req, {
      eventType: "invite_accept_error",
      userId: null,
      role: null,
      partnerCode: null,
      identifier: null,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return sendJson(res, 500, {
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && {
        debug_error: err?.message,
        debug_file: err?.stack?.split("\n")[1]?.trim(),
      }),
    });
  }
};

module.exports = { acceptInvite };