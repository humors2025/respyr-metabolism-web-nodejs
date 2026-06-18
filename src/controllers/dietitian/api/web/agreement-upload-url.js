"use strict";

const crypto = require("crypto");
const pool = require("../../../../config/db");

const { PutObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const {
  applySecurityHeaders,
  sendJson,
  ensurePostOrReject,
  getJsonBody,
  secureHash,
} = require("./auth_common");

const { s3, AGREEMENT_S3_BUCKET } = require("../../../../config/s3");

const MAX_BYTES =
  parseInt(process.env.AGREEMENT_UPLOAD_MAX_BYTES || "10485760", 10);

const agreementUploadUrl = async (req, res) => {
  applySecurityHeaders(res);

  if (ensurePostOrReject(req, res)) return;

  if (!AGREEMENT_S3_BUCKET) {
    return sendJson(res, 500, {
      ok: false,
      message: "Agreement S3 bucket is not configured",
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
  const contentType =
    typeof body.content_type === "string" ? body.content_type.trim() : "";
  const sizeBytes = Number(body.size_bytes || 0);

  if (!token) {
    return sendJson(res, 400, {
      ok: false,
      message: "Invite token is required",
    });
  }

  if (contentType !== "application/pdf") {
    return sendJson(res, 400, {
      ok: false,
      message: "Only PDF upload is allowed",
    });
  }

  if (!Number.isFinite(sizeBytes) || sizeBytes <= 0 || sizeBytes > MAX_BYTES) {
    return sendJson(res, 400, {
      ok: false,
      message: "PDF size is invalid or too large",
    });
  }

  const tokenHash = secureHash(token);

  try {
    const [rows] = await pool.execute(
      `
        SELECT
          id,
          status,
          (expires_at <= UTC_TIMESTAMP()) AS is_expired
        FROM app_user_invitations
        WHERE token_hash = ?
        LIMIT 1
      `,
      [tokenHash]
    );

    const invite = rows[0];

    if (!invite) {
      return sendJson(res, 404, {
        ok: false,
        message: "Invalid invitation link",
      });
    }

    if (String(invite.status) !== "pending") {
      return sendJson(res, 409, {
        ok: false,
        message: "Invitation is already used or no longer valid",
      });
    }

    if (Number(invite.is_expired) === 1) {
      return sendJson(res, 410, {
        ok: false,
        message: "Invitation link has expired",
      });
    }

    const key = `agreements/pending/${invite.id}/${crypto.randomUUID()}.pdf`;

    const command = new PutObjectCommand({
      Bucket: AGREEMENT_S3_BUCKET,
      Key: key,
      ContentType: "application/pdf",
      CacheControl: "no-store",
      Metadata: {
        invitation_id: String(invite.id),
        agreement_type: "terms_conditions_agreement",
      },
    });

    const uploadUrl = await getSignedUrl(s3, command, {
      expiresIn: 300,
    });

    return sendJson(res, 200, {
      ok: true,
      message: "Agreement upload URL created",
      data: {
        upload_url: uploadUrl,
        key,
        expires_in_seconds: 300,
      },
    });
  } catch (err) {
    console.error("AGREEMENT_UPLOAD_URL_ERROR:", {
      code: err?.code,
      message: err?.message,
    });

    return sendJson(res, 500, {
      ok: false,
      message: "Could not create agreement upload URL",
    });
  }
};

module.exports = { agreementUploadUrl };