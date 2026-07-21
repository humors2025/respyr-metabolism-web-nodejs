"use strict";

/**
 * list-accepted-agreements.js
 *
 * Platform : Respyr Dietitian API (api.respyr.ai)
 * Security : VAPT-hardened, HIPAA-aligned
 *
 * Purpose:
 *   Admin-facing report of which users have accepted the Device Evaluation
 *   (Terms & Conditions) agreement during invite signup.
 *
 *   Joins agreement_terms_conditions → app_user_invitations so each row shows
 *   the signer's name/email/role, who invited them, when they accepted, and a
 *   short-lived presigned S3 download URL for the signed PDF.
 *
 * Role scoping:
 *   - super_admin → all accepted agreements
 *   - admin       → only agreements for invites under this admin
 *                   (LOWER(parent_user_id) = admin email)
 *   - trainer / other roles → 403
 *
 * VAPT Controls applied:
 *   - Token-bound authorization. Actor identity comes from the verified JWT
 *     (authMiddleware) — never from the request body — preventing privilege
 *     escalation and IDOR.
 *   - Actor is re-fetched from DB and role/status re-checked server-side
 *     (stale or tampered tokens cannot grant access to a disabled account).
 *   - Fully parameterized queries — zero string interpolation.
 *   - Method gate: only POST is accepted — returns 405 otherwise.
 *   - Presigned GET URLs expire in 600 seconds and are generated per-request
 *     for the authorized actor only. The bucket stays private.
 *   - Internal error details suppressed in production responses.
 *
 * HIPAA Controls applied:
 *   - Minimum-necessary data: only columns required for the report.
 *   - Cache-Control: no-store, Pragma: no-cache enforced per-response.
 *   - Audit log written via fail-safe wrapper; PHI identifiers are
 *     HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

const { GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const { s3, AGREEMENT_S3_BUCKET } = require("../../../../config/s3");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const VALID_ACTOR_ROLES = new Set(["super_admin", "admin", "trainer"]);

const DOWNLOAD_URL_EXPIRES_SECONDS = 600;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Format a mysql2 DATETIME value as "YYYY-MM-DD HH:MM:SS" to match the
 * response shape used across the API. Accepts Date objects and strings.
 */
function toMysqlDateTime(val) {
  if (val === null || val === undefined) return null;

  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return (
      `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
      `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
    );
  }

  return String(val);
}

function lowerStr(val) {
  return val === null || val === undefined ? "" : String(val).toLowerCase();
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
    (typeof req.get === "function" && req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";
  return String(ua).slice(0, 500);
}

function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

/**
 * Fail-safe audit log writer (same schema/pattern as
 * list-admin-trainer-users-jwt.js). Never throws — audit failures must not
 * surface to clients.
 */
async function writeAuthLogSafe(req, {
  eventType,
  userId,
  role,
  partnerCode,
  identifier,
  success,
  failureReason,
}) {
  try {
    const ipHash = authLogHash(getClientIp(req));
    const userAgentHash = authLogHash(getUserAgent(req));
    const identifierHash = identifier !== null && identifier !== undefined
      ? authLogHash(identifier)
      : null;

    const truncatedEvent = String(eventType || "").slice(0, 60);
    const truncatedReason =
      failureReason !== null && failureReason !== undefined
        ? String(failureReason).slice(0, 255)
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
  } catch (err) {
    console.error("AUTH_LOG_WRITE_FAILED:", err?.code || err?.message);
  }
}

// ─── Actor resolution ────────────────────────────────────────────────────────

/**
 * Re-fetch the authenticated actor from DB using the JWT subject.
 * Returns { actor, actorEmail } on success or { error: { status, body } }.
 */
async function resolveActorFromToken(req) {
  const payload = req.user || {};

  const dieticianId = String(payload.sub || payload.dietician_id || "").trim();

  if (!dieticianId || dieticianId.length > 64) {
    return {
      error: {
        status: 401,
        body: { ok: false, error: "Invalid token user" },
      },
    };
  }

  const [rows] = await pool.execute(
    `
      SELECT
        td.id,
        td.dietician_id,
        td.name,
        td.email,

        aur.role,
        aur.partner_code,
        aur.parent_user_id,
        aur.status
      FROM table_dietician td
      INNER JOIN app_user_roles aur
        ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE td.dietician_id = ?
      LIMIT 1
    `,
    [dieticianId]
  );

  const actor = rows[0];

  if (!actor) {
    return {
      error: {
        status: 401,
        body: { ok: false, error: "Token user not found" },
      },
    };
  }

  if (String(actor.status) !== "active") {
    return {
      error: {
        status: 403,
        body: { ok: false, error: "Account is not active" },
      },
    };
  }

  if (!VALID_ACTOR_ROLES.has(actor.role)) {
    return {
      error: {
        status: 403,
        body: { ok: false, error: "Invalid role configuration" },
      },
    };
  }

  return { actor, actorEmail: String(actor.email || "").trim().toLowerCase() };
}

// ─── Query ───────────────────────────────────────────────────────────────────

/**
 * Fetch accepted agreements joined with invitation details.
 *
 * scopeParentEmail:
 *   - null  → no scope filter (super_admin sees everything)
 *   - email → only invites whose parent_user_id matches (admin scope)
 */
async function getAcceptedAgreements(scopeParentEmail) {
  const params = [];

  let scopeSql = "";
  if (scopeParentEmail !== null) {
    scopeSql = "AND LOWER(i.parent_user_id) = LOWER(?)";
    params.push(scopeParentEmail);
  }

  const [rows] = await pool.execute(
    `
      SELECT
        a.id               AS agreement_id,
        a.invitation_id,
        a.agreement_type,
        a.s3_bucket,
        a.s3_key,
        a.pdf_name,
        a.file_size_bytes,
        a.status           AS agreement_status,
        a.uploaded_at,
        a.accepted_at,

        i.invited_first_name,
        i.invited_last_name,
        i.invited_email,
        i.invited_phone,
        i.invited_role,
        i.partner_code,
        i.invited_by_user_id,
        i.parent_user_id,
        i.status           AS invite_status
      FROM agreement_terms_conditions a
      INNER JOIN app_user_invitations i
        ON i.id = a.invitation_id
      WHERE a.status = 'accepted'
      ${scopeSql}
      ORDER BY a.accepted_at DESC, a.id DESC
    `,
    params
  );

  return rows;
}

/**
 * Build a short-lived presigned GET URL for the signed PDF so the bucket can
 * stay fully private. Presigning is a local (offline) operation — no network
 * round-trip per row. Returns null on failure rather than failing the report.
 */
async function buildDownloadUrl(bucket, key) {
  if (!bucket || !key) return null;

  try {
    const command = new GetObjectCommand({
      Bucket: bucket,
      Key: key,
      ResponseContentType: "application/pdf",
      ResponseContentDisposition: 'inline; filename="agreement.pdf"',
    });

    return await getSignedUrl(s3, command, {
      expiresIn: DOWNLOAD_URL_EXPIRES_SECONDS,
    });
  } catch (err) {
    console.error("AGREEMENT_PRESIGN_GET_FAILED:", {
      code: err?.code,
      message: err?.message,
    });
    return null;
  }
}

// ─── Controller ──────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/list-accepted-agreements
 *
 * Headers: Authorization: Bearer <JWT>
 * Body   : {} (ignored — actor identity comes from JWT)
 *
 * Returns:
 *   super_admin → all accepted agreements
 *   admin       → accepted agreements for invites under this admin
 *   trainer     → 403
 *
 * Response row shape:
 *   {
 *     agreement_id, invitation_id,
 *     name, first_name, last_name, email, phone_no, role, partner_code,
 *     invited_by, parent_user_id,
 *     agreement_status, invite_status,
 *     pdf_name, file_size_bytes, s3_key,
 *     uploaded_at, accepted_at,
 *     download_url,            // presigned GET, expires in 600s (or null)
 *     download_expires_in_seconds
 *   }
 */
const listAcceptedAgreements = async (req, res) => {
  // HIPAA: never let intermediaries cache PHI-adjacent responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate.
  if (req.method !== "POST") {
    return res.status(405).json({
      ok:    false,
      error: "Method not allowed",
    });
  }

  try {
    // ── 1. Resolve actor from JWT + DB ──────────────────────────────────────
    const resolved = await resolveActorFromToken(req);

    if (resolved.error) {
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor, actorEmail } = resolved;
    const actorRole = String(actor.role);

    // ── 2. Role scoping ─────────────────────────────────────────────────────
    let scopeParentEmail;

    if (actorRole === "super_admin") {
      scopeParentEmail = null;            // no filter — sees everything
    } else if (actorRole === "admin") {
      scopeParentEmail = actorEmail;      // only their own network
    } else {
      // trainer (or anything else) may not view the agreements report
      writeAuthLogSafe(req, {
        eventType:     "agreements_list_denied",
        userId:        actorEmail,
        role:          actorRole,
        partnerCode:   actor.partner_code ?? null,
        identifier:    actorEmail,
        success:       false,
        failureReason: "Role not permitted to view accepted agreements",
      });

      return res.status(403).json({
        ok:    false,
        error: "You are not allowed to view this list",
      });
    }

    // ── 3. Fetch rows ───────────────────────────────────────────────────────
    const rows = await getAcceptedAgreements(scopeParentEmail);

    // ── 4. Shape response + presigned download URLs ─────────────────────────
    const agreements = [];

    for (const row of rows) {
      const firstName = String(row.invited_first_name ?? "").trim();
      const lastName  = String(row.invited_last_name  ?? "").trim();
      const fullName  = `${firstName} ${lastName}`.trim();

      // Prefer the bucket recorded on the row; fall back to the configured one.
      const bucket = row.s3_bucket || AGREEMENT_S3_BUCKET || null;

      const downloadUrl = await buildDownloadUrl(bucket, row.s3_key);

      agreements.push({
        agreement_id:    Number(row.agreement_id),
        invitation_id:   Number(row.invitation_id),

        name:            fullName,
        first_name:      firstName,
        last_name:       lastName,
        email:           lowerStr(row.invited_email),
        phone_no:        row.invited_phone ?? null,
        role:            row.invited_role,
        partner_code:    row.partner_code ?? null,

        invited_by:      lowerStr(row.invited_by_user_id),
        parent_user_id:  lowerStr(row.parent_user_id),

        agreement_type:  row.agreement_type,
        agreement_status: row.agreement_status,
        invite_status:    row.invite_status,

        pdf_name:        row.pdf_name ?? null,
        file_size_bytes: row.file_size_bytes === null || row.file_size_bytes === undefined
          ? null
          : Number(row.file_size_bytes),
        s3_key:          row.s3_key ?? null,

        uploaded_at:     toMysqlDateTime(row.uploaded_at),
        accepted_at:     toMysqlDateTime(row.accepted_at),

        download_url:                downloadUrl,
        download_expires_in_seconds: downloadUrl
          ? DOWNLOAD_URL_EXPIRES_SECONDS
          : null,
      });
    }

    // ── 5. Audit log (fire-and-forget) ──────────────────────────────────────
    writeAuthLogSafe(req, {
      eventType:     "agreements_list_viewed",
      userId:        actorEmail,
      role:          actorRole,
      partnerCode:   actor.partner_code ?? null,
      identifier:    actorEmail,
      success:       true,
      failureReason:
        actorRole === "super_admin"
          ? "Super admin viewed accepted agreements list"
          : "Admin viewed accepted agreements list",
    });

    // ── 6. Respond ──────────────────────────────────────────────────────────
    return res.status(200).json({
      ok:   true,
      mode: actorRole === "super_admin"
        ? "super_admin_all_agreements"
        : "admin_network_agreements",
      actor: {
        user_id:        actorEmail,
        role:           actorRole,
        partner_code:   actor.partner_code   ?? null,
        parent_user_id: actor.parent_user_id ?? null,
      },
      title:      "Accepted Agreements",
      agreements,
      totals: {
        accepted_count: agreements.length,
      },
    });
  } catch (err) {
    // ── 7. Error handling — never leak internals in production ──────────────
    console.error("LIST_ACCEPTED_AGREEMENTS_ERROR:", {
      code:     err?.code,
      errno:    err?.errno,
      sqlState: err?.sqlState,
      message:  err?.message,
    });

    return res.status(500).json({
      ok:    false,
      error: "Internal server error",
      ...(process.env.NODE_ENV !== "production" && {
        debug_error: err?.message,
      }),
    });
  }
};

module.exports = { listAcceptedAgreements };