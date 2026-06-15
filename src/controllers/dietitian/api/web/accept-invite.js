"use strict";

/**
 * accept-invite.js
 *
 * Converted from: accept-invite.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/accept-invite
 * Auth       : NONE (public). The single-use invite TOKEN is the credential —
 *              this is how an invited admin/trainer sets their password and
 *              activates their account. authMiddleware must NOT be mounted here.
 *
 * Flow (transactional, row-locked — parity with the PHP):
 *   1. Validate token + password policy (>=10, upper, lower, digit, special).
 *   2. Open a transaction; SELECT the invitation by token_hash FOR UPDATE.
 *   3. Reject: not found (404), not pending (409), expired (410 + mark expired).
 *   4. Re-validate the snapshot stored on the invite (email/role/partner_code/
 *      parent) — defense in depth even though we wrote it.
 *   5. Lock & guard against races: existing role, active partner_code, a
 *      table_dietician row whose code/email conflicts.
 *   6. Upsert table_dietician with a bcrypt password hash + is_reset_password=1.
 *   7. Upsert features_allow (all features on).
 *   8. INSERT app_user_roles as 'active' with email_verified_at = now.
 *   9. Mark the invitation 'accepted'. Commit.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  HARDENING DIFFERENCES FROM THE PHP (intentional)
 * ──────────────────────────────────────────────────────────────────────────
 *  - Password hashing: bcrypt (bcryptjs, cost 12) instead of PHP
 *    password_hash(PASSWORD_DEFAULT). bcrypt.compare in loginController already
 *    expects bcrypt hashes, so this is the correct, compatible choice. Inputs
 *    longer than bcrypt's 72-byte limit are REJECTED (not silently truncated).
 *  - Expiry is evaluated IN SQL (`expires_at <= UTC_TIMESTAMP()`). The PHP set
 *    date_default_timezone_set('Asia/Kolkata') and compared with PHP strtotime/
 *    time(), but invites are STORED in UTC (auth_common uses UTC_TIMESTAMP()).
 *    That tz mismatch could accept an expired invite or expire a valid one.
 *    Comparing in the DB removes all Node/MySQL timezone drift.
 *  - All write timestamps use UTC_TIMESTAMP() (not NOW()) so created_at /
 *    accepted_at / email_verified_at are consistent with how the invite row was
 *    written — HIPAA audit timestamps must be coherent.
 *  - The raw token never appears in logs or responses; only its
 *    SECURITY_PEPPER-keyed HMAC (secureHash) is used to look the invite up.
 *  - Internal error details are gated behind APP_DEBUG; production returns a
 *    generic 500.
 *  - Audit-logs every accept / failure with PHI hashed (writeAuthLogSafe).
 *
 * VAPT controls:
 *  - Single-use token: the invitation row is locked FOR UPDATE and flipped to
 *    'accepted' inside the same transaction, so two concurrent redemptions
 *    cannot both win (the second blocks, then sees status != 'pending').
 *  - Fully parameterized queries; zero string interpolation.
 *  - Strict password policy + length cap; generic responses; method gate.
 *
 * Tables touched (identical to the PHP — none added/removed):
 *   app_user_invitations, app_user_roles, table_dietician, features_allow,
 *   app_auth_logs (audit).
 */

const bcrypt = require("bcryptjs");
const pool = require("../../../../config/db");

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

// bcrypt cost — matches update_diatitian_password.js / loginController re-hash.
const BCRYPT_ROUNDS = 12;

// bcrypt only consumes the first 72 BYTES of a password; anything longer is
// silently ignored. Reject it so two different long passwords can't collide.
const PASSWORD_MAX_BYTES = 72;

const EMAIL_MAX_LENGTH = 150;
const PHONE_MAX_LENGTH = 15;
const PARTNER_CODE_MAX_LENGTH = 10;

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Mirrors PHP validateInvitePassword() + a byte-length cap for bcrypt safety.
 * Returns { ok: true } or { ok: false, status, message }.
 */
function validateInvitePassword(password) {
  if (typeof password !== "string" || password.length < 10) {
    return { ok: false, status: 400, message: "Password must be at least 10 characters" };
  }
  if (Buffer.byteLength(password, "utf8") > PASSWORD_MAX_BYTES) {
    return { ok: false, status: 400, message: "Password is too long (max 72 bytes)" };
  }
  if (!/[A-Z]/.test(password)) {
    return { ok: false, status: 400, message: "Password must contain at least one uppercase letter" };
  }
  if (!/[a-z]/.test(password)) {
    return { ok: false, status: 400, message: "Password must contain at least one lowercase letter" };
  }
  if (!/[0-9]/.test(password)) {
    return { ok: false, status: 400, message: "Password must contain at least one number" };
  }
  if (!/[^A-Za-z0-9]/.test(password)) {
    return { ok: false, status: 400, message: "Password must contain at least one special character" };
  }
  return { ok: true };
}

/**
 * PHP ensureFeaturesAllowForDietician(). Upsert features_allow (all on) for the
 * dietician, locking the row. Runs on the transaction connection.
 * Returns { ok: true } or { ok: false, status, message }.
 */
async function ensureFeaturesAllowForDietician(conn, dieticianIdRaw) {
  const dieticianId = String(dieticianIdRaw || "").trim().toUpperCase();
  if (dieticianId === "") {
    return { ok: false, status: 409, message: "Invalid dietician_id for features_allow" };
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

/**
 * POST /dietitian/api/web/accept-invite
 *
 * Body: { token, password, confirm_password }
 */
const acceptInvite = async (req, res) => {
  applySecurityHeaders(res);

  if (ensurePostOrReject(req, res)) return;

  // Fail closed if required secrets are missing (SECURITY_PEPPER, Resend keys).
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
    return sendJson(res, parsed.status, { ok: false, message: parsed.message });
  }
  const body = parsed.body;

  const token = typeof body.token === "string" ? body.token.trim() : "";
  const password =
    body.password === null || body.password === undefined ? "" : String(body.password);
  const confirmPassword =
    body.confirm_password === null || body.confirm_password === undefined
      ? ""
      : String(body.confirm_password);

  // ── Input validation (before any DB work) ──────────────────────────────────
  if (token === "") {
    return sendJson(res, 400, { ok: false, message: "Invite token is required" });
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
    return sendJson(res, pwCheck.status, { ok: false, message: pwCheck.message });
  }

  const tokenHash = secureHash(token);

  let conn = null;

  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // ── 1. Lock the invitation row by token hash ──────────────────────────────
    // Evaluate expiry in SQL (UTC) to avoid any Node/MySQL tz drift.
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
      return sendJson(res, 404, { ok: false, message: "Invalid invitation link" });
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
      // Mark expired, then commit that state change (parity with PHP).
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
      return sendJson(res, 410, { ok: false, message: "Invitation link has expired" });
    }

    // ── 2. Re-validate the invite snapshot (defense in depth) ─────────────────
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

    // Helper: rollback + audit + 409 for the snapshot/race guards below.
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
      return sendJson(res, 409, { ok: false, message });
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

    // ── 3. Race guards (locked) ───────────────────────────────────────────────
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

    // table_dietician keyed by dietician_id == partner_code.
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

    // ── 4. Upsert table_dietician ─────────────────────────────────────────────
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

      // Existing location/logo are preserved (PHP behavior — no location payload).
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
      // Insert default location 'NA' to satisfy the legacy table_dietician schema.
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

    // ── 5. features_allow upsert ──────────────────────────────────────────────
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

    // ── 6. Activate the role ──────────────────────────────────────────────────
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

    // ── 7. Consume the invitation ─────────────────────────────────────────────
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

    // ── 8. Respond (matches PHP JSON shape exactly) ───────────────────────────
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
        /* ignore */
      }
      try {
        conn.release();
      } catch (_) {
        /* ignore */
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
