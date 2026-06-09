"use strict";

/**
 * update_diatitian_password.js
 *
 * Converted from: update_diatitian_password.php
 * Endpoint : POST /auth/update_diatitian_password  (PUBLIC, rate-limited)
 * Purpose  : Step 3 of the dietitian "forgot password" flow — set the new password.
 *
 * CRITICAL FIX vs. the PHP:
 *  - The PHP updated the password for ANY email with NO proof of OTP ownership —
 *    a complete account-takeover vulnerability. This version REQUIRES the
 *    single-use reset_token issued by verify_diatitian_otp.js. No valid token →
 *    no password change.
 *
 * Other VAPT / HIPAA hardening vs. the PHP:
 *  - Password policy lifted from len>=6 to the frontend's rules (configurable):
 *    >= 8 chars, lower + upper + number + special, and confirm_password match.
 *  - bcrypt(12) instead of PHP password_hash() default; <=72 bytes enforced.
 *  - On success ALL refresh tokens for the dietitian are revoked
 *    (DELETE FROM dietician_refresh_tokens) — a stolen session cannot survive a
 *    password reset. is_reset_password is cleared, matching changePasswordController.
 *  - Generic responses + audit to app_auth_logs (no clear-text PII).
 *
 * No DB tables added/removed — table_dietician + dietician_refresh_tokens, both
 * already used by login/refresh/logout.
 */

const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const pool = require("../../../../config/db");
const otpStore = require("../../../../services/dietitianOtpStore");

// ─── Config ───────────────────────────────────────────────────────────────────

const APP_DEBUG = process.env.NODE_ENV !== "production";
const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS, 10) || 12;

// Mirrors the frontend checklist. Bump MIN to 12 to match changePasswordController
// (recommended for HIPAA) by setting RESET_MIN_PASSWORD_LENGTH=12.
const MIN_PASSWORD_LENGTH = Math.max(
  8,
  parseInt(process.env.RESET_MIN_PASSWORD_LENGTH, 10) || 8
);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isValidEmail(value) {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) &&
    value.length <= 254;
}

/** Returns an error string, or null if the password satisfies the policy. */
function validatePassword(password) {
  if (typeof password !== "string") return "Password must be a string.";
  if (password.length < MIN_PASSWORD_LENGTH) {
    return `Password must be at least ${MIN_PASSWORD_LENGTH} characters long.`;
  }
  if (Buffer.byteLength(password, "utf8") > 72) {
    return "Password must not exceed 72 bytes.";
  }
  if (!/[a-z]/.test(password)) return "Password must contain a lowercase letter.";
  if (!/[A-Z]/.test(password)) return "Password must contain an uppercase letter.";
  if (!/\d/.test(password)) return "Password must contain a number.";
  if (!/[^A-Za-z0-9]/.test(password)) return "Password must contain a special character.";
  return null;
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "0.0.0.0").substring(0, 45);
}
function getUserAgent(req) {
  return String(req.headers?.["user-agent"] || "").substring(0, 255);
}
function authLogHash(value) {
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value == null ? "" : value).trim().toLowerCase())
    .digest("hex");
}

async function writeAuthLogSafe(conn, req, { eventType, userId, identifier, success, failureReason }) {
  try {
    const identifierHash =
      identifier !== null && identifier !== undefined ? authLogHash(identifier) : null;
    const exec = conn || pool;
    await exec.execute(
      `INSERT INTO app_auth_logs (
         event_type, user_id, role, partner_code,
         identifier_hash, ip_hash, user_agent_hash, session_id_hash,
         success, failure_reason
       ) VALUES (?, ?, NULL, NULL, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").substring(0, 60),
        userId !== null && userId !== undefined ? String(userId).substring(0, 191) : null,
        identifierHash,
        authLogHash(getClientIp(req)),
        authLogHash(getUserAgent(req)),
        success ? 1 : 0,
        failureReason !== null && failureReason !== undefined
          ? String(failureReason).substring(0, 255)
          : null,
      ]
    );
  } catch (err) {
    console.error("PWD_RESET_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Controller ───────────────────────────────────────────────────────────────

exports.updateDietitianPassword = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ success: false, message: "Method not allowed" });
  }

  if (typeof req.body === "string") {
    try {
      req.body = JSON.parse(req.body);
    } catch {
      return res.status(400).json({ success: false, message: "Invalid JSON body" });
    }
  }

  const body = req.body && typeof req.body === "object" && !Array.isArray(req.body)
    ? req.body
    : {};

  const email = otpStore.normalizeEmail(body.email);
  const resetToken = String(body.reset_token == null ? "" : body.reset_token).trim();

  // Accept both {password,confirm_password} and {new_password,confirm_password}.
  const password = String(
    (body.password != null ? body.password : body.new_password) ?? ""
  );
  const confirmPassword = String(
    (body.confirm_password != null ? body.confirm_password : body.confirm) ?? ""
  );

  // ── Validate inputs ─────────────────────────────────────────────────────────
  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "A valid email is required." });
  }
  if (resetToken === "") {
    return res.status(400).json({ success: false, message: "A valid reset token is required." });
  }
  if (confirmPassword === "" || password !== confirmPassword) {
    return res.status(400).json({ success: false, message: "Passwords do not match." });
  }
  const policyError = validatePassword(password);
  if (policyError) {
    return res.status(400).json({ success: false, message: policyError });
  }

  let conn;

  try {
    // ── 1. Consume the single-use reset token (proof of OTP) ──────────────────
    const tokenResult = await otpStore.consumeResetToken(email, resetToken);
    if (!tokenResult.ok) {
      await writeAuthLogSafe(null, req, {
        eventType: "password_reset_denied",
        userId: null,
        identifier: email,
        success: false,
        failureReason: "Invalid or expired reset token",
      });
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset session. Please verify your OTP again.",
      });
    }

    conn = await pool.getConnection();
    await conn.beginTransaction();

    // ── 2. Load the account (lock the row) ────────────────────────────────────
    const [rows] = await conn.execute(
      `SELECT id, dietician_id, email, password
         FROM table_dietician
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
        FOR UPDATE`,
      [email]
    );
    const user = rows && rows.length ? rows[0] : null;

    if (!user) {
      // Token was valid but the account vanished — fail safely.
      await conn.rollback();
      conn.release();
      conn = null;
      await writeAuthLogSafe(null, req, {
        eventType: "password_reset_denied",
        userId: tokenResult.dietician_id,
        identifier: email,
        success: false,
        failureReason: "Account not found at reset time",
      });
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset session. Please verify your OTP again.",
      });
    }

    // ── 3. Reject reuse of the current password ───────────────────────────────
    const currentHash = String(user.password || "");
    if (currentHash !== "") {
      let same = false;
      try {
        same = await bcrypt.compare(password, currentHash);
      } catch (_) {
        same = false;
      }
      if (same) {
        await conn.rollback();
        conn.release();
        conn = null;
        return res.status(400).json({
          success: false,
          message: "New password must be different from your current password.",
        });
      }
    }

    // ── 4. Hash + update ──────────────────────────────────────────────────────
    const newHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    const [updateResult] = await conn.execute(
      `UPDATE table_dietician
          SET password = ?, is_reset_password = 0
        WHERE dietician_id = ?
        LIMIT 1`,
      [newHash, String(user.dietician_id)]
    );

    if (updateResult.affectedRows !== 1) {
      await conn.rollback();
      conn.release();
      conn = null;
      return res.status(500).json({ success: false, message: "Password could not be updated." });
    }

    // ── 5. Revoke ALL sessions (HIPAA: invalidate on credential change) ───────
    await conn.execute(
      `DELETE FROM dietician_refresh_tokens WHERE dietician_id = ?`,
      [String(user.dietician_id)]
    );

    await writeAuthLogSafe(conn, req, {
      eventType: "password_reset_success",
      userId: user.dietician_id,
      identifier: email,
      success: true,
      failureReason: null,
    });

    await conn.commit();
    conn.release();
    conn = null;

    return res.status(200).json({
      success: true,
      message: "Password updated successfully. Please log in with your new password.",
    });
  } catch (error) {
    if (conn) {
      try { await conn.rollback(); } catch (_) { /* ignore */ }
      try { conn.release(); } catch (_) { /* ignore */ }
      conn = null;
    }
    console.error("UPDATE_PASSWORD_ERROR:", { code: error?.code, message: error?.message });
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: error?.message }),
    });
  }
};
