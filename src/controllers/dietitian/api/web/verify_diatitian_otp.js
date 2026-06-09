"use strict";

/**
 * verify_diatitian_otp.js
 *
 * Endpoint : POST /auth/verify_diatitian_otp   (PUBLIC, rate-limited)
 * Purpose  : Step 2 of the dietitian "forgot password" flow.
 *
 * The original PHP had NO verify endpoint and never checked the OTP — the
 * password update trusted the email alone (a full account-takeover hole). This
 * endpoint closes that gap: it validates the 6-digit OTP and, on success, mints
 * a SHORT-LIVED, SINGLE-USE reset token. Only that token authorises the actual
 * password change (see update_diatitian_password.js). This binds step 3 to a
 * proven OTP.
 *
 * VAPT / HIPAA:
 *  - OTP compared in constant time against a bcrypt hash; never stored in clear.
 *  - Per-OTP attempt cap (in the store) defeats online brute force of the code.
 *  - Generic "invalid or expired" responses — no distinction that would let an
 *    attacker enumerate which emails have a live OTP.
 *  - Reset token is random (32 bytes); only its SHA-256 hash is stored in Redis.
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");
const otpStore = require("../../../../services/dietitianOtpStore");

const APP_DEBUG = process.env.NODE_ENV !== "production";
const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

function isValidEmail(value) {
  return typeof value === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) &&
    value.length <= 254;
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

async function writeAuthLogSafe(req, { eventType, userId, identifier, success, failureReason }) {
  try {
    const identifierHash =
      identifier !== null && identifier !== undefined ? authLogHash(identifier) : null;
    await pool.execute(
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
    console.error("OTP_VERIFY_AUDIT_FAILED:", err?.code || err?.message);
  }
}

exports.verifyDietitianOtp = async (req, res) => {
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
  const otp = String(body.otp == null ? "" : body.otp).trim();

  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "A valid email is required." });
  }

  // Shape check only — exact value is verified against the store.
  if (!/^\d{4,10}$/.test(otp)) {
    return res.status(400).json({ success: false, message: "A valid OTP is required." });
  }

  try {
    const result = await otpStore.verifyOtp(email, otp);

    if (!result.ok) {
      if (result.reason === "locked") {
        await writeAuthLogSafe(req, {
          eventType: "otp_verify_locked",
          userId: null,
          identifier: email,
          success: false,
          failureReason: "OTP attempt limit reached",
        });
        return res.status(429).json({
          success: false,
          message: "Too many incorrect attempts. Please request a new code.",
        });
      }

      // not_found OR mismatch → same generic message (no enumeration).
      await writeAuthLogSafe(req, {
        eventType: "otp_verify_failed",
        userId: null,
        identifier: email,
        success: false,
        failureReason: result.reason,
      });
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP.",
        ...(typeof result.attemptsLeft === "number" && { attempts_left: result.attemptsLeft }),
      });
    }

    // OTP correct → mint a single-use reset token.
    const { token, ttl } = await otpStore.createResetToken(email, result.dietician_id);

    await writeAuthLogSafe(req, {
      eventType: "otp_verified",
      userId: result.dietician_id,
      identifier: email,
      success: true,
      failureReason: null,
    });

    return res.status(200).json({
      success: true,
      message: "OTP verified successfully.",
      reset_token: token,
      reset_token_expires_in: ttl,
    });
  } catch (error) {
    console.error("VERIFY_OTP_ERROR:", { code: error?.code, message: error?.message });
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: error?.message }),
    });
  }
};
