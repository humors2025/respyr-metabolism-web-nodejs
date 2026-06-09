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
 *  - Email is sent via Resend (the project's provider), not PHP mail().
 *
 * No DB tables added/removed — reads table_dietician only; audits app_auth_logs.
 */

const crypto = require("crypto");
const axios = require("axios");
const pool = require("../../../../config/db");
const otpStore = require("../../../../services/dietitianOtpStore");

// ─── Config ───────────────────────────────────────────────────────────────────

const APP_DEBUG = process.env.NODE_ENV !== "production";
const OTP_DEBUG_RETURN =
  String(process.env.OTP_DEBUG_RETURN || "").toLowerCase() === "true";

const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL || "Respyr <no-reply@respyr.ai>";

const GENERIC_MESSAGE =
  "Verification code has been sent to your email.";

// ─── Helpers ──────────────────────────────────────────────────────────────────

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
    console.error("OTP_SEND_AUDIT_FAILED:", err?.code || err?.message);
  }
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderOtpHtml(name, otp, ttlMinutes) {
  const safeName = escapeHtml(name || "there");
  const safeOtp = escapeHtml(otp);
  return `<!doctype html>
<html>
  <body style="font-family:Arial,sans-serif;font-size:16px;color:#0B1A15;line-height:1.5;">
    <p>Hi ${safeName},</p>
    <p>Use the verification code below to reset your Respyr password:</p>
    <p style="font-size:30px;letter-spacing:8px;margin:16px 0;"><strong>${safeOtp}</strong></p>
    <p>This code expires in ${ttlMinutes} minutes. If you did not request a password
       reset, you can safely ignore this email — your password will not change.</p>
    <p style="font-size:12px;color:#666;">For your security, never share this code with anyone.</p>
  </body>
</html>`;
}

/** Send the OTP email via Resend. Returns { ok, status?, error? }. */
async function sendOtpEmail(toEmail, name, otp, ttlMinutes) {
  if (!RESEND_API_KEY) {
    return { ok: false, status: 0, error: "RESEND_API_KEY not configured" };
  }
  try {
    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: RESEND_FROM_EMAIL,
        to: [toEmail],
        subject: "Your Respyr password reset code",
        html: renderOtpHtml(name, otp, ttlMinutes),
        tags: [{ name: "kind", value: "password_reset_otp" }],
      },
      {
        timeout: 10_000,
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        validateStatus: () => true,
      }
    );
    if (response.status >= 200 && response.status < 300) {
      return { ok: true, status: response.status };
    }
    return { ok: false, status: response.status, error: response.data ?? "Resend non-2xx" };
  } catch (err) {
    return { ok: false, status: 0, error: err?.code || err?.message || "Resend request failed" };
  }
}

// ─── Controller ───────────────────────────────────────────────────────────────

exports.sendDietitianOtp = async (req, res) => {
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

  // A malformed email is a client error, not an enumeration vector.
  if (!isValidEmail(email)) {
    return res.status(400).json({ success: false, message: "A valid email is required." });
  }

  const ttlMinutes = Math.ceil(otpStore.OTP_TTL_SECONDS / 60);

  try {
    // Look up the dietician. We deliberately DO NOT branch the response on this.
    const [rows] = await pool.execute(
      `SELECT id, dietician_id, name, email
         FROM table_dietician
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1`,
      [email]
    );
    const user = rows && rows.length ? rows[0] : null;

    if (!user) {
      // Equalise work, log, and return the SAME generic response.
      await otpStore.dummyHashWork();
      await writeAuthLogSafe(req, {
        eventType: "otp_request_no_account",
        userId: null,
        identifier: email,
        success: false,
        failureReason: "No account for email",
      });
      return res.status(200).json({ success: true, message: GENERIC_MESSAGE });
    }

    // Resend cooldown — silently skip resending (does not leak existence because
    // the response is identical to the no-account path).
    const cooldown = await otpStore.getResendCooldown(email);
    if (cooldown > 0) {
      await writeAuthLogSafe(req, {
        eventType: "otp_request_cooldown",
        userId: user.dietician_id,
        identifier: email,
        success: false,
        failureReason: `Resend cooldown ${cooldown}s`,
      });
      return res.status(200).json({ success: true, message: GENERIC_MESSAGE });
    }

    // Issue + store the OTP (bcrypt-hashed, TTL'd in Redis).
    const { otp } = await otpStore.setOtp(email, user.dietician_id);

    // Email it.
    const emailResult = await sendOtpEmail(user.email, user.name, otp, ttlMinutes);

    await writeAuthLogSafe(req, {
      eventType: emailResult.ok ? "otp_requested" : "otp_send_failed",
      userId: user.dietician_id,
      identifier: email,
      success: emailResult.ok,
      failureReason: emailResult.ok ? null : "OTP email send failed",
    });

    if (!emailResult.ok && APP_DEBUG) {
      console.error("OTP_EMAIL_FAILED:", emailResult.status, emailResult.error);
    }

    const response = { success: true, message: GENERIC_MESSAGE };

    // DEV ONLY — never enable in production. Lets you test without a mailbox.
    if (OTP_DEBUG_RETURN && APP_DEBUG) {
      response.debug_otp = otp;
      response.debug_email_sent = emailResult.ok;
    }

    return res.status(200).json(response);
  } catch (error) {
    console.error("SEND_OTP_ERROR:", {
      code: error?.code,
      message: error?.message,
    });
    return res.status(500).json({
      success: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: error?.message }),
    });
  }
};
