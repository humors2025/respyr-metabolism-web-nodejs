"use strict";

/**
 * otpRateLimiter.js
 *
 * Rate limiters for the public (unauthenticated) dietitian forgot-password flow.
 * These endpoints are reachable without a JWT, so they are the prime target for
 * abuse:
 *   - OTP send  → email-bombing / enumeration
 *   - OTP verify → online brute force of the numeric OTP
 *   - reset     → token guessing
 *
 * We layer a per-(IP+email) limiter with a broad per-IP limiter, mirroring the
 * login limiters in loginRateLimiter.js. The OTP store adds a second, stateful
 * defence (per-OTP attempt cap + resend cooldown) — this middleware is the cheap
 * front-line filter.
 */

const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");

const formatTime = (seconds) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
};

const makeHandler = (message) => (req, res) => {
  const retryAfter = req.rateLimit.resetTime - Date.now();
  const secondsLeft = Math.max(1, Math.ceil(retryAfter / 1000));
  return res.status(429).json({
    success: false,
    message,
    retry_after_seconds: secondsLeft,
    retry_after_time: formatTime(secondsLeft),
  });
};

const emailKey = (req) =>
  String(req.body?.email || "unknown").trim().toLowerCase();

// ── Send OTP ──────────────────────────────────────────────────────────────────
// Tight per IP+email (stops repeatedly mailing one victim), plus broad per IP.
const otpSendRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `otp-send:${ipKeyGenerator(req)}:${emailKey(req)}`,
  handler: makeHandler("Too many OTP requests. Please try again later."),
});

const otpSendIpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `otp-send-ip:${ipKeyGenerator(req)}`,
  handler: makeHandler("Too many OTP requests from this network. Please try again later."),
});

// ── Verify OTP ──────────────────────────────────────────────────────────────────
// Stricter — this is the brute-force surface for the 6-digit code.
const otpVerifyRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `otp-verify:${ipKeyGenerator(req)}:${emailKey(req)}`,
  handler: makeHandler("Too many verification attempts. Please request a new OTP."),
});

const otpVerifyIpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `otp-verify-ip:${ipKeyGenerator(req)}`,
  handler: makeHandler("Too many verification attempts from this network. Please try again later."),
});

// ── Reset password ──────────────────────────────────────────────────────────────
const passwordResetRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `pwd-reset:${ipKeyGenerator(req)}:${emailKey(req)}`,
  handler: makeHandler("Too many password reset attempts. Please try again later."),
});

module.exports = {
  otpSendRateLimiter,
  otpSendIpRateLimiter,
  otpVerifyRateLimiter,
  otpVerifyIpRateLimiter,
  passwordResetRateLimiter,
};
