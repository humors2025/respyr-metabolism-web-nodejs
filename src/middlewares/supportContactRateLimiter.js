"use strict";

/**
 * supportContactRateLimiter.js
 *
 * Rate limiters for the public help-centre contact form
 * (POST /dietitian/api/web/support-contact). The endpoint has no JWT and every
 * accepted request sends an email to the team, so it is a spam target. A tight
 * per-(IP+email) limiter stops one sender flooding the inbox; a broader per-IP
 * limiter stops rotating fake emails from one network. Same shape as
 * otpRateLimiter.js. Counters live in the Lambda container's memory, so this is
 * a front-line filter, not a hard global cap.
 */

const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");

const handler = (req, res) => {
  const secondsLeft = Math.max(1, Math.ceil((req.rateLimit.resetTime - Date.now()) / 1000));
  return res.status(429).json({
    ok: false,
    message: "Too many messages. Please try again later.",
    retry_after_seconds: secondsLeft,
  });
};

// ipKeyGenerator takes the IP string (it masks IPv6 to a /56); given `req` it
// returns the object, which stringifies to the same key for every caller.
const ipKey = (req) => ipKeyGenerator(req.ip || "0.0.0.0");

const emailKey = (req) => String(req.body?.email || "unknown").trim().toLowerCase().slice(0, 254);

const supportContactRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `support-contact:${ipKey(req)}:${emailKey(req)}`,
  handler,
});

const supportContactIpRateLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `support-contact-ip:${ipKey(req)}`,
  handler,
});

module.exports = { supportContactRateLimiter, supportContactIpRateLimiter };
