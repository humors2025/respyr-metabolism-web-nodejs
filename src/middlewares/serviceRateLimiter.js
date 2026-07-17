"use strict";

/**
 * serviceRateLimiter.js
 *
 * Front-line limiter for HMAC-signed service-to-service endpoints.
 *
 * This runs BEFORE serviceAuthMiddleware, so it must key on something the caller
 * cannot forge cheaply. That means the client IP — NOT x-respyr-key-id. Keying on
 * the key-id header would let an attacker mint a fresh id per request and walk
 * straight past the limiter into the (comparatively expensive) HMAC + nonce path.
 *
 * The ceiling is generous relative to the login limiters because the callers are
 * batch jobs generating plans, not humans typing passwords. It exists to bound
 * signature-brute-force and DB-abuse attempts, not to shape legitimate traffic.
 */

const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");

/**
 * ipKeyGenerator's signature is (ip: string) — it normalises IPv6 to a /56 subnet
 * so a single host cannot rotate through its address space. Passing `req` instead
 * of `req.ip` returns the object, which stringifies to the constant
 * "[object Object]", silently collapsing every client into ONE shared bucket.
 * That converts a per-IP limit into a global one: any single caller can exhaust
 * it for everyone (DoS), and no attacker is ever isolated.
 *
 * NOTE: loginRateLimiter.js and otpRateLimiter.js currently pass `req` and have
 * exactly this defect on their per-IP limiters.
 */
const ipKey = (req) => ipKeyGenerator(req.ip || "0.0.0.0");

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  if (typeof min === "number" && v < min) return min;
  if (typeof max === "number" && v > max) return max;
  return v;
}

const WINDOW_MS = 15 * 60 * 1000;
const MAX_REQUESTS = intEnv("SERVICE_API_RATE_LIMIT_MAX", 300, 10, 5000);

const serviceApiRateLimiter = rateLimit({
  windowMs: WINDOW_MS,
  max: MAX_REQUESTS,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `service-api:${ipKey(req)}`,
  handler: (req, res) =>
    res.status(429).json({
      success: false,
      message: "Too many requests. Please try again later.",
      error: { code: "RATE_LIMITED" },
    }),
});

module.exports = { serviceApiRateLimiter };
