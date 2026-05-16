// const rateLimit = require("express-rate-limit");
// const { ipKeyGenerator } = require("express-rate-limit");

// const formatTime = (seconds) => {
//   const h = Math.floor(seconds / 3600);
//   const m = Math.floor((seconds % 3600) / 60);
//   const s = seconds % 60;

//   return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
// };

// const loginRateLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000, // 15 minutes
//   max: 3, // limit each IP to 5 requests per windowMs
//   standardHeaders: true,
//   legacyHeaders: false,

//   keyGenerator: (req) => {
//     const ip = ipKeyGenerator(req);
//     return `${ip}:${req.body.identifier || "unknown"}`;
//   },

//   handler: (req, res) => {
//     const retryAfter = req.rateLimit.resetTime - Date.now(); // milliseconds left
//     const secondsLeft = Math.ceil(retryAfter / 1000);

//     return res.status(429).json({
//       ok: false,
//       message: "Too many login attempts. Please try again later.",
//       retry_after_seconds: secondsLeft,
//       retry_after_time: formatTime(secondsLeft) // HH:MM:SS
//     });
//   }
// });

// module.exports = loginRateLimiter;







const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');

const formatTime = (seconds) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};

const rateLimitHandler = (req, res) => {
  const retryAfter = req.rateLimit.resetTime - Date.now();
  const secondsLeft = Math.max(1, Math.ceil(retryAfter / 1000));

  return res.status(429).json({
    ok: false,
    message: 'Too many login attempts. Please try again later.',
    retry_after_seconds: secondsLeft,
    retry_after_time: formatTime(secondsLeft),
  });
};

// Strict limiter: per IP + identifier (catches targeted brute force)
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // 5 attempts per window
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // don't count successful logins against the limit
  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);
    const identifier = String(req.body?.identifier || 'unknown')
      .trim()
      .toLowerCase();
    return `login:${ip}:${identifier}`;
  },
  handler: rateLimitHandler,
});

// Broad limiter: per IP only (catches distributed identifier guessing)
const loginIpRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                  // 20 attempts per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => `login-ip:${ipKeyGenerator(req)}`,
  handler: rateLimitHandler,
});

module.exports = { loginRateLimiter, loginIpRateLimiter };








// const rateLimit = require('express-rate-limit');
// const { ipKeyGenerator } = require('express-rate-limit');
// const crypto = require('crypto');

// const isProduction =
//   process.env.NODE_ENV === 'production' ||
//   Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

// const formatTime = (seconds) => {
//   const h = Math.floor(seconds / 3600);
//   const m = Math.floor((seconds % 3600) / 60);
//   const s = seconds % 60;

//   return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(
//     s
//   ).padStart(2, '0')}`;
// };

// const hashValue = (value) => {
//   return crypto
//     .createHash('sha256')
//     .update(String(value))
//     .digest('hex')
//     .slice(0, 24);
// };

// const getSafeIpKey = (req) => {
//   const ip = req.ip || req.socket?.remoteAddress || 'unknown';
//   return ipKeyGenerator(ip);
// };

// const normalizeIdentifier = (req) => {
//   return String(req.body?.identifier || 'unknown').trim().toLowerCase();
// };

// const rateLimitHandler = (req, res) => {
//   const resetTime = req.rateLimit?.resetTime;

//   const retryAfterMs =
//     resetTime instanceof Date
//       ? resetTime.getTime() - Date.now()
//       : 60 * 1000;

//   const secondsLeft = Math.max(1, Math.ceil(retryAfterMs / 1000));

//   return res.status(429).json({
//     ok: false,
//     message: 'Too many attempts. Please try again later.',
//     retry_after_seconds: secondsLeft,
//     retry_after_time: formatTime(secondsLeft),
//   });
// };

// /*
// |--------------------------------------------------------------------------
// | Broad Login Limiter
// | Per IP. Catches password spraying and bot attacks.
// |--------------------------------------------------------------------------
// */

// const loginIpRateLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: isProduction ? 20 : 100,
//   standardHeaders: true,
//   legacyHeaders: false,
//   skipSuccessfulRequests: true,
//   keyGenerator: (req) => `login-ip:${getSafeIpKey(req)}`,
//   handler: rateLimitHandler,
// });

// /*
// |--------------------------------------------------------------------------
// | Strict Login Limiter
// | Per IP + identifier. Catches targeted brute force.
// |--------------------------------------------------------------------------
// */

// const loginRateLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: isProduction ? 5 : 50,
//   standardHeaders: true,
//   legacyHeaders: false,
//   skipSuccessfulRequests: true,
//   keyGenerator: (req) => {
//     const ip = getSafeIpKey(req);
//     const identifierHash = hashValue(normalizeIdentifier(req));

//     return `login:${ip}:${identifierHash}`;
//   },
//   handler: rateLimitHandler,
// });

// /*
// |--------------------------------------------------------------------------
// | Refresh Token Limiter
// |--------------------------------------------------------------------------
// */

// const refreshTokenRateLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   max: isProduction ? 30 : 200,
//   standardHeaders: true,
//   legacyHeaders: false,
//   keyGenerator: (req) => `refresh-token:${getSafeIpKey(req)}`,
//   handler: rateLimitHandler,
// });

// module.exports = {
//   loginIpRateLimiter,
//   loginRateLimiter,
//   refreshTokenRateLimiter,
// };