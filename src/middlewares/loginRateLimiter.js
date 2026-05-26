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