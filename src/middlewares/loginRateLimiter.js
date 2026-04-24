const rateLimit = require("express-rate-limit");
const { ipKeyGenerator } = require("express-rate-limit");

const formatTime = (seconds) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
};

const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // limit each IP to 5 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);
    return `${ip}:${req.body.identifier || "unknown"}`;
  },

  handler: (req, res) => {
    const retryAfter = req.rateLimit.resetTime - Date.now(); // milliseconds left
    const secondsLeft = Math.ceil(retryAfter / 1000);

    return res.status(429).json({
      ok: false,
      message: "Too many login attempts. Please try again later.",
      retry_after_seconds: secondsLeft,
      retry_after_time: formatTime(secondsLeft) // HH:MM:SS
    });
  }
});

module.exports = loginRateLimiter;
