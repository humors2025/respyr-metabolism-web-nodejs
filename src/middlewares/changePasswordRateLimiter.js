const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');

const formatTime = (seconds) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;

  return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
};

const changePasswordRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,

  keyGenerator: (req) => {
    const ip = ipKeyGenerator(req);

    const dieticianId = String(req.user?.sub || 'unknown')
      .trim()
      .toUpperCase();

    return `change-password:${ip}:${dieticianId}`;
  },

  handler: (req, res) => {
    const retryAfter = req.rateLimit.resetTime - Date.now();
    const secondsLeft = Math.max(1, Math.ceil(retryAfter / 1000));

    return res.status(429).json({
      ok: false,
      message: 'Too many password change attempts. Please try again later.',
      retry_after_seconds: secondsLeft,
      retry_after_time: formatTime(secondsLeft),
    });
  },
});

module.exports = changePasswordRateLimiter;