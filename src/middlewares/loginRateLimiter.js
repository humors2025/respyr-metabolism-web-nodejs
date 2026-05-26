// middlewares/loginRateLimiter.js
//
// Two login rate limiters:
//   - loginRateLimiter   : strict per-IP + per-identifier (catches targeted brute force)
//   - loginIpRateLimiter : broad per-IP only (catches distributed identifier guessing)
//
// Uses Redis when REDIS_URL is set so counters survive across Lambda
// invocations and instances. Otherwise falls back to the in-memory store
// (per-process only — fine for single-instance dev).

'use strict';

const rateLimit = require('express-rate-limit');
const { ipKeyGenerator } = require('express-rate-limit');

let store = undefined; // undefined = use default in-memory store

if (process.env.REDIS_URL) {
  try {
    const Redis = require('ioredis');
    const RedisStore = require('rate-limit-redis').default || require('rate-limit-redis');

    const client = new Redis(process.env.REDIS_URL, {
      enableOfflineQueue: false,
      maxRetriesPerRequest: 1,
      lazyConnect: false,
    });

    client.on('error', (e) => {
      console.error('LOGIN_RATELIMIT_REDIS_ERROR:', e.message);
    });

    store = new RedisStore({
      sendCommand: (...args) => client.call(...args),
      prefix: 'rl:login:',
    });

    console.log('Login rate limiter using Redis store');
  } catch (e) {
    console.error(
      'LOGIN_RATELIMIT_REDIS_INIT_FAILED, falling back to memory store:',
      e.message
    );
    store = undefined;
  }
}

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
  store: store,
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
  store: store,
  keyGenerator: (req) => `login-ip:${ipKeyGenerator(req)}`,
  handler: rateLimitHandler,
});

module.exports = { loginRateLimiter, loginIpRateLimiter };
