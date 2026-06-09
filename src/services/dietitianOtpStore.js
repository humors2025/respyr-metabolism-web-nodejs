"use strict";

/**
 * dietitianOtpStore.js
 *
 * Shared Redis-backed store for the dietitian "forgot password" OTP flow.
 * Converted from the PHP `$_SESSION['dietician_otp']` mechanism — there are NO
 * PHP sessions in the Node app, so OTP state lives in Redis and is the single
 * source of truth shared by the three endpoints:
 *
 *   send_diatitian_otp.js        → setOtp()      (issue a 6-digit OTP)
 *   verify_diatitian_otp.js      → verifyOtp()   + createResetToken()
 *   update_diatitian_password.js → consumeResetToken()
 *
 * Centralising the key names + hashing here is deliberate: the verify and reset
 * endpoints MUST agree with the send endpoint on the exact contract, and a
 * shared module makes drift impossible.
 *
 * Security model (VAPT / HIPAA):
 *  - The OTP is NEVER stored in clear text. Only a bcrypt hash is kept, so a
 *    Redis dump cannot reveal a live OTP. Verification is constant-time
 *    (bcrypt.compare).
 *  - Every OTP and reset token has a hard TTL — Redis expires them automatically
 *    (the PHP set "no expiry", a finding closed here).
 *  - Verify attempts are capped per OTP to stop online brute force of the
 *    6-digit space.
 *  - A successful OTP verification does NOT itself change the password. It mints
 *    a short-lived, single-use reset token; only that token authorises the
 *    password change. This binds step 3 to step 2.
 */

const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const redis = require("../config/redis");

// ─── Config (all env-overridable) ─────────────────────────────────────────────

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  if (typeof min === "number" && v < min) return min;
  if (typeof max === "number" && v > max) return max;
  return v;
}

const OTP_LENGTH = intEnv("OTP_LENGTH", 6, 4, 10);
const OTP_TTL_SECONDS = intEnv("OTP_TTL_SECONDS", 300, 30, 3600);
const OTP_RESEND_COOLDOWN_SECONDS = intEnv("OTP_RESEND_COOLDOWN_SECONDS", 60, 0, 3600);
const OTP_MAX_VERIFY_ATTEMPTS = intEnv("OTP_MAX_VERIFY_ATTEMPTS", 5, 1, 20);
const OTP_BCRYPT_ROUNDS = intEnv("OTP_BCRYPT_ROUNDS", 10, 8, 14);
const RESET_TOKEN_TTL_SECONDS = intEnv("OTP_RESET_TOKEN_TTL_SECONDS", 600, 60, 3600);

// A dummy bcrypt hash used for timing-equalisation when an account does not
// exist — the caller does the same work either way so response time does not
// leak account existence. Generated AT THE CONFIGURED COST so it always matches
// the real verify path's work, even if OTP_BCRYPT_ROUNDS changes.
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(
  "otp-timing-equalizer-" + crypto.randomBytes(8).toString("hex"),
  OTP_BCRYPT_ROUNDS
);

// ─── Keys ─────────────────────────────────────────────────────────────────────

function normalizeEmail(email) {
  return String(email == null ? "" : email).trim().toLowerCase();
}

const otpKey = (email) => `dietician_otp:${normalizeEmail(email)}`;
const cooldownKey = (email) => `dietician_otp_cooldown:${normalizeEmail(email)}`;
const resetKey = (email) => `dietician_pwd_reset:${normalizeEmail(email)}`;

// ─── OTP generation ───────────────────────────────────────────────────────────

/** Cryptographically-uniform numeric OTP of OTP_LENGTH digits (zero-padded). */
function generateNumericOtp() {
  const max = 10 ** OTP_LENGTH;
  const n = crypto.randomInt(0, max);
  return String(n).padStart(OTP_LENGTH, "0");
}

// ─── Cooldown ─────────────────────────────────────────────────────────────────

/** Remaining resend cooldown in seconds (0 if none / disabled). */
async function getResendCooldown(email) {
  if (OTP_RESEND_COOLDOWN_SECONDS <= 0) return 0;
  const ttl = await redis.ttl(cooldownKey(email));
  return ttl > 0 ? ttl : 0;
}

// ─── Issue OTP ────────────────────────────────────────────────────────────────

/**
 * Generate + persist a fresh OTP for an email. Overwrites any existing OTP
 * (resets the attempt counter). Returns the PLAINTEXT otp — for emailing ONLY;
 * it must never be sent back to the client.
 *
 * Store contract (value is JSON):
 *   { dietician_id, email, otp_hash, verified:false, attempts:0, created_at }
 */
async function setOtp(email, dieticianId) {
  const normalized = normalizeEmail(email);
  const otp = generateNumericOtp();
  const otpHash = await bcrypt.hash(otp, OTP_BCRYPT_ROUNDS);

  const record = {
    dietician_id: dieticianId == null ? null : String(dieticianId),
    email: normalized,
    otp_hash: otpHash,
    verified: false,
    attempts: 0,
    created_at: Math.floor(Date.now() / 1000),
  };

  await redis.set(otpKey(normalized), JSON.stringify(record), "EX", OTP_TTL_SECONDS);

  if (OTP_RESEND_COOLDOWN_SECONDS > 0) {
    await redis.set(cooldownKey(normalized), "1", "EX", OTP_RESEND_COOLDOWN_SECONDS);
  }

  return { otp, ttl: OTP_TTL_SECONDS };
}

/** Burn equivalent work when no account exists (timing-equalisation). */
async function dummyHashWork() {
  try {
    await bcrypt.compare("0".repeat(OTP_LENGTH), DUMMY_BCRYPT_HASH);
  } catch (_) {
    /* ignore */
  }
}

// ─── Verify OTP ───────────────────────────────────────────────────────────────

/** Re-write a record without losing its remaining TTL. */
async function rewriteKeepTtl(key, record) {
  const pttl = await redis.pttl(key);
  if (pttl <= 0) return; // expired in the meantime — let it stay gone
  await redis.set(key, JSON.stringify(record), "PX", pttl);
}

/**
 * Verify a submitted OTP against the stored hash.
 * Returns one of:
 *   { ok: true,  dietician_id, email }
 *   { ok: false, reason: 'not_found' | 'locked' | 'mismatch', attemptsLeft? }
 *
 * On every wrong attempt the counter is incremented; once it reaches
 * OTP_MAX_VERIFY_ATTEMPTS the OTP is destroyed (the user must request a new one).
 */
async function verifyOtp(email, submittedOtp) {
  const key = otpKey(email);
  const raw = await redis.get(key);

  if (!raw) {
    await dummyHashWork(); // equalise timing vs. the match path
    return { ok: false, reason: "not_found" };
  }

  let record;
  try {
    record = JSON.parse(raw);
  } catch (_) {
    await redis.del(key);
    return { ok: false, reason: "not_found" };
  }

  if (Number(record.attempts) >= OTP_MAX_VERIFY_ATTEMPTS) {
    await redis.del(key);
    return { ok: false, reason: "locked" };
  }

  const otpStr = String(submittedOtp == null ? "" : submittedOtp).trim();
  const matches = otpStr !== "" && (await bcrypt.compare(otpStr, record.otp_hash));

  if (!matches) {
    record.attempts = Number(record.attempts) + 1;
    if (record.attempts >= OTP_MAX_VERIFY_ATTEMPTS) {
      await redis.del(key); // lock out — force a fresh OTP
      return { ok: false, reason: "locked" };
    }
    await rewriteKeepTtl(key, record);
    return {
      ok: false,
      reason: "mismatch",
      attemptsLeft: OTP_MAX_VERIFY_ATTEMPTS - record.attempts,
    };
  }

  // Correct OTP — consume it so it cannot be replayed, then let the caller mint
  // a reset token.
  await redis.del(key);
  await redis.del(cooldownKey(email));

  return { ok: true, dietician_id: record.dietician_id, email: record.email };
}

// ─── Reset token (bridges Verify → Reset Password) ────────────────────────────

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function timingSafeEqualHex(a, b) {
  const bufA = Buffer.from(String(a), "utf8");
  const bufB = Buffer.from(String(b), "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Mint a single-use, short-lived reset token for an email that just passed OTP
 * verification. Only the SHA-256 hash is stored; the raw token is returned to
 * the client and must be presented to the reset-password endpoint.
 */
async function createResetToken(email, dieticianId) {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const record = {
    token_hash: sha256(rawToken),
    dietician_id: dieticianId == null ? null : String(dieticianId),
    email: normalizeEmail(email),
    created_at: Math.floor(Date.now() / 1000),
  };
  await redis.set(resetKey(email), JSON.stringify(record), "EX", RESET_TOKEN_TTL_SECONDS);
  return { token: rawToken, ttl: RESET_TOKEN_TTL_SECONDS };
}

/**
 * Validate + CONSUME a reset token (single use). Returns:
 *   { ok: true,  dietician_id, email }
 *   { ok: false }
 */
async function consumeResetToken(email, rawToken) {
  const key = resetKey(email);
  const raw = await redis.get(key);
  if (!raw) return { ok: false };

  let record;
  try {
    record = JSON.parse(raw);
  } catch (_) {
    await redis.del(key);
    return { ok: false };
  }

  const submittedHash = sha256(String(rawToken == null ? "" : rawToken).trim());
  if (!timingSafeEqualHex(submittedHash, record.token_hash)) {
    // Wrong token — do NOT delete the legitimate one; just fail.
    return { ok: false };
  }

  await redis.del(key); // single use
  return { ok: true, dietician_id: record.dietician_id, email: record.email };
}

module.exports = {
  // config (exposed for messages/headers)
  OTP_LENGTH,
  OTP_TTL_SECONDS,
  OTP_RESEND_COOLDOWN_SECONDS,
  OTP_MAX_VERIFY_ATTEMPTS,
  RESET_TOKEN_TTL_SECONDS,
  // helpers
  normalizeEmail,
  // operations
  getResendCooldown,
  setOtp,
  dummyHashWork,
  verifyOtp,
  createResetToken,
  consumeResetToken,
};
