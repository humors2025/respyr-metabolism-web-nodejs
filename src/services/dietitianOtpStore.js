"use strict";

/**
 * dietitianOtpStore.js  (MySQL-backed)
 *
 * Shared store for the dietitian "forgot password" OTP flow.
 *
 * WHY THIS IS NO LONGER REDIS-BACKED
 * ----------------------------------
 * On AWS Lambda the previous ioredis client pointed at 127.0.0.1:6379 (a leftover
 * local-dev default). With no Redis reachable inside the VPC, every command hit
 * the 20-retry limit and threw, surfacing as a 500 on /auth/send_diatitian_otp
 * and ~30s invocations (past API Gateway's 29s ceiling). RDS/MySQL is already
 * reachable and reliable from this function, and a short-lived TTL'd OTP does not
 * justify standing up + securing ElastiCache (VPC, SG:6379, TLS). So OTP state now
 * lives in MySQL.
 *
 * CONTRACT IS UNCHANGED. Every exported name + signature + return shape matches
 * the Redis version, so send_diatitian_otp.js, verify_diatitian_otp.js, and
 * update_diatitian_password.js require NO changes.
 *
 * STORAGE MODEL
 * -------------
 * One row per (normalized) email in `dietician_password_otp`. The three former
 * Redis keys map to columns with independent expiries:
 *   OTP        -> otp_hash, otp_attempts, otp_expires_at
 *   Cooldown   -> cooldown_expires_at
 *   Reset tok  -> reset_token_hash, reset_expires_at
 * MySQL does not auto-expire, so every read filters on `*_expires_at > NOW()`
 * (expired == absent) and setOtp() best-effort prunes fully-dead rows. All
 * expiries are computed with the DB clock (DATE_ADD(NOW(), ...)) so the app/DB
 * clock relationship is never a factor.
 *
 * SECURITY MODEL (VAPT / HIPAA) — unchanged from the Redis version:
 *  - OTP is never stored in clear text; only a bcrypt hash is kept. Verification
 *    is constant-time (bcrypt.compare).
 *  - Every OTP and reset token has a hard TTL (the PHP "no expiry" finding).
 *  - Verify attempts are capped per OTP to stop online brute force.
 *  - A correct OTP does not itself change the password; it lets the caller mint a
 *    single-use reset token. Only that token authorises the password change,
 *    binding step 3 to step 2.
 *
 * Required table (run once):
 *
 *   CREATE TABLE IF NOT EXISTS dietician_password_otp (
 *     email                VARCHAR(254)  NOT NULL,
 *     dietician_id         VARCHAR(191)  NULL,
 *     otp_hash             VARCHAR(255)  NULL,
 *     otp_attempts         INT UNSIGNED  NOT NULL DEFAULT 0,
 *     otp_expires_at       DATETIME      NULL,
 *     cooldown_expires_at  DATETIME      NULL,
 *     reset_token_hash     CHAR(64)      NULL,
 *     reset_expires_at     DATETIME      NULL,
 *     created_at           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     updated_at           DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP
 *                                        ON UPDATE CURRENT_TIMESTAMP,
 *     PRIMARY KEY (email),
 *     KEY idx_otp_expires   (otp_expires_at),
 *     KEY idx_reset_expires (reset_expires_at)
 *   ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci ROW_FORMAT=DYNAMIC;
 */

const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const pool = require("../config/db");

const TABLE = "dietician_password_otp";

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

// A dummy bcrypt hash used for timing-equalisation when an account / OTP does not
// exist — the caller does the same work either way so response time does not leak
// existence. Generated AT THE CONFIGURED COST so it always matches the real verify
// path's work, even if OTP_BCRYPT_ROUNDS changes.
const DUMMY_BCRYPT_HASH = bcrypt.hashSync(
  "otp-timing-equalizer-" + crypto.randomBytes(8).toString("hex"),
  OTP_BCRYPT_ROUNDS
);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function normalizeEmail(email) {
  return String(email == null ? "" : email).trim().toLowerCase();
}

/** Cryptographically-uniform numeric OTP of OTP_LENGTH digits (zero-padded). */
function generateNumericOtp() {
  const max = 10 ** OTP_LENGTH;
  const n = crypto.randomInt(0, max);
  return String(n).padStart(OTP_LENGTH, "0");
}

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

function timingSafeEqualHex(a, b) {
  const bufA = Buffer.from(String(a), "utf8");
  const bufB = Buffer.from(String(b), "utf8");
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/** Burn equivalent work when no account / OTP exists (timing-equalisation). */
async function dummyHashWork() {
  try {
    await bcrypt.compare("0".repeat(OTP_LENGTH), DUMMY_BCRYPT_HASH);
  } catch (_) {
    /* ignore */
  }
}

/**
 * Best-effort removal of rows whose OTP, cooldown, AND reset token are all gone.
 * Replaces Redis auto-expiry. Never throws into the caller — issuance must not
 * fail because a housekeeping DELETE failed. For higher traffic, prefer a MySQL
 * EVENT / scheduled job over this opportunistic call.
 */
async function pruneExpired() {
  try {
    await pool.execute(
      `DELETE FROM ${TABLE}
        WHERE (otp_hash IS NULL          OR otp_expires_at      <= NOW())
          AND (cooldown_expires_at IS NULL OR cooldown_expires_at <= NOW())
          AND (reset_token_hash IS NULL  OR reset_expires_at     <= NOW())`
    );
  } catch (err) {
    console.error("OTP_STORE_PRUNE_FAILED:", err?.code || err?.message);
  }
}

/** Clear ONLY the OTP fields (cooldown/reset untouched). */
async function clearOtp(normalizedEmail) {
  await pool.execute(
    `UPDATE ${TABLE}
        SET otp_hash = NULL, otp_attempts = 0, otp_expires_at = NULL
      WHERE email = ?`,
    [normalizedEmail]
  );
}

// ─── Cooldown ─────────────────────────────────────────────────────────────────

/** Remaining resend cooldown in seconds (0 if none / disabled / expired). */
async function getResendCooldown(email) {
  if (OTP_RESEND_COOLDOWN_SECONDS <= 0) return 0;
  const [rows] = await pool.execute(
    `SELECT TIMESTAMPDIFF(SECOND, NOW(), cooldown_expires_at) AS remaining
       FROM ${TABLE}
      WHERE email = ?
        AND cooldown_expires_at IS NOT NULL
        AND cooldown_expires_at > NOW()
      LIMIT 1`,
    [normalizeEmail(email)]
  );
  if (!rows || !rows.length) return 0;
  const remaining = Number(rows[0].remaining);
  return remaining > 0 ? remaining : 0;
}

// ─── Issue OTP ────────────────────────────────────────────────────────────────

/**
 * Generate + persist a fresh OTP for an email. Overwrites any existing OTP and
 * resets the attempt counter. Returns the PLAINTEXT otp — for emailing ONLY; it
 * must never be sent back to the client.
 */
async function setOtp(email, dieticianId) {
  const normalized = normalizeEmail(email);
  const otp = generateNumericOtp();
  const otpHash = await bcrypt.hash(otp, OTP_BCRYPT_ROUNDS);
  const did = dieticianId == null ? null : String(dieticianId);

  if (OTP_RESEND_COOLDOWN_SECONDS > 0) {
    await pool.execute(
      `INSERT INTO ${TABLE}
         (email, dietician_id, otp_hash, otp_attempts, otp_expires_at, cooldown_expires_at)
       VALUES
         (?, ?, ?, 0,
          DATE_ADD(NOW(), INTERVAL ? SECOND),
          DATE_ADD(NOW(), INTERVAL ? SECOND))
       ON DUPLICATE KEY UPDATE
         dietician_id        = VALUES(dietician_id),
         otp_hash            = VALUES(otp_hash),
         otp_attempts        = 0,
         otp_expires_at      = VALUES(otp_expires_at),
         cooldown_expires_at = VALUES(cooldown_expires_at)`,
      [normalized, did, otpHash, OTP_TTL_SECONDS, OTP_RESEND_COOLDOWN_SECONDS]
    );
  } else {
    await pool.execute(
      `INSERT INTO ${TABLE}
         (email, dietician_id, otp_hash, otp_attempts, otp_expires_at, cooldown_expires_at)
       VALUES
         (?, ?, ?, 0, DATE_ADD(NOW(), INTERVAL ? SECOND), NULL)
       ON DUPLICATE KEY UPDATE
         dietician_id        = VALUES(dietician_id),
         otp_hash            = VALUES(otp_hash),
         otp_attempts        = 0,
         otp_expires_at      = VALUES(otp_expires_at),
         cooldown_expires_at = VALUES(cooldown_expires_at)`,
      [normalized, did, otpHash, OTP_TTL_SECONDS]
    );
  }

  // Opportunistic housekeeping; never blocks/fails issuance.
  pruneExpired().catch(() => {});

  return { otp, ttl: OTP_TTL_SECONDS };
}

// ─── Verify OTP ───────────────────────────────────────────────────────────────

/**
 * Verify a submitted OTP against the stored hash.
 * Returns one of:
 *   { ok: true,  dietician_id, email }
 *   { ok: false, reason: 'not_found' | 'locked' | 'mismatch', attemptsLeft? }
 *
 * On every wrong attempt the counter is incremented; once it reaches
 * OTP_MAX_VERIFY_ATTEMPTS the OTP is destroyed (user must request a new one).
 * The OTP's TTL is preserved across attempts (we never touch otp_expires_at on
 * a mismatch), matching the Redis rewriteKeepTtl behaviour.
 */
async function verifyOtp(email, submittedOtp) {
  const normalized = normalizeEmail(email);

  const [rows] = await pool.execute(
    `SELECT dietician_id, otp_hash, otp_attempts
       FROM ${TABLE}
      WHERE email = ?
        AND otp_hash IS NOT NULL
        AND otp_expires_at > NOW()
      LIMIT 1`,
    [normalized]
  );
  const record = rows && rows.length ? rows[0] : null;

  if (!record) {
    await dummyHashWork(); // equalise timing vs. the match path
    return { ok: false, reason: "not_found" };
  }

  const attempts = Number(record.otp_attempts) || 0;
  if (attempts >= OTP_MAX_VERIFY_ATTEMPTS) {
    await clearOtp(normalized);
    return { ok: false, reason: "locked" };
  }

  const otpStr = String(submittedOtp == null ? "" : submittedOtp).trim();
  const matches = otpStr !== "" && (await bcrypt.compare(otpStr, record.otp_hash));

  if (!matches) {
    const newAttempts = attempts + 1;
    if (newAttempts >= OTP_MAX_VERIFY_ATTEMPTS) {
      await clearOtp(normalized); // lock out — force a fresh OTP
      return { ok: false, reason: "locked" };
    }
    await pool.execute(
      `UPDATE ${TABLE} SET otp_attempts = ? WHERE email = ?`,
      [newAttempts, normalized]
    );
    return {
      ok: false,
      reason: "mismatch",
      attemptsLeft: OTP_MAX_VERIFY_ATTEMPTS - newAttempts,
    };
  }

  // Correct OTP — consume it (cannot be replayed) and clear the cooldown.
  await pool.execute(
    `UPDATE ${TABLE}
        SET otp_hash = NULL, otp_attempts = 0, otp_expires_at = NULL,
            cooldown_expires_at = NULL
      WHERE email = ?`,
    [normalized]
  );

  return { ok: true, dietician_id: record.dietician_id, email: normalized };
}

// ─── Reset token (bridges Verify → Reset Password) ────────────────────────────

/**
 * Mint a single-use, short-lived reset token for an email that just passed OTP
 * verification. Only the SHA-256 hash is stored; the raw token is returned to the
 * client and must be presented to the reset-password endpoint.
 */
async function createResetToken(email, dieticianId) {
  const normalized = normalizeEmail(email);
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256(rawToken);
  const did = dieticianId == null ? null : String(dieticianId);

  await pool.execute(
    `INSERT INTO ${TABLE}
       (email, dietician_id, reset_token_hash, reset_expires_at)
     VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL ? SECOND))
     ON DUPLICATE KEY UPDATE
       dietician_id     = VALUES(dietician_id),
       reset_token_hash = VALUES(reset_token_hash),
       reset_expires_at = VALUES(reset_expires_at)`,
    [normalized, did, tokenHash, RESET_TOKEN_TTL_SECONDS]
  );

  return { token: rawToken, ttl: RESET_TOKEN_TTL_SECONDS };
}

/**
 * Validate + CONSUME a reset token (single use). Returns:
 *   { ok: true,  dietician_id, email }
 *   { ok: false }
 * A wrong token does NOT delete the legitimate one — it just fails.
 */
async function consumeResetToken(email, rawToken) {
  const normalized = normalizeEmail(email);

  const [rows] = await pool.execute(
    `SELECT dietician_id, reset_token_hash
       FROM ${TABLE}
      WHERE email = ?
        AND reset_token_hash IS NOT NULL
        AND reset_expires_at > NOW()
      LIMIT 1`,
    [normalized]
  );
  const record = rows && rows.length ? rows[0] : null;
  if (!record) return { ok: false };

  const submittedHash = sha256(String(rawToken == null ? "" : rawToken).trim());
  if (!timingSafeEqualHex(submittedHash, record.reset_token_hash)) {
    return { ok: false };
  }

  await pool.execute(
    `UPDATE ${TABLE}
        SET reset_token_hash = NULL, reset_expires_at = NULL
      WHERE email = ?`,
    [normalized]
  );

  return { ok: true, dietician_id: record.dietician_id, email: normalized };
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