"use strict";

/**
 * dietitianOtpStore.js  (MySQL-backed, reuses the existing `otp_verifications` table)
 *
 * Shared store for the dietitian "forgot password" OTP flow.
 *
 * WHY MYSQL (not Redis)
 * ---------------------
 * On AWS Lambda the previous ioredis client pointed at 127.0.0.1:6379 with no
 * reachable Redis, so every command hit the retry limit and surfaced as a 500 /
 * ~30s timeout. RDS/MySQL is already reachable and reliable from this function,
 * and a short-lived TTL'd OTP does not justify standing up + securing ElastiCache.
 * So OTP state lives in MySQL.
 *
 * WHY `otp_verifications` (not a new table)
 * -----------------------------------------
 * The app already has a generic `otp_verifications` table (used by the login OTP
 * flow, purpose='login'). We reuse it instead of adding a table — chosen by the
 * project owner. The table is a one-row-per-OTP design with a `purpose` discriminator,
 * so the password-reset flow stores its own rows under dedicated purposes and NEVER
 * touches rows of other purposes (every statement filters on purpose).
 *
 * EXISTING TABLE (unchanged):
 *   id          INT PK AUTO_INCREMENT
 *   email       VARCHAR(100)
 *   otp_code    TEXT            -- we store a bcrypt hash (OTP) or sha256 (reset token)
 *   purpose     VARCHAR(50)     -- 'password_reset' | 'password_reset_token' (default 'login')
 *   is_verified TINYINT(1)      -- 0/1; set to 1 when an OTP is successfully verified
 *   attempts    INT             -- verify attempt counter for the OTP row
 *   expires_at  DATETIME NOT NULL
 *   created_at  DATETIME        -- DEFAULT CURRENT_TIMESTAMP; used to derive resend cooldown
 *   verified_at DATETIME NULL
 *
 * STORAGE MODEL (this flow)
 * -------------------------
 *   OTP        -> purpose='password_reset'        : otp_code=bcrypt(otp), attempts, expires_at, is_verified/verified_at
 *   Reset tok  -> purpose='password_reset_token'  : otp_code=sha256(token), expires_at
 *   Cooldown   -> derived from the latest password_reset row's created_at (no column needed)
 * MySQL does not auto-expire, so every read filters on `expires_at > NOW()` (expired ==
 * absent) and setOtp()/pruneExpired() remove dead rows. All expiries are computed with
 * the DB clock (DATE_ADD(NOW(), ...)) so app/DB clock skew is never a factor. There is
 * no unique key on email, so "overwrite" is implemented as DELETE-by-purpose + INSERT.
 *
 * NOTE: `otp_verifications` has no dietician_id column, so the store returns
 * dietician_id:null. This is fine — the reset-password controller re-resolves the
 * account by email before updating, and audit logs still key on the (hashed) email.
 *
 * SECURITY MODEL (VAPT / HIPAA) — unchanged:
 *  - OTP is never stored in clear text; only a bcrypt hash. Verification is
 *    constant-time (bcrypt.compare).
 *  - Every OTP and reset token has a hard TTL (closes the PHP "no expiry" finding).
 *  - Verify attempts are capped per OTP to stop online brute force.
 *  - A correct OTP does not itself change the password; it lets the caller mint a
 *    single-use reset token. Only that token authorises the password change,
 *    binding step 3 to step 2.
 */

const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const pool = require("../config/db");

const TABLE = "otp_verifications";
const PURPOSE_OTP = "password_reset";
const PURPOSE_RESET = "password_reset_token";

// ─── Config (all env-overridable) ─────────────────────────────────────────────

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  if (typeof min === "number" && v < min) return min;
  if (typeof max === "number" && v > max) return max;
  return v;
}

const OTP_LENGTH = intEnv("OTP_LENGTH", 6, 4, 10);
// const OTP_TTL_SECONDS = intEnv("OTP_TTL_SECONDS", 300, 30, 3600);
const OTP_TTL_SECONDS = intEnv("OTP_TTL_SECONDS", 60, 30, 3600);
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
 * Best-effort removal of THIS FLOW's expired rows (never other purposes like
 * 'login'). Replaces Redis auto-expiry. Never throws into the caller — issuance
 * must not fail because a housekeeping DELETE failed. For higher traffic, prefer a
 * MySQL EVENT / scheduled job over this opportunistic call.
 */
async function pruneExpired() {
  try {
    await pool.execute(
      `DELETE FROM ${TABLE}
        WHERE purpose IN (?, ?)
          AND expires_at <= NOW()`,
      [PURPOSE_OTP, PURPOSE_RESET]
    );
  } catch (err) {
    console.error("OTP_STORE_PRUNE_FAILED:", err?.code || err?.message);
  }
}

// ─── Cooldown ─────────────────────────────────────────────────────────────────

/**
 * Remaining resend cooldown in seconds (0 if none / disabled). Derived from the
 * most recent password_reset OTP row's created_at — no dedicated column needed.
 */
async function getResendCooldown(email) {
  if (OTP_RESEND_COOLDOWN_SECONDS <= 0) return 0;
  const [rows] = await pool.execute(
    `SELECT TIMESTAMPDIFF(SECOND, NOW(), DATE_ADD(created_at, INTERVAL ? SECOND)) AS remaining
       FROM ${TABLE}
      WHERE email = ?
        AND purpose = ?
      ORDER BY id DESC
      LIMIT 1`,
    [OTP_RESEND_COOLDOWN_SECONDS, normalizeEmail(email), PURPOSE_OTP]
  );
  if (!rows || !rows.length) return 0;
  const remaining = Number(rows[0].remaining);
  return remaining > 0 ? remaining : 0;
}

// ─── Issue OTP ────────────────────────────────────────────────────────────────

/**
 * Generate + persist a fresh OTP for an email. Overwrites any existing
 * password_reset OTP (DELETE + INSERT, since there is no unique key on email) and
 * resets the attempt counter. Returns the PLAINTEXT otp — for emailing ONLY; it
 * must never be sent back to the client. `dieticianId` is accepted for signature
 * compatibility but not stored (no column on this table).
 */
async function setOtp(email, dieticianId) { // eslint-disable-line no-unused-vars
  const normalized = normalizeEmail(email);
  const otp = generateNumericOtp();
  const otpHash = await bcrypt.hash(otp, OTP_BCRYPT_ROUNDS);

  // Overwrite any previous OTP for this email (this flow only).
  await pool.execute(
    `DELETE FROM ${TABLE} WHERE email = ? AND purpose = ?`,
    [normalized, PURPOSE_OTP]
  );

  await pool.execute(
    `INSERT INTO ${TABLE}
       (email, otp_code, purpose, is_verified, attempts, expires_at)
     VALUES
       (?, ?, ?, 0, 0, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
    [normalized, otpHash, PURPOSE_OTP, OTP_TTL_SECONDS]
  );

  // Opportunistic housekeeping; never blocks/fails issuance.
  pruneExpired().catch(() => {});

  return { otp, ttl: OTP_TTL_SECONDS };
}

// ─── Verify OTP ───────────────────────────────────────────────────────────────

/**
 * Verify a submitted OTP against the stored hash.
 * Returns one of:
 *   { ok: true,  dietician_id: null, email }
 *   { ok: false, reason: 'not_found' | 'locked' | 'mismatch', attemptsLeft? }
 *
 * On every wrong attempt the counter is incremented; once it reaches
 * OTP_MAX_VERIFY_ATTEMPTS the OTP row is destroyed (user must request a new one).
 * On success the row is marked is_verified=1 (so it can't be re-verified) and
 * cannot be replayed.
 */
async function verifyOtp(email, submittedOtp) {
  const normalized = normalizeEmail(email);

  const [rows] = await pool.execute(
    `SELECT id, otp_code, attempts
       FROM ${TABLE}
      WHERE email = ?
        AND purpose = ?
        AND is_verified = 0
        AND expires_at > NOW()
      ORDER BY id DESC
      LIMIT 1`,
    [normalized, PURPOSE_OTP]
  );
  const record = rows && rows.length ? rows[0] : null;

  if (!record) {
    await dummyHashWork(); // equalise timing vs. the match path
    return { ok: false, reason: "not_found" };
  }

  const attempts = Number(record.attempts) || 0;
  if (attempts >= OTP_MAX_VERIFY_ATTEMPTS) {
    await pool.execute(`DELETE FROM ${TABLE} WHERE id = ?`, [record.id]);
    return { ok: false, reason: "locked" };
  }

  const otpStr = String(submittedOtp == null ? "" : submittedOtp).trim();
  const matches = otpStr !== "" && (await bcrypt.compare(otpStr, record.otp_code));

  if (!matches) {
    const newAttempts = attempts + 1;
    if (newAttempts >= OTP_MAX_VERIFY_ATTEMPTS) {
      await pool.execute(`DELETE FROM ${TABLE} WHERE id = ?`, [record.id]);
      return { ok: false, reason: "locked" };
    }
    await pool.execute(
      `UPDATE ${TABLE} SET attempts = ? WHERE id = ?`,
      [newAttempts, record.id]
    );
    return {
      ok: false,
      reason: "mismatch",
      attemptsLeft: OTP_MAX_VERIFY_ATTEMPTS - newAttempts,
    };
  }

  // Correct OTP — mark verified so it cannot be re-verified or replayed.
  await pool.execute(
    `UPDATE ${TABLE} SET is_verified = 1, verified_at = NOW() WHERE id = ?`,
    [record.id]
  );

  return { ok: true, dietician_id: null, email: normalized };
}

// ─── Reset token (bridges Verify → Reset Password) ────────────────────────────

/**
 * Mint a single-use, short-lived reset token for an email that just passed OTP
 * verification. Only the SHA-256 hash is stored (in otp_code under the
 * password_reset_token purpose); the raw token is returned to the client and must
 * be presented to the reset-password endpoint. `dieticianId` is accepted for
 * signature compatibility but not stored.
 */
async function createResetToken(email, dieticianId) { // eslint-disable-line no-unused-vars
  const normalized = normalizeEmail(email);
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = sha256(rawToken);

  // Overwrite any previous reset token for this email (this flow only).
  await pool.execute(
    `DELETE FROM ${TABLE} WHERE email = ? AND purpose = ?`,
    [normalized, PURPOSE_RESET]
  );

  await pool.execute(
    `INSERT INTO ${TABLE}
       (email, otp_code, purpose, is_verified, attempts, expires_at)
     VALUES
       (?, ?, ?, 0, 0, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
    [normalized, tokenHash, PURPOSE_RESET, RESET_TOKEN_TTL_SECONDS]
  );

  return { token: rawToken, ttl: RESET_TOKEN_TTL_SECONDS };
}

/**
 * Validate + CONSUME a reset token (single use). Returns:
 *   { ok: true,  dietician_id: null, email }
 *   { ok: false }
 * A wrong token does NOT delete the legitimate one — it just fails.
 */
async function consumeResetToken(email, rawToken) {
  const normalized = normalizeEmail(email);

  const [rows] = await pool.execute(
    `SELECT id, otp_code
       FROM ${TABLE}
      WHERE email = ?
        AND purpose = ?
        AND expires_at > NOW()
      ORDER BY id DESC
      LIMIT 1`,
    [normalized, PURPOSE_RESET]
  );
  const record = rows && rows.length ? rows[0] : null;
  if (!record) return { ok: false };

  const submittedHash = sha256(String(rawToken == null ? "" : rawToken).trim());
  if (!timingSafeEqualHex(submittedHash, record.otp_code)) {
    return { ok: false };
  }

  await pool.execute(`DELETE FROM ${TABLE} WHERE id = ?`, [record.id]);

  return { ok: true, dietician_id: null, email: normalized };
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
