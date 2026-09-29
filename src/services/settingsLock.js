"use strict";

/**
 * settingsLock.js — Google Authenticator (TOTP) gate for Super Admin › Settings.
 *
 * The Settings page changes platform pricing and the commission rate, so a
 * signed-in super admin must also enter the 6-digit code from their
 * authenticator app before the page unlocks.
 *
 * FLOW
 *   First time (no authenticator yet):
 *     1. requestCode / verifyCode  -> 6-digit code emailed to SETTINGS_OTP_EMAIL
 *        proves the enrolment is allowed (a stolen password alone can't enrol)
 *     2. startMfaSetup / confirmMfaSetup -> QR code scanned into Google
 *        Authenticator, confirmed with one app code; 8 backup codes issued
 *   Every time after:
 *     verifyMfa(code)  -> app code (or a one-time backup code) unlocks
 *   Guard:
 *     requireSettingsUnlock -> session unlocked AND authenticator enrolled
 *
 * The unlock is bound to the login session id (JWT `sid` =
 * dietician_refresh_tokens.id), which stays the same across access-token
 * refreshes. Logging out revokes that session, so the unlock ends with it.
 * It is also capped at SETTINGS_UNLOCK_HOURS, because a login session can
 * last JWT_REFRESH_TTL_DAYS (30 days).
 *
 * STORAGE — reuses `otp_verifications` (see dietitianOtpStore.js) under
 * dedicated purposes; every statement filters on purpose so other flows'
 * rows are never touched. The `email` column holds the key "sa:<dietician_id>".
 *   settings_otp        : otp_code = bcrypt(email code), attempts, expires_at
 *   settings_unlock     : otp_code = sha256(sid), expires_at
 *   settings_mfa_pending: otp_code = encrypted TOTP secret, 10-minute expiry
 *   settings_mfa        : otp_code = encrypted TOTP secret, attempts = last
 *                         used 30s time step (blocks code replay), no expiry
 *   settings_mfa_backup : otp_code = bcrypt(backup code), one row per code
 * TOTP secrets are AES-256-GCM encrypted with SETTINGS_MFA_KEY (falls back to
 * a key derived from JWT_SECRET — rotating that secret means re-enrolling).
 *
 * Lost phone and backup codes: delete the admin's settings_mfa and
 * settings_mfa_backup rows; the next visit starts enrolment again via email.
 */

const crypto = require("crypto");
const axios = require("axios");
const bcrypt = require("bcrypt");
const pool = require("../config/db");

const TABLE = "otp_verifications";
const PURPOSE_OTP = "settings_otp";
const PURPOSE_UNLOCK = "settings_unlock";
const PURPOSE_MFA_PENDING = "settings_mfa_pending";
const PURPOSE_MFA = "settings_mfa";
const PURPOSE_MFA_BACKUP = "settings_mfa_backup";
const NEVER_EXPIRES = "2099-12-31 23:59:59";

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  return Math.min(max, Math.max(min, v));
}

// Temporary default for testing; set SETTINGS_OTP_EMAIL to change the inbox.
const SETTINGS_OTP_EMAIL = (process.env.SETTINGS_OTP_EMAIL || "harsh@respyr.in").trim().toLowerCase();
const OTP_TTL_SECONDS = intEnv("SETTINGS_OTP_TTL_SECONDS", 300, 60, 1800);
const OTP_RESEND_COOLDOWN_SECONDS = intEnv("SETTINGS_OTP_RESEND_COOLDOWN_SECONDS", 60, 0, 3600);
const OTP_MAX_VERIFY_ATTEMPTS = intEnv("SETTINGS_OTP_MAX_ATTEMPTS", 5, 1, 10);
const UNLOCK_HOURS = intEnv("SETTINGS_UNLOCK_HOURS", 8, 1, 720);
const MFA_ISSUER = process.env.SETTINGS_MFA_ISSUER || "Rysflo Settings";
const MFA_SETUP_TTL_SECONDS = 600;
const BACKUP_CODE_COUNT = 8;

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "Rysflo <no-reply@respyr.ai>";

const keyFor = (actorId) => `sa:${String(actorId).trim()}`;
const sha256 = (v) => crypto.createHash("sha256").update(String(v)).digest("hex");

/** "harsh@respyr.in" -> "h***h@respyr.in" — shown on the lock screen. */
function maskEmail(email) {
  const [local, domain] = String(email).split("@");
  if (!domain) return "***";
  const shown = local.length <= 2 ? local[0] + "***" : `${local[0]}***${local[local.length - 1]}`;
  return `${shown}@${domain}`;
}

async function pruneExpired() {
  try {
    await pool.execute(
      `DELETE FROM ${TABLE} WHERE purpose IN (?, ?, ?) AND expires_at <= NOW()`,
      [PURPOSE_OTP, PURPOSE_UNLOCK, PURPOSE_MFA_PENDING]
    );
  } catch (err) {
    console.error("SETTINGS_LOCK_PRUNE_FAILED:", err?.code || err?.message);
  }
}

// ─── TOTP (RFC 6238: SHA-1, 6 digits, 30s — what Google Authenticator uses) ──

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buf) {
  let bits = 0, value = 0, out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(str) {
  let bits = 0, value = 0;
  const out = [];
  for (const ch of String(str).replace(/=+$/, "").toUpperCase()) {
    const idx = B32.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(secret, counter) {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const h = crypto.createHmac("sha1", secret).update(msg).digest();
  const offset = h[h.length - 1] & 0xf;
  return String((h.readUInt32BE(offset) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

const currentStep = () => Math.floor(Date.now() / 1000 / 30);

/** Time step the code belongs to (±1 step for clock drift), or null. */
function matchTotp(secretB32, code) {
  const secret = base32Decode(secretB32);
  const now = currentStep();
  for (const step of [now - 1, now, now + 1]) {
    if (crypto.timingSafeEqual(Buffer.from(hotp(secret, step)), Buffer.from(code))) return step;
  }
  return null;
}

// ─── Secret encryption ────────────────────────────────────────────────────────

function mfaKey() {
  if (process.env.SETTINGS_MFA_KEY) return crypto.createHash("sha256").update(process.env.SETTINGS_MFA_KEY).digest();
  if (!process.env.JWT_SECRET) throw new Error("SETTINGS_MFA_KEY or JWT_SECRET required");
  return Buffer.from(crypto.hkdfSync("sha256", process.env.JWT_SECRET, "rysflo-settings-mfa", "totp-secret", 32));
}

function encryptSecret(plain) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", mfaKey(), iv);
  const ct = Buffer.concat([c.update(plain, "utf8"), c.final()]);
  return ["v1", iv.toString("base64"), c.getAuthTag().toString("base64"), ct.toString("base64")].join(":");
}

function decryptSecret(stored) {
  const [v, iv, tag, ct] = String(stored).split(":");
  if (v !== "v1") throw new Error("unknown secret format");
  const d = crypto.createDecipheriv("aes-256-gcm", mfaKey(), Buffer.from(iv, "base64"));
  d.setAuthTag(Buffer.from(tag, "base64"));
  return Buffer.concat([d.update(Buffer.from(ct, "base64")), d.final()]).toString("utf8");
}

// ─── Session unlock ───────────────────────────────────────────────────────────

async function grantUnlock(actorId, sid) {
  const key = keyFor(actorId);
  const sidHash = sha256(sid);
  await pool.execute(`DELETE FROM ${TABLE} WHERE email = ? AND purpose = ? AND otp_code = ?`, [key, PURPOSE_UNLOCK, sidHash]);
  await pool.execute(
    `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at, verified_at)
     VALUES (?, ?, ?, 1, 0, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())`,
    [key, sidHash, PURPOSE_UNLOCK, UNLOCK_HOURS]
  );
  return UNLOCK_HOURS * 3600;
}

/** Seconds of unlock left for this admin's login session (0 = locked). */
async function unlockRemaining(actorId, sid) {
  if (!actorId || !sid) return 0;
  const [rows] = await pool.execute(
    `SELECT TIMESTAMPDIFF(SECOND, NOW(), expires_at) AS remaining
       FROM ${TABLE}
      WHERE email = ? AND purpose = ? AND otp_code = ? AND expires_at > NOW()
      ORDER BY id DESC
      LIMIT 1`,
    [keyFor(actorId), PURPOSE_UNLOCK, sha256(sid)]
  );
  const remaining = Number(rows?.[0]?.remaining);
  return remaining > 0 ? remaining : 0;
}

// ─── Email code (first-time enrolment only) ──────────────────────────────────

/** Seconds until this admin may ask for another code (0 = now). */
async function getResendCooldown(actorId) {
  if (OTP_RESEND_COOLDOWN_SECONDS <= 0) return 0;
  const [rows] = await pool.execute(
    `SELECT TIMESTAMPDIFF(SECOND, NOW(), DATE_ADD(created_at, INTERVAL ? SECOND)) AS remaining
       FROM ${TABLE}
      WHERE email = ? AND purpose = ?
      ORDER BY id DESC
      LIMIT 1`,
    [OTP_RESEND_COOLDOWN_SECONDS, keyFor(actorId), PURPOSE_OTP]
  );
  const remaining = Number(rows?.[0]?.remaining);
  return remaining > 0 ? remaining : 0;
}

async function sendCodeEmail(code, requestedBy) {
  if (!RESEND_API_KEY) return { ok: false, reason: "RESEND_API_KEY not set" };
  const minutes = Math.round(OTP_TTL_SECONDS / 60);
  const html = `
    <div style="font-family:Poppins,Arial,sans-serif;max-width:560px;margin:0 auto;color:#252525">
      <h2 style="margin:0 0 8px">Rysflo Settings access code</h2>
      <p style="color:#535359">Someone signed in as <b>${String(requestedBy).replace(/[<>&"]/g, "")}</b> asked to set up Google Authenticator for Super Admin › Settings.</p>
      <p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:16px 0">${code}</p>
      <p style="color:#535359">The code expires in ${minutes} minutes. If you did not expect this, do not share it.</p>
    </div>`;
  const res = await axios.post(
    "https://api.resend.com/emails",
    {
      from: RESEND_FROM_EMAIL,
      to: [SETTINGS_OTP_EMAIL],
      subject: "Your Rysflo Settings access code",
      html,
      tags: [{ name: "kind", value: "settings_otp" }],
    },
    { headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" }, timeout: 15000, validateStatus: () => true }
  );
  if (res.status >= 200 && res.status < 300) return { ok: true };
  const detail = res.data?.message || res.data?.name || "";
  return { ok: false, reason: `resend ${res.status}${detail ? `: ${detail}` : ""}` };
}

/**
 * Issue a fresh email code for this admin.
 * -> { ok: true, ttl, sentTo } | { ok: false, reason: 'cooldown', retryAfter } | { ok: false, reason: 'send_failed' }
 */
async function requestCode(actorId, requestedBy) {
  const retryAfter = await getResendCooldown(actorId);
  if (retryAfter > 0) return { ok: false, reason: "cooldown", retryAfter };

  const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
  const codeHash = await bcrypt.hash(code, 10);
  const key = keyFor(actorId);

  await pool.execute(`DELETE FROM ${TABLE} WHERE email = ? AND purpose = ?`, [key, PURPOSE_OTP]);
  await pool.execute(
    `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at)
     VALUES (?, ?, ?, 0, 0, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
    [key, codeHash, PURPOSE_OTP, OTP_TTL_SECONDS]
  );
  pruneExpired().catch(() => {});

  const sent = await sendCodeEmail(code, requestedBy);
  if (!sent.ok) {
    console.error("SETTINGS_OTP_SEND_FAILED:", sent.reason);
    // Drop the row so the cooldown does not block a retry after a send failure.
    await pool.execute(`DELETE FROM ${TABLE} WHERE email = ? AND purpose = ?`, [key, PURPOSE_OTP]);
    return { ok: false, reason: "send_failed" };
  }
  return { ok: true, ttl: OTP_TTL_SECONDS, sentTo: maskEmail(SETTINGS_OTP_EMAIL) };
}

/**
 * Check an email code; on success unlock this login session (setup still required).
 * -> { ok: true, expiresInSeconds } | { ok: false, reason: 'not_found' | 'locked' | 'mismatch', attemptsLeft? }
 */
async function verifyCode(actorId, sid, submitted) {
  const key = keyFor(actorId);
  const [rows] = await pool.execute(
    `SELECT id, otp_code, attempts
       FROM ${TABLE}
      WHERE email = ? AND purpose = ? AND is_verified = 0 AND expires_at > NOW()
      ORDER BY id DESC
      LIMIT 1`,
    [key, PURPOSE_OTP]
  );
  const record = rows?.[0];
  if (!record) return { ok: false, reason: "not_found" };

  const code = String(submitted == null ? "" : submitted).trim();
  const matches = /^\d{6}$/.test(code) && (await bcrypt.compare(code, record.otp_code));
  if (!matches) {
    const attempts = (Number(record.attempts) || 0) + 1;
    if (attempts >= OTP_MAX_VERIFY_ATTEMPTS) {
      await pool.execute(`DELETE FROM ${TABLE} WHERE id = ?`, [record.id]);
      return { ok: false, reason: "locked" };
    }
    await pool.execute(`UPDATE ${TABLE} SET attempts = ? WHERE id = ?`, [attempts, record.id]);
    return { ok: false, reason: "mismatch", attemptsLeft: OTP_MAX_VERIFY_ATTEMPTS - attempts };
  }

  await pool.execute(`DELETE FROM ${TABLE} WHERE id = ?`, [record.id]);
  return { ok: true, expiresInSeconds: await grantUnlock(actorId, sid) };
}

// ─── Google Authenticator ─────────────────────────────────────────────────────

async function mfaEnrolled(actorId) {
  const [rows] = await pool.execute(
    `SELECT id FROM ${TABLE} WHERE email = ? AND purpose = ? LIMIT 1`,
    [keyFor(actorId), PURPOSE_MFA]
  );
  return rows.length > 0;
}

/** New secret for the QR code; kept as pending until confirmMfaSetup. */
async function startMfaSetup(actorId, accountLabel) {
  const key = keyFor(actorId);
  const secret = base32Encode(crypto.randomBytes(20));
  await pool.execute(`DELETE FROM ${TABLE} WHERE email = ? AND purpose = ?`, [key, PURPOSE_MFA_PENDING]);
  await pool.execute(
    `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at)
     VALUES (?, ?, ?, 0, 0, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
    [key, encryptSecret(secret), PURPOSE_MFA_PENDING, MFA_SETUP_TTL_SECONDS]
  );
  const label = `${encodeURIComponent(MFA_ISSUER)}:${encodeURIComponent(accountLabel)}`;
  const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(MFA_ISSUER)}&algorithm=SHA1&digits=6&period=30`;
  return { secret, otpauthUrl };
}

/**
 * Confirm the pending secret with one app code: it becomes the admin's
 * authenticator, backup codes are issued and this session is unlocked.
 * -> { ok: true, backupCodes, expiresInSeconds } | { ok: false, reason: 'not_found' | 'mismatch' }
 */
async function confirmMfaSetup(actorId, sid, submitted) {
  const key = keyFor(actorId);
  const [rows] = await pool.execute(
    `SELECT id, otp_code FROM ${TABLE}
      WHERE email = ? AND purpose = ? AND expires_at > NOW()
      ORDER BY id DESC LIMIT 1`,
    [key, PURPOSE_MFA_PENDING]
  );
  const pending = rows?.[0];
  if (!pending) return { ok: false, reason: "not_found" };

  const code = String(submitted == null ? "" : submitted).trim();
  const step = /^\d{6}$/.test(code) ? matchTotp(decryptSecret(pending.otp_code), code) : null;
  if (step == null) return { ok: false, reason: "mismatch" };

  const backupCodes = Array.from({ length: BACKUP_CODE_COUNT }, () => {
    const hex = crypto.randomBytes(4).toString("hex");
    return `${hex.slice(0, 4)}-${hex.slice(4)}`;
  });
  const backupHashes = await Promise.all(backupCodes.map((c) => bcrypt.hash(c, 10)));

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.execute(`DELETE FROM ${TABLE} WHERE email = ? AND purpose IN (?, ?, ?)`, [key, PURPOSE_MFA, PURPOSE_MFA_BACKUP, PURPOSE_MFA_PENDING]);
    await conn.execute(
      `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at, verified_at)
       VALUES (?, ?, ?, 1, ?, ?, NOW())`,
      [key, pending.otp_code, PURPOSE_MFA, step, NEVER_EXPIRES]
    );
    for (const h of backupHashes) {
      await conn.execute(
        `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at)
         VALUES (?, ?, ?, 0, 0, ?)`,
        [key, h, PURPOSE_MFA_BACKUP, NEVER_EXPIRES]
      );
    }
    await conn.commit();
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }

  return { ok: true, backupCodes, expiresInSeconds: await grantUnlock(actorId, sid) };
}

/**
 * Unlock with an app code, or a one-time backup code ("abcd-1234").
 * -> { ok: true, expiresInSeconds, usedBackup, backupLeft? } | { ok: false, reason: 'not_enrolled' | 'mismatch' }
 */
async function verifyMfa(actorId, sid, submitted) {
  const key = keyFor(actorId);
  const code = String(submitted == null ? "" : submitted).trim().toLowerCase();

  if (/^\d{6}$/.test(code)) {
    const [rows] = await pool.execute(
      `SELECT id, otp_code, attempts FROM ${TABLE} WHERE email = ? AND purpose = ? LIMIT 1`,
      [key, PURPOSE_MFA]
    );
    const mfa = rows?.[0];
    if (!mfa) return { ok: false, reason: "not_enrolled" };
    const step = matchTotp(decryptSecret(mfa.otp_code), code);
    // A code is good once: reject its step (or an older one) if already used.
    if (step == null || step <= Number(mfa.attempts)) return { ok: false, reason: "mismatch" };
    await pool.execute(`UPDATE ${TABLE} SET attempts = ?, verified_at = NOW() WHERE id = ?`, [step, mfa.id]);
    return { ok: true, usedBackup: false, expiresInSeconds: await grantUnlock(actorId, sid) };
  }

  if (/^[0-9a-f]{4}-?[0-9a-f]{4}$/.test(code)) {
    const normalized = code.includes("-") ? code : `${code.slice(0, 4)}-${code.slice(4)}`;
    const [rows] = await pool.execute(
      `SELECT id, otp_code FROM ${TABLE} WHERE email = ? AND purpose = ?`,
      [key, PURPOSE_MFA_BACKUP]
    );
    for (const r of rows) {
      if (await bcrypt.compare(normalized, r.otp_code)) {
        await pool.execute(`DELETE FROM ${TABLE} WHERE id = ?`, [r.id]);
        return { ok: true, usedBackup: true, backupLeft: rows.length - 1, expiresInSeconds: await grantUnlock(actorId, sid) };
      }
    }
  }
  return { ok: false, reason: "mismatch" };
}

// ─── Guard ────────────────────────────────────────────────────────────────────

const actorIdOf = (req) => String(req.user?.sub || req.user?.dietician_id || "").trim();
const sidOf = (req) => String(req.user?.sid || "").trim();

/** Route guard for settings writes; runs after authMiddleware. */
async function requireSettingsUnlock(req, res, next) {
  if (req.method === "OPTIONS") return next();
  try {
    const actorId = actorIdOf(req);
    if ((await unlockRemaining(actorId, sidOf(req))) > 0 && (await mfaEnrolled(actorId))) return next();
    return res.status(403).json({ ok: false, code: "SETTINGS_LOCKED", message: "Settings are locked. Enter your Google Authenticator code to unlock." });
  } catch (err) {
    console.error("SETTINGS_LOCK_CHECK_FAILED:", err?.code || err?.message);
    return res.status(500).json({ ok: false, message: "Unable to verify settings access" });
  }
}

module.exports = {
  maskEmail,
  settingsOtpEmail: () => SETTINGS_OTP_EMAIL,
  requestCode,
  verifyCode,
  unlockRemaining,
  mfaEnrolled,
  startMfaSetup,
  confirmMfaSetup,
  verifyMfa,
  actorIdOf,
  sidOf,
  requireSettingsUnlock,
  // exposed for tests
  _totp: { base32Encode, base32Decode, hotp, matchTotp, encryptSecret, decryptSecret },
};
