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
 * ALERTS (email to SETTINGS_ALERT_EMAIL, default SETTINGS_OTP_EMAIL):
 *   authenticator set up, backup code used, unlock from a new IP address,
 *   too many wrong codes. Each names the account, IP, browser and time.
 *
 * STORAGE
 *   admin_mfa (one row per super admin; created manually, see below):
 *     secret_enc      AES-256-GCM encrypted TOTP secret (SETTINGS_MFA_KEY,
 *                     falls back to a key derived from JWT_SECRET — rotating
 *                     that secret means re-enrolling)
 *     confirmed_at    NULL while the QR is shown but not yet confirmed
 *     last_used_step  last accepted 30s step; older/equal steps are refused
 *     backup_codes    JSON array of bcrypt hashes of unused backup codes
 *     confirmed_ip / confirmed_user_agent / last_used_ip — who and where
 *   otp_verifications (short-lived rows only, UNIQUE (email, purpose)):
 *     settings_otp    : email "sa:<dietician_id>", otp_code = bcrypt(email code)
 *     settings_unlock : email "su:" + sha256(dietician_id:sid), one row per
 *                       login session, expires_at = end of the unlock
 *
 * Lost phone and backup codes: DELETE FROM admin_mfa WHERE dietician_id = ?;
 * the next visit starts enrolment again via the email code.
 *
 *   CREATE TABLE admin_mfa (
 *     dietician_id VARCHAR(64) NOT NULL PRIMARY KEY, email VARCHAR(255) NOT NULL,
 *     secret_enc TEXT NOT NULL, last_used_step BIGINT NOT NULL DEFAULT 0,
 *     backup_codes JSON NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *     confirmed_at DATETIME NULL, confirmed_ip VARCHAR(45) NULL,
 *     confirmed_user_agent VARCHAR(255) NULL, last_used_at DATETIME NULL,
 *     last_used_ip VARCHAR(45) NULL);
 */

const crypto = require("crypto");
const axios = require("axios");
const bcrypt = require("bcrypt");
const pool = require("../config/db");
const { escapeHtml } = require("../utils/securityValidation");

const TABLE = "otp_verifications";
const MFA_TABLE = "admin_mfa";
const PURPOSE_OTP = "settings_otp";
const PURPOSE_UNLOCK = "settings_unlock";

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  return Math.min(max, Math.max(min, v));
}

// Comma-separated inbox lists; every address gets the code / alert.
const emailList = (v) => String(v || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
const SETTINGS_OTP_EMAIL = emailList(process.env.SETTINGS_OTP_EMAIL || "harsh@respyr.in,chandan@respyr.in");
const SETTINGS_ALERT_EMAIL = process.env.SETTINGS_ALERT_EMAIL ? emailList(process.env.SETTINGS_ALERT_EMAIL) : SETTINGS_OTP_EMAIL;
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

/** "harsh@respyr.in" -> "h***h@respyr.in" — shown on the lock screen. Lists are masked per address. */
function maskEmail(email) {
  if (Array.isArray(email)) return email.map(maskEmail).join(", ");
  const [local, domain] = String(email).split("@");
  if (!domain) return "***";
  const shown = local.length <= 2 ? local[0] + "***" : `${local[0]}***${local[local.length - 1]}`;
  return `${shown}@${domain}`;
}

async function pruneExpired() {
  try {
    await pool.execute(
      `DELETE FROM ${TABLE} WHERE purpose IN (?, ?) AND expires_at <= NOW()`,
      [PURPOSE_OTP, PURPOSE_UNLOCK]
    );
  } catch (err) {
    console.error("SETTINGS_LOCK_PRUNE_FAILED:", err?.code || err?.message);
  }
}

// ─── Email (codes + alerts) ───────────────────────────────────────────────────

async function sendEmail(to, subject, html, kind) {
  if (!RESEND_API_KEY) return { ok: false, reason: "RESEND_API_KEY not set" };
  const res = await axios.post(
    "https://api.resend.com/emails",
    { from: RESEND_FROM_EMAIL, to: Array.isArray(to) ? to : [to], subject, html, tags: [{ name: "kind", value: kind }] },
    { headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" }, timeout: 15000, validateStatus: () => true }
  );
  if (res.status >= 200 && res.status < 300) return { ok: true };
  const detail = res.data?.message || res.data?.name || "";
  return { ok: false, reason: `resend ${res.status}${detail ? `: ${detail}` : ""}` };
}

/**
 * Security alert to SETTINGS_ALERT_EMAIL. ctx = { email, ip, userAgent, country }.
 * Awaited by callers (Lambda drops work after the response) but never throws.
 */
async function sendAlert(title, summary, ctx = {}) {
  try {
    const when = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";
    const ip = ctx.ip || "unknown";
    const row = (k, v) => `<tr><td style="padding:4px 12px;color:#535359">${k}</td><td style="padding:4px 12px;font-weight:600">${v}</td></tr>`;
    const html = `
      <div style="font-family:Poppins,Arial,sans-serif;max-width:560px;margin:0 auto;color:#252525">
        <h2 style="margin:0 0 8px">${escapeHtml(title)}</h2>
        <p style="color:#535359">${escapeHtml(summary)}</p>
        <table style="border-collapse:collapse;font-size:14px">
          ${row("Account", escapeHtml(ctx.email || "unknown"))}
          ${row("IP address", ctx.ip ? `${escapeHtml(ip)} (<a href="https://ipinfo.io/${encodeURIComponent(ip)}">see location</a>)` : "unknown")}
          ${ctx.country ? row("Country", escapeHtml(ctx.country)) : ""}
          ${row("Browser / device", escapeHtml(ctx.userAgent || "unknown"))}
          ${row("Time", when)}
        </table>
        <p style="color:#535359;margin-top:16px">If this wasn't expected, reset this admin's Google Authenticator (delete their row in admin_mfa) and change their password.</p>
      </div>`;
    const r = await sendEmail(SETTINGS_ALERT_EMAIL, `Rysflo security alert: ${title}`, html, "settings_alert");
    if (!r.ok) console.error("SETTINGS_ALERT_SEND_FAILED:", r.reason);
  } catch (err) {
    console.error("SETTINGS_ALERT_SEND_FAILED:", err?.message);
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

const unlockKeyFor = (actorId, sid) => `su:${sha256(`${String(actorId).trim()}:${sid}`)}`;

async function grantUnlock(actorId, sid) {
  await pool.execute(
    `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at, verified_at)
     VALUES (?, '', ?, 1, 0, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())
     ON DUPLICATE KEY UPDATE expires_at = VALUES(expires_at), verified_at = NOW()`,
    [unlockKeyFor(actorId, sid), PURPOSE_UNLOCK, UNLOCK_HOURS]
  );
  return UNLOCK_HOURS * 3600;
}

/** Seconds of unlock left for this admin's login session (0 = locked). */
async function unlockRemaining(actorId, sid) {
  if (!actorId || !sid) return 0;
  const [rows] = await pool.execute(
    `SELECT TIMESTAMPDIFF(SECOND, NOW(), expires_at) AS remaining
       FROM ${TABLE}
      WHERE email = ? AND purpose = ? AND expires_at > NOW()
      LIMIT 1`,
    [unlockKeyFor(actorId, sid), PURPOSE_UNLOCK]
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

function codeEmailHtml(code, requestedBy) {
  const minutes = Math.round(OTP_TTL_SECONDS / 60);
  return `
    <div style="font-family:Poppins,Arial,sans-serif;max-width:560px;margin:0 auto;color:#252525">
      <h2 style="margin:0 0 8px">Rysflo Settings access code</h2>
      <p style="color:#535359">Someone signed in as <b>${escapeHtml(String(requestedBy))}</b> asked to set up Google Authenticator for Super Admin › Settings.</p>
      <p style="font-size:32px;font-weight:700;letter-spacing:6px;margin:16px 0">${code}</p>
      <p style="color:#535359">The code expires in ${minutes} minutes. If you did not expect this, do not share it.</p>
    </div>`;
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

  const sent = await sendEmail(SETTINGS_OTP_EMAIL, "Your Rysflo Settings access code", codeEmailHtml(code, requestedBy), "settings_otp");
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

// ─── Google Authenticator (admin_mfa) ─────────────────────────────────────────

const clip = (v, n) => (v == null ? null : String(v).slice(0, n));

function parseBackup(value) {
  if (Array.isArray(value)) return value;
  try {
    const parsed = JSON.parse(value || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch (_) {
    return [];
  }
}

async function mfaEnrolled(actorId) {
  const [rows] = await pool.execute(
    `SELECT 1 FROM ${MFA_TABLE} WHERE dietician_id = ? AND confirmed_at IS NOT NULL LIMIT 1`,
    [String(actorId)]
  );
  return rows.length > 0;
}

/** New secret for the QR code; stays unconfirmed until confirmMfaSetup. */
async function startMfaSetup(actorId, email) {
  const secret = base32Encode(crypto.randomBytes(20));
  // Only replaces an unconfirmed row; a confirmed authenticator is never overwritten.
  await pool.execute(
    `INSERT INTO ${MFA_TABLE} (dietician_id, email, secret_enc, last_used_step, backup_codes, created_at)
     VALUES (?, ?, ?, 0, NULL, NOW())
     ON DUPLICATE KEY UPDATE
       email      = IF(confirmed_at IS NULL, VALUES(email), email),
       secret_enc = IF(confirmed_at IS NULL, VALUES(secret_enc), secret_enc),
       created_at = IF(confirmed_at IS NULL, NOW(), created_at)`,
    [String(actorId), clip(email, 255), encryptSecret(secret)]
  );
  const label = `${encodeURIComponent(MFA_ISSUER)}:${encodeURIComponent(email)}`;
  const otpauthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(MFA_ISSUER)}&algorithm=SHA1&digits=6&period=30`;
  return { secret, otpauthUrl };
}

/**
 * Confirm the pending secret with one app code: it becomes the admin's
 * authenticator, backup codes are issued, this session is unlocked and an
 * alert is sent. ctx = { email, ip, userAgent, country }.
 * -> { ok: true, backupCodes, expiresInSeconds } | { ok: false, reason: 'not_found' | 'mismatch' }
 */
async function confirmMfaSetup(actorId, sid, submitted, ctx) {
  const [rows] = await pool.execute(
    `SELECT secret_enc FROM ${MFA_TABLE}
      WHERE dietician_id = ? AND confirmed_at IS NULL
        AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)
      LIMIT 1`,
    [String(actorId), MFA_SETUP_TTL_SECONDS]
  );
  const pending = rows?.[0];
  if (!pending) return { ok: false, reason: "not_found" };

  const code = String(submitted == null ? "" : submitted).trim();
  const step = /^\d{6}$/.test(code) ? matchTotp(decryptSecret(pending.secret_enc), code) : null;
  if (step == null) return { ok: false, reason: "mismatch" };

  const backupCodes = Array.from({ length: BACKUP_CODE_COUNT }, () => {
    const hex = crypto.randomBytes(4).toString("hex");
    return `${hex.slice(0, 4)}-${hex.slice(4)}`;
  });
  const backupHashes = await Promise.all(backupCodes.map((c) => bcrypt.hash(c, 10)));

  const [r] = await pool.execute(
    `UPDATE ${MFA_TABLE}
        SET confirmed_at = NOW(), last_used_step = ?, backup_codes = ?,
            confirmed_ip = ?, confirmed_user_agent = ?,
            last_used_at = NOW(), last_used_ip = ?
      WHERE dietician_id = ? AND confirmed_at IS NULL`,
    [step, JSON.stringify(backupHashes), clip(ctx.ip, 45), clip(ctx.userAgent, 255), clip(ctx.ip, 45), String(actorId)]
  );
  if (r.affectedRows !== 1) return { ok: false, reason: "not_found" };

  const expiresInSeconds = await grantUnlock(actorId, sid);
  await sendAlert("Google Authenticator set up", "A super admin set up Google Authenticator for the Settings page.", ctx);
  return { ok: true, backupCodes, expiresInSeconds };
}

/**
 * Unlock with an app code, or a one-time backup code ("abcd-1234").
 * Alerts on a backup code or an IP this admin has not used before.
 * -> { ok: true, expiresInSeconds, usedBackup, backupLeft? } | { ok: false, reason: 'not_enrolled' | 'mismatch' }
 */
async function verifyMfa(actorId, sid, submitted, ctx) {
  const code = String(submitted == null ? "" : submitted).trim().toLowerCase();
  const id = String(actorId);

  const [rows] = await pool.execute(
    `SELECT secret_enc, last_used_step, backup_codes, confirmed_ip, last_used_ip
       FROM ${MFA_TABLE} WHERE dietician_id = ? AND confirmed_at IS NOT NULL LIMIT 1`,
    [id]
  );
  const mfa = rows?.[0];
  if (!mfa) return { ok: false, reason: "not_enrolled" };
  const newIp = ctx.ip && ctx.ip !== mfa.last_used_ip && ctx.ip !== mfa.confirmed_ip;

  if (/^\d{6}$/.test(code)) {
    const step = matchTotp(decryptSecret(mfa.secret_enc), code);
    if (step == null) return { ok: false, reason: "mismatch" };
    // A code is good once: the step must be newer than the last accepted one.
    const [r] = await pool.execute(
      `UPDATE ${MFA_TABLE} SET last_used_step = ?, last_used_at = NOW(), last_used_ip = ?
        WHERE dietician_id = ? AND last_used_step < ?`,
      [step, clip(ctx.ip, 45), id, step]
    );
    if (r.affectedRows !== 1) return { ok: false, reason: "mismatch" };
    const expiresInSeconds = await grantUnlock(actorId, sid);
    if (newIp) await sendAlert("Settings unlocked from a new IP address", "A super admin unlocked the Settings page from an IP address they have not used before.", ctx);
    return { ok: true, usedBackup: false, expiresInSeconds };
  }

  if (/^[0-9a-f]{4}-?[0-9a-f]{4}$/.test(code)) {
    const normalized = code.includes("-") ? code : `${code.slice(0, 4)}-${code.slice(4)}`;
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [locked] = await conn.execute(
        `SELECT backup_codes FROM ${MFA_TABLE} WHERE dietician_id = ? FOR UPDATE`,
        [id]
      );
      const hashes = parseBackup(locked?.[0]?.backup_codes);
      let idx = -1;
      for (let i = 0; i < hashes.length; i++) {
        if (await bcrypt.compare(normalized, hashes[i])) {
          idx = i;
          break;
        }
      }
      if (idx === -1) {
        await conn.rollback();
        return { ok: false, reason: "mismatch" };
      }
      const left = hashes.filter((_, j) => j !== idx);
      await conn.execute(
        `UPDATE ${MFA_TABLE} SET backup_codes = ?, last_used_at = NOW(), last_used_ip = ? WHERE dietician_id = ?`,
        [JSON.stringify(left), clip(ctx.ip, 45), id]
      );
      await conn.commit();
      const expiresInSeconds = await grantUnlock(actorId, sid);
      await sendAlert(
        "Backup code used",
        `A super admin unlocked Settings with a backup code (${left.length} left). This usually means a lost phone.`,
        ctx
      );
      return { ok: true, usedBackup: true, backupLeft: left.length, expiresInSeconds };
    } catch (err) {
      await conn.rollback().catch(() => {});
      throw err;
    } finally {
      conn.release();
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
  sendAlert,
  actorIdOf,
  sidOf,
  requireSettingsUnlock,
  // exposed for tests
  _totp: { base32Encode, base32Decode, hotp, matchTotp, encryptSecret, decryptSecret },
};
