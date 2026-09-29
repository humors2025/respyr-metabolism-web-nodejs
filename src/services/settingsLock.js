"use strict";

/**
 * settingsLock.js — email code gate for Super Admin › Settings.
 *
 * The Settings page changes platform pricing and the commission rate, so a
 * signed-in super admin must also enter a 6-digit code emailed to a fixed
 * inbox (SETTINGS_OTP_EMAIL) before the page unlocks.
 *
 * FLOW
 *   1. requestCode(actorId)      -> code emailed to SETTINGS_OTP_EMAIL
 *   2. verifyCode(actorId, sid, code) -> unlocks THIS login session (sid)
 *   3. isUnlocked(actorId, sid)  -> checked by requireSettingsUnlock on every
 *                                   settings write
 *
 * The unlock is bound to the login session id (JWT `sid` =
 * dietician_refresh_tokens.id), which stays the same across access-token
 * refreshes. Logging out revokes that session, so the unlock ends with it.
 * It is also capped at SETTINGS_UNLOCK_HOURS, because a login session can
 * last JWT_REFRESH_TTL_DAYS (30 days).
 *
 * STORAGE — reuses `otp_verifications` (see dietitianOtpStore.js) under two
 * dedicated purposes; every statement filters on purpose so other flows'
 * rows are never touched. The `email` column holds the key "sa:<dietician_id>"
 * (the code belongs to the admin who asked for it, not to the inbox).
 *   settings_otp    : otp_code = bcrypt(code), attempts, expires_at
 *   settings_unlock : otp_code = sha256(sid),  expires_at
 */

const crypto = require("crypto");
const axios = require("axios");
const bcrypt = require("bcrypt");
const pool = require("../config/db");

const TABLE = "otp_verifications";
const PURPOSE_OTP = "settings_otp";
const PURPOSE_UNLOCK = "settings_unlock";

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
      `DELETE FROM ${TABLE} WHERE purpose IN (?, ?) AND expires_at <= NOW()`,
      [PURPOSE_OTP, PURPOSE_UNLOCK]
    );
  } catch (err) {
    console.error("SETTINGS_LOCK_PRUNE_FAILED:", err?.code || err?.message);
  }
}

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
      <p style="color:#535359">Someone signed in as <b>${String(requestedBy).replace(/[<>&"]/g, "")}</b> asked to open Super Admin › Settings.</p>
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
 * Issue a fresh code for this admin and email it.
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
 * Check a code; on success unlock this login session.
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
  const sidHash = sha256(sid);
  await pool.execute(`DELETE FROM ${TABLE} WHERE email = ? AND purpose = ? AND otp_code = ?`, [key, PURPOSE_UNLOCK, sidHash]);
  await pool.execute(
    `INSERT INTO ${TABLE} (email, otp_code, purpose, is_verified, attempts, expires_at, verified_at)
     VALUES (?, ?, ?, 1, 0, DATE_ADD(NOW(), INTERVAL ? HOUR), NOW())`,
    [key, sidHash, PURPOSE_UNLOCK, UNLOCK_HOURS]
  );
  return { ok: true, expiresInSeconds: UNLOCK_HOURS * 3600 };
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

const actorIdOf = (req) => String(req.user?.sub || req.user?.dietician_id || "").trim();
const sidOf = (req) => String(req.user?.sid || "").trim();

/** Route guard for settings writes; runs after authMiddleware. */
async function requireSettingsUnlock(req, res, next) {
  if (req.method === "OPTIONS") return next();
  try {
    if ((await unlockRemaining(actorIdOf(req), sidOf(req))) > 0) return next();
    return res.status(403).json({ ok: false, code: "SETTINGS_LOCKED", message: "Settings are locked. Enter the email code to unlock." });
  } catch (err) {
    console.error("SETTINGS_LOCK_CHECK_FAILED:", err?.code || err?.message);
    return res.status(500).json({ ok: false, message: "Unable to verify settings access" });
  }
}

module.exports = {
  OTP_TTL_SECONDS,
  OTP_RESEND_COOLDOWN_SECONDS,
  UNLOCK_HOURS,
  maskEmail,
  settingsOtpEmail: () => SETTINGS_OTP_EMAIL,
  getResendCooldown,
  requestCode,
  verifyCode,
  unlockRemaining,
  actorIdOf,
  sidOf,
  requireSettingsUnlock,
};
