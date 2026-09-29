"use strict";

/**
 * Google Authenticator gate for Super Admin › Settings (see services/settingsLock.js).
 *
 *  POST /dietitian/api/web/settings-lock-status      (super_admin)
 *       -> { ok, unlocked, mfa_enrolled, expires_in_seconds, sent_to }
 *  First-time enrolment (no authenticator yet):
 *  POST /dietitian/api/web/settings-lock-request     -> email code to SETTINGS_OTP_EMAIL
 *  POST /dietitian/api/web/settings-lock-verify      body { code } -> email code accepted
 *  POST /dietitian/api/web/settings-mfa-setup        -> { secret, otpauth_url } (needs email step)
 *  POST /dietitian/api/web/settings-mfa-confirm      body { code } -> { backup_codes }
 *  Every visit after:
 *  POST /dietitian/api/web/settings-mfa-verify       body { code } (app code or backup code)
 */

const rateLimit = require("express-rate-limit");
const { _helpers: H } = require("./admin-invite-trainer");
const lock = require("../../../../services/settingsLock");

function guard(fn) {
  return async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
    try {
      const resolved = await H.resolveActorFromToken(req, "super_admin");
      if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
      const actorId = lock.actorIdOf(req);
      const sid = lock.sidOf(req);
      if (!actorId || !sid) return res.status(401).json({ ok: false, message: "Invalid session" });
      return await fn(req, res, { actorId, sid, actorEmail: resolved.actorEmail });
    } catch (err) {
      console.error("SETTINGS_LOCK_ERROR:", err?.code || err?.message);
      return res.status(500).json({ ok: false, message: "Something went wrong" });
    }
  };
}

const alreadyEnrolled = (res) =>
  res.status(409).json({ ok: false, code: "MFA_ENROLLED", message: "Google Authenticator is already set up. Use the code from the app." });

// Wrong-code throttle per admin; the codes are 6 digits, so this is the
// brute-force brake on top of the per-code attempt cap.
const settingsCodeRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `settings-code:${lock.actorIdOf(req) || "unknown"}`,
  handler: (req, res) => res.status(429).json({ ok: false, message: "Too many attempts. Try again in 15 minutes." }),
});

const settingsLockStatus = guard(async (req, res, { actorId, sid }) => {
  const [remaining, enrolled] = await Promise.all([lock.unlockRemaining(actorId, sid), lock.mfaEnrolled(actorId)]);
  return res.json({
    ok: true,
    unlocked: remaining > 0,
    mfa_enrolled: enrolled,
    expires_in_seconds: remaining,
    sent_to: lock.maskEmail(lock.settingsOtpEmail()),
  });
});

const settingsLockRequest = guard(async (req, res, { actorId, actorEmail }) => {
  if (await lock.mfaEnrolled(actorId)) return alreadyEnrolled(res);
  const r = await lock.requestCode(actorId, actorEmail || actorId);
  if (r.ok) return res.json({ ok: true, sent_to: r.sentTo, ttl_seconds: r.ttl });
  if (r.reason === "cooldown") {
    return res.status(429).json({ ok: false, message: `Please wait ${r.retryAfter}s before requesting another code.`, retry_after_seconds: r.retryAfter });
  }
  return res.status(502).json({ ok: false, message: "Could not send the code email. Try again." });
});

const settingsLockVerify = guard(async (req, res, { actorId, sid }) => {
  if (await lock.mfaEnrolled(actorId)) return alreadyEnrolled(res);
  const r = await lock.verifyCode(actorId, sid, req.body?.code);
  if (r.ok) return res.json({ ok: true, unlocked: true, expires_in_seconds: r.expiresInSeconds });
  const message =
    r.reason === "mismatch" ? `Incorrect code. ${r.attemptsLeft} attempt${r.attemptsLeft === 1 ? "" : "s"} left.`
    : r.reason === "locked" ? "Too many wrong attempts. Request a new code."
    : "Code expired or not requested. Request a new code.";
  return res.status(400).json({ ok: false, reason: r.reason, message, attempts_left: r.attemptsLeft });
});

const settingsMfaSetup = guard(async (req, res, { actorId, sid, actorEmail }) => {
  if (await lock.mfaEnrolled(actorId)) return alreadyEnrolled(res);
  if ((await lock.unlockRemaining(actorId, sid)) <= 0) {
    return res.status(403).json({ ok: false, code: "SETTINGS_LOCKED", message: "Verify the email code first." });
  }
  const { secret, otpauthUrl } = await lock.startMfaSetup(actorId, actorEmail || actorId);
  return res.json({ ok: true, secret, otpauth_url: otpauthUrl });
});

const settingsMfaConfirm = guard(async (req, res, { actorId, sid }) => {
  if (await lock.mfaEnrolled(actorId)) return alreadyEnrolled(res);
  if ((await lock.unlockRemaining(actorId, sid)) <= 0) {
    return res.status(403).json({ ok: false, code: "SETTINGS_LOCKED", message: "Verify the email code first." });
  }
  const r = await lock.confirmMfaSetup(actorId, sid, req.body?.code);
  if (r.ok) return res.json({ ok: true, unlocked: true, backup_codes: r.backupCodes, expires_in_seconds: r.expiresInSeconds });
  const message = r.reason === "mismatch" ? "Incorrect code. Check the app and try again." : "Setup expired. Start again.";
  return res.status(400).json({ ok: false, reason: r.reason, message });
});

const settingsMfaVerify = guard(async (req, res, { actorId, sid }) => {
  const r = await lock.verifyMfa(actorId, sid, req.body?.code);
  if (r.ok) {
    return res.json({ ok: true, unlocked: true, used_backup: r.usedBackup, backup_codes_left: r.backupLeft, expires_in_seconds: r.expiresInSeconds });
  }
  if (r.reason === "not_enrolled") {
    return res.status(409).json({ ok: false, code: "MFA_NOT_ENROLLED", message: "Google Authenticator is not set up yet." });
  }
  return res.status(400).json({ ok: false, reason: r.reason, message: "Incorrect code." });
});

module.exports = {
  settingsCodeRateLimiter,
  settingsLockStatus,
  settingsLockRequest,
  settingsLockVerify,
  settingsMfaSetup,
  settingsMfaConfirm,
  settingsMfaVerify,
};
