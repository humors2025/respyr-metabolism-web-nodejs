"use strict";

/**
 * Google Authenticator gate for Super Admin › Settings (see services/settingsLock.js).
 *
 *  POST /dietitian/api/web/settings-lock-status      (super_admin)
 *       -> { ok, unlocked, mfa_enrolled, expires_in_seconds, sent_to }
 *  First-time enrolment (no authenticator yet):
 *  POST /dietitian/api/web/settings-lock-request     -> email code to SETTINGS_OTP_EMAIL
 *  POST /dietitian/api/web/settings-lock-verify      body { code } -> email code accepted
 *  POST /dietitian/api/web/settings-mfa-setup        -> { secret, otpauth_url, issuer } (needs email step)
 *  POST /dietitian/api/web/settings-mfa-confirm      body { code } -> { backup_codes }
 *  Every visit after:
 *  POST /dietitian/api/web/settings-mfa-verify       body { code } (app code or backup code)
 *
 * The Test codes tab has the same set under test-codes-* (test-codes-lock.js),
 * built from lockHandlers() below with its own authenticator and unlock.
 */

const rateLimit = require("express-rate-limit");
const { _helpers: H } = require("./admin-invite-trainer");
const { getClientIp, getUserAgent } = require("./auth_common");
const lock = require("../../../../services/settingsLock");

/** Who and where, for admin_mfa and the security alert emails. */
function requestContext(req, email) {
  const ip = String(getClientIp(req) || "").replace(/^::ffff:/, "");
  return {
    email,
    ip: ip && ip !== "0.0.0.0" ? ip : null,
    userAgent: getUserAgent(req) || null,
    country: req.get?.("cloudfront-viewer-country") || null,
  };
}

function guard(fn, errorTag = "SETTINGS_LOCK_ERROR") {
  return async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
    try {
      const resolved = await H.resolveActorFromToken(req, "super_admin");
      if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
      const actorId = lock.actorIdOf(req);
      const sid = lock.sidOf(req);
      if (!actorId || !sid) return res.status(401).json({ ok: false, message: "Invalid session" });
      const actorEmail = resolved.actorEmail || actorId;
      return await fn(req, res, { actorId, sid, actorEmail, ctx: requestContext(req, actorEmail) });
    } catch (err) {
      console.error(`${errorTag}:`, err?.code || err?.message);
      return res.status(500).json({ ok: false, message: "Something went wrong" });
    }
  };
}

// Wrong-code throttle per admin; the codes are 6 digits, so this is the
// brute-force brake on top of the per-code attempt cap. The Test codes routes
// mount this same instance, so wrong codes on either screen share it.
const settingsCodeRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => `settings-code:${lock.actorIdOf(req) || "unknown"}`,
  handler: async (req, res) => {
    // Alert once, on the first request over the limit, not on every retry after it.
    if (req.rateLimit?.current === req.rateLimit?.limit + 1) {
      const email = req.user?.email || req.user?.dietician?.email || lock.actorIdOf(req);
      await lock.sendAlert("Too many wrong Google Authenticator codes", "Someone entered 10 wrong codes on the Settings or Test codes lock screen within 15 minutes.", requestContext(req, email));
    }
    return res.status(429).json({ ok: false, message: "Too many attempts. Try again in 15 minutes." });
  },
});

/**
 * The six handlers for one locked area ("settings" | "test_codes").
 * lockedCode is the 403 code its guarded routes answer with.
 */
function lockHandlers(area, lockedCode) {
  const errorTag = `${String(area).toUpperCase()}_LOCK_ERROR`;
  const g = (fn) => guard(fn, errorTag);
  const alreadyEnrolled = (res) =>
    res.status(409).json({ ok: false, code: "MFA_ENROLLED", message: "Google Authenticator is already set up. Use the code from the app." });
  const needEmailStep = (res) => res.status(403).json({ ok: false, code: lockedCode, message: "Verify the email code first." });

  const status = g(async (req, res, { actorId, sid }) => {
    const [remaining, enrolled] = await Promise.all([lock.unlockRemaining(actorId, sid, area), lock.mfaEnrolled(actorId, area)]);
    return res.json({
      ok: true,
      unlocked: remaining > 0,
      mfa_enrolled: enrolled,
      expires_in_seconds: remaining,
      sent_to: lock.maskEmail(lock.settingsOtpEmail()),
    });
  });

  const request = g(async (req, res, { actorId, actorEmail }) => {
    if (await lock.mfaEnrolled(actorId, area)) return alreadyEnrolled(res);
    const r = await lock.requestCode(actorId, actorEmail, area);
    if (r.ok) return res.json({ ok: true, sent_to: r.sentTo, ttl_seconds: r.ttl });
    if (r.reason === "cooldown") {
      return res.status(429).json({ ok: false, message: `Please wait ${r.retryAfter}s before requesting another code.`, retry_after_seconds: r.retryAfter });
    }
    return res.status(502).json({ ok: false, message: "Could not send the code email. Try again." });
  });

  const verifyEmail = g(async (req, res, { actorId, sid }) => {
    if (await lock.mfaEnrolled(actorId, area)) return alreadyEnrolled(res);
    const r = await lock.verifyCode(actorId, sid, req.body?.code, area);
    if (r.ok) return res.json({ ok: true, unlocked: true, expires_in_seconds: r.expiresInSeconds });
    const message =
      r.reason === "mismatch" ? `Incorrect code. ${r.attemptsLeft} attempt${r.attemptsLeft === 1 ? "" : "s"} left.`
      : r.reason === "locked" ? "Too many wrong attempts. Request a new code."
      : "Code expired or not requested. Request a new code.";
    return res.status(400).json({ ok: false, reason: r.reason, message, attempts_left: r.attemptsLeft });
  });

  const setup = g(async (req, res, { actorId, sid, actorEmail }) => {
    if (await lock.mfaEnrolled(actorId, area)) return alreadyEnrolled(res);
    if ((await lock.unlockRemaining(actorId, sid, area)) <= 0) return needEmailStep(res);
    const hosts = [req.get?.("x-forwarded-host"), req.get?.("host"), req.get?.("origin")];
    const { secret, otpauthUrl, issuer } = await lock.startMfaSetup(actorId, actorEmail, area, hosts);
    return res.json({ ok: true, secret, otpauth_url: otpauthUrl, issuer });
  });

  const confirm = g(async (req, res, { actorId, sid, ctx }) => {
    if (await lock.mfaEnrolled(actorId, area)) return alreadyEnrolled(res);
    if ((await lock.unlockRemaining(actorId, sid, area)) <= 0) return needEmailStep(res);
    const r = await lock.confirmMfaSetup(actorId, sid, req.body?.code, ctx, area);
    if (r.ok) return res.json({ ok: true, unlocked: true, backup_codes: r.backupCodes, expires_in_seconds: r.expiresInSeconds });
    const message = r.reason === "mismatch" ? "Incorrect code. Check the app and try again." : "Setup expired. Start again.";
    return res.status(400).json({ ok: false, reason: r.reason, message });
  });

  const verify = g(async (req, res, { actorId, sid, ctx }) => {
    const r = await lock.verifyMfa(actorId, sid, req.body?.code, ctx, area);
    if (r.ok) {
      return res.json({ ok: true, unlocked: true, used_backup: r.usedBackup, backup_codes_left: r.backupLeft, expires_in_seconds: r.expiresInSeconds });
    }
    if (r.reason === "not_enrolled") {
      return res.status(409).json({ ok: false, code: "MFA_NOT_ENROLLED", message: "Google Authenticator is not set up yet." });
    }
    const off = Math.abs(r.clockOffsetMinutes || 0);
    const message =
      r.reason === "reused" ? "This code was already used. Wait for the next code in Google Authenticator."
      : r.reason === "clock" ? `Your phone's clock is about ${off || 1} minute${off === 1 ? "" : "s"} ${r.clockOffsetMinutes > 0 ? "fast" : "slow"}. Turn on automatic date and time, then try again.`
      : `Incorrect code. Use the ${lock.issuerFor(area)} entry for this site in Google Authenticator (UAT and live each have their own).`;
    return res.status(400).json({ ok: false, reason: r.reason, message, clock_offset_minutes: r.clockOffsetMinutes });
  });

  return { status, request, verifyEmail, setup, confirm, verify };
}

const settings = lockHandlers("settings", "SETTINGS_LOCKED");

module.exports = {
  settingsCodeRateLimiter,
  settingsLockStatus: settings.status,
  settingsLockRequest: settings.request,
  settingsLockVerify: settings.verifyEmail,
  settingsMfaSetup: settings.setup,
  settingsMfaConfirm: settings.confirm,
  settingsMfaVerify: settings.verify,
  _helpers: { lockHandlers },
};
