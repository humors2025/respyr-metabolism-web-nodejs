"use strict";

/**
 * Email code gate for Super Admin › Settings (see services/settingsLock.js).
 *
 *  POST /dietitian/api/web/settings-lock-status   (super_admin)
 *       -> { ok, unlocked, expires_in_seconds, sent_to }
 *  POST /dietitian/api/web/settings-lock-request  (super_admin)
 *       -> { ok, sent_to, ttl_seconds }  | 429 { retry_after_seconds }
 *  POST /dietitian/api/web/settings-lock-verify   (super_admin) body { code }
 *       -> { ok, unlocked: true, expires_in_seconds } | 400 { attempts_left? }
 */

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

const settingsLockStatus = guard(async (req, res, { actorId, sid }) => {
  const remaining = await lock.unlockRemaining(actorId, sid);
  return res.json({
    ok: true,
    unlocked: remaining > 0,
    expires_in_seconds: remaining,
    sent_to: lock.maskEmail(lock.settingsOtpEmail()),
  });
});

const settingsLockRequest = guard(async (req, res, { actorId, actorEmail }) => {
  const r = await lock.requestCode(actorId, actorEmail || actorId);
  if (r.ok) return res.json({ ok: true, sent_to: r.sentTo, ttl_seconds: r.ttl });
  if (r.reason === "cooldown") {
    return res.status(429).json({ ok: false, message: `Please wait ${r.retryAfter}s before requesting another code.`, retry_after_seconds: r.retryAfter });
  }
  return res.status(502).json({ ok: false, message: "Could not send the code email. Try again." });
});

const settingsLockVerify = guard(async (req, res, { actorId, sid }) => {
  const r = await lock.verifyCode(actorId, sid, req.body?.code);
  if (r.ok) return res.json({ ok: true, unlocked: true, expires_in_seconds: r.expiresInSeconds });
  const message =
    r.reason === "mismatch" ? `Incorrect code. ${r.attemptsLeft} attempt${r.attemptsLeft === 1 ? "" : "s"} left.`
    : r.reason === "locked" ? "Too many wrong attempts. Request a new code."
    : "Code expired or not requested. Request a new code.";
  return res.status(400).json({ ok: false, reason: r.reason, message, attempts_left: r.attemptsLeft });
});

module.exports = { settingsLockStatus, settingsLockRequest, settingsLockVerify };
