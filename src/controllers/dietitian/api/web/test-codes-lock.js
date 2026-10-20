"use strict";

/**
 * Google Authenticator gate for the Test codes tab on Super Admin › Orders
 * (see services/settingsLock.js).
 *
 * Same authenticator entry as Settings (admin_mfa, set up once on the Settings
 * page), but its own APIs and its own unlock: unlocking Test codes does not
 * open Settings, and the reverse. super-admin-test-codes answers 403
 * TEST_CODES_LOCKED until this session is unlocked.
 *
 *  POST /dietitian/api/web/test-codes-lock-status   (super_admin)
 *       -> { ok, unlocked, mfa_enrolled, expires_in_seconds }
 *  POST /dietitian/api/web/test-codes-mfa-verify    body { code } (app code or backup code)
 *
 * mfa_enrolled false -> Google Authenticator has to be set up on the Settings
 * page first; there is no second enrolment here.
 */

const lock = require("../../../../services/settingsLock");
const { _helpers: S } = require("./settings-lock");

const AREA = "test_codes";
const guard = (fn) => S.guard(fn, "TEST_CODES_LOCK_ERROR");

const testCodesLockStatus = guard(async (req, res, { actorId, sid }) => {
  const [remaining, enrolled] = await Promise.all([lock.unlockRemaining(actorId, sid, AREA), lock.mfaEnrolled(actorId)]);
  return res.json({
    ok: true,
    unlocked: enrolled && remaining > 0,
    mfa_enrolled: enrolled,
    expires_in_seconds: enrolled ? remaining : 0,
  });
});

const testCodesMfaVerify = guard(S.mfaVerifyHandler(AREA));

module.exports = { testCodesLockStatus, testCodesMfaVerify };
