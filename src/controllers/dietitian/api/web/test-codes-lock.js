"use strict";

/**
 * Google Authenticator gate for the Test codes tab on Super Admin › Orders
 * (see services/settingsLock.js).
 *
 * Fully separate from Settings: its own authenticator entry ("Rysflo Test
 * codes", admin_mfa row "tc:<id>"), its own backup codes and its own unlock.
 * super-admin-test-codes answers 403 TEST_CODES_LOCKED until this session is
 * unlocked.
 *
 *  POST /dietitian/api/web/test-codes-lock-status   (super_admin)
 *       -> { ok, unlocked, mfa_enrolled, expires_in_seconds, sent_to }
 *  First-time enrolment (no Test codes authenticator yet):
 *  POST /dietitian/api/web/test-codes-lock-request  -> email code to SETTINGS_OTP_EMAIL
 *  POST /dietitian/api/web/test-codes-lock-verify   body { code } -> email code accepted
 *  POST /dietitian/api/web/test-codes-mfa-setup     -> { secret, otpauth_url, issuer } (needs email step)
 *  POST /dietitian/api/web/test-codes-mfa-confirm   body { code } -> { backup_codes }
 *  Every visit after:
 *  POST /dietitian/api/web/test-codes-mfa-verify    body { code } (app code or backup code)
 */

const { _helpers: S } = require("./settings-lock");

const h = S.lockHandlers("test_codes", "TEST_CODES_LOCKED");

module.exports = {
  testCodesLockStatus: h.status,
  testCodesLockRequest: h.request,
  testCodesLockVerify: h.verifyEmail,
  testCodesMfaSetup: h.setup,
  testCodesMfaConfirm: h.confirm,
  testCodesMfaVerify: h.verify,
};
