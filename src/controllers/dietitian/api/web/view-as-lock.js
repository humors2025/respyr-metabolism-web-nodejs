"use strict";

/**
 * Google Authenticator gate for Super Admin › View as (see
 * services/settingsLock.js and super-admin-view-as.js).
 *
 * Fully separate from Settings and Test codes: its own authenticator entry
 * ("Rysflo View as", admin_mfa row "va:<id>"), its own backup codes and its
 * own unlock. super-admin-view-as-list and super-admin-view-as answer
 * 403 VIEW_AS_LOCKED until this login session is unlocked.
 *
 *  POST /dietitian/api/web/view-as-lock-status   (super_admin)
 *       -> { ok, unlocked, mfa_enrolled, expires_in_seconds, sent_to }
 *  First-time enrolment (no View as authenticator yet):
 *  POST /dietitian/api/web/view-as-lock-request  -> email code to SETTINGS_OTP_EMAIL
 *  POST /dietitian/api/web/view-as-lock-verify   body { code } -> email code accepted
 *  POST /dietitian/api/web/view-as-mfa-setup     -> { secret, otpauth_url, issuer } (needs email step)
 *  POST /dietitian/api/web/view-as-mfa-confirm   body { code } -> { backup_codes }
 *  Every visit after:
 *  POST /dietitian/api/web/view-as-mfa-verify    body { code } (app code or backup code)
 */

const { _helpers: S } = require("./settings-lock");

const h = S.lockHandlers("view_as", "VIEW_AS_LOCKED");

module.exports = {
  viewAsLockStatus: h.status,
  viewAsLockRequest: h.request,
  viewAsLockVerify: h.verifyEmail,
  viewAsMfaSetup: h.setup,
  viewAsMfaConfirm: h.confirm,
  viewAsMfaVerify: h.verify,
};
