"use strict";

/**
 * onboardingFailureAlert.js
 *
 * Sends an internal alert email (via Resend) whenever a user's onboarding
 * (accept-invite) attempt fails, so ops gets notified immediately with:
 *   - failure reason
 *   - user_id / identifier (invite email when known)
 *   - API HTTP status returned to the client
 *   - endpoint, timestamp (UTC), and any extra context
 *
 * Design constraints (Lambda-safe):
 *   - MUST be awaited by the caller BEFORE the HTTP response is sent
 *     (Lambda may freeze the sandbox once the response returns, so
 *     fire-and-forget without await is unreliable).
 *   - NEVER throws. Any Resend failure is logged to CloudWatch as
 *     ONBOARDING_ALERT_EMAIL_FAILED and swallowed — an alert failure
 *     must never break or change the onboarding API response.
 *   - Short timeout (5s) so failure paths are not delayed noticeably.
 *
 * Required env vars (add via AWS Console, NOT the CLI --environment flag):
 *   RESEND_API_KEY          (already configured for invite emails)
 *   RESEND_FROM_EMAIL       (already configured; falls back to no-reply)
 *   ONBOARDING_ALERT_EMAIL  (optional — comma-separated recipient list.
 *                            Defaults to "connect@humorstech.com" when unset;
 *                            set the env var to override without a deploy.)
 */

const axios = require("axios");

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL =
  process.env.RESEND_FROM_EMAIL || "Respyr <no-reply@respyr.ai>";
const ONBOARDING_ALERT_EMAIL =
  process.env.ONBOARDING_ALERT_EMAIL || "connect@humorstech.com";

const RESEND_TIMEOUT_MS = 5000;

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function row(label, value) {
  return `
    <tr>
      <td style="padding:6px 12px;border:1px solid #ddd;background:#f7f7f7;font-weight:bold;white-space:nowrap;">${escapeHtml(
        label
      )}</td>
      <td style="padding:6px 12px;border:1px solid #ddd;">${escapeHtml(
        value === null || value === undefined || value === "" ? "—" : value
      )}</td>
    </tr>`;
}

/**
 * Sends the onboarding-failure alert email.
 *
 * @param {object} params
 * @param {string|null} params.userId      user_id if known (email), else null
 * @param {string|null} params.identifier  invite email / identifier if known
 * @param {string}      params.reason      machine failure reason (e.g. "expired")
 * @param {string}      [params.message]   human-readable message sent to client
 * @param {number}      params.apiStatus   HTTP status returned to the client
 * @param {string}      [params.endpoint]  API endpoint path
 * @param {object}      [params.extra]     any extra key/value context
 * @returns {Promise<{ok: boolean, skipped?: boolean, status?: number, error?: any}>}
 */
async function notifyOnboardingFailure({
  userId = null,
  identifier = null,
  reason,
  message = "",
  apiStatus,
  endpoint = "/dietitian/api/web/accept-invite",
  extra = {},
}) {
  // No-op when not configured — never block onboarding on alerting.
  if (!ONBOARDING_ALERT_EMAIL || !RESEND_API_KEY) {
    return { ok: false, skipped: true };
  }

  const recipients = ONBOARDING_ALERT_EMAIL.split(",")
    .map((e) => e.trim())
    .filter(Boolean);

  if (recipients.length === 0) {
    return { ok: false, skipped: true };
  }

  const nowUtc = new Date().toISOString();

  const extraRows = Object.entries(extra || {})
    .map(([k, v]) => row(k, v))
    .join("");

  const html = `
    <div style="font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#222;">
      <h2 style="color:#c0392b;margin-bottom:4px;">⚠️ Onboarding Failed</h2>
      <p style="margin-top:0;">A user's onboarding attempt failed on the Respyr platform.</p>
      <table style="border-collapse:collapse;min-width:420px;">
        ${row("Failure Reason", reason)}
        ${row("Client Message", message)}
        ${row("User ID", userId)}
        ${row("Identifier (invite email)", identifier)}
        ${row("API Status", apiStatus)}
        ${row("Endpoint", endpoint)}
        ${row("Timestamp (UTC)", nowUtc)}
        ${extraRows}
      </table>
      <p style="color:#888;font-size:12px;margin-top:16px;">
        Automated alert from the Respyr onboarding API. Do not reply.
      </p>
    </div>`;

  try {
    const response = await axios.post(
      "https://api.resend.com/emails",
      {
        from: RESEND_FROM_EMAIL,
        to: recipients,
        subject: `[Respyr] Onboarding failed — ${reason} (HTTP ${apiStatus})`,
        html,
        tags: [
          { name: "kind", value: "onboarding_failure_alert" },
          { name: "reason", value: String(reason || "unknown").slice(0, 50) },
        ],
      },
      {
        timeout: RESEND_TIMEOUT_MS,
        headers: {
          Authorization: `Bearer ${RESEND_API_KEY}`,
          "Content-Type": "application/json",
        },
        // Never throw on 4xx/5xx — inspect status instead.
        validateStatus: () => true,
      }
    );

    if (response.status >= 200 && response.status < 300) {
      return { ok: true, status: response.status };
    }

    console.error("ONBOARDING_ALERT_EMAIL_FAILED:", {
      status: response.status,
      error: response.data,
      reason,
      apiStatus,
    });

    return { ok: false, status: response.status, error: response.data };
  } catch (err) {
    console.error("ONBOARDING_ALERT_EMAIL_FAILED:", {
      code: err?.code,
      message: err?.message,
      reason,
      apiStatus,
    });

    return { ok: false, status: 0, error: err?.code || err?.message };
  }
}

module.exports = { notifyOnboardingFailure };