"use strict";

/**
 * Global API access audit — writes one app_auth_logs row per request for every
 * endpoint that does not already audit itself.
 *
 * Why this exists: ~30 controllers (mostly read/PHI endpoints, plus
 * change-password and refresh-token) never call writeAuthLogSafe, so there was
 * no trail of who accessed them. Mounting this once in index.js covers all of
 * them AND any endpoint added in the future — new routes are logged by default.
 *
 * Duplicate avoidance: endpoints whose controllers already write domain events
 * to app_auth_logs (login_success, super_admin_overview_viewed, ...) are listed
 * in SELF_AUDITED_PATHS and skipped here. If you add writeAuthLogSafe to a
 * controller later, add its route path to that set.
 *
 * Lambda constraint (the reason for the res.end interception): lambda.js sets
 * callbackWaitsForEmptyEventLoop = false, so any DB write still in flight when
 * the response goes out can be frozen with the container and lost. The insert
 * therefore runs BEFORE the original res.end is invoked, bounded by
 * AUDIT_WRITE_TIMEOUT_MS so a DB stall can never hang responses. The same
 * "audit before respond" ordering is what the self-auditing controllers do.
 *
 * PII policy matches writeAuthLogSafe: ip / user-agent / identifier / sid are
 * HMAC-hashed with SECURITY_PEPPER; user_id carries the same value the JWT
 * carries (email), consistent with the existing rows in the table.
 */

const pool = require("../config/db");
const {
  authLogHash,
  getClientIp,
  getUserAgent,
} = require("../controllers/dietitian/api/web/auth_common");

const AUDIT_WRITE_TIMEOUT_MS = 1500;

// Never audited: health checks and CORS preflight.
const SKIP_EXACT = new Set(["/", "/health"]);

// Routes whose controllers already write their own app_auth_logs rows
// (generated from apiRoutes.js x "which controllers reference
// writeAuthLogSafe/app_auth_logs" on 2026-09-19).
const SELF_AUDITED_PATHS = new Set([
  "/auth/login",
  "/auth/logout",
  "/auth/send_diatitian_otp",
  "/auth/verify_diatitian_otp",
  "/auth/update_diatitian_password",
  "/dietitian/api/web/accept-invite",
  "/dietitian/api/web/trainer-update-weekly-food-json",
  "/dietitian/api/web/food_json_suggestion_approve_plan",
  "/dietitian/api/web/level-type-update-change",
  "/dietitian/api/web/get_macro_summary_by_date",
  "/dietitian/api/web/get_client_profile_details",
  "/dietitian/api/web/get_client_profile_details_masked",
  "/dietitian/api/web/list-admin-trainer-users-jwt",
  "/dietitian/api/web/list-accepted-agreements",
  "/dietitian/api/web/super-admin-invite-admin",
  "/dietitian/api/web/list-trainer-client-invites",
  "/dietitian/api/web/send_trainer_client_invite",
  "/dietitian/api/web/resend-client-subscription-invite",
  "/dietitian/api/web/revoke-client-subscription-invite",
  "/dietitian/api/web/extend-client-free-trial-14days",
  "/dietitian/api/web/super-admin-overview",
  "/dietitian/api/web/audit-logs",
  "/dietitian/api/web/audit-logs/live",
  "/dietitian/api/web/super-admin-all-clients-overview",
  "/dietitian/api/web/list-admin-trainer-users",
  "/dietitian/api/web/list-all-trainers-for-super-admin",
  "/dietitian/api/web/trainer-admin-clients-list-dir",
  "/dietitian/api/web/trainer-admin-overview",
  "/dietitian/api/web/get_group_details",
  "/dietitian/api/web/get_group_period_readers",
  "/dietitian/api/web/get_group_onboarding",
  "/dietitian/api/web/manage_admin_groups",
  "/dietitian/api/web/weight-tracking",
  "/dietitian/api/web/trainer-sales-analytics",
  "/dietitian/api/web/trainer-admin-trainers-summary",
  "/dietitian/api/web/super-admin-trainers-summary",
  "/dietitian/api/web/trainer-clients-overview-for-super-admin",
  "/dietitian/api/web/get-clients-data-total-missed-test-masked",
  "/dietitian/api/web/get-data-points-score-all-ranges-coach-masking",
  "/dietitian/api/web/get-data-points-score-all-ranges-coach",
  "/dietitian/api/web/get-graph-all-seven-trends-graph",
  "/dietitian/api/web/resend-user-invite",
  "/dietitian/api/web/admin-invite-trainer",
  "/dietitian/api/web/admin-invite-facility-admin",
  "/dietitian/api/web/set-trainer-commission-split",
  "/dietitian/api/web/stripe-connect-status",
  "/dietitian/api/web/stripe-connect-onboarding-link",
  "/dietitian/api/web/stripe-connect-dashboard-link",
  "/dietitian/api/web/get-commission-rate",
  "/dietitian/api/web/set-commission-rate",
  "/dietitian/api/web/run-breath-credits",
  "/dietitian/api/web/run-payouts",
  "/dietitian/api/web/list-payouts",
  "/dietitian/api/web/commission-overview",
  "/dietitian/api/web/super-admin-sales-analytics",
  "/dietitian/api/web/super-admin-orders",
  "/dietitian/api/web/order-page-context",
  "/dietitian/api/web/order-session-status",
  "/dietitian/api/web/referred-members",
  "/dietitian/api/web/resend-purchase-code",
  "/dietitian/api/web/qr-generate",
  "/dietitian/api/web/qr-link",
  "/dietitian/api/web/qr-list",
  "/dietitian/api/web/qr-assign",
  "/dietitian/api/web/qr-setup",
  "/dietitian/api/web/qr-revoke",
  "/dietitian/api/web/invite-revoke",
  "/dietitian/api/web/list-trainer-admins",
  "/dietitian/api/web/get-pricing",
  "/dietitian/api/web/set-pricing",
  "/dietitian/api/web/super-admin-invite-trainer",
  "/dietitian/api/web/super-admin-resend-trainers",
  "/dietitian/api/web/super-admin-revoke-trainers",
  "/dietitian/api/web/revoke-user-invite",
  "/dietitian/api/web/remove-user",
  "/dietitian/api/web/referral-client-list",
  "/dietitian/api/web/store_weekly_food_json_suggestion",
  "/dietitian/api/web/store_weekly_food_json_suggestion_newtest",
  "/dietitian/api/web/trainer-update-weekly-food-json-newtest",
  "/dietitian/api/web/reset-weekly-food-json-newtest",
  "/dietitian/api/web/food_json_suggestion_approve_plan_newtest",
  "/dietitian/api/web/super-admin-all-clients-overview-newtest",
  "/dietitian/api/web/get_latest_72hr_tests",
  "/dietitian/api/web/fetch-single-client-worker-job-test",
]);

/** "/dietitian/api/web/create-checkout-session" -> "create_checkout_session" */
function eventTypeFromPath(path) {
  const segments = String(path || "").split("/").filter(Boolean);
  const slug = segments.slice(-1)[0] || "root";
  return slug.replace(/[^a-zA-Z0-9]+/g, "_").toLowerCase().slice(0, 60);
}

function normalizePath(path) {
  const clean = String(path || "/").split("?")[0];
  return clean.length > 1 && clean.endsWith("/") ? clean.slice(0, -1) : clean;
}

function shouldAudit(req, res) {
  if (req.method === "OPTIONS") return false;

  const path = normalizePath(req.path);
  if (SKIP_EXACT.has(path)) return false;
  if (SELF_AUDITED_PATHS.has(path)) return false;

  // Unknown routes: 404 probes from scanners would flood the table.
  if (res.statusCode === 404) return false;

  return true;
}

async function writeAccessLog(req, res) {
  const user = req.user || null;
  const userId = user?.user_id || user?.dietician_id || null;

  await pool.execute(
    `INSERT INTO app_auth_logs (
       event_type,
       user_id,
       role,
       partner_code,
       identifier_hash,
       ip_hash,
       user_agent_hash,
       session_id_hash,
       success,
       failure_reason
     )
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      eventTypeFromPath(req.path),
      userId !== null ? String(userId).slice(0, 191) : null,
      user?.role ? String(user.role).slice(0, 60) : null,
      user?.partner_code ? String(user.partner_code).toUpperCase().slice(0, 60) : null,
      userId !== null ? authLogHash(userId) : null,
      authLogHash(getClientIp(req)),
      authLogHash(getUserAgent(req)),
      user?.sid ? authLogHash(String(user.sid)) : null,
      res.statusCode < 400 ? 1 : 0,
      res.statusCode < 400 ? null : `HTTP ${res.statusCode}`,
    ]
  );
}

module.exports = (req, res, next) => {
  const originalEnd = res.end;
  let intercepted = false;

  res.end = function (...args) {
    if (intercepted) {
      return originalEnd.apply(this, args);
    }
    intercepted = true;

    if (!shouldAudit(req, res)) {
      return originalEnd.apply(this, args);
    }

    const finish = () => originalEnd.apply(this, args);

    // Bounded: a slow/unreachable DB must never hang API responses, and a
    // failed audit write must never fail the request (same fail-safe stance
    // as writeAuthLogSafe).
    Promise.race([
      writeAccessLog(req, res),
      new Promise((resolve) =>
        setTimeout(resolve, AUDIT_WRITE_TIMEOUT_MS).unref?.()
      ),
    ]).then(finish, (err) => {
      console.error("ACCESS_AUDIT_FAILED:", err?.code || err?.message);
      finish();
    });

    return this;
  };

  next();
};
