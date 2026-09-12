"use strict";

/**
 * Stripe Connect payout setup for payees (facility_admin, trainer, admin).
 *
 *  POST /dietitian/api/web/stripe-connect-status
 *       -> { ok, account: null | { onboarding_status, payouts_enabled, ... },
 *            held_minor, pending_minor }
 *  POST /dietitian/api/web/stripe-connect-onboarding-link
 *       -> { ok, url }   creates the Express account on first call
 *  POST /dietitian/api/web/stripe-connect-dashboard-link
 *       -> { ok, url }   Express dashboard login link
 *
 * Every call acts on the authenticated user only (self-service); there is no
 * way to address another user's account.
 */

const pool = require("../../../../config/db");
const connect = require("../../../../services/stripeConnectAccounts");
const { _helpers: H } = require("./admin-invite-trainer");

const PAYEE_ROLES = ["admin", "facility_admin", "trainer"];
const STALE_MS = 60 * 60 * 1000;

// Stripe requires HTTPS for both onboarding URLs, even in test mode.
const PAYOUT_SETUP_URL =
  String(process.env.FRONTEND_PAYOUT_SETUP_URL || "https://admin.rysflo.com/payout-setup").trim();
if (!/^https:\/\//i.test(PAYOUT_SETUP_URL)) {
  console.warn("FRONTEND_PAYOUT_SETUP_URL must be https:// — Stripe rejects http onboarding URLs.");
}

function publicAccount(row) {
  if (!row) return null;
  let req = null;
  try {
    req = typeof row.requirements_json === "string" ? JSON.parse(row.requirements_json) : row.requirements_json;
  } catch {
    req = null;
  }
  return {
    onboarding_status: row.onboarding_status,
    details_submitted: Number(row.details_submitted) === 1,
    payouts_enabled: Number(row.payouts_enabled) === 1,
    requirements: req,
    last_synced_at: row.last_synced_at,
  };
}

async function resolvePayee(req, res) {
  const resolved = await H.resolveActorFromToken(req, PAYEE_ROLES);
  if (resolved.error) {
    res.status(resolved.error.status).json(resolved.error.body);
    return null;
  }
  return resolved;
}

const stripeConnectStatus = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await resolvePayee(req, res);
    if (!resolved) return;
    const userId = resolved.actorEmail;

    let row = await connect.getAccountRow(userId);
    const force = req.body?.force_sync === true; // the payout-setup page passes this on ?return=1
    if (row && (force || !row.last_synced_at || Date.now() - new Date(row.last_synced_at).getTime() > STALE_MS)) {
      row = await connect.syncAccount(userId, row.stripe_account_id);
    }

    const [sums] = await pool.execute(
      `
        SELECT
          COALESCE(SUM(CASE WHEN status = 'held'    THEN amount_minor END), 0) AS held_minor,
          COALESCE(SUM(CASE WHEN status = 'pending' THEN amount_minor END), 0) AS pending_minor,
          COALESCE(SUM(CASE WHEN status = 'paid'    THEN amount_minor END), 0) AS paid_minor
        FROM commission_entries
        WHERE LOWER(payee_user_id) = ?
      `,
      [userId]
    );

    return res.status(200).json({
      ok: true,
      account: publicAccount(row),
      held_minor: Number(sums[0].held_minor),
      pending_minor: Number(sums[0].pending_minor),
      paid_minor: Number(sums[0].paid_minor),
    });
  } catch (err) {
    console.error("STRIPE_CONNECT_STATUS_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

const stripeConnectOnboardingLink = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await resolvePayee(req, res);
    if (!resolved) return;
    const { actor, actorEmail } = resolved;

    const row = await connect.getOrCreateAccount({
      user_id: actorEmail,
      role: actor.role,
      partner_code: actor.partner_code,
      facility_id: actor.facility_id,
      display_name: actor.name || undefined,
    });

    const url = await connect.createOnboardingLink(row.stripe_account_id, {
      refreshUrl: `${PAYOUT_SETUP_URL}?refresh=1`,
      returnUrl: `${PAYOUT_SETUP_URL}?return=1`,
    });

    await H.writeAuthLogSafe(req, {
      eventType: "stripe_connect_onboarding_started",
      userId: actorEmail,
      role: String(actor.role),
      partnerCode: actor.partner_code ?? null,
      identifier: actorEmail,
      success: true,
      failureReason: row.stripe_account_id,
    });

    return res.status(200).json({ ok: true, url });
  } catch (err) {
    console.error("STRIPE_CONNECT_ONBOARDING_ERROR:", { code: err?.code, type: err?.type, message: err?.message });
    return res.status(500).json({ ok: false, message: "Unable to start payout setup" });
  }
};

const stripeConnectDashboardLink = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await resolvePayee(req, res);
    if (!resolved) return;

    const row = await connect.getAccountRow(resolved.actorEmail);
    if (!row || Number(row.details_submitted) !== 1) {
      return res.status(409).json({ ok: false, message: "Complete payout setup first" });
    }

    const url = await connect.createDashboardLink(row.stripe_account_id);
    return res.status(200).json({ ok: true, url });
  } catch (err) {
    console.error("STRIPE_CONNECT_DASHBOARD_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Unable to open Stripe dashboard" });
  }
};

module.exports = { stripeConnectStatus, stripeConnectOnboardingLink, stripeConnectDashboardLink };
