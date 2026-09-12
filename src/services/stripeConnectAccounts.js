"use strict";

/**
 * Stripe Connect Express accounts for payees (facility admins; trainers with a
 * commission split). We store only the account id and its verification state.
 * Stripe collects identity, bank and tax (W-9 / 1099) details on its own
 * hosted onboarding — no SSN / EIN ever touches this system.
 */

const pool = require("../config/db");
const { requireStripe } = require("../config/stripe");
const ledger = require("./commissionLedger");

function lower(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

function statusFromAccount(acct) {
  const due = acct.requirements?.currently_due || [];
  const pastDue = acct.requirements?.past_due || [];
  const disabled = acct.requirements?.disabled_reason || null;

  if (disabled && !acct.payouts_enabled) return "disabled";
  if (acct.payouts_enabled && acct.details_submitted && due.length === 0) return "verified";
  if (acct.details_submitted && (due.length > 0 || pastDue.length > 0)) return "action_required";
  return "pending";
}

async function upsertFromAccount(userId, acct) {
  const status = statusFromAccount(acct);
  await pool.execute(
    `
      INSERT INTO partner_payout_accounts (
        user_id, stripe_account_id, onboarding_status, details_submitted,
        charges_enabled, payouts_enabled, requirements_json, last_synced_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())
      ON DUPLICATE KEY UPDATE
        onboarding_status = VALUES(onboarding_status),
        details_submitted = VALUES(details_submitted),
        charges_enabled   = VALUES(charges_enabled),
        payouts_enabled   = VALUES(payouts_enabled),
        requirements_json = VALUES(requirements_json),
        last_synced_at    = UTC_TIMESTAMP()
    `,
    [
      lower(userId),
      acct.id,
      status,
      acct.details_submitted ? 1 : 0,
      acct.charges_enabled ? 1 : 0,
      acct.payouts_enabled ? 1 : 0,
      JSON.stringify({
        currently_due: acct.requirements?.currently_due || [],
        past_due: acct.requirements?.past_due || [],
        pending_verification: acct.requirements?.pending_verification || [],
        disabled_reason: acct.requirements?.disabled_reason || null,
      }),
    ]
  );

  if (acct.payouts_enabled) {
    await ledger.releaseHeldForPayee(userId);
  }

  return status;
}

/** Row for a user, or null. */
async function getAccountRow(userId) {
  const [rows] = await pool.execute(
    `SELECT * FROM partner_payout_accounts WHERE LOWER(user_id) = ? LIMIT 1`,
    [lower(userId)]
  );
  return rows[0] || null;
}

/**
 * Create the Express account on first use, or return the existing one.
 * `user` is the app_user_roles row (+ email). Business type is left for the
 * owner to choose inside Stripe onboarding (company for a gym, individual for
 * a trainer) — we only prefill what we know.
 */
async function getOrCreateAccount(user) {
  const existing = await getAccountRow(user.user_id);
  if (existing) return existing;

  const stripe = requireStripe();
  const acct = await stripe.accounts.create(
    {
      type: "express",
      country: "US",
      email: lower(user.user_id),
      capabilities: { transfers: { requested: true } },
      business_profile: {
        product_description: "Rysflo referral commission",
      },
      metadata: {
        user_id: lower(user.user_id),
        role: String(user.role),
        partner_code: user.partner_code || "",
        facility_id: user.facility_id == null ? "" : String(user.facility_id),
      },
    },
    { idempotencyKey: `connect-create-${lower(user.user_id)}` }
  );

  await upsertFromAccount(user.user_id, acct);
  return getAccountRow(user.user_id);
}

/** One-time hosted onboarding URL. */
async function createOnboardingLink(stripeAccountId, { refreshUrl, returnUrl }) {
  const stripe = requireStripe();
  const link = await stripe.accountLinks.create({
    account: stripeAccountId,
    type: "account_onboarding",
    refresh_url: refreshUrl,
    return_url: returnUrl,
  });
  return link.url;
}

/** Express dashboard login link for "Manage in Stripe". */
async function createDashboardLink(stripeAccountId) {
  const stripe = requireStripe();
  const link = await stripe.accounts.createLoginLink(stripeAccountId);
  return link.url;
}

/** Refresh our copy from Stripe (used by the status endpoint when stale). */
async function syncAccount(userId, stripeAccountId) {
  const stripe = requireStripe();
  const acct = await stripe.accounts.retrieve(stripeAccountId);
  await upsertFromAccount(userId, acct);
  return getAccountRow(userId);
}

/** Webhook: account.updated carries the full account object. */
async function syncAccountFromStripeObject(acct) {
  const [rows] = await pool.execute(
    `SELECT user_id FROM partner_payout_accounts WHERE stripe_account_id = ? LIMIT 1`,
    [acct.id]
  );
  const userId = rows[0]?.user_id || acct.metadata?.user_id;
  if (!userId) return;
  await upsertFromAccount(userId, acct);
}

module.exports = {
  getAccountRow,
  getOrCreateAccount,
  createOnboardingLink,
  createDashboardLink,
  syncAccount,
  syncAccountFromStripeObject,
  statusFromAccount,
};
