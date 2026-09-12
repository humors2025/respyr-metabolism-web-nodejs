"use strict";

/**
 * Stripe Connect accounts for payees (facility admins; trainers with a
 * commission split). Accounts v2, "recipient" configuration only — the gym can
 * receive Transfers from Rysflo's balance and nothing else. Stripe's hosted
 * onboarding collects identity, bank and tax (W-9 / 1099) details; we store
 * only the account id and its capability state.
 *
 * Readiness is the v2 capability status
 *   configuration.recipient.capabilities.stripe_balance.stripe_transfers.status === "active"
 * (payouts_enabled / charges_enabled are v1 fields and are not used).
 *
 * v2 accounts emit v2 "thin" events (v2.core.account[requirements].updated)
 * rather than the classic account.updated webhook, so status is pulled:
 *   - when the user returns from onboarding (status endpoint, force=true)
 *   - when our copy is older than STALE_MS
 *   - always, right before a Transfer (payoutRuns.js)
 */

const pool = require("../config/db");
const { requireStripe } = require("../config/stripe");
const ledger = require("./commissionLedger");

function lower(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

const ACCOUNT_INCLUDE = ["configuration.recipient", "identity", "requirements"];

/** Map a v2 Account to our onboarding_status. */
function statusFromAccount(acct) {
  const cap = acct.configuration?.recipient?.capabilities?.stripe_balance?.stripe_transfers;
  const capStatus = cap?.status || "unsupported";
  const code = cap?.status_details?.code || null;
  const entries = acct.requirements?.entries || [];
  const due = entries.filter((e) => ["currently_due", "past_due"].includes(e?.minimum_deadline?.status));
  const pastDue = entries.some((e) => e?.minimum_deadline?.status === "past_due");

  if (capStatus === "active" && due.length === 0) return "verified";
  if (capStatus === "active") return "action_required";      // active but new requirements are due
  if (pastDue || code === "requirements_past_due") return "action_required";
  if (["restricted", "unsupported"].includes(capStatus) && code && code !== "requirements_pending") return "disabled";
  return "pending";
}

function transfersActive(acct) {
  return acct.configuration?.recipient?.capabilities?.stripe_balance?.stripe_transfers?.status === "active";
}

function requirementsSummary(acct) {
  const entries = acct.requirements?.entries || [];
  const byStatus = (s) =>
    entries
      .filter((e) => e?.minimum_deadline?.status === s)
      .map((e) => (e.impact?.restricts_capabilities ? "capability" : null) || e.errors?.[0]?.code || e.name || e.type || "requirement");
  return {
    currently_due: byStatus("currently_due"),
    past_due: byStatus("past_due"),
    eventually_due: byStatus("eventually_due"),
    capability_status: acct.configuration?.recipient?.capabilities?.stripe_balance?.stripe_transfers?.status || null,
    capability_code: acct.configuration?.recipient?.capabilities?.stripe_balance?.stripe_transfers?.status_details?.code || null,
  };
}

async function upsertFromAccount(userId, acct) {
  const status = statusFromAccount(acct);
  const active = transfersActive(acct);
  // "Submitted" = nothing is currently or past due (the form was completed),
  // even if Stripe is still verifying. Drives the "Manage in Stripe" button.
  const outstanding = (acct.requirements?.entries || []).some((e) =>
    ["currently_due", "past_due"].includes(e?.minimum_deadline?.status)
  );
  const detailsSubmitted = active || !outstanding ? 1 : 0;

  await pool.execute(
    `
      INSERT INTO partner_payout_accounts (
        user_id, stripe_account_id, onboarding_status, details_submitted,
        charges_enabled, payouts_enabled, requirements_json, last_synced_at
      ) VALUES (?, ?, ?, ?, 0, ?, ?, UTC_TIMESTAMP())
      ON DUPLICATE KEY UPDATE
        onboarding_status = VALUES(onboarding_status),
        details_submitted = VALUES(details_submitted),
        payouts_enabled   = VALUES(payouts_enabled),
        requirements_json = VALUES(requirements_json),
        last_synced_at    = UTC_TIMESTAMP()
    `,
    [
      lower(userId),
      acct.id,
      status,
      detailsSubmitted,
      active ? 1 : 0,               // payouts_enabled column now means "stripe_transfers active"
      JSON.stringify(requirementsSummary(acct)),
    ]
  );

  if (active) {
    await ledger.releaseHeldForPayee(userId);
  }

  return status;
}

async function getAccountRow(userId) {
  const [rows] = await pool.execute(
    `SELECT * FROM partner_payout_accounts WHERE LOWER(user_id) = ? LIMIT 1`,
    [lower(userId)]
  );
  return rows[0] || null;
}

/**
 * Create the recipient account on first use, or return the existing row.
 * `user` = { user_id, role, partner_code, facility_id, display_name? }.
 * Entity type (company vs individual) is chosen by the owner inside Stripe
 * onboarding; we do not prefill anything we would have to store.
 */
async function getOrCreateAccount(user) {
  const existing = await getAccountRow(user.user_id);
  if (existing) return existing;

  const stripe = requireStripe();
  const acct = await stripe.v2.core.accounts.create(
    {
      contact_email: lower(user.user_id),
      display_name: user.display_name || lower(user.user_id),
      dashboard: "express",
      identity: { country: "us" },
      configuration: {
        recipient: {
          capabilities: { stripe_balance: { stripe_transfers: { requested: true } } },
        },
      },
      defaults: {
        currency: "usd",
        responsibilities: { fees_collector: "application", losses_collector: "application" },
      },
      metadata: {
        user_id: lower(user.user_id),
        role: String(user.role),
        partner_code: user.partner_code || "",
        facility_id: user.facility_id == null ? "" : String(user.facility_id),
      },
      include: ACCOUNT_INCLUDE,
    },
    { idempotencyKey: `connect-create-${lower(user.user_id)}` }
  );

  await upsertFromAccount(user.user_id, acct);
  return getAccountRow(user.user_id);
}

/** Single-use hosted onboarding URL. Both URLs must be HTTPS (Stripe rule). */
async function createOnboardingLink(stripeAccountId, { refreshUrl, returnUrl }) {
  const stripe = requireStripe();
  const link = await stripe.v2.core.accountLinks.create({
    account: stripeAccountId,
    use_case: {
      type: "account_onboarding",
      account_onboarding: {
        configurations: ["recipient"],
        refresh_url: refreshUrl,
        return_url: returnUrl,
      },
    },
  });
  return link.url;
}

/** Express dashboard login link for "Manage in Stripe". */
async function createDashboardLink(stripeAccountId) {
  const stripe = requireStripe();
  const link = await stripe.accounts.createLoginLink(stripeAccountId);
  return link.url;
}

/** Pull the account from Stripe and refresh our copy. Returns the row. */
async function syncAccount(userId, stripeAccountId) {
  const stripe = requireStripe();
  const acct = await stripe.v2.core.accounts.retrieve(stripeAccountId, { include: ACCOUNT_INCLUDE });
  await upsertFromAccount(userId, acct);
  return getAccountRow(userId);
}

/** Live check used immediately before moving money. */
async function canReceiveTransfers(stripeAccountId) {
  const stripe = requireStripe();
  const acct = await stripe.v2.core.accounts.retrieve(stripeAccountId, { include: ["configuration.recipient"] });
  return transfersActive(acct);
}

/** Classic account.updated (v1 accounts only) — kept for accounts created before v2. */
async function syncAccountFromStripeObject(acct) {
  const [rows] = await pool.execute(
    `SELECT user_id FROM partner_payout_accounts WHERE stripe_account_id = ? LIMIT 1`,
    [acct.id]
  );
  const userId = rows[0]?.user_id || acct.metadata?.user_id;
  if (!userId) return;
  await syncAccount(userId, acct.id);
}

module.exports = {
  getAccountRow,
  getOrCreateAccount,
  createOnboardingLink,
  createDashboardLink,
  syncAccount,
  canReceiveTransfers,
  syncAccountFromStripeObject,
  statusFromAccount,
  transfersActive,
};
