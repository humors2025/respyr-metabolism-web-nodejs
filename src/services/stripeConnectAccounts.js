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
 * v2 accounts emit both v2 "thin" events (Your account scope) and the classic
 * v1 account.updated (Connected accounts scope only, so it reaches
 * /stripe/webhook only through a second, Connect-scoped endpoint signed with
 * STRIPE_CONNECT_WEBHOOK_SECRET). Status is therefore also pulled:
 *   - when the user returns from onboarding (status endpoint, force=true)
 *   - when our copy is older than STALE_MS
 *   - always, right before a Transfer (payoutRuns.js)
 *
 * Once an account is verified, every write of partner_payout_accounts is
 * copied to sales_crm.stripe_payout_accounts (salesCrmMirror.js) when that is
 * enabled; see mirrorToSalesCrm.
 */

const pool = require("../config/db");
const { requireStripe, isLive } = require("../config/stripe");
const ledger = require("./commissionLedger");
const salesCrmMirror = require("./salesCrmMirror");

function lower(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

const ACCOUNT_INCLUDE = ["configuration.recipient", "identity", "requirements"];

/**
 * Accounts v2 rejects empty metadata values ("must be between 1 and 500
 * characters"), so drop null/empty keys instead of sending "". Trainers
 * without a facility, for example, have facility_id = null.
 */
function compactMetadata(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v === null || v === undefined) continue;
    const str = String(v).trim();
    if (str === "") continue;
    out[k] = str.slice(0, 500);
  }
  return out;
}

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

  await mirrorToSalesCrm(userId, acct);

  if (active) {
    await ledger.releaseHeldForPayee(userId);
  }

  return status;
}

/**
 * Copy the row just written, plus who the payee is, to sales_crm. The sales
 * team wants verified payees only: an account is added there the first time
 * it is verified, and from then on every change is copied (so a later
 * action_required or disabled still shows). Best-effort: a failure is logged
 * and never reaches onboarding, the status page, the webhook or a payout.
 */
async function mirrorToSalesCrm(userId, acct) {
  if (!salesCrmMirror.isEnabled()) return;
  try {
    const [rows] = await pool.execute(
      `
        SELECT ppa.stripe_account_id, ppa.user_id, ppa.onboarding_status,
               ppa.details_submitted, ppa.payouts_enabled, ppa.requirements_json,
               ppa.created_at, ppa.last_synced_at,
               aur.role, aur.partner_code, aur.facility_id,
               f.name AS facility_name,
               (SELECT td.name FROM table_dietician td
                 WHERE LOWER(td.email) = LOWER(aur.user_id) LIMIT 1) AS user_name
        FROM partner_payout_accounts ppa
        LEFT JOIN app_user_roles aur ON LOWER(aur.user_id) = LOWER(ppa.user_id)
        LEFT JOIN facilities f ON f.id = aur.facility_id
        WHERE LOWER(ppa.user_id) = ?
        ORDER BY (aur.status = 'active') DESC
        LIMIT 1
      `,
      [lower(userId)]
    );
    const row = rows[0];
    if (!row) return;
    const verified = row.onboarding_status === "verified" && Number(row.payouts_enabled) === 1;
    await salesCrmMirror.upsertPayoutAccount({
      stripe_account_id: row.stripe_account_id,
      user_email: row.user_id,
      user_name: row.user_name,
      role: row.role,
      partner_code: row.partner_code,
      facility_id: row.facility_id,
      facility_name: row.facility_name,
      livemode: typeof acct?.livemode === "boolean" ? acct.livemode : isLive,
      onboarding_status: row.onboarding_status,
      details_submitted: row.details_submitted,
      payouts_enabled: row.payouts_enabled,
      requirements_json: row.requirements_json,
      setup_started_at: row.created_at,
      last_synced_at: row.last_synced_at,
    }, { insertIfMissing: verified });
  } catch (err) {
    console.warn("SALES_CRM_MIRROR_FAILED:", {
      stripe_account: acct?.id,
      step: "read payee",
      code: err?.code,
      message: err?.message,
    });
  }
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
      metadata: compactMetadata({
        user_id: lower(user.user_id),
        role: String(user.role),
        partner_code: user.partner_code,
        facility_id: user.facility_id,
      }),
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
