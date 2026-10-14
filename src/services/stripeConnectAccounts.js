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
 * Every save goes to two databases independently (saveAccount):
 * dietician_db.partner_payout_accounts and, once the account is verified,
 * sales_crm.stripe_payout_accounts (salesCrmMirror.js). Both rows are built
 * from Stripe's data, so either database can be down without blocking the
 * other.
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

/** What we store about an account, computed from Stripe's v2 Account. */
function summarize(acct) {
  const status = statusFromAccount(acct);
  const active = transfersActive(acct);
  // "Submitted" = nothing is currently or past due (the form was completed),
  // even if Stripe is still verifying. Drives the "Manage in Stripe" button.
  const outstanding = (acct.requirements?.entries || []).some((e) =>
    ["currently_due", "past_due"].includes(e?.minimum_deadline?.status)
  );
  return {
    status,
    active,
    detailsSubmitted: active || !outstanding ? 1 : 0,
    requirements: requirementsSummary(acct),
  };
}

/** dietician_db: partner_payout_accounts row (+ release held commission). Throws on failure. */
async function saveToDieticianDb(userId, acct, s) {
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
      s.status,
      s.detailsSubmitted,
      s.active ? 1 : 0,               // payouts_enabled column now means "stripe_transfers active"
      JSON.stringify(s.requirements),
    ]
  );

  if (s.active) {
    await ledger.releaseHeldForPayee(userId);
  }
}

// How long the sales_crm write waits for dietician_db to name the payee.
const PAYEE_LOOKUP_MS = 2000;

/** Resolves to `promise`'s value, or to null after `ms` (the promise keeps running). */
function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve) => {
      timer = setTimeout(() => resolve(null), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Current name, role, code and facility of the payee from dietician_db. Only
 * enriches the sales_crm row: null when dietician_db is slow or down, and the
 * caller falls back to what Stripe holds.
 */
async function lookupPayee(userId) {
  try {
    const res = await withTimeout(
      pool.execute(
        `
          SELECT aur.role, aur.partner_code, aur.facility_id,
                 f.name AS facility_name,
                 (SELECT td.name FROM table_dietician td
                   WHERE LOWER(td.email) = LOWER(aur.user_id) LIMIT 1) AS user_name
          FROM app_user_roles aur
          LEFT JOIN facilities f ON f.id = aur.facility_id
          WHERE LOWER(aur.user_id) = ?
          ORDER BY (aur.status = 'active') DESC
          LIMIT 1
        `,
        [lower(userId)]
      ),
      PAYEE_LOOKUP_MS
    );
    return res ? res[0][0] || null : null;
  } catch {
    return null;
  }
}

/**
 * sales_crm: stripe_payout_accounts row, built from Stripe's data so it does
 * not depend on dietician_db (the payee's role, code and facility were put in
 * the account's metadata when we created it). The sales team wants verified
 * payees only: an account is added the first time it is verified, and from
 * then on every change is copied (so a later action_required or disabled
 * still shows). Never throws; returns { ok, skipped?, reason? }.
 */
async function saveToSalesCrm(userId, acct, s) {
  if (!salesCrmMirror.isEnabled()) return { ok: true, skipped: true };
  try {
    const meta = acct.metadata || {};
    const payee = await lookupPayee(userId);
    const displayName =
      typeof acct.display_name === "string" && lower(acct.display_name) !== lower(userId) ? acct.display_name : null;
    const metaFacilityId = /^\d+$/.test(String(meta.facility_id || "")) ? Number(meta.facility_id) : null;
    const result = await salesCrmMirror.upsertPayoutAccount(
      {
        stripe_account_id: acct.id,
        user_email: lower(userId),
        user_name: payee?.user_name || displayName,
        role: payee?.role || meta.role || null,
        partner_code: payee?.partner_code || meta.partner_code || null,
        facility_id: payee ? payee.facility_id : metaFacilityId,
        facility_name: payee?.facility_name || null,
        livemode: typeof acct.livemode === "boolean" ? acct.livemode : isLive,
        onboarding_status: s.status,
        details_submitted: s.detailsSubmitted,
        payouts_enabled: s.active ? 1 : 0,
        requirements_json: s.requirements,
        setup_started_at: acct.created ? new Date(acct.created) : null,
        last_synced_at: new Date(),
      },
      { insertIfMissing: s.status === "verified" && s.active }
    );
    return result.skipped ? { ok: true, skipped: true } : result;
  } catch (err) {
    console.warn("SALES_CRM_MIRROR_FAILED:", { stripe_account: acct?.id, code: err?.code, message: err?.message });
    return { ok: false, reason: err?.message || "sales_crm write failed" };
  }
}

/**
 * Save Stripe's current view of an account to both databases. The two writes
 * run side by side and neither depends on the other, so if one database is
 * down the other is still written. Returns
 * { status, dieticianDb: { ok, error?, reason? }, salesCrm: { ok, reason? } }.
 */
async function saveAccount(userId, acct) {
  const s = summarize(acct);
  const [dieticianDb, salesCrm] = await Promise.all([
    saveToDieticianDb(userId, acct, s).then(
      () => ({ ok: true }),
      (err) => ({ ok: false, error: err, reason: err?.message || "dietician_db write failed" })
    ),
    saveToSalesCrm(userId, acct, s),
  ]);
  return { status: s.status, dieticianDb, salesCrm };
}

/**
 * Dashboard paths (onboarding, status page, pre-payout check). Both databases
 * are written as in saveAccount; a dietician_db failure is re-thrown because
 * these callers read that row back, a sales_crm failure is only logged.
 */
async function upsertFromAccount(userId, acct) {
  const r = await saveAccount(userId, acct);
  if (!r.dieticianDb.ok) throw r.dieticianDb.error;
  return r.status;
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

/**
 * account.updated from the Connected-accounts webhook. Re-reads the account
 * from Stripe (the source of truth) and saves it to both databases
 * independently (saveAccount). The payee comes from the account's metadata,
 * set when we created it, so a dietician_db outage does not stop the
 * sales_crm write; our own row is only consulted for an account without it.
 * Returns { handled, dieticianDb, salesCrm }. Throws when Stripe cannot be
 * read (or, for an account without metadata, dietician_db), so the webhook
 * answers with an error and Stripe retries.
 */
async function syncFromWebhook(eventAccount) {
  const stripe = requireStripe();
  const acct = await stripe.v2.core.accounts.retrieve(eventAccount.id, { include: ACCOUNT_INCLUDE });
  let userId = lower(acct.metadata?.user_id) || lower(eventAccount.metadata?.user_id);
  if (!userId) {
    const [rows] = await pool.execute(
      `SELECT user_id FROM partner_payout_accounts WHERE stripe_account_id = ? LIMIT 1`,
      [acct.id]
    );
    userId = lower(rows[0]?.user_id);
  }
  if (!userId) {
    // Not one of our payees.
    return { handled: false, dieticianDb: { ok: true, skipped: true }, salesCrm: { ok: true, skipped: true } };
  }
  const r = await saveAccount(userId, acct);
  return { handled: true, dieticianDb: r.dieticianDb, salesCrm: r.salesCrm };
}

module.exports = {
  getAccountRow,
  getOrCreateAccount,
  createOnboardingLink,
  createDashboardLink,
  syncAccount,
  canReceiveTransfers,
  syncFromWebhook,
  statusFromAccount,
  transfersActive,
};
