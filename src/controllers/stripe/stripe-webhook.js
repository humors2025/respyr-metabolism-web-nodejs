"use strict";

/**
 * POST /stripe/webhook
 *
 * Single Stripe webhook endpoint for the referral programme. Verified with the
 * endpoint's signing secret against the raw request bytes (req.rawBody, kept by
 * the JSON parser in index.js). Every event is recorded in webhook_events
 * before it is handled, so redelivery is a no-op and a handler crash is
 * visible as status='error' with the message.
 *
 * Events handled:
 *   checkout.session.completed   -> referral_subscriptions row (attribution)
 *                                   + subscription_shipping_addresses row
 *                                   + "payment received" email to the buyer
 *   payment_intent.payment_failed
 *   checkout.session.async_payment_failed
 *                                -> "payment failed" email to the buyer
 *   invoice.payment_failed       -> payment_transactions row (failed)
 *                                   + "payment failed" email (renewals)
 *   customer.subscription.*      -> keep status / period in sync
 *   invoice.paid                 -> payment_transactions row
 *                                   + commission_entries (the ledger)
 *                                   + "membership renewed" email (renewals)
 *   charge.refunded              -> payment_transactions refund amount/status
 *                                   + reverse ledger entries for that invoice
 *   account.updated              -> dietician_db.partner_payout_accounts and
 *                                   sales_crm.stripe_payout_accounts, each
 *                                   written on its own (handleAccountUpdated);
 *                                   500 until both are written, so Stripe
 *                                   retries
 *   transfer.reversed            -> payouts + ledger entries reversed
 *   (a Transfer settles synchronously on create; there is no transfer.paid)
 *
 * Every payment attempt above (new purchase, renewal, any decline) is also
 * copied to the team as an internal alert (paymentEmails.sendPaymentAlert,
 * recipients in PAYMENT_ALERT_EMAILS). It never throws.
 *
 * Two Stripe endpoints can point at this URL. The main one ("Events from: Your
 * account") is signed with STRIPE_WEBHOOK_SECRET. For Accounts v2 payees
 * Stripe sends account.updated only in the "Connected accounts" scope, so a
 * second endpoint with that scope, subscribed to account.updated alone, is
 * signed with STRIPE_CONNECT_WEBHOOK_SECRET. Events from a connected account
 * (event.account set) other than account.updated are acknowledged and ignored:
 * they belong to the gym's own Stripe account, not to Rysflo's sales.
 *
 * Anything else is acknowledged and ignored. Apart from account.updated,
 * always returns 200 once the event is recorded, even if handling failed —
 * Stripe retries are not useful for a bug; the error is logged and visible
 * for a super_admin to replay.
 */

const pool = require("../../config/db");
const {
  requireStripe,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_CONNECT_WEBHOOK_SECRET,
  STRIPE_TERM_MONTHS,
  PLAN_CODE,
} = require("../../config/stripe");
const ledger = require("../../services/commissionLedger");
const connect = require("../../services/stripeConnectAccounts");
const pricing = require("../../services/pricing");
const purchaseCodes = require("../../services/purchaseCodes");
const paymentEmails = require("../../services/paymentEmails");
const paymentTransactions = require("../../services/paymentTransactions");
const { resolvePartnerCode } = require("../../utils/partnerCodeResolver");

function toMysqlDateTime(unixSeconds) {
  if (unixSeconds == null) return null;
  return new Date(Number(unixSeconds) * 1000).toISOString().slice(0, 19).replace("T", " ");
}

function lower(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : null;
}

/** Referral code attributed to a subscription, from our own row (renewals). */
async function partnerCodeForSubscription(stripeSubscriptionId) {
  if (!stripeSubscriptionId) return null;
  const [rows] = await pool.execute(
    `SELECT attributed_partner_code FROM referral_subscriptions WHERE stripe_subscription_id = ? LIMIT 1`,
    [String(stripeSubscriptionId)]
  );
  return rows[0]?.attributed_partner_code || null;
}

function invoiceMetadata(invoice) {
  return invoice?.parent?.subscription_details?.metadata || invoice?.subscription_details?.metadata || invoice?.metadata || {};
}

function invoiceSubscriptionId(invoice) {
  const v = invoice?.parent?.subscription_details?.subscription || invoice?.subscription || null;
  return v ? (typeof v === "string" ? v : v.id) : null;
}

// ─── Event handlers ──────────────────────────────────────────────────────────

async function onCheckoutSessionCompleted(stripe, session) {
  if (session.mode !== "subscription" || !session.subscription) return;

  const subscription = await stripe.subscriptions.retrieve(String(session.subscription), { expand: ["discounts"] });
  const item = subscription.items?.data?.[0];
  const price = item?.price;
  const md = { ...(session.metadata || {}), ...(subscription.metadata || {}) };

  // Attribution rule (a): the code used at purchase. Website links stamp it in
  // metadata; a code typed on Checkout (or an in-app purchase through the PHP
  // checkout) shows up as a promotion code on the subscription's discount.
  const promoId = await promotionCodeIdOf(subscription);
  if (!md.attributed_partner_code && promoId) {
    const code = await pricing.partnerCodeForPromotion(promoId);
    const resolved = code ? await resolvePartnerCode(code) : null;
    if (resolved) {
      md.attributed_partner_code = resolved.partner_code;
      md.attributed_user_id = resolved.user_id;
      md.attributed_role = resolved.role;
      md.facility_id = resolved.facility_id == null ? "" : String(resolved.facility_id);
    }
  }

  const purchaserEmail = lower(session.customer_details?.email || session.customer_email);
  const purchaserName = String(session.customer_details?.name || "").trim().slice(0, 150) || null;

  // Link to an app profile if the buyer already has one; otherwise the credit
  // job keeps trying by email.
  let profileId = null;
  if (purchaserEmail) {
    const [rows] = await pool.execute(
      `SELECT profile_id FROM table_clients WHERE LOWER(email) = ? ORDER BY id DESC LIMIT 1`,
      [purchaserEmail]
    );
    profileId = rows[0]?.profile_id || null;
  }

  await pool.execute(
    `
      INSERT INTO referral_subscriptions (
        stripe_subscription_id, stripe_customer_id, stripe_checkout_session_id,
        purchaser_email, purchaser_name, profile_id, linked_via, linked_at,
        attributed_partner_code, attributed_user_id, attributed_role, qr_id, stripe_promotion_code_id, facility_id,
        plan_code, price_id, currency, unit_amount_minor, status,
        current_period_start, current_period_end
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        stripe_checkout_session_id = VALUES(stripe_checkout_session_id),
        purchaser_email = COALESCE(purchaser_email, VALUES(purchaser_email)),
        purchaser_name  = COALESCE(purchaser_name, VALUES(purchaser_name)),
        profile_id      = COALESCE(profile_id, VALUES(profile_id)),
        linked_via      = COALESCE(linked_via, VALUES(linked_via)),
        linked_at       = COALESCE(linked_at, VALUES(linked_at)),
        attributed_partner_code = COALESCE(attributed_partner_code, VALUES(attributed_partner_code)),
        attributed_user_id      = COALESCE(attributed_user_id, VALUES(attributed_user_id)),
        attributed_role         = COALESCE(attributed_role, VALUES(attributed_role)),
        facility_id             = COALESCE(facility_id, VALUES(facility_id)),
        stripe_promotion_code_id = COALESCE(stripe_promotion_code_id, VALUES(stripe_promotion_code_id)),
        status          = VALUES(status),
        current_period_start = VALUES(current_period_start),
        current_period_end   = VALUES(current_period_end)
    `,
    [
      subscription.id,
      String(subscription.customer),
      session.id,
      purchaserEmail,
      purchaserName,
      profileId,
      profileId ? "email" : null,
      profileId ? new Date().toISOString().slice(0, 19).replace("T", " ") : null,
      md.attributed_partner_code || null,
      md.attributed_user_id || null,
      md.attributed_role || null,
      md.qr_id || null,
      promoId,
      md.facility_id ? Number(md.facility_id) : null,
      md.plan_code || PLAN_CODE,
      price?.id || "",
      String(subscription.currency || price?.currency || "usd").toUpperCase(),
      Number(price?.unit_amount || 0),
      String(subscription.status),
      toMysqlDateTime(item?.current_period_start ?? subscription.current_period_start),
      toMysqlDateTime(item?.current_period_end ?? subscription.current_period_end),
    ]
  );

  // Device term: after STRIPE_TERM_MONTHS invoices the schedule releases the
  // subscription, which then continues month-to-month until cancelled.
  // Self-healing: if a schedule already exists (earlier partial run), reuse it
  // and only apply the term if it has not been applied yet.
  let schedule = subscription.schedule
    ? await stripe.subscriptionSchedules.retrieve(String(subscription.schedule))
    : await stripe.subscriptionSchedules.create(
        { from_subscription: subscription.id },
        { idempotencyKey: `sched-create-${subscription.id}` }
      );

  if (schedule.metadata?.rysflo_term_months !== String(STRIPE_TERM_MONTHS)) {
    const phase = schedule.phases[0];
    // Rewriting the phase replaces it wholesale, so the referral coupon
    // (duration "forever") must be carried over or every renewal bills list
    // price instead of the referred price.
    const phaseDiscounts = (phase.discounts || [])
      .map((d) => {
        const promo = typeof d.promotion_code === "string" ? d.promotion_code : d.promotion_code?.id;
        if (promo) return { promotion_code: promo };
        const coupon = typeof d.coupon === "string" ? d.coupon : d.coupon?.id;
        return coupon ? { coupon } : null;
      })
      .filter(Boolean);
    schedule = await stripe.subscriptionSchedules.update(
      schedule.id,
      {
        end_behavior: "release",
        phases: [
          {
            items: phase.items.map((i) => ({ price: i.price, quantity: i.quantity })),
            start_date: phase.start_date,
            duration: { interval: "month", interval_count: STRIPE_TERM_MONTHS },
            ...(phaseDiscounts.length ? { discounts: phaseDiscounts } : {}),
            metadata: md,
          },
        ],
        metadata: { ...md, rysflo_term_months: String(STRIPE_TERM_MONTHS) },
      },
      { idempotencyKey: `sched-term-${subscription.id}-${STRIPE_TERM_MONTHS}` }
    );
  }

  await pool.execute(
    `UPDATE referral_subscriptions SET stripe_schedule_id = ? WHERE stripe_subscription_id = ?`,
    [schedule.id, subscription.id]
  );

  // Purchase code for the app (skipped when the buyer is already a linked app
  // user — they bought in-app or by email match, nothing to redeem).
  let purchaseCodeSent = false;
  if (!profileId) {
    const pc = await purchaseCodes.ensurePurchaseCode({ stripeSubscriptionId: subscription.id });
    if (pc?.created) {
      const mail = await purchaseCodes.sendPurchaseCodeEmail({ stripeSubscriptionId: subscription.id });
      purchaseCodeSent = !!mail.ok;
      if (!mail.ok) console.warn("PURCHASE_CODE_EMAIL_NOT_SENT:", { subscription: subscription.id, reason: mail.reason });
    }
  }

  // Payment confirmation to the buyer (once per session).
  const receipt = await paymentEmails.sendPaymentReceipt({ session, subscription, partnerCode: md.attributed_partner_code || null, purchaseCodeSent });
  if (!receipt.ok) console.warn("PAYMENT_RECEIPT_EMAIL_NOT_SENT:", { session: session.id, reason: receipt.reason });

  // Internal copy to the team (once per session). A delayed payment method
  // leaves the session completed but unpaid; that is reported as PENDING and
  // its outcome arrives later as async_payment_failed / invoice.paid.
  const pendingPayment = session.payment_status === "unpaid";
  await paymentEmails.sendPaymentAlert({
    outcome: pendingPayment ? "pending" : "success",
    kind: pendingPayment ? "New purchase (payment pending)" : "New purchase",
    amountMinor: session.amount_total,
    currency: session.currency || subscription.currency,
    buyerEmail: purchaserEmail,
    buyerName: purchaserName,
    partnerCode: md.attributed_partner_code || null,
    objectId: session.id,
    stripePath: `subscriptions/${subscription.id}`,
    livemode: session.livemode,
  });

  // Phone + shipping address for the device, kept out of referral_subscriptions.
  await paymentTransactions.saveShippingAddress({ session, stripeSubscriptionId: subscription.id });

  // Bookkeeping last, so a ledger problem (missing commission rate, payee
  // setup…) can never cost the buyer their code or emails. Stripe does not
  // order events: invoice.paid for the first invoice usually arrives before
  // this one and found no subscription to attribute, so backfill any paid
  // invoices now — the ledger's unique key makes this idempotent. The error
  // is rethrown after the customer steps so the event is still recorded as
  // 'error' and can be replayed once the ledger is fixed; every step above
  // is idempotent, so a replay only redoes the bookkeeping.
  const paid = await stripe.invoices.list({
    subscription: subscription.id,
    status: "paid",
    limit: 12,
  });
  for (const inv of paid.data) {
    await paymentTransactions.syncInvoice(stripe, inv);
    await recordInvoice(inv);
  }
}

/**
 * Card declined on the order page (initial Checkout attempt). Renewal declines
 * come through invoice.payment_failed and are skipped here so the member is
 * not told twice.
 */
async function onPaymentIntentFailed(stripe, pi) {
  // PaymentIntents no longer carry `invoice` (API 2025-03-31+); the link is
  // looked up through the invoice's payments list, as for refunds.
  let invoiceId = pi.invoice ? String(pi.invoice) : null;
  if (!invoiceId) {
    try {
      invoiceId = await paymentTransactions.invoiceIdForPaymentIntent(stripe, pi.id);
    } catch (err) {
      console.warn("PAYMENT_FAILED_INVOICE_LOOKUP:", { payment_intent: pi.id, reason: err?.message });
    }
  }
  const invoice = invoiceId ? await stripe.invoices.retrieve(invoiceId) : null;

  // Renewal declines come through invoice.payment_failed; skip them here so
  // the member and the team are not told twice.
  if (invoice?.billing_reason && invoice.billing_reason !== "subscription_create") return;
  // Another channel's invoice (the in-app PHP checkout shares the account).
  const ours = invoice ? paymentEmails.invoiceIsOurs(invoice) : pi.metadata?.plan_code === PLAN_CODE;
  if (invoice && !ours) return;

  const err = pi.last_payment_error || {};
  let to = pi.receipt_email || err.payment_method?.billing_details?.email || invoice?.customer_email || null;
  if (!to && pi.customer) {
    const customer = await stripe.customers.retrieve(String(pi.customer));
    to = customer?.email || null;
  }
  const md = invoice ? invoiceMetadata(invoice) : pi.metadata || {};
  const partnerCode = md.link_partner_code || md.attributed_partner_code || null;
  const reason = err.message || err.decline_code || err.code || null;

  // Team alert first. It goes out even when the attempt cannot be tied to the
  // programme (a subscription-mode Checkout decline may carry neither invoice
  // nor metadata), labelled so the reader knows attribution is missing.
  await paymentEmails.sendPaymentAlert({
    outcome: "failed",
    kind: ours ? "Checkout card declined" : "Card declined (unattributed)",
    amountMinor: pi.amount,
    currency: pi.currency,
    buyerEmail: to,
    buyerName: err.payment_method?.billing_details?.name || invoice?.customer_name || null,
    partnerCode,
    reason,
    objectId: pi.id,
    stripePath: `payments/${pi.id}`,
    livemode: pi.livemode,
  });

  if (!ours) {
    console.warn("PAYMENT_FAILED_EMAIL_SKIPPED:", { payment_intent: pi.id, reason: "no invoice / plan metadata" });
    return;
  }
  const mail = await paymentEmails.sendPaymentFailed({
    to,
    reason: err.message,
    amountMinor: pi.amount,
    currency: pi.currency,
    retryUrl: paymentEmails.retryUrlFor(partnerCode),
    objectId: pi.id,
  });
  if (!mail.ok) console.warn("PAYMENT_FAILED_EMAIL_NOT_SENT:", { payment_intent: pi.id, reason: mail.reason });
}

/** Renewal payment failed (Stripe keeps retrying per the dunning settings). */
async function onInvoicePaymentFailed(stripe, invoice) {
  if (!paymentEmails.invoiceIsOurs(invoice)) return;
  const synced = await paymentTransactions.syncInvoice(stripe, invoice, { failure: true });
  if (invoice.billing_reason === "subscription_create") return; // handled by onPaymentIntentFailed
  const mail = await paymentEmails.sendPaymentFailed({
    to: invoice.customer_email,
    reason: null,
    amountMinor: invoice.amount_due,
    currency: invoice.currency,
    objectId: invoice.id,
    renewal: true,
  });
  if (!mail.ok) console.warn("PAYMENT_FAILED_EMAIL_NOT_SENT:", { invoice: invoice.id, reason: mail.reason });

  // Team alert, once per dunning attempt (the member hears about it once).
  const subId = invoiceSubscriptionId(invoice);
  await paymentEmails.sendPaymentAlert({
    outcome: "failed",
    kind: `Renewal card declined (attempt ${Number(invoice.attempt_count || 1)})`,
    amountMinor: invoice.amount_due,
    currency: invoice.currency,
    buyerEmail: invoice.customer_email,
    buyerName: invoice.customer_name,
    partnerCode: invoiceMetadata(invoice).attributed_partner_code || (await partnerCodeForSubscription(subId)),
    reason: synced?.failureMessage || null,
    objectId: invoice.id,
    dedupeKey: `${invoice.id}#${Number(invoice.attempt_count || 1)}`,
    stripePath: `invoices/${invoice.id}`,
    livemode: invoice.livemode,
  });
}

/** Delayed payment method (e.g. bank debit) failed after Checkout completed. */
async function onAsyncPaymentFailed(session) {
  const md = session.metadata || {};
  if (md.plan_code && md.plan_code !== PLAN_CODE) return;
  const mail = await paymentEmails.sendPaymentFailed({
    to: session.customer_details?.email || session.customer_email,
    reason: null,
    amountMinor: session.amount_total,
    currency: session.currency,
    retryUrl: paymentEmails.retryUrlFor(md.link_partner_code || md.attributed_partner_code || null),
    objectId: session.id,
  });
  if (!mail.ok) console.warn("PAYMENT_FAILED_EMAIL_NOT_SENT:", { session: session.id, reason: mail.reason });

  await paymentEmails.sendPaymentAlert({
    outcome: "failed",
    kind: "Delayed payment failed after checkout",
    amountMinor: session.amount_total,
    currency: session.currency,
    buyerEmail: session.customer_details?.email || session.customer_email,
    buyerName: session.customer_details?.name || null,
    partnerCode: md.link_partner_code || md.attributed_partner_code || null,
    objectId: session.id,
    stripePath: session.subscription
      ? `subscriptions/${session.subscription}`
      : session.customer
        ? `customers/${session.customer}`
        : "payments",
    livemode: session.livemode,
  });
}

/** promo_… id on a subscription's discount, if any (current and legacy shapes). */
async function promotionCodeIdOf(subscription) {
  const discounts = Array.isArray(subscription.discounts) ? subscription.discounts : [];
  for (const d of discounts) {
    const disc = typeof d === "string" ? null : d;
    const pc = disc?.promotion_code;
    if (pc) return typeof pc === "string" ? pc : pc.id;
  }
  const legacy = subscription.discount?.promotion_code;
  if (legacy) return typeof legacy === "string" ? legacy : legacy.id;
  return null;
}

async function recordInvoice(invoice) {
  const subscriptionId =
    invoice.parent?.subscription_details?.subscription ||
    invoice.subscription ||
    null;
  if (!subscriptionId) return null;
  return ledger.recordInvoicePaid({
    stripeInvoiceId: invoice.id,
    stripeSubscriptionId: String(subscriptionId),
    amountPaidMinor: Number(invoice.amount_paid || 0),
    currency: String(invoice.currency || "usd").toUpperCase(),
    paidAt: toMysqlDateTime(invoice.status_transitions?.paid_at || invoice.created),
  });
}

async function onSubscriptionChanged(subscription) {
  const item = subscription.items?.data?.[0];
  await pool.execute(
    `
      UPDATE referral_subscriptions
      SET status = ?, current_period_start = ?, current_period_end = ?, canceled_at = ?
      WHERE stripe_subscription_id = ?
    `,
    [
      String(subscription.status),
      toMysqlDateTime(item?.current_period_start ?? subscription.current_period_start),
      toMysqlDateTime(item?.current_period_end ?? subscription.current_period_end),
      toMysqlDateTime(subscription.canceled_at),
      subscription.id,
    ]
  );
}

async function onInvoicePaid(stripe, invoice) {
  const synced = await paymentTransactions.syncInvoice(stripe, invoice); // null: not ours
  await recordInvoice(invoice);

  // First invoices are announced by checkout.session.completed; renewals here.
  if (!synced || invoice.billing_reason === "subscription_create") return;
  if (invoice.billing_reason === "subscription_cycle") await paymentEmails.sendRenewalConfirmation(invoice);
  const subId = invoiceSubscriptionId(invoice);
  await paymentEmails.sendPaymentAlert({
    outcome: "success",
    kind: "Renewal paid",
    amountMinor: invoice.amount_paid,
    currency: invoice.currency,
    buyerEmail: invoice.customer_email,
    buyerName: invoice.customer_name,
    partnerCode: invoiceMetadata(invoice).attributed_partner_code || (await partnerCodeForSubscription(subId)),
    objectId: invoice.id,
    stripePath: `invoices/${invoice.id}`,
    livemode: invoice.livemode,
  });
}

async function onChargeRefunded(stripe, charge) {
  // Find the invoice for this charge, record the refund and reverse its
  // ledger entries. Charges no longer carry `invoice` (API 2025-03-31+), so
  // the link is looked up through the charge's PaymentIntent.
  let invoiceId = charge.invoice ? String(charge.invoice) : null;
  if (!invoiceId && charge.payment_intent) {
    invoiceId = await paymentTransactions.invoiceIdForPaymentIntent(stripe, charge.payment_intent);
  }
  if (!invoiceId) return;
  await paymentTransactions.syncInvoice(stripe, invoiceId);
  await ledger.reverseInvoice({ stripeInvoiceId: invoiceId, reason: `charge.refunded ${charge.id}` });
}

async function onTransferReversed(transfer) {
  // Only a full reversal un-pays the payout; a partial one is left for a
  // super_admin to reconcile by hand (rare, and money is involved).
  if (Number(transfer.amount_reversed || 0) < Number(transfer.amount || 0)) return;
  await pool.execute(
    `
      UPDATE payouts
      SET status = 'reversed', failure_reason = ?, updated_at = UTC_TIMESTAMP()
      WHERE stripe_transfer_id = ?
    `,
    [`reversed ${transfer.id}`, transfer.id]
  );
  await pool.execute(
    `
      UPDATE commission_entries ce
      JOIN payouts p ON p.id = ce.payout_id
      SET ce.status = 'pending', ce.payout_id = NULL, ce.updated_at = UTC_TIMESTAMP()
      WHERE p.stripe_transfer_id = ?
    `,
    [transfer.id]
  );
}

// ─── Endpoint ────────────────────────────────────────────────────────────────

/** webhook_events row for an event handled outside the main path. Never throws. */
async function recordEventSafe(event, status, error) {
  try {
    await pool.execute(
      `INSERT INTO webhook_events (event_id, type, status, error, processed_at)
       VALUES (?, ?, ?, ?, UTC_TIMESTAMP())
       ON DUPLICATE KEY UPDATE status = VALUES(status), error = VALUES(error), processed_at = VALUES(processed_at)`,
      [event.id, event.type, status, error ? String(error).slice(0, 2000) : null]
    );
  } catch (err) {
    console.warn("WEBHOOK_EVENT_RECORD_FAILED:", { event_id: event.id, code: err?.code, message: err?.message });
  }
}

/**
 * account.updated: the payee's account is saved to dietician_db and sales_crm
 * independently (connect.syncFromWebhook), so one database being down never
 * stops the other. It runs outside the webhook_events first-writer-wins check
 * because the save is an idempotent upsert of Stripe's current state and a
 * redelivery must re-run it. Answers 500 when either database was not written
 * so Stripe retries (up to 3 days in live mode) until both have it.
 */
async function handleAccountUpdated(event, res) {
  let result;
  try {
    result = await connect.syncFromWebhook(event.data.object);
  } catch (err) {
    console.error("STRIPE_WEBHOOK_ACCOUNT_SYNC_FAILED:", {
      event_id: event.id,
      account: event.data.object?.id,
      code: err?.code,
      message: err?.message,
    });
    await recordEventSafe(event, "error", `stripe: ${err?.message || "account read failed"}`);
    return res.status(500).json({ ok: false, retry: true });
  }

  const failed = [];
  if (!result.dieticianDb.ok) failed.push(`dietician_db: ${result.dieticianDb.reason}`);
  if (!result.salesCrm.ok) failed.push(`sales_crm: ${result.salesCrm.reason}`);

  // When dietician_db is the one that failed, recording there would fail too.
  if (result.dieticianDb.ok) {
    await recordEventSafe(event, failed.length ? "error" : "processed", failed.join("; ") || null);
  }

  if (failed.length) {
    console.error("STRIPE_WEBHOOK_ACCOUNT_SYNC_PARTIAL:", {
      event_id: event.id,
      account: event.data.object?.id,
      failed,
    });
    return res.status(500).json({ ok: false, retry: true });
  }
  return res.status(200).json({ ok: true });
}

const stripeWebhook = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  let stripe;
  try {
    stripe = requireStripe();
  } catch {
    return res.status(503).json({ ok: false, message: "Stripe not configured" });
  }

  if (!STRIPE_WEBHOOK_SECRET) {
    console.error("STRIPE_WEBHOOK_SECRET missing — refusing webhook");
    return res.status(503).json({ ok: false, message: "Webhook not configured" });
  }

  const signature = req.headers["stripe-signature"];
  const rawBody = req.rawBody;

  if (!signature || !rawBody || !rawBody.length) {
    return res.status(400).json({ ok: false, message: "Missing signature or body" });
  }

  // Main endpoint first, then the Connected-accounts one when configured.
  let event = null;
  let lastErr = null;
  for (const secret of [STRIPE_WEBHOOK_SECRET, STRIPE_CONNECT_WEBHOOK_SECRET]) {
    if (!secret) continue;
    try {
      event = stripe.webhooks.constructEvent(rawBody, signature, secret);
      break;
    } catch (err) {
      lastErr = err;
    }
  }
  if (!event) {
    console.warn("STRIPE_WEBHOOK_SIGNATURE_INVALID:", lastErr?.message);
    return res.status(400).json({ ok: false, message: "Invalid signature" });
  }

  if (event.account && event.type !== "account.updated") {
    return res.status(200).json({ ok: true, ignored: true });
  }

  if (event.type === "account.updated") {
    return handleAccountUpdated(event, res);
  }

  // Idempotency: first writer wins. A redelivered event is acknowledged only.
  const [ins] = await pool.execute(
    `INSERT IGNORE INTO webhook_events (event_id, type, status) VALUES (?, ?, 'received')`,
    [event.id, event.type]
  );
  if (!ins.affectedRows) {
    return res.status(200).json({ ok: true, duplicate: true });
  }

  try {
    const obj = event.data.object;
    switch (event.type) {
      case "checkout.session.completed":
        await onCheckoutSessionCompleted(stripe, obj);
        break;
      case "customer.subscription.created":
      case "customer.subscription.updated":
      case "customer.subscription.deleted":
        await onSubscriptionChanged(obj);
        break;
      case "invoice.paid":
        await onInvoicePaid(stripe, obj);
        break;
      case "payment_intent.payment_failed":
        await onPaymentIntentFailed(stripe, obj);
        break;
      case "invoice.payment_failed":
        await onInvoicePaymentFailed(stripe, obj);
        break;
      case "checkout.session.async_payment_failed":
        await onAsyncPaymentFailed(obj);
        break;
      case "charge.refunded":
        await onChargeRefunded(stripe, obj);
        break;
      case "transfer.reversed":
        await onTransferReversed(obj);
        break;
      default:
        break;
    }

    await pool.execute(
      `UPDATE webhook_events SET status = 'processed', processed_at = UTC_TIMESTAMP() WHERE event_id = ?`,
      [event.id]
    );
    return res.status(200).json({ ok: true });
  } catch (err) {
    // A MySQL error names the column but not the table; keep the statement
    // (first line, no bind values) so a schema drift between environments
    // can be located from webhook_events.error alone.
    const sqlSnippet = typeof err?.sql === "string" ? err.sql.replace(/\s+/g, " ").trim().slice(0, 600) : null;
    console.error("STRIPE_WEBHOOK_HANDLER_ERROR:", {
      event_id: event.id,
      type: event.type,
      code: err?.code,
      errno: err?.errno,
      message: err?.message,
      sql: sqlSnippet,
    });
    const errorText = sqlSnippet ? `${err.message} | sql: ${sqlSnippet}` : String(err?.message || "handler error");
    await pool.execute(
      `UPDATE webhook_events SET status = 'error', error = ?, processed_at = UTC_TIMESTAMP() WHERE event_id = ?`,
      [errorText.slice(0, 2000), event.id]
    );
    // 200: the event is stored; a super_admin can replay it once the bug is fixed.
    return res.status(200).json({ ok: false, recorded: true });
  }
};

module.exports = { stripeWebhook };
