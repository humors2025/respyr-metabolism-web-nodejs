"use strict";

/**
 * sales_invoices — the revenue record behind Super Admin Sales Analytics.
 *
 * One row per Stripe invoice of a membership subscription (first payment and
 * every renewal), written from the Stripe webhook and from a backfill that
 * reads Stripe directly (syncFromStripe). The commission ledger only records
 * invoices that earn commission; this table records all of them, including
 * website (no-code) sales, failures and refunds.
 *
 * The webhook uses the *Safe wrappers: a problem here (e.g. the table has not
 * been created yet in an environment) is logged and swallowed so it can never
 * cost a buyer their subscription row, purchase code or emails.
 */

const pool = require("../config/db");

function toMysqlDateTime(unixSeconds) {
  if (unixSeconds == null) return null;
  return new Date(Number(unixSeconds) * 1000).toISOString().slice(0, 19).replace("T", " ");
}

function idOf(v) {
  if (!v) return null;
  return typeof v === "string" ? v : v.id || null;
}

function subscriptionIdOf(invoice) {
  return idOf(invoice?.parent?.subscription_details?.subscription) || idOf(invoice?.subscription) || null;
}

// Current API: the payment intent sits on invoice.payments (when expanded or
// included); older API versions had invoice.payment_intent.
function paymentIntentIdOf(invoice) {
  const payments = invoice?.payments?.data || [];
  const chosen = payments.find((p) => p.status === "paid") || payments.find((p) => p.is_default) || payments[0];
  return idOf(chosen?.payment?.payment_intent) || idOf(invoice?.payment_intent) || null;
}

function discountOf(invoice) {
  const list = Array.isArray(invoice?.total_discount_amounts) ? invoice.total_discount_amounts : [];
  return list.reduce((sum, d) => sum + (Number(d?.amount) || 0), 0);
}

async function recordPaid(invoice) {
  const subscriptionId = subscriptionIdOf(invoice);
  if (!invoice?.id || !subscriptionId) return { recorded: false, reason: "no_subscription" };

  const [res] = await pool.execute(
    `
      INSERT INTO sales_invoices (
        stripe_invoice_id, stripe_subscription_id, stripe_customer_id, stripe_payment_intent_id,
        billing_reason, status, currency, subtotal_minor, discount_minor, amount_paid_minor, paid_at
      ) VALUES (?, ?, ?, ?, ?, 'paid', ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        stripe_customer_id       = COALESCE(VALUES(stripe_customer_id), stripe_customer_id),
        stripe_payment_intent_id = COALESCE(VALUES(stripe_payment_intent_id), stripe_payment_intent_id),
        billing_reason           = COALESCE(VALUES(billing_reason), billing_reason),
        status                   = IF(status IN ('refunded', 'partially_refunded'), status, 'paid'),
        currency                 = VALUES(currency),
        subtotal_minor           = VALUES(subtotal_minor),
        discount_minor           = VALUES(discount_minor),
        amount_paid_minor        = VALUES(amount_paid_minor),
        paid_at                  = VALUES(paid_at)
    `,
    [
      invoice.id,
      subscriptionId,
      idOf(invoice.customer),
      paymentIntentIdOf(invoice),
      invoice.billing_reason || null,
      String(invoice.currency || "usd").toUpperCase(),
      Number(invoice.subtotal || 0),
      discountOf(invoice),
      Number(invoice.amount_paid || 0),
      toMysqlDateTime(invoice.status_transitions?.paid_at || invoice.created),
    ]
  );
  return { recorded: res.affectedRows > 0 };
}

/** A payment attempt failed. Never downgrades an invoice that is already paid. */
async function recordFailed(invoice, failedAtUnix) {
  const subscriptionId = subscriptionIdOf(invoice);
  if (!invoice?.id || !subscriptionId) return { recorded: false, reason: "no_subscription" };

  const [res] = await pool.execute(
    `
      INSERT INTO sales_invoices (
        stripe_invoice_id, stripe_subscription_id, stripe_customer_id, billing_reason,
        status, currency, subtotal_minor, discount_minor, amount_paid_minor, failed_at
      ) VALUES (?, ?, ?, ?, 'failed', ?, ?, ?, 0, ?)
      ON DUPLICATE KEY UPDATE
        failed_at = IF(status = 'failed', VALUES(failed_at), failed_at)
    `,
    [
      invoice.id,
      subscriptionId,
      idOf(invoice.customer),
      invoice.billing_reason || null,
      String(invoice.currency || "usd").toUpperCase(),
      Number(invoice.subtotal || 0),
      discountOf(invoice),
      toMysqlDateTime(failedAtUnix || invoice.created),
    ]
  );
  return { recorded: res.affectedRows > 0 };
}

/** Sets the refunded total of an invoice's payment (Stripe reports it cumulatively). */
async function recordRefund({ stripeInvoiceId, amountRefundedMinor, refundedAtUnix }) {
  if (!stripeInvoiceId) return { recorded: false };
  const refunded = Math.max(0, Number(amountRefundedMinor) || 0);
  if (!refunded) return { recorded: false };
  const [res] = await pool.execute(
    `
      UPDATE sales_invoices
      SET amount_refunded_minor = LEAST(amount_paid_minor, ?),
          status = IF(? >= amount_paid_minor, 'refunded', 'partially_refunded'),
          refunded_at = COALESCE(?, refunded_at, UTC_TIMESTAMP())
      WHERE stripe_invoice_id = ?
        AND status IN ('paid', 'refunded', 'partially_refunded')
    `,
    [refunded, refunded, toMysqlDateTime(refundedAtUnix), stripeInvoiceId]
  );
  return { recorded: res.affectedRows > 0 };
}

/** Invoice id for a payment intent (charges no longer carry `invoice`). */
async function invoiceIdForPaymentIntent(stripe, paymentIntentId) {
  if (!paymentIntentId) return null;
  const list = await stripe.invoicePayments.list({
    payment: { type: "payment_intent", payment_intent: String(paymentIntentId) },
    limit: 1,
  });
  return idOf(list.data[0]?.invoice);
}

// ─── Webhook-safe wrappers ───────────────────────────────────────────────────

let warnedMissingTable = false;

function safe(fn, label) {
  return async (...args) => {
    try {
      return await fn(...args);
    } catch (err) {
      if (err?.code === "ER_NO_SUCH_TABLE") {
        if (!warnedMissingTable) {
          console.warn("SALES_INVOICES_TABLE_MISSING: run database/migrations/006_sales_invoices.sql");
          warnedMissingTable = true;
        }
      } else {
        console.error("SALES_INVOICES_WRITE_FAILED:", { step: label, code: err?.code, message: err?.message });
      }
      return null;
    }
  };
}

// ─── Backfill from Stripe ────────────────────────────────────────────────────

/**
 * Reads every invoice (and refund) of a batch of referral_subscriptions from
 * Stripe and upserts them. Batched so one call stays well inside the API
 * Gateway timeout; the caller loops on next_offset until it is null.
 */
async function syncFromStripe(stripe, { offset = 0, batchSize = 15 } = {}) {
  const safeOffset = Math.max(0, Math.trunc(Number(offset) || 0));
  const safeBatch = Math.max(1, Math.min(50, Math.trunc(Number(batchSize) || 15)));

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM referral_subscriptions`);
  const [subs] = await pool.query(
    `SELECT stripe_subscription_id, stripe_customer_id FROM referral_subscriptions ORDER BY id ASC LIMIT ${safeBatch} OFFSET ${safeOffset}`
  );

  let paid = 0;
  let failed = 0;
  let refunds = 0;

  for (const sub of subs) {
    const piToInvoice = new Map();

    for await (const inv of stripe.invoices.list({
      subscription: sub.stripe_subscription_id,
      limit: 100,
      expand: ["data.payments"],
    })) {
      if (inv.status === "paid") {
        await recordPaid(inv);
        paid += 1;
        const pi = paymentIntentIdOf(inv);
        if (pi) piToInvoice.set(pi, inv.id);
      } else if ((inv.status === "open" || inv.status === "uncollectible") && Number(inv.attempt_count) > 0) {
        await recordFailed(inv, inv.created);
        failed += 1;
      }
    }

    if (sub.stripe_customer_id && piToInvoice.size) {
      for await (const ch of stripe.charges.list({ customer: sub.stripe_customer_id, limit: 100 })) {
        if (!(Number(ch.amount_refunded) > 0)) continue;
        const pi = idOf(ch.payment_intent);
        const invoiceId = piToInvoice.get(pi);
        if (!invoiceId) continue;
        const latestRefund = ch.refunds?.data?.[0]?.created || ch.created;
        await recordRefund({ stripeInvoiceId: invoiceId, amountRefundedMinor: ch.amount_refunded, refundedAtUnix: latestRefund });
        refunds += 1;
      }
    }
  }

  const next = safeOffset + subs.length;
  return {
    subscriptions_total: Number(total),
    subscriptions_processed: next,
    next_offset: next < Number(total) && subs.length ? next : null,
    invoices_paid: paid,
    invoices_failed: failed,
    refunds,
  };
}

module.exports = {
  recordPaid,
  recordFailed,
  recordRefund,
  invoiceIdForPaymentIntent,
  syncFromStripe,
  recordPaidSafe: safe(recordPaid, "paid"),
  recordFailedSafe: safe(recordFailed, "failed"),
  recordRefundSafe: safe(recordRefund, "refund"),
};
