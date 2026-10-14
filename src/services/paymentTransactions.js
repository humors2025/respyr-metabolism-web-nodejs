"use strict";

/**
 * Stripe payment records for website (/order) purchases.
 *
 *   payment_transactions             one row per Stripe invoice: the first
 *                                    payment, each renewal, failed attempts
 *                                    and refunds (migration 006)
 *   subscription_shipping_addresses  phone + shipping address collected on
 *                                    Checkout, one row per subscription
 *
 * Every write is an upsert keyed on a Stripe id, and each sync re-reads the
 * invoice from Stripe, so webhook redelivery or replay only refreshes a row.
 *
 * API 2026-08-26 (basil and later): an invoice no longer carries
 * payment_intent / charge, and a charge no longer carries invoice. Both
 * directions go through InvoicePayments.
 */

const pool = require("../config/db");
const { invoiceIsOurs } = require("./paymentEmails");
const salesCrm = require("./salesCrmMirror");

function toMysqlDateTime(unixSeconds) {
  if (unixSeconds == null) return null;
  return new Date(Number(unixSeconds) * 1000).toISOString().slice(0, 19).replace("T", " ");
}

function idOf(v) {
  if (!v) return null;
  return typeof v === "string" ? v : v.id || null;
}

function clip(v, max) {
  const s = v == null ? "" : String(v).trim();
  return s ? s.slice(0, max) : null;
}

// Production has chosen not to create the migration-006 tables. Their absence
// must not cost the buyer, the commission ledger or the sales_crm copy, so a
// missing table is logged once per container and the row is skipped (or, for
// a read, nothing is found). Any other database error still propagates.
const missingTableWarned = new Set();
function isMissingTable(err) {
  return err?.code === "ER_NO_SUCH_TABLE" || err?.errno === 1146;
}
async function optionalTable(table, run) {
  try {
    await run();
    return true;
  } catch (err) {
    if (!isMissingTable(err)) throw err;
    if (!missingTableWarned.has(table)) {
      missingTableWarned.add(table);
      console.warn("PAYMENT_TABLE_MISSING:", { table, note: "row skipped; run database/migrations/006 to store it" });
    }
    return false;
  }
}

/** Our subscription row (id, attribution, buyer) for a Stripe subscription, or null. */
async function referralSubscriptionFor(stripeSubscriptionId) {
  if (!stripeSubscriptionId) return null;
  const [rows] = await pool.execute(
    `SELECT id, attributed_partner_code, purchaser_email, purchaser_name
       FROM referral_subscriptions WHERE stripe_subscription_id = ? LIMIT 1`,
    [stripeSubscriptionId]
  );
  return rows[0] || null;
}

async function referralSubscriptionIdFor(stripeSubscriptionId) {
  const rs = await referralSubscriptionFor(stripeSubscriptionId);
  return rs ? Number(rs.id) : null;
}

/**
 * Shipping columns for the sales_crm copy of an invoice: the address saved
 * from Checkout (subscription_shipping_addresses), else Stripe's copy on the
 * invoice. All null when neither has one yet: invoice.paid can arrive before
 * checkout.session.completed, whose invoice backfill then fills them in.
 * Renewals carry the subscription's address too.
 */
async function shippingForSalesCrm(stripeSubscriptionId, invoice) {
  let saved = null;
  if (stripeSubscriptionId) {
    await optionalTable("subscription_shipping_addresses", async () => {
      const [rows] = await pool.execute(
        `SELECT name, phone, line1, line2, city, state, postal_code, country
           FROM subscription_shipping_addresses WHERE stripe_subscription_id = ? LIMIT 1`,
        [stripeSubscriptionId]
      );
      saved = rows[0] || null;
    });
  }
  const snap = invoice.customer_shipping || {};
  const a = saved || {
    name: snap.name,
    phone: snap.phone || invoice.customer_phone,
    ...(snap.address || {}),
  };

  const line1 = clip(a.line1, 255);
  const line2 = clip(a.line2, 255);
  const city = clip(a.city, 100);
  const state = clip(a.state, 100);
  const postalCode = clip(a.postal_code, 20);
  const country = clip(a.country, 2);
  // One line for the sales console: "915 W Price Rd, A, Brownsville, TX 78520, US".
  const oneLine = [line1, line2, city, [state, postalCode].filter(Boolean).join(" "), country]
    .filter(Boolean)
    .join(", ");
  return {
    shipping_address: oneLine || null,
    shipping_name: clip(a.name, 150),
    phone: clip(a.phone, 32),
    shipping_line1: line1,
    shipping_line2: line2,
    shipping_city: city,
    shipping_state: state,
    shipping_postal_code: postalCode,
    shipping_country: country,
  };
}

/** The invoice id a PaymentIntent paid, or null. */
async function invoiceIdForPaymentIntent(stripe, paymentIntentId) {
  if (!paymentIntentId) return null;
  const list = await stripe.invoicePayments.list({
    payment: { type: "payment_intent", payment_intent: String(paymentIntentId) },
    limit: 1,
  });
  return idOf(list.data[0]?.invoice);
}

/**
 * Upsert the payment_transactions row for one invoice, from Stripe's current
 * state. `failure` marks an invoice.payment_failed delivery (the invoice is
 * still 'open' then, so its status alone cannot say it failed).
 * Returns { invoice, status, failureMessage }, or null for invoices that are
 * not this programme's.
 */
async function syncInvoice(stripe, invoiceOrId, { failure = false } = {}) {
  const invoice = await stripe.invoices.retrieve(idOf(invoiceOrId), { expand: ["payments"] });
  if (!invoiceIsOurs(invoice)) return null;

  const subscriptionId = idOf(invoice.parent?.subscription_details?.subscription || invoice.subscription);
  const line = invoice.lines?.data?.[0];

  // The default payment is the one Stripe keeps in step with the invoice.
  const payments = invoice.payments?.data || [];
  const invoicePayment = payments.find((p) => p.is_default) || payments[0] || null;
  const paymentIntentId = idOf(invoicePayment?.payment?.payment_intent);

  let pi = null;
  let charge = null;
  if (paymentIntentId) {
    pi = await stripe.paymentIntents.retrieve(paymentIntentId, { expand: ["latest_charge.balance_transaction"] });
    charge = pi.latest_charge && typeof pi.latest_charge === "object" ? pi.latest_charge : null;
  }

  const currency = String(invoice.currency || "usd").toUpperCase();

  // Fee / net are in the platform's settlement currency. Only stored when that
  // matches the invoice currency, so the row never mixes currencies (with
  // Adaptive Pricing a buyer can pay in INR while Stripe settles in USD).
  const bt = charge?.balance_transaction && typeof charge.balance_transaction === "object" ? charge.balance_transaction : null;
  const sameCurrency = bt && String(bt.currency || "").toUpperCase() === currency;

  const refunded = Number(charge?.amount_refunded || 0);
  let status;
  if (invoice.status === "paid") {
    status = refunded <= 0 ? "paid" : charge?.refunded ? "refunded" : "partially_refunded";
  } else if (failure || invoice.status === "uncollectible") {
    status = "failed";
  } else {
    status = "open";
  }

  const pmDetails = charge?.payment_method_details || null;
  const failureMessage = status === "failed"
    ? clip(pi?.last_payment_error?.message || charge?.failure_message || "Payment failed", 500)
    : null;

  const rs = await referralSubscriptionFor(subscriptionId);

  await optionalTable("payment_transactions", () => pool.execute(
    `
      INSERT INTO payment_transactions (
        referral_subscription_id, stripe_subscription_id, stripe_customer_id,
        stripe_invoice_id, stripe_payment_intent_id, stripe_charge_id, billing_reason,
        period_start, period_end, amount_paid_minor, amount_refunded_minor, currency,
        fee_minor, net_minor, status, failure_message, payment_method_type, card_last4, paid_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        referral_subscription_id = COALESCE(VALUES(referral_subscription_id), referral_subscription_id),
        stripe_payment_intent_id = COALESCE(VALUES(stripe_payment_intent_id), stripe_payment_intent_id),
        stripe_charge_id         = COALESCE(VALUES(stripe_charge_id), stripe_charge_id),
        amount_paid_minor        = VALUES(amount_paid_minor),
        amount_refunded_minor    = VALUES(amount_refunded_minor),
        fee_minor                = COALESCE(VALUES(fee_minor), fee_minor),
        net_minor                = COALESCE(VALUES(net_minor), net_minor),
        status                   = VALUES(status),
        failure_message          = VALUES(failure_message),
        payment_method_type      = COALESCE(VALUES(payment_method_type), payment_method_type),
        card_last4               = COALESCE(VALUES(card_last4), card_last4),
        paid_at                  = COALESCE(VALUES(paid_at), paid_at)
    `,
    [
      rs ? Number(rs.id) : null,
      subscriptionId,
      idOf(invoice.customer),
      invoice.id,
      paymentIntentId,
      idOf(charge),
      clip(invoice.billing_reason, 32),
      toMysqlDateTime(line?.period?.start ?? invoice.period_start),
      toMysqlDateTime(line?.period?.end ?? invoice.period_end),
      Number(invoice.amount_paid || 0),
      refunded,
      currency,
      sameCurrency ? Number(bt.fee) : null,
      sameCurrency ? Number(bt.net) : null,
      status,
      failureMessage,
      clip(pmDetails?.type, 32),
      clip(pmDetails?.card?.last4, 4),
      toMysqlDateTime(invoice.status_transitions?.paid_at),
    ]
  ));

  // Sales team copy (sales_crm.stripe_payments). Best-effort: logs and moves
  // on, so a sales_crm problem can never cost the ledger or the buyer.
  const md = invoice.parent?.subscription_details?.metadata || invoice.subscription_details?.metadata || invoice.metadata || {};
  const purchaserEmail = clip(invoice.customer_email || rs?.purchaser_email, 255);
  const shipping = salesCrm.isEnabled() ? await shippingForSalesCrm(subscriptionId, invoice) : {};
  await salesCrm.upsertPayment({
    stripe_invoice_id: invoice.id,
    stripe_subscription_id: subscriptionId,
    stripe_customer_id: idOf(invoice.customer),
    stripe_payment_intent_id: paymentIntentId,
    stripe_charge_id: idOf(charge),
    livemode: !!invoice.livemode,
    purchaser_email: purchaserEmail ? purchaserEmail.toLowerCase() : null,
    purchaser_name: clip(invoice.customer_name || rs?.purchaser_name, 150),
    partner_code: clip(md.attributed_partner_code || rs?.attributed_partner_code, 50),
    billing_reason: clip(invoice.billing_reason, 32),
    period_start: toMysqlDateTime(line?.period?.start ?? invoice.period_start),
    period_end: toMysqlDateTime(line?.period?.end ?? invoice.period_end),
    amount_paid_minor: Number(invoice.amount_paid || 0),
    amount_refunded_minor: refunded,
    currency,
    fee_minor: sameCurrency ? Number(bt.fee) : null,
    net_minor: sameCurrency ? Number(bt.net) : null,
    status,
    failure_message: failureMessage,
    payment_method_type: clip(pmDetails?.type, 32),
    card_last4: clip(pmDetails?.card?.last4, 4),
    paid_at: toMysqlDateTime(invoice.status_transitions?.paid_at),
    ...shipping,
  });

  return { invoice: invoice.id, status, failureMessage };
}

/**
 * Phone + shipping address from a completed Checkout Session. Nothing is
 * written when the session collected neither. An existing row keeps any value
 * the new delivery lacks.
 */
async function saveShippingAddress({ session, stripeSubscriptionId }) {
  const ship = session.collected_information?.shipping_details || session.shipping_details || null;
  const addr = ship?.address || null;
  const phone = clip(session.customer_details?.phone, 32);
  if (!addr && !phone) return false;

  return optionalTable("subscription_shipping_addresses", async () => pool.execute(
    `
      INSERT INTO subscription_shipping_addresses (
        referral_subscription_id, stripe_subscription_id, stripe_checkout_session_id,
        name, phone, line1, line2, city, state, postal_code, country
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        referral_subscription_id   = COALESCE(VALUES(referral_subscription_id), referral_subscription_id),
        stripe_checkout_session_id = COALESCE(VALUES(stripe_checkout_session_id), stripe_checkout_session_id),
        name        = COALESCE(VALUES(name), name),
        phone       = COALESCE(VALUES(phone), phone),
        line1       = COALESCE(VALUES(line1), line1),
        line2       = COALESCE(VALUES(line2), line2),
        city        = COALESCE(VALUES(city), city),
        state       = COALESCE(VALUES(state), state),
        postal_code = COALESCE(VALUES(postal_code), postal_code),
        country     = COALESCE(VALUES(country), country)
    `,
    [
      await referralSubscriptionIdFor(stripeSubscriptionId),
      stripeSubscriptionId,
      clip(session.id, 255),
      clip(ship?.name || session.customer_details?.name, 150),
      phone,
      clip(addr?.line1, 255),
      clip(addr?.line2, 255),
      clip(addr?.city, 100),
      clip(addr?.state, 100),
      clip(addr?.postal_code, 20),
      clip(addr?.country, 2),
    ]
  ));
}

module.exports = { syncInvoice, saveShippingAddress, invoiceIdForPaymentIntent };
