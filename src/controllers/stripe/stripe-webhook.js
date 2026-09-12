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
 *   customer.subscription.*      -> keep status / period in sync
 *   invoice.paid                 -> commission_entries (the ledger)
 *   charge.refunded              -> reverse ledger entries for that invoice
 *   account.updated              -> partner_payout_accounts status
 *   transfer.reversed            -> payouts + ledger entries reversed
 *   (a Transfer settles synchronously on create; there is no transfer.paid)
 *
 * Anything else is acknowledged and ignored. Always returns 200 once the event
 * is recorded, even if handling failed — Stripe retries are not useful for a
 * bug; the error is logged and visible for a super_admin to replay.
 */

const pool = require("../../config/db");
const { requireStripe, STRIPE_WEBHOOK_SECRET, STRIPE_TERM_MONTHS, PLAN_CODE } = require("../../config/stripe");
const ledger = require("../../services/commissionLedger");
const connect = require("../../services/stripeConnectAccounts");

function toMysqlDateTime(unixSeconds) {
  if (unixSeconds == null) return null;
  return new Date(Number(unixSeconds) * 1000).toISOString().slice(0, 19).replace("T", " ");
}

function lower(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : null;
}

// ─── Event handlers ──────────────────────────────────────────────────────────

async function onCheckoutSessionCompleted(stripe, session) {
  if (session.mode !== "subscription" || !session.subscription) return;

  const subscription = await stripe.subscriptions.retrieve(String(session.subscription));
  const item = subscription.items?.data?.[0];
  const price = item?.price;
  const md = subscription.metadata || session.metadata || {};

  const purchaserEmail = lower(session.customer_details?.email || session.customer_email);

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
        purchaser_email, profile_id,
        attributed_partner_code, attributed_user_id, attributed_role, facility_id,
        plan_code, price_id, currency, unit_amount_minor, status,
        current_period_start, current_period_end
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        stripe_checkout_session_id = VALUES(stripe_checkout_session_id),
        purchaser_email = COALESCE(purchaser_email, VALUES(purchaser_email)),
        profile_id      = COALESCE(profile_id, VALUES(profile_id)),
        status          = VALUES(status),
        current_period_start = VALUES(current_period_start),
        current_period_end   = VALUES(current_period_end)
    `,
    [
      subscription.id,
      String(subscription.customer),
      session.id,
      purchaserEmail,
      profileId,
      md.attributed_partner_code || null,
      md.attributed_user_id || null,
      md.attributed_role || null,
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
  if (!subscription.schedule) {
    const schedule = await stripe.subscriptionSchedules.create(
      { from_subscription: subscription.id },
      { idempotencyKey: `sched-create-${subscription.id}` }
    );
    const phase = schedule.phases[0];
    await stripe.subscriptionSchedules.update(
      schedule.id,
      {
        end_behavior: "release",
        phases: [
          {
            items: phase.items.map((i) => ({ price: i.price, quantity: i.quantity })),
            start_date: phase.start_date,
            iterations: STRIPE_TERM_MONTHS,
            metadata: md,
          },
        ],
      },
      { idempotencyKey: `sched-term-${subscription.id}` }
    );
    await pool.execute(
      `UPDATE referral_subscriptions SET stripe_schedule_id = ? WHERE stripe_subscription_id = ?`,
      [schedule.id, subscription.id]
    );
  }

  // Stripe does not order events: invoice.paid for the first invoice usually
  // arrives before this one and found no subscription to attribute. Backfill
  // any paid invoices now — the ledger's unique key makes this idempotent.
  const paid = await stripe.invoices.list({
    subscription: subscription.id,
    status: "paid",
    limit: 12,
  });
  for (const inv of paid.data) {
    await recordInvoice(inv);
  }
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

async function onInvoicePaid(invoice) {
  await recordInvoice(invoice);
}

async function onChargeRefunded(stripe, charge) {
  // Find the invoice for this charge and reverse its ledger entries.
  let invoiceId = charge.invoice ? String(charge.invoice) : null;
  if (!invoiceId && charge.payment_intent) {
    const invoices = await stripe.invoices.list({ payment_intent: String(charge.payment_intent), limit: 1 });
    invoiceId = invoices.data[0]?.id || null;
  }
  if (!invoiceId) return;
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

  let event;
  try {
    event = stripe.webhooks.constructEvent(rawBody, signature, STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.warn("STRIPE_WEBHOOK_SIGNATURE_INVALID:", err?.message);
    return res.status(400).json({ ok: false, message: "Invalid signature" });
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
        await onInvoicePaid(obj);
        break;
      case "charge.refunded":
        await onChargeRefunded(stripe, obj);
        break;
      case "account.updated":
        await connect.syncAccountFromStripeObject(obj);
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
    console.error("STRIPE_WEBHOOK_HANDLER_ERROR:", {
      event_id: event.id,
      type: event.type,
      code: err?.code,
      message: err?.message,
    });
    await pool.execute(
      `UPDATE webhook_events SET status = 'error', error = ?, processed_at = UTC_TIMESTAMP() WHERE event_id = ?`,
      [String(err?.message || "handler error").slice(0, 2000), event.id]
    );
    // 200: the event is stored; a super_admin can replay it once the bug is fixed.
    return res.status(200).json({ ok: false, recorded: true });
  }
};

module.exports = { stripeWebhook };
