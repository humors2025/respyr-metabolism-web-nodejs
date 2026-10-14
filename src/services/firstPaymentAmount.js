"use strict";

/**
 * What a member paid for their membership (first payment only), one rule for
 * every page that shows it, so the numbers agree:
 *   super-admin-sales-analytics   Sales analytics (gross / discount / net)
 *   super-admin-facility-people   Facilities > Active members (Price)
 *
 *   gross     list price charged (referral_subscriptions.unit_amount_minor)
 *   net       the first invoice's amount from commission_entries when that
 *             invoice was paid at checkout time; otherwise gross minus the
 *             referral coupon, which only applies when a promotion code or
 *             sticker was used
 *   discount  gross - net
 *
 * FIRST_PAYMENT_COLUMNS goes in the SELECT list of a query over
 * referral_subscriptions aliased `rs`; firstPaymentAmounts() reads the row it
 * returns (which must also carry rs.unit_amount_minor, rs.created_at,
 * rs.stripe_promotion_code_id and rs.qr_id).
 */

const FIRST_PAYMENT_COLUMNS = `
        (
          SELECT ps.list_price_minor - ps.referred_price_minor
          FROM partner_promotion_codes ppc
          JOIN pricing_settings ps ON ps.stripe_coupon_id = ppc.stripe_coupon_id
          WHERE ppc.stripe_promotion_code_id = rs.stripe_promotion_code_id
          ORDER BY ps.id DESC
          LIMIT 1
        ) AS coupon_off_minor,
        (
          -- Fallback when the coupon was replaced (pricing re-saved, e.g. after a
          -- Stripe account change): the referral discount in effect that day.
          SELECT ps.list_price_minor - ps.referred_price_minor
          FROM pricing_settings ps
          WHERE ps.effective_from <= rs.created_at
          ORDER BY ps.effective_from DESC, ps.id DESC
          LIMIT 1
        ) AS pricing_off_minor,
        (
          SELECT ce.stripe_invoice_id
          FROM commission_entries ce
          WHERE ce.stripe_subscription_id = rs.stripe_subscription_id
          ORDER BY ce.invoice_paid_at ASC, ce.id ASC
          LIMIT 1
        ) AS first_invoice_id,
        (
          SELECT ce.invoice_net_minor
          FROM commission_entries ce
          WHERE ce.stripe_subscription_id = rs.stripe_subscription_id
          ORDER BY ce.invoice_paid_at ASC, ce.id ASC
          LIMIT 1
        ) AS first_invoice_net_minor,
        (
          SELECT ce.invoice_paid_at
          FROM commission_entries ce
          WHERE ce.stripe_subscription_id = rs.stripe_subscription_id
          ORDER BY ce.invoice_paid_at ASC, ce.id ASC
          LIMIT 1
        ) AS first_invoice_paid_at`;

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toMs(v) {
  if (!v) return null;
  if (v instanceof Date) return v.getTime();
  const t = Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(t) ? null : t;
}

/**
 * { gross, discount, net, amountSource: "invoice" | "price", firstInvoiceId }
 * in minor units. firstInvoiceId is null unless the earliest ledger invoice is
 * the purchase itself.
 */
function firstPaymentAmounts(r) {
  // The referral coupon only exists when a promotion code or sticker was applied.
  const discounted = !!(r.stripe_promotion_code_id || r.qr_id);
  const gross = Number(r.unit_amount_minor) || 0;
  const couponOff =
    r.coupon_off_minor != null ? Math.max(0, Number(r.coupon_off_minor))
    : r.pricing_off_minor != null ? Math.max(0, Number(r.pricing_off_minor))
    : null;
  // The earliest ledger invoice is the purchase itself only if it was paid
  // at checkout time; a member attributed later has ledger rows for renewals only.
  const createdMs = toMs(r.created_at);
  const invoiceMs = toMs(r.first_invoice_paid_at);
  const isFirstPayment = invoiceMs != null && createdMs != null && Math.abs(invoiceMs - createdMs) <= 2 * 86400000;
  const invoiceNet = isFirstPayment && r.first_invoice_net_minor != null ? Number(r.first_invoice_net_minor) : null;

  let net;
  let discount;
  if (invoiceNet != null) {
    net = invoiceNet;
    discount = Math.max(0, gross - invoiceNet);
  } else {
    // A code or sticker at checkout always applies the referral coupon.
    discount = discounted ? Math.min(gross, couponOff ?? 0) : 0;
    net = Math.max(0, gross - discount);
  }

  return {
    gross,
    discount,
    net,
    amountSource: invoiceNet != null ? "invoice" : "price",
    firstInvoiceId: isFirstPayment ? r.first_invoice_id : null,
  };
}

module.exports = { FIRST_PAYMENT_COLUMNS, firstPaymentAmounts };
