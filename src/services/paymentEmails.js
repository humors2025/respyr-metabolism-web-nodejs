"use strict";

/**
 * Transactional emails for the order page checkout (Resend).
 *
 *   sendPaymentReceipt  — checkout.session.completed: "Payment received", with
 *                         the amount, plan, referral code used and next billing
 *                         date. The app purchase code goes out separately
 *                         (purchaseCodes.sendPurchaseCodeEmail).
 *   sendPaymentFailed   — payment_intent.payment_failed / invoice.payment_failed
 *                         / checkout.session.async_payment_failed: the decline
 *                         reason and a link back to the order page. Sent once
 *                         per PaymentIntent / invoice, not per retry.
 *
 * Each email goes through a published Resend template when its template ID is
 * configured (emails/resend/*.html — same mechanism as the invite email);
 * otherwise the same content is sent as inline HTML. Resend rejects a template
 * send that is missing any variable the template uses, so every variable is
 * always supplied ("—" / "" when there is nothing to show).
 *
 * Same sender rules as purchaseCodes.js: RESEND_FROM_EMAIL must be a verified
 * domain, SKIP_OUTBOUND_EMAIL short-circuits outside production.
 */

const axios = require("axios");
const pool = require("../config/db");
const { ORDER_CANCEL_URL, PLAN_CODE } = require("../config/stripe");
const { escapeHtml } = require("../utils/securityValidation");

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "Rysflo <no-reply@respyr.ai>";
const SKIP_OUTBOUND_EMAIL =
  process.env.NODE_ENV !== "production" && String(process.env.SKIP_OUTBOUND_EMAIL || "").toLowerCase() === "true";
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || "support@rysflo.com";

// Published Resend template IDs (or slugs). Unset → inline HTML fallback.
const TEMPLATE = {
  receipt: process.env.RESEND_PAYMENT_RECEIPT_TEMPLATE_ID || "",
  failed: process.env.RESEND_PAYMENT_FAILED_TEMPLATE_ID || "",
  renewal: process.env.RESEND_RENEWAL_FAILED_TEMPLATE_ID || "",
};

const APP_CODE_NOTE = "Your Rysflo Referral Code for the app is in a separate email — you'll need it when you create your account.";
const APP_LINKED_NOTE = "Open the Rysflo app and sign in with this email address — your purchase is already linked to your account.";

function money(minor, currency) {
  const cur = String(currency || "usd").toUpperCase();
  const n = Number(minor || 0) / 100;
  try {
    return new Intl.NumberFormat("en-US", { style: "currency", currency: cur }).format(n);
  } catch {
    return `${cur} ${n.toFixed(2)}`;
  }
}

function dateOf(unixSeconds) {
  if (unixSeconds == null) return null;
  return new Date(Number(unixSeconds) * 1000).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
}

// ── Inline fallbacks: same markup as emails/resend/*.html with the variables filled in ──

function shell(title, body) {
  return `
    <div style="font-family:Poppins,Arial,sans-serif;max-width:560px;margin:0 auto;color:#252525">
      <h2 style="margin:0 0 8px">${title}</h2>
      ${body}
      <p style="color:#A1A1A1;font-size:12px;margin-top:24px">Questions? Reply to this email or write to <a href="mailto:${SUPPORT_EMAIL}">${SUPPORT_EMAIL}</a>.</p>
    </div>`;
}

function row(label, value) {
  return `<tr><td style="padding:6px 16px;color:#535359">${label}</td><td style="padding:6px 16px;text-align:right;font-weight:600">${value}</td></tr>`;
}

function receiptHtml(v) {
  return shell(
    "Payment received — welcome to Rysflo",
    `
      <p style="color:#535359">Hi ${v.MEMBER_NAME}, thanks for your order. Your membership is active and your Rysflo device will ship to the address below.</p>
      <table style="width:100%;border-collapse:collapse;background:#F5F7FA;border-radius:10px;padding:12px 16px;margin:16px 0" cellpadding="0" cellspacing="0">
        ${row("Amount paid", v.AMOUNT_PAID)}
        ${row("Plan", v.PLAN)}
        ${row("Referral code", `<span style="font-family:monospace">${v.REFERRAL_CODE}</span>`)}
        ${row("Date", v.PAID_ON)}
        ${row("Next billing date", v.NEXT_BILLING_DATE)}
        ${row("Ships to", v.SHIP_TO)}
      </table>
      <p style="color:#535359">Every day you take a reading, 20¢ comes off next month's bill — up to $6.</p>
      <p style="color:#535359"><strong>Next step:</strong> ${v.APP_CODE_NOTE}</p>
    `
  );
}

function failedHtml(v) {
  return shell(
    "Your Rysflo payment didn't go through",
    `
      <p style="color:#535359">The payment of <strong>${v.AMOUNT}</strong> was not completed. Nothing has been charged.</p>
      <div style="background:#FFF4E0;color:#A66B00;padding:12px 16px;border-radius:10px;margin:16px 0">${v.REASON}</div>
      <p style="color:#535359">Please check the card details or try another card:</p>
      <p><a href="${v.RETRY_URL}" style="display:inline-block;background:#308BF9;color:#ffffff;text-decoration:none;font-weight:600;padding:12px 20px;border-radius:10px">Try again</a></p>
    `
  );
}

function renewalHtml(v) {
  return shell(
    "We couldn't renew your Rysflo membership",
    `
      <p style="color:#535359">This month's payment of <strong>${v.AMOUNT}</strong> was not completed. Nothing has been charged.</p>
      <div style="background:#FFF4E0;color:#A66B00;padding:12px 16px;border-radius:10px;margin:16px 0">${v.REASON}</div>
      <p style="color:#535359">Please update your card so your membership stays active — Stripe will retry automatically over the next few days.</p>
    `
  );
}

// ── Transport ────────────────────────────────────────────────────────────────

/**
 * Send via the Resend template when `templateId` is set (Resend rejects
 * html/text alongside `template`), else as inline HTML. `refId` goes in
 * X-Entity-Ref-ID so the recipient's client threads retries together.
 */
async function send({ to, subject, templateId, variables, html, kind, refId }) {
  if (!to) return { ok: false, reason: "no recipient" };
  if (SKIP_OUTBOUND_EMAIL) return { ok: true, skipped: true, dev: true };
  if (!RESEND_API_KEY) return { ok: false, reason: "RESEND_API_KEY not configured" };
  const body = {
    from: RESEND_FROM_EMAIL,
    to: [to],
    subject,
    ...(templateId ? { template: { id: templateId, variables } } : { html }),
    headers: { "X-Entity-Ref-ID": `payment-${refId}` },
    tags: [
      { name: "kind", value: kind },
      { name: "template_id", value: templateId || "inline" },
    ],
  };
  const res = await axios.post("https://api.resend.com/emails", body, {
    headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
    timeout: 15000,
    validateStatus: () => true,
  });
  if (res.status >= 200 && res.status < 300) return { ok: true, id: res.data?.id ?? null };
  const detail = res.data?.message || res.data?.name || "";
  return { ok: false, reason: `resend ${res.status}${detail ? `: ${detail}` : ""}` };
}

/**
 * One-shot guard keyed on the Stripe object (pi_… / in_… / cs_…). A card
 * declined three times in the same Checkout fires three events on the same
 * PaymentIntent; the member should hear about it once. Rides on the
 * webhook_events log (event_id is the PK) so no extra table is needed.
 */
async function claimOnce(kind, objectId) {
  const [ins] = await pool.execute(
    `INSERT IGNORE INTO webhook_events (event_id, type, status, processed_at) VALUES (?, ?, 'processed', UTC_TIMESTAMP())`,
    [`email:${kind}:${objectId}`.slice(0, 255), `email.${kind}`]
  );
  return ins.affectedRows > 0;
}

// ── Public ───────────────────────────────────────────────────────────────────

/**
 * Payment received. `session` is the completed Checkout Session, `subscription`
 * the retrieved subscription (for the next billing date), `partnerCode` the
 * referral code attributed to the sale, if any.
 */
async function sendPaymentReceipt({ session, subscription, partnerCode = null, purchaseCodeSent = false }) {
  const to = String(session.customer_details?.email || session.customer_email || "").trim().toLowerCase();
  if (!to) return { ok: false, reason: "no recipient" };
  if (!(await claimOnce("receipt", session.id))) return { ok: true, skipped: true };

  const item = subscription?.items?.data?.[0];
  const price = item?.price;
  const currency = session.currency || subscription?.currency || "usd";
  const ship = session.shipping_details?.address || session.collected_information?.shipping_details?.address || null;
  const shipLine = ship ? [ship.line1, ship.line2, ship.city, ship.state, ship.postal_code].filter(Boolean).join(", ") : "";
  const amount = money(session.amount_total, currency);

  const variables = {
    MEMBER_NAME: escapeHtml(String(session.customer_details?.name || "").trim() || "there"),
    AMOUNT_PAID: amount,
    PLAN: price?.unit_amount != null ? `Rysflo Membership · ${money(price.unit_amount, currency)}/month` : "Rysflo Membership",
    REFERRAL_CODE: partnerCode ? escapeHtml(partnerCode) : "—",
    PAID_ON: dateOf(session.created) || "—",
    NEXT_BILLING_DATE: dateOf(item?.current_period_end ?? subscription?.current_period_end) || "—",
    SHIP_TO: shipLine ? escapeHtml(shipLine) : "—",
    APP_CODE_NOTE: purchaseCodeSent ? APP_CODE_NOTE : APP_LINKED_NOTE,
    SUPPORT_EMAIL,
  };
  return send({
    to,
    subject: `Payment received — ${amount} for your Rysflo membership`,
    templateId: TEMPLATE.receipt,
    variables,
    html: receiptHtml(variables),
    kind: "payment_received",
    refId: session.id,
  });
}

/**
 * Payment failed. `to` is the member's email, `reason` Stripe's decline
 * message, `amountMinor`/`currency` what was attempted, `retryUrl` where to
 * try again, `objectId` the PaymentIntent / invoice / session (dedupe key).
 * `renewal` switches to the month-2+ wording (no retry link — Stripe retries).
 */
async function sendPaymentFailed({ to, reason, amountMinor, currency, retryUrl, objectId, renewal = false }) {
  const rcpt = String(to || "").trim().toLowerCase();
  if (!rcpt) return { ok: false, reason: "no recipient" };
  if (objectId && !(await claimOnce("failed", objectId))) return { ok: true, skipped: true };

  const variables = {
    AMOUNT: amountMinor != null ? money(amountMinor, currency) : "—",
    REASON: reason ? escapeHtml(String(reason).slice(0, 300)) : "Your card was declined.",
    SUPPORT_EMAIL,
  };
  if (renewal) {
    return send({
      to: rcpt,
      subject: "Action needed: your Rysflo renewal payment failed",
      templateId: TEMPLATE.renewal,
      variables,
      html: renewalHtml(variables),
      kind: "renewal_failed",
      refId: objectId || rcpt,
    });
  }
  variables.RETRY_URL = retryUrl || ORDER_CANCEL_URL;
  return send({
    to: rcpt,
    subject: "Your Rysflo payment didn't go through",
    templateId: TEMPLATE.failed,
    variables,
    html: failedHtml(variables),
    kind: "payment_failed",
    refId: objectId || rcpt,
  });
}

/** Order page URL to retry from, with the referral code preserved when known. */
function retryUrlFor(partnerCode) {
  return partnerCode ? `${ORDER_CANCEL_URL}/${encodeURIComponent(partnerCode)}` : ORDER_CANCEL_URL;
}

/** True when a Stripe invoice belongs to this programme (metadata stamped at checkout). */
function invoiceIsOurs(invoice) {
  const md = invoice?.parent?.subscription_details?.metadata || invoice?.subscription_details?.metadata || invoice?.metadata || {};
  return md.plan_code === PLAN_CODE;
}

module.exports = { sendPaymentReceipt, sendPaymentFailed, retryUrlFor, invoiceIsOurs };
