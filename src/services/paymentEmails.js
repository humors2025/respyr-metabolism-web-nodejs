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
 *   sendRenewalConfirmation — invoice.paid for a renewal (month 2+): "Your
 *                         membership has been renewed", with the amount, plan,
 *                         renewal date and next billing date. Never throws.
 *   sendPaymentAlert    — internal copy of every attempt, success or failure,
 *                         to the team (PAYMENT_ALERT_EMAILS, default
 *                         connect@humorstech.com): outcome, amount, buyer, referral
 *                         code, decline reason and a Stripe Dashboard link.
 *                         Inline HTML only; never throws, so a Resend problem
 *                         cannot cost the buyer their receipt or code.
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

// Team inboxes for the per-attempt payment alert. Comma / semicolon / space
// separated. Unset → connect@humorstech.com; set to an empty string to turn it off.
const PAYMENT_ALERT_EMAILS = [
  ...new Set(
    String(process.env.PAYMENT_ALERT_EMAILS ?? "connect@humorstech.com")
      .split(/[,;\s]+/)
      .map((e) => e.trim().toLowerCase())
      .filter((e) => e.includes("@"))
  ),
];

// Published Resend template IDs (or slugs). Unset → inline HTML fallback.
const TEMPLATE = {
  receipt: process.env.RESEND_PAYMENT_RECEIPT_TEMPLATE_ID || "",
  failed: process.env.RESEND_PAYMENT_FAILED_TEMPLATE_ID || "",
  renewal: process.env.RESEND_RENEWAL_FAILED_TEMPLATE_ID || "",
  // "Membership Renewal Confirmation", designed in Resend, so it defaults to
  // that template's ID; an empty env value sends the inline HTML instead.
  renewalPaid: process.env.RESEND_RENEWAL_CONFIRMATION_TEMPLATE_ID ?? "448aa7e5-46bf-4fbb-99f2-05c9ac638a4e",
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
      <p style="color:#535359">Every breath test you take knocks 20¢ off next month's bill — up to $6.</p>
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

function renewalPaidHtml(v) {
  return shell(
    "Your Rysflo membership has been renewed",
    `
      <p style="color:#535359">Hi ${v.customer_name}, thanks for continuing with Rysflo. Your renewal payment went through and your membership remains active.</p>
      <table style="width:100%;border-collapse:collapse;background:#F5F7FA;border-radius:10px;padding:12px 16px;margin:16px 0" cellpadding="0" cellspacing="0">
        ${row("Amount paid", v.amount_paid)}
        ${row("Membership plan", v.plan_name)}
        ${row("Account email", v.customer_email)}
        ${row("Renewal date", v.renewal_date)}
        ${row("Next billing date", v.next_billing_date)}
      </table>
      <p style="color:#535359">Every breath test you take knocks 20¢ off next month's bill — up to $6.</p>
      <p style="color:#535359">No action is needed: keep using your Rysflo device and app as usual.</p>
    `
  );
}

const ALERT_STYLE = {
  SUCCESS: { bg: "#E6F7EE", fg: "#1B7F4D" },
  FAILED: { bg: "#FDECEC", fg: "#B42318" },
  PENDING: { bg: "#FFF4E0", fg: "#A66B00" },
};

/** Internal alert: no customer wording, no support footer. */
function alertHtml(v) {
  const c = ALERT_STYLE[v.OUTCOME] || ALERT_STYLE.PENDING;
  return `
    <div style="font-family:Poppins,Arial,sans-serif;max-width:560px;margin:0 auto;color:#252525">
      <p style="margin:0 0 12px">
        <span style="display:inline-block;padding:4px 10px;border-radius:999px;font-weight:600;font-size:12px;background:${c.bg};color:${c.fg}">${v.OUTCOME}</span>
        &nbsp;<strong>${v.KIND}</strong>${v.MODE === "Test" ? ` &nbsp;<span style="color:#A66B00;font-size:12px">TEST MODE</span>` : ""}
      </p>
      <table style="width:100%;border-collapse:collapse;background:#F5F7FA;border-radius:10px;margin:0 0 16px" cellpadding="0" cellspacing="0">
        ${row("Amount", v.AMOUNT)}
        ${row("Buyer", v.BUYER)}
        ${row("Email", v.EMAIL)}
        ${row("Referral code", `<span style="font-family:monospace">${v.REFERRAL_CODE}</span>`)}
        ${v.OUTCOME === "SUCCESS" ? "" : row("Reason", v.REASON)}
        ${row("When", v.WHEN)}
        ${row("Stripe object", `<span style="font-family:monospace;font-size:12px">${v.OBJECT_ID}</span>`)}
      </table>
      <p style="margin:0"><a href="${v.STRIPE_URL}" style="display:inline-block;background:#308BF9;color:#ffffff;text-decoration:none;font-weight:600;padding:10px 18px;border-radius:10px">Open in Stripe</a></p>
    </div>`;
}

// ── Transport ────────────────────────────────────────────────────────────────

/**
 * Send via the Resend template when `templateId` is set (Resend rejects
 * html/text alongside `template`), else as inline HTML. `refId` goes in
 * X-Entity-Ref-ID so the recipient's client threads retries together.
 */
async function send({ to, subject, templateId, variables, html, kind, refId }) {
  const recipients = (Array.isArray(to) ? to : [to]).filter(Boolean);
  if (!recipients.length) return { ok: false, reason: "no recipient" };
  if (SKIP_OUTBOUND_EMAIL) return { ok: true, skipped: true, dev: true };
  if (!RESEND_API_KEY) return { ok: false, reason: "RESEND_API_KEY not configured" };
  const body = {
    from: RESEND_FROM_EMAIL,
    to: recipients,
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

/**
 * Renewal paid. `invoice` is the paid renewal invoice from the invoice.paid
 * event (billing_reason subscription_cycle). Buyer email and name come from
 * the invoice, else from the purchase (referral_subscriptions). Sent once per
 * invoice.
 *
 * The Resend template's variables are lower-case and in double braces, so
 * Resend escapes them itself: they go in raw, and only the inline copy is
 * escaped here. If the template send is refused (not published, a variable
 * not created on it) the inline copy goes out instead, so the member still
 * hears about it. Never throws: the webhook must still record the payment.
 */
async function sendRenewalConfirmation(invoice) {
  try {
    if (!invoice?.id) return { ok: false, reason: "no invoice" };
    const sub = invoice.parent?.subscription_details?.subscription || invoice.subscription || null;
    const subId = sub ? (typeof sub === "string" ? sub : sub.id) : null;

    let to = String(invoice.customer_email || "").trim().toLowerCase();
    let name = String(invoice.customer_name || "").trim();
    if ((!to || !name) && subId) {
      const [rows] = await pool.execute(
        `SELECT purchaser_email, purchaser_name FROM referral_subscriptions WHERE stripe_subscription_id = ? LIMIT 1`,
        [subId]
      );
      to = to || String(rows[0]?.purchaser_email || "").trim().toLowerCase();
      name = name || String(rows[0]?.purchaser_name || "").trim();
    }
    if (!to) return { ok: false, reason: "no recipient" };
    if (!(await claimOnce("renewal_paid", invoice.id))) return { ok: true, skipped: true };

    // The subscription line covers the period just paid for; its end is the
    // next billing date (invoice.period_end is the previous period).
    const line = (invoice.lines?.data || []).find((l) => l?.period?.end) || null;
    const variables = {
      customer_name: name || "there",
      customer_email: to,
      amount_paid: money(invoice.amount_paid, invoice.currency),
      plan_name: "Rysflo Monthly Membership",
      renewal_date: dateOf(invoice.status_transitions?.paid_at ?? invoice.created) || "—",
      next_billing_date: dateOf(line?.period?.end) || "—",
    };
    const escaped = Object.fromEntries(Object.entries(variables).map(([k, v]) => [k, escapeHtml(v)]));
    const message = {
      to,
      subject: `Your Rysflo membership has been renewed — ${variables.amount_paid}`,
      variables,
      html: renewalPaidHtml(escaped),
      kind: "renewal_paid",
      refId: invoice.id,
    };

    let res = await send({ ...message, templateId: TEMPLATE.renewalPaid });
    if (!res.ok && TEMPLATE.renewalPaid && RESEND_API_KEY) {
      console.warn("RENEWAL_CONFIRMATION_TEMPLATE_FAILED:", { invoice: invoice.id, reason: res.reason });
      res = await send({ ...message, templateId: "" });
    }
    if (!res.ok) console.warn("RENEWAL_CONFIRMATION_EMAIL_NOT_SENT:", { invoice: invoice.id, reason: res.reason });
    return res;
  } catch (err) {
    console.warn("RENEWAL_CONFIRMATION_EMAIL_NOT_SENT:", { invoice: invoice?.id, reason: err?.message });
    return { ok: false, reason: err?.message || "renewal confirmation failed" };
  }
}

/**
 * Internal alert to the team for one payment attempt.
 *   outcome     "success" | "failed" | "pending" (delayed payment method)
 *   kind        short label: "New purchase", "Renewal", "Checkout card declined"…
 *   objectId    Stripe object this is about (cs_/pi_/in_). With `outcome` it
 *               is the dedupe key, so a renewal that fails and then succeeds
 *               produces one FAILED and one SUCCESS alert, never two of either.
 *   dedupeKey   overrides objectId as the dedupe key (e.g. invoice + attempt
 *               number, so every dunning retry is reported once).
 *   stripePath  Dashboard path after the mode prefix, e.g. "payments/pi_…".
 * Never throws: a failure here is logged as PAYMENT_ALERT_EMAIL_NOT_SENT.
 */
async function sendPaymentAlert({ outcome, kind, amountMinor, currency, buyerEmail, buyerName, partnerCode, reason, objectId, dedupeKey, stripePath, livemode }) {
  if (!PAYMENT_ALERT_EMAILS.length) return { ok: true, skipped: true, reason: "no recipients" };
  try {
    const OUTCOME = outcome === "success" ? "SUCCESS" : outcome === "pending" ? "PENDING" : "FAILED";
    const key = dedupeKey || objectId;
    if (key && !(await claimOnce(`alert_${OUTCOME.toLowerCase()}`, key))) return { ok: true, skipped: true };

    const amount = amountMinor != null ? money(amountMinor, currency) : "—";
    const email = String(buyerEmail || "").trim().toLowerCase();
    const mode = livemode === false ? "Test" : "Live";
    const variables = {
      OUTCOME,
      KIND: escapeHtml(String(kind || "Payment")),
      AMOUNT: amount,
      BUYER: escapeHtml(String(buyerName || "").trim() || "—"),
      EMAIL: email ? escapeHtml(email) : "—",
      REFERRAL_CODE: partnerCode ? escapeHtml(String(partnerCode)) : "—",
      REASON: escapeHtml(String(reason || "Card declined").slice(0, 300)),
      WHEN: `${new Date().toISOString().slice(0, 19).replace("T", " ")} UTC`,
      MODE: mode,
      OBJECT_ID: escapeHtml(String(objectId || "—")),
      STRIPE_URL: `https://dashboard.stripe.com/${mode === "Test" ? "test/" : ""}${stripePath || "payments"}`,
    };
    const res = await send({
      to: PAYMENT_ALERT_EMAILS,
      subject: `[Rysflo] Payment ${OUTCOME} · ${amount} · ${email || "unknown buyer"}${mode === "Test" ? " (test)" : ""}`,
      html: alertHtml(variables),
      kind: `alert_${OUTCOME.toLowerCase()}`,
      refId: `alert-${objectId || Date.now()}`,
    });
    if (!res.ok) console.warn("PAYMENT_ALERT_EMAIL_NOT_SENT:", { object: objectId, reason: res.reason });
    return res;
  } catch (err) {
    console.warn("PAYMENT_ALERT_EMAIL_NOT_SENT:", { object: objectId, reason: err?.message });
    return { ok: false, reason: err?.message || "alert failed" };
  }
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

module.exports = { sendPaymentReceipt, sendPaymentFailed, sendRenewalConfirmation, sendPaymentAlert, retryUrlFor, invoiceIsOurs };
