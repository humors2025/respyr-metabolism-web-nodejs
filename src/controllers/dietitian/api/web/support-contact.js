"use strict";

/**
 * POST /dietitian/api/web/support-contact                 (public — no JWT)
 *
 * The "Still need help?" form on rysflo.com/help. Emails the message to the
 * team (SUPPORT_CONTACT_EMAILS, default connect@humorstech.com) through Resend,
 * with Reply-To set to the visitor so the team can answer straight from the
 * inbox. Nothing is stored.
 *
 * Body (JSON, what the help page already sends):
 *  {
 *    "name":    "Jane Doe",            // required, ≤ 100
 *    "email":   "jane@example.com",    // required
 *    "order":   "RYS-00000",           // optional, ≤ 60
 *    "topic":   "device",              // one of TOPICS; anything else → "other"
 *    "message": "…",                   // required, ≤ 5000
 *    "page":    "https://rysflo.com/help/",  // optional, ≤ 300
 *    "website": ""                     // honeypot: bots fill it, people never see it
 *  }
 *
 * Response: 200 { ok: true } · 422 { ok: false, message } · 429 (rate limit)
 *           · 502 { ok: false } when Resend refuses, so the page shows its
 *           "please email us" fallback instead of a false "thanks".
 *
 * Abuse controls: supportContactRateLimiter (per IP and per sender email), the
 * honeypot (answered 200 so the bot learns nothing, but never sent), and every
 * visitor value is HTML-escaped and stripped of line breaks where it reaches a
 * header (subject).
 */

const axios = require("axios");
const { validateEmailAddress, escapeHtml } = require("../../../../utils/securityValidation");

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "Rysflo <no-reply@respyr.ai>";
const SKIP_OUTBOUND_EMAIL =
  process.env.NODE_ENV !== "production" && String(process.env.SKIP_OUTBOUND_EMAIL || "").toLowerCase() === "true";

// Team inboxes. Comma / semicolon / space separated. Unset → connect@humorstech.com.
const SUPPORT_CONTACT_EMAILS = [
  ...new Set(
    String(process.env.SUPPORT_CONTACT_EMAILS ?? "connect@humorstech.com")
      .split(/[,;\s]+/)
      .map((e) => e.trim().toLowerCase())
      .filter((e) => e.includes("@"))
  ),
];

// Same values and wording as the <select> on the help page.
const TOPICS = {
  device: "My device",
  reading: "Taking a reading",
  app: "App or account",
  billing: "Billing or plan",
  shipping: "Shipping, returns or warranty",
  other: "Something else",
};

const LIMITS = { name: 100, order: 60, message: 5000, page: 300 };

function text(value, max) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}

// For anything that ends up in a header: no CR/LF or other control characters.
function oneLine(value) {
  return value.replace(/[\x00-\x1f\x7f]+/g, " ").trim();
}

function row(label, value) {
  return `<tr><td style="padding:6px 16px;color:#535359;vertical-align:top;white-space:nowrap">${label}</td><td style="padding:6px 16px;font-weight:600">${value}</td></tr>`;
}

function messageHtml(v) {
  return `
    <div style="font-family:Poppins,Arial,sans-serif;max-width:600px;margin:0 auto;color:#252525">
      <h2 style="margin:0 0 8px">Help centre message — ${escapeHtml(v.topicLabel)}</h2>
      <p style="color:#535359;margin:0 0 16px">Sent from the rysflo.com help page. Reply to this email to answer ${escapeHtml(v.name)} directly.</p>
      <table style="width:100%;border-collapse:collapse;background:#F5F7FA;border-radius:10px;margin:16px 0" cellpadding="0" cellspacing="0">
        ${row("Name", escapeHtml(v.name))}
        ${row("Email", `<a href="mailto:${escapeHtml(v.email)}">${escapeHtml(v.email)}</a>`)}
        ${row("Order", v.order ? `<span style="font-family:monospace">${escapeHtml(v.order)}</span>` : "—")}
        ${row("Topic", escapeHtml(v.topicLabel))}
        ${row("Page", v.page ? escapeHtml(v.page) : "—")}
        ${row("Received", escapeHtml(v.receivedAt))}
      </table>
      <div style="white-space:pre-wrap;line-height:1.5;border-left:3px solid #308BF9;padding:4px 0 4px 14px">${escapeHtml(v.message)}</div>
    </div>`;
}

const supportContact = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  const body = req.body && typeof req.body === "object" ? req.body : {};

  // Honeypot: look successful, send nothing.
  if (typeof body.website === "string" && body.website.trim()) {
    console.warn("SUPPORT_CONTACT_HONEYPOT");
    return res.status(200).json({ ok: true });
  }

  const name = oneLine(text(body.name, LIMITS.name));
  const message = text(body.message, LIMITS.message);
  const order = oneLine(text(body.order, LIMITS.order));
  const page = oneLine(text(body.page, LIMITS.page));
  const topic = Object.prototype.hasOwnProperty.call(TOPICS, body.topic) ? body.topic : "other";
  const email = validateEmailAddress(body.email);

  if (!name || !message) {
    return res.status(422).json({ ok: false, message: "Please fill in your name, email and message." });
  }
  if (!email.ok) {
    return res.status(422).json({ ok: false, message: "That email address does not look right." });
  }

  if (!SUPPORT_CONTACT_EMAILS.length) {
    console.error("SUPPORT_CONTACT_NOT_SENT", { reason: "SUPPORT_CONTACT_EMAILS is empty" });
    return res.status(503).json({ ok: false, message: "Messages are not being accepted right now." });
  }
  if (SKIP_OUTBOUND_EMAIL) return res.status(200).json({ ok: true, dev: true });
  if (!RESEND_API_KEY) {
    console.error("SUPPORT_CONTACT_NOT_SENT", { reason: "RESEND_API_KEY not configured" });
    return res.status(502).json({ ok: false, message: "That did not send." });
  }

  const v = {
    name,
    email: email.value,
    order,
    topic,
    topicLabel: TOPICS[topic],
    message,
    page,
    receivedAt: new Date().toUTCString(),
  };
  const subject = `Help centre — ${v.topicLabel} — ${name}${order ? ` (${order})` : ""}`;

  try {
    const r = await axios.post(
      "https://api.resend.com/emails",
      {
        from: RESEND_FROM_EMAIL,
        to: SUPPORT_CONTACT_EMAILS,
        reply_to: v.email,
        subject: subject.slice(0, 200),
        html: messageHtml(v),
        tags: [
          { name: "kind", value: "support_contact" },
          { name: "topic", value: topic },
        ],
      },
      {
        headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
        timeout: 15000,
        validateStatus: () => true,
      }
    );
    if (r.status >= 200 && r.status < 300) {
      console.log("SUPPORT_CONTACT_SENT", { id: r.data?.id ?? null, topic });
      return res.status(200).json({ ok: true });
    }
    console.error("SUPPORT_CONTACT_NOT_SENT", { reason: `resend ${r.status}`, detail: r.data?.message || r.data?.name || "" });
  } catch (err) {
    console.error("SUPPORT_CONTACT_NOT_SENT", { reason: err.message });
  }
  return res.status(502).json({ ok: false, message: "That did not send." });
};

module.exports = { supportContact, _messageHtml: messageHtml };
