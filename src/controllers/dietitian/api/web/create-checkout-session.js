"use strict";

/**
 * POST /dietitian/api/web/create-checkout-session        (public — no JWT)
 *
 * Starts a Stripe Checkout for the Rysflo membership ($29 / month, device
 * included) from an /order/<CODE> link or QR code. The referral code is
 * resolved server-side and stamped onto the subscription as metadata, which is
 * the only attribution the commission ledger trusts. Nothing about pricing or
 * the code comes from the browser.
 *
 * Body:
 *  {
 *    "partner_code": "TRN0000001",   // optional; unknown/inactive codes still sell (at list price)
 *    "qr_id":        "K7M2P9",       // optional; a printed sticker, resolved to its current partner code
 *    "email":        "buyer@x.com"   // optional; pre-fills Checkout
 *  }
 *
 * Pricing: the list price from pricing_settings; a valid partner code applies
 * that code's Stripe promotion code (list -> referred price). With no code the
 * member can still type one on the Checkout page (allow_promotion_codes).
 *
 * Response: { ok, checkout_url, session_id, attributed_to: { partner_code, role } | null }
 *
 * Abuse controls: the global API rate limiter applies; every session carries
 * the caller IP hash in metadata for the audit trail; the endpoint never
 * reveals whether a code exists (attributed_to is omitted unless the code is
 * valid, and an invalid code is not an error).
 */

const crypto = require("crypto");
const {
  requireStripe,
  ORDER_SUCCESS_URL,
  ORDER_CANCEL_URL,
  PLAN_CODE,
} = require("../../../../config/stripe");
const { resolvePartnerCode, normalizeCode } = require("../../../../utils/partnerCodeResolver");
const pricing = require("../../../../services/pricing");
const qr = require("../../../../services/qrCodes");
const { validateEmailAddress } = require("../../../../utils/securityValidation");

const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

function hashIp(req) {
  const ip = (typeof req.ip === "string" && req.ip) || req.socket?.remoteAddress || "";
  return crypto.createHmac("sha256", SECURITY_PEPPER).update(String(ip)).digest("hex").slice(0, 32);
}

const createCheckoutSession = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  try {
    const stripe = requireStripe();
    const body = req.body && typeof req.body === "object" ? req.body : {};

    // A sticker id wins over a typed code: the sticker is what was scanned.
    let qrId = null;
    let rawCode = normalizeCode(body.partner_code);
    if (typeof body.qr_id === "string" && body.qr_id.trim()) {
      const sticker = await qr.resolve(body.qr_id);
      if (sticker) {
        qrId = sticker.id;
        if (sticker.partner_code) rawCode = sticker.partner_code;
      }
    }
    const attributed = rawCode ? await resolvePartnerCode(rawCode) : null;

    let email = null;
    if (typeof body.email === "string" && body.email.trim() !== "") {
      const check = validateEmailAddress(body.email);
      if (!check.ok) {
        return res.status(422).json({ ok: false, message: "Invalid email address" });
      }
      email = check.value;
    }

    const pr = await pricing.ensureStripePricing();
    const priceId = pr.stripe_list_price_id;
    const promotionCodeId = attributed ? await pricing.ensurePromotionCode(attributed.partner_code) : null;

    // Everything the webhook needs to attribute this sale, on both the session
    // and the subscription (the subscription is what invoices reference).
    const metadata = {
      plan_code: PLAN_CODE,
      link_partner_code: rawCode || "",
      attributed_partner_code: attributed ? attributed.partner_code : "",
      attributed_user_id: attributed ? attributed.user_id : "",
      attributed_role: attributed ? attributed.role : "",
      facility_id: attributed && attributed.facility_id != null ? String(attributed.facility_id) : "",
      qr_id: qrId || "",
      ip_hash: hashIp(req),
    };

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${ORDER_SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: rawCode ? `${ORDER_CANCEL_URL}/${encodeURIComponent(rawCode)}` : ORDER_CANCEL_URL,
      customer_email: email || undefined,
      client_reference_id: attributed ? attributed.partner_code : undefined,
      // Pre-apply the referral discount; otherwise let the member type a code.
      ...(promotionCodeId
        ? { discounts: [{ promotion_code: promotionCodeId }] }
        : { allow_promotion_codes: true }),
      billing_address_collection: "required",
      shipping_address_collection: { allowed_countries: ["US"] },
      phone_number_collection: { enabled: true },
      // consent_collection.terms_of_service needs a ToS URL in Stripe Dashboard
      // > Settings > Public details before it can be enabled (go-live item).
      metadata,
      subscription_data: { metadata },
      // Dashboard label for this checkout flow (random suffix per Stripe guidance).
      integration_identifier: "rysflo_order_page_kqzmwvtb",
    });

    if (qrId) await qr.recordScan(qrId);

    return res.status(200).json({
      ok: true,
      checkout_url: session.url,
      session_id: session.id,
      pricing: {
        currency: pr.currency,
        list_price_minor: Number(pr.list_price_minor),
        price_minor: attributed ? Number(pr.referred_price_minor) : Number(pr.list_price_minor),
      },
      ...(attributed && {
        attributed_to: { partner_code: attributed.partner_code, role: attributed.role },
      }),
    });
  } catch (err) {
    console.error("CREATE_CHECKOUT_SESSION_ERROR:", {
      code: err?.code,
      type: err?.type,
      message: err?.message,
    });
    return res.status(500).json({ ok: false, message: "Unable to start checkout" });
  }
};

module.exports = { createCheckoutSession };
