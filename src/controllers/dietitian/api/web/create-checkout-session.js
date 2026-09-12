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
 *    "partner_code": "TRN0000001",   // optional; unknown/inactive codes still sell
 *    "email":        "buyer@x.com"   // optional; pre-fills Checkout
 *  }
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
  STRIPE_PRICE_LOOKUP_KEY,
  ORDER_SUCCESS_URL,
  ORDER_CANCEL_URL,
  PLAN_CODE,
} = require("../../../../config/stripe");
const { resolvePartnerCode, normalizeCode } = require("../../../../utils/partnerCodeResolver");
const { validateEmailAddress } = require("../../../../utils/securityValidation");

const SECURITY_PEPPER = process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

function hashIp(req) {
  const ip = (typeof req.ip === "string" && req.ip) || req.socket?.remoteAddress || "";
  return crypto.createHmac("sha256", SECURITY_PEPPER).update(String(ip)).digest("hex").slice(0, 32);
}

let cachedPriceId = null;
let cachedPriceAt = 0;
const PRICE_CACHE_MS = 10 * 60 * 1000;

/** Look the recurring price up by lookup_key so the id never lives in code. */
async function resolvePriceId(stripe) {
  if (cachedPriceId && Date.now() - cachedPriceAt < PRICE_CACHE_MS) return cachedPriceId;

  const prices = await stripe.prices.list({
    lookup_keys: [STRIPE_PRICE_LOOKUP_KEY],
    active: true,
    limit: 1,
  });

  if (!prices.data.length) {
    const err = new Error(`No active Stripe price with lookup_key ${STRIPE_PRICE_LOOKUP_KEY}`);
    err.code = "STRIPE_PRICE_MISSING";
    throw err;
  }

  cachedPriceId = prices.data[0].id;
  cachedPriceAt = Date.now();
  return cachedPriceId;
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

    const rawCode = normalizeCode(body.partner_code);
    const attributed = rawCode ? await resolvePartnerCode(rawCode) : null;

    let email = null;
    if (typeof body.email === "string" && body.email.trim() !== "") {
      const check = validateEmailAddress(body.email);
      if (!check.ok) {
        return res.status(422).json({ ok: false, message: "Invalid email address" });
      }
      email = check.value;
    }

    const priceId = await resolvePriceId(stripe);

    // Everything the webhook needs to attribute this sale, on both the session
    // and the subscription (the subscription is what invoices reference).
    const metadata = {
      plan_code: PLAN_CODE,
      link_partner_code: rawCode || "",
      attributed_partner_code: attributed ? attributed.partner_code : "",
      attributed_user_id: attributed ? attributed.user_id : "",
      attributed_role: attributed ? attributed.role : "",
      facility_id: attributed && attributed.facility_id != null ? String(attributed.facility_id) : "",
      ip_hash: hashIp(req),
    };

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${ORDER_SUCCESS_URL}?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: rawCode ? `${ORDER_CANCEL_URL}/${encodeURIComponent(rawCode)}` : ORDER_CANCEL_URL,
      customer_email: email || undefined,
      client_reference_id: attributed ? attributed.partner_code : undefined,
      allow_promotion_codes: false,
      billing_address_collection: "required",
      shipping_address_collection: { allowed_countries: ["US"] },
      phone_number_collection: { enabled: true },
      // consent_collection.terms_of_service needs a ToS URL in Stripe Dashboard
      // > Settings > Public details before it can be enabled (go-live item).
      metadata,
      subscription_data: { metadata },
    });

    return res.status(200).json({
      ok: true,
      checkout_url: session.url,
      session_id: session.id,
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
