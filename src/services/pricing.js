"use strict";

/**
 * Pricing for the referral programme.
 *
 * Two numbers, set by super_admin: list price (what the website shows) and
 * referred price (what a member pays with a gym/trainer code). Everything in
 * Stripe is derived from them and cached in pricing_settings:
 *
 *   list price      -> a recurring Stripe Price (created once per amount)
 *   list - referred -> a Stripe Coupon, amount_off, duration "forever"
 *   partner code    -> a Stripe Promotion Code on the current coupon, whose
 *                      customer-facing code IS the partner code (TRX1234), so
 *                      the same code works on the website and in the app.
 *
 * Changing either number makes a new pricing_settings row; the coupon and the
 * promotion codes are (re)created lazily. Existing subscribers keep their
 * price (Stripe default).
 */

const pool = require("../config/db");
const { requireStripe, STRIPE_PRICE_LOOKUP_KEY } = require("../config/stripe");

const PRODUCT_NAME = "Rysflo Membership";
const PRODUCT_LOOKUP_METADATA = "rysflo_membership";

let cache = { at: 0, row: null };
const CACHE_MS = 60 * 1000;

async function currentPricing({ fresh = false } = {}) {
  if (!fresh && cache.row && Date.now() - cache.at < CACHE_MS) return cache.row;
  const [rows] = await pool.execute(
    `SELECT * FROM pricing_settings WHERE effective_from <= UTC_TIMESTAMP() ORDER BY effective_from DESC, id DESC LIMIT 1`
  );
  cache = { at: Date.now(), row: rows[0] || null };
  return cache.row;
}

/** Find or create the single product. */
async function ensureProduct(stripe) {
  const found = await stripe.products.search({ query: `metadata['rysflo']:'${PRODUCT_LOOKUP_METADATA}' AND active:'true'`, limit: 1 });
  if (found.data[0]) return found.data[0].id;
  const p = await stripe.products.create(
    { name: PRODUCT_NAME, description: "Rysflo breath device + app, billed monthly. Device included.", metadata: { rysflo: PRODUCT_LOOKUP_METADATA } },
    { idempotencyKey: `product-${PRODUCT_LOOKUP_METADATA}` }
  );
  return p.id;
}

/** Find or create the recurring list price for an amount. */
async function ensureListPrice(stripe, currency, amountMinor) {
  const lookupKey = `rysflo_list_${currency.toLowerCase()}_${amountMinor}`;
  const found = await stripe.prices.list({ lookup_keys: [lookupKey], active: true, limit: 1 });
  if (found.data[0]) return found.data[0].id;
  const productId = await ensureProduct(stripe);
  const price = await stripe.prices.create(
    {
      product: productId,
      currency: currency.toLowerCase(),
      unit_amount: amountMinor,
      recurring: { interval: "month" },
      lookup_key: lookupKey,
      metadata: { plan_code: "rysflo_monthly" },
    },
    { idempotencyKey: `price-${lookupKey}` }
  );
  return price.id;
}

/** Find or create the "list - referred" coupon. */
async function ensureCoupon(stripe, currency, listMinor, referredMinor) {
  const off = listMinor - referredMinor;
  if (off <= 0) return null;
  const couponId = `rysflo_ref_${currency.toLowerCase()}_${listMinor}_${referredMinor}`; // deterministic id
  try {
    const c = await stripe.coupons.retrieve(couponId);
    if (c && c.valid) return c.id;
  } catch (err) {
    if (err?.code !== "resource_missing") throw err;
  }
  const c = await stripe.coupons.create(
    {
      id: couponId,
      name: `Rysflo referral ${(referredMinor / 100).toFixed(0)} (list ${(listMinor / 100).toFixed(0)})`, // <= 40 chars
      amount_off: off,
      currency: currency.toLowerCase(),
      duration: "forever",
      metadata: { list_price_minor: String(listMinor), referred_price_minor: String(referredMinor) },
    },
    { idempotencyKey: `coupon-${couponId}` }
  );
  return c.id;
}

/**
 * Make sure Stripe objects exist for the current pricing row; persist ids.
 * Returns { row, stripe_list_price_id, stripe_coupon_id }.
 */
async function ensureStripePricing() {
  const row = await currentPricing({ fresh: true });
  if (!row) {
    const err = new Error("No pricing configured");
    err.code = "NO_PRICING";
    throw err;
  }
  if (row.stripe_list_price_id && (row.stripe_coupon_id || row.list_price_minor <= row.referred_price_minor)) return row;

  const stripe = requireStripe();
  const priceId = row.stripe_list_price_id || (await ensureListPrice(stripe, row.currency, Number(row.list_price_minor)));
  const couponId = row.stripe_coupon_id || (await ensureCoupon(stripe, row.currency, Number(row.list_price_minor), Number(row.referred_price_minor)));

  await pool.execute(`UPDATE pricing_settings SET stripe_list_price_id = ?, stripe_coupon_id = ? WHERE id = ?`, [priceId, couponId, row.id]);
  cache = { at: 0, row: null };
  return currentPricing({ fresh: true });
}

/**
 * Promotion code for a partner code on the current coupon. The customer-facing
 * code is the partner code itself. Returns the promo_… id, or null when there
 * is no discount configured.
 */
async function ensurePromotionCode(partnerCode) {
  const pricing = await ensureStripePricing();
  if (!pricing.stripe_coupon_id) return null;
  const code = String(partnerCode).toUpperCase();

  const [rows] = await pool.execute(
    `SELECT stripe_promotion_code_id FROM partner_promotion_codes WHERE partner_code = ? AND stripe_coupon_id = ? AND active = 1 LIMIT 1`,
    [code, pricing.stripe_coupon_id]
  );
  if (rows[0]) return rows[0].stripe_promotion_code_id;

  const stripe = requireStripe();
  // Stripe rejects a duplicate customer-facing code; an older coupon may own it.
  const existing = await stripe.promotionCodes.list({ code, limit: 1 });
  const couponOf = (pc) => pc.promotion?.coupon?.id || pc.promotion?.coupon || pc.coupon?.id || pc.coupon;
  for (const pc of existing.data) {
    if (couponOf(pc) !== pricing.stripe_coupon_id && pc.active) {
      await stripe.promotionCodes.update(pc.id, { active: false });
      await pool.execute(`UPDATE partner_promotion_codes SET active = 0 WHERE stripe_promotion_code_id = ?`, [pc.id]);
    }
  }
  let promo = existing.data.find((pc) => couponOf(pc) === pricing.stripe_coupon_id);
  if (!promo) {
    promo = await stripe.promotionCodes.create(
      { promotion: { type: "coupon", coupon: pricing.stripe_coupon_id }, code, metadata: { partner_code: code } },
      { idempotencyKey: `promo-${code}-${pricing.stripe_coupon_id}` }
    );
  } else if (!promo.active) {
    promo = await stripe.promotionCodes.update(promo.id, { active: true });
  }

  await pool.execute(
    `INSERT INTO partner_promotion_codes (partner_code, stripe_coupon_id, stripe_promotion_code_id, active)
     VALUES (?, ?, ?, 1) ON DUPLICATE KEY UPDATE active = 1, stripe_promotion_code_id = VALUES(stripe_promotion_code_id)`,
    [code, pricing.stripe_coupon_id, promo.id]
  );
  return promo.id;
}

/** partner code for a Stripe promotion code id (attribution for in-app purchases). */
async function partnerCodeForPromotion(promotionCodeId) {
  if (!promotionCodeId) return null;
  const [rows] = await pool.execute(
    `SELECT partner_code FROM partner_promotion_codes WHERE stripe_promotion_code_id = ? LIMIT 1`,
    [promotionCodeId]
  );
  if (rows[0]) return rows[0].partner_code;
  // Not ours (created elsewhere) — ask Stripe; the customer-facing code is the partner code by convention.
  try {
    const pc = await requireStripe().promotionCodes.retrieve(promotionCodeId);
    return pc?.metadata?.partner_code || pc?.code || null;
  } catch {
    return null;
  }
}

/** Super admin: set new pricing (append-only). */
async function setPricing({ listMinor, referredMinor, currency = "USD", setBy, note = null, effectiveFrom = null }) {
  await pool.execute(
    `INSERT INTO pricing_settings (currency, list_price_minor, referred_price_minor, effective_from, set_by_user_id, note)
     VALUES (?, ?, ?, COALESCE(?, UTC_TIMESTAMP()), ?, ?)`,
    [currency.toUpperCase(), listMinor, referredMinor, effectiveFrom, setBy, note]
  );
  cache = { at: 0, row: null };
  return ensureStripePricing();
}

/** Public view for the order page. */
async function publicPricing() {
  const row = await currentPricing();
  if (!row) return null;
  return {
    currency: row.currency,
    list_price_minor: Number(row.list_price_minor),
    referred_price_minor: Number(row.referred_price_minor),
  };
}

module.exports = { currentPricing, ensureStripePricing, ensurePromotionCode, partnerCodeForPromotion, setPricing, publicPricing };
