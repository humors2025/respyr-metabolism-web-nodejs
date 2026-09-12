"use strict";

/**
 * Stripe client + the handful of platform settings the referral programme
 * needs. Secrets come from the environment (Secrets Manager on Lambda, .env
 * locally) — never from the database.
 *
 *   STRIPE_SECRET_KEY        sk_test_… / sk_live_… (production: use a restricted
 *                            key, rk_…, scoped to Checkout, Billing, Customers,
 *                            Connect accounts/transfers and webhooks)
 *   STRIPE_WEBHOOK_SECRET    whsec_… for the /stripe/webhook endpoint
 *   STRIPE_PRICE_LOOKUP_KEY  lookup_key of the recurring price (rysflo_monthly_29)
 *   STRIPE_TERM_MONTHS       device term; the schedule releases after this (12)
 *   ORDER_SUCCESS_URL / ORDER_CANCEL_URL
 *                            where Checkout returns the buyer
 */

const Stripe = require("stripe");

const STRIPE_SECRET_KEY = String(process.env.STRIPE_SECRET_KEY || "").trim();
const STRIPE_WEBHOOK_SECRET = String(process.env.STRIPE_WEBHOOK_SECRET || "").trim();
const STRIPE_PRICE_LOOKUP_KEY =
  String(process.env.STRIPE_PRICE_LOOKUP_KEY || "rysflo_monthly_29").trim();
const STRIPE_TERM_MONTHS = Math.max(
  1,
  parseInt(process.env.STRIPE_TERM_MONTHS, 10) || 12
);
const ORDER_SUCCESS_URL =
  String(process.env.ORDER_SUCCESS_URL || "https://admin.rysflo.com/order/success").trim();
const ORDER_CANCEL_URL =
  String(process.env.ORDER_CANCEL_URL || "https://admin.rysflo.com/order").trim();

const PLAN_CODE = "rysflo_monthly";

// Breath-test credit rule (product decision, 12 Sep 2026).
const BREATH_CREDIT_PER_DAY_MINOR = 20;   // $0.20 per reading-day
const BREATH_CREDIT_CAP_MINOR = 600;      // $6.00 per billing month
const BREATH_CREDIT_FULL_DAYS = 30;       // a "full" month; Feb reaches the cap at 28

const isLive = /^(sk|rk)_live_/.test(STRIPE_SECRET_KEY);

if (STRIPE_SECRET_KEY === "") {
  console.warn("STRIPE_SECRET_KEY is not set — Stripe endpoints will fail closed.");
}

// Refuse to run live-mode money movement outside production. A mis-copied
// live key on a laptop must never create real transfers.
if (isLive && process.env.NODE_ENV !== "production") {
  throw new Error(
    "FATAL_CONFIG: live Stripe key in a non-production environment. Use sk_test_."
  );
}

const stripe = STRIPE_SECRET_KEY
  ? new Stripe(STRIPE_SECRET_KEY, {
      // SDK default (2026-08-26.dahlia at time of writing); Accounts v2 needs it.
      maxNetworkRetries: 2,
      timeout: 20000,
      appInfo: { name: "respyr-metabolism-web-nodejs", version: "1.0.0" },
    })
  : null;

function requireStripe() {
  if (!stripe) {
    const err = new Error("Stripe is not configured");
    err.code = "STRIPE_NOT_CONFIGURED";
    throw err;
  }
  return stripe;
}

module.exports = {
  stripe,
  requireStripe,
  isLive,
  STRIPE_WEBHOOK_SECRET,
  STRIPE_PRICE_LOOKUP_KEY,
  STRIPE_TERM_MONTHS,
  ORDER_SUCCESS_URL,
  ORDER_CANCEL_URL,
  PLAN_CODE,
  BREATH_CREDIT_PER_DAY_MINOR,
  BREATH_CREDIT_CAP_MINOR,
  BREATH_CREDIT_FULL_DAYS,
};
