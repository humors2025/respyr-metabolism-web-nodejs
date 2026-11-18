"use strict";

/**
 * Turn off referral promotion codes whose owner is not an active account.
 *
 * A partner code's Stripe promotion code is the $ off at Checkout and in the
 * app. It must only work while the code belongs to an accepted, active
 * account. Invites expire, get cancelled and accounts get deactivated in many
 * places, so instead of hooking each one this sweep checks every active
 * partner_promotion_codes row and deactivates (Stripe + DB) the ones whose code
 * no longer resolves to an active account. Pending invites do not count.
 *
 * Safe to re-run. A code that becomes active again (invite accepted, account
 * reactivated) is switched back on by pricing.ensurePromotionCode.
 *
 * Runs nightly with the breath-credits job, or alone: { "job": "promo-codes" }.
 */

const pool = require("../config/db");
const { requireStripe } = require("../config/stripe");
const { resolvePartnerCode } = require("../utils/partnerCodeResolver");

async function sweepInactivePromotionCodes({ dryRun = false, stripe = null } = {}) {
  const [rows] = await pool.execute(
    `SELECT partner_code, stripe_promotion_code_id FROM partner_promotion_codes WHERE active = 1`
  );

  const summary = { checked: rows.length, deactivated: [], kept: 0, errors: 0 };
  let client = stripe;

  for (const row of rows) {
    const code = String(row.partner_code || "").toUpperCase();
    let owner;
    try {
      owner = await resolvePartnerCode(code, { allowPending: false });
    } catch (err) {
      summary.errors += 1;
      console.error("PROMO_SWEEP_RESOLVE_ERROR:", { code, message: err?.message });
      continue;
    }
    if (owner) {
      summary.kept += 1;
      continue;
    }

    summary.deactivated.push(code);
    if (dryRun) continue;

    try {
      if (!client) client = requireStripe();
      await client.promotionCodes.update(row.stripe_promotion_code_id, { active: false });
    } catch (err) {
      // A promo id from another Stripe account (e.g. old sandbox rows) does not
      // exist here; nothing to switch off in Stripe, still clear the row.
      if (err?.code !== "resource_missing") {
        summary.errors += 1;
        summary.deactivated.pop();
        console.error("PROMO_SWEEP_STRIPE_ERROR:", { code, promo: row.stripe_promotion_code_id, message: err?.message });
        continue;
      }
    }
    await pool.execute(
      `UPDATE partner_promotion_codes SET active = 0 WHERE stripe_promotion_code_id = ?`,
      [row.stripe_promotion_code_id]
    );
  }

  if (summary.deactivated.length) {
    console.log("PROMO_SWEEP_DEACTIVATED:", { dry_run: dryRun, codes: summary.deactivated });
  }
  return summary;
}

module.exports = { sweepInactivePromotionCodes };
