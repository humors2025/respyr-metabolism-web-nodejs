"use strict";

/**
 * POST /dietitian/api/web/restore-subscription-discount   (super_admin only)
 *
 * Repair for subscriptions whose referral coupon was lost: the webhook's
 * device-term schedule rewrite used to drop the phase's discounts, so
 * renewals billed list price ($50) instead of the referred price ($29).
 * Fixed in the webhook on 5 Oct 2026 (d633517); this restores subscriptions
 * created before that fix.
 *
 * Re-adds the purchase's own promotion code (stripe_promotion_code_id on the
 * referral_subscriptions row) to the schedule's current phase, changing
 * nothing else. Safe to call twice: a phase that already has a discount is
 * left alone.
 *
 * Body: { stripe_subscription_id }
 */

const pool = require("../../../../config/db");
const { requireStripe } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

const restoreSubscriptionDiscount = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    const id = String(body.stripe_subscription_id || "").trim();
    if (!id) throw httpError(422, "stripe_subscription_id is required");
    if (!/^sub_[A-Za-z0-9]+$/.test(id)) throw httpError(422, "stripe_subscription_id must look like sub_…");

    const [rows] = await pool.query(
      `SELECT stripe_subscription_id, stripe_promotion_code_id, purchaser_email, status
       FROM referral_subscriptions WHERE stripe_subscription_id = ?`,
      [id]
    );
    if (!rows.length) throw httpError(404, "No website subscription with that id");
    const row = rows[0];
    if (String(row.status) === "canceled") throw httpError(409, "Subscription is canceled — nothing to repair");
    if (!row.stripe_promotion_code_id) {
      throw httpError(409, "Purchase had no promotion code — list price is correct for it");
    }

    const stripe = requireStripe();
    const subscription = await stripe.subscriptions.retrieve(id);
    const promo = String(row.stripe_promotion_code_id);

    if (!subscription.schedule) {
      // Released from its schedule (or never had one): the discount can be
      // set on the subscription directly.
      const has = (Array.isArray(subscription.discounts) ? subscription.discounts : []).length > 0;
      if (has) {
        return res.status(200).json({ status: true, ok: true, repaired: false, message: "Subscription already has its discount" });
      }
      await stripe.subscriptions.update(id, { discounts: [{ promotion_code: promo }] });
    } else {
      const schedule = await stripe.subscriptionSchedules.retrieve(String(subscription.schedule));
      const phase = schedule.phases[schedule.phases.length - 1];
      if ((phase.discounts || []).length) {
        return res.status(200).json({ status: true, ok: true, repaired: false, message: "Schedule phase already has its discount" });
      }
      // Resend the phase unchanged except for the restored discount.
      await stripe.subscriptionSchedules.update(schedule.id, {
        phases: [
          {
            items: phase.items.map((i) => ({ price: i.price, quantity: i.quantity })),
            start_date: phase.start_date,
            end_date: phase.end_date,
            discounts: [{ promotion_code: promo }],
            metadata: phase.metadata || {},
          },
        ],
      });
    }

    // This changes what a customer will be billed: log who repaired what.
    await H.writeAuthLogSafe(req, {
      eventType: "restore_subscription_discount",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: row.purchaser_email || id,
      success: true,
      failureReason: `sub=${id} promo=${promo}`,
    });

    return res.status(200).json({
      status: true,
      ok: true,
      repaired: true,
      stripe: { subscription_id: id, promotion_code_id: promo },
      note: "Future renewal invoices bill the referred price again.",
    });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, message: err.message });
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ status: false, ok: false, message: err.message });
    }
    console.error("RESTORE_SUBSCRIPTION_DISCOUNT_ERROR:", { code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "restore_subscription_discount",
        userId: resolved.actorEmail,
        role: "super_admin",
        partnerCode: null,
        identifier: String(body.stripe_subscription_id || ""),
        success: false,
        failureReason: String(err?.code || "internal_error"),
      });
    }
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { restoreSubscriptionDiscount };
