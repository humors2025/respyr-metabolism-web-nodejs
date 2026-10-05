"use strict";

/**
 * POST /dietitian/api/web/simulate-renewal   (super_admin only, TEST MODE only)
 *
 * Makes a website subscription renew NOW instead of at period end, using a
 * Stripe test clock: the customer is attached to a new clock frozen at the
 * current time, and the clock is advanced just past current_period_end.
 * Stripe then generates the real renewal invoice (billing_reason
 * subscription_cycle), charges the saved test card and fires invoice.paid /
 * customer.subscription.updated to the webhook — so payment_transactions,
 * commission_entries and referral_subscriptions update exactly as on a real
 * renewal. Writes nothing to the database itself.
 *
 * Advancing is asynchronous on Stripe's side (seconds up to ~a minute);
 * check webhook_events / payment_transactions shortly after calling.
 *
 * ONE-WAY DOOR: attaching a customer to a test clock cannot be undone, and
 * deleting a test clock deletes its customers. Use only on throwaway UAT
 * test purchases. Refuses to run with a live key.
 *
 * Body: { stripe_subscription_id }
 */

const pool = require("../../../../config/db");
const { requireStripe, isLive } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");

const toIso = (unixSeconds) =>
  unixSeconds ? new Date(unixSeconds * 1000).toISOString().replace(".000Z", "Z") : null;

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

const simulateRenewal = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    if (isLive) return res.status(403).json({ status: false, ok: false, message: "Test clocks are test-mode only" });

    const id = String(body.stripe_subscription_id || "").trim();
    if (!id) throw httpError(422, "stripe_subscription_id is required");
    if (!/^sub_[A-Za-z0-9]+$/.test(id)) throw httpError(422, "stripe_subscription_id must look like sub_…");

    const [rows] = await pool.query(
      `SELECT stripe_subscription_id, purchaser_email, status FROM referral_subscriptions WHERE stripe_subscription_id = ?`,
      [id]
    );
    if (!rows.length) throw httpError(404, "No website subscription with that id");
    if (String(rows[0].status) === "canceled") throw httpError(409, "Subscription is canceled — nothing will renew");

    const stripe = requireStripe();
    const subscription = await stripe.subscriptions.retrieve(id);
    const item = subscription.items?.data?.[0];
    const periodEnd = Number(item?.current_period_end ?? subscription.current_period_end);
    if (!periodEnd) throw httpError(500, "Subscription has no current_period_end");

    const customerId = String(subscription.customer);
    let clockId = subscription.test_clock ? String(subscription.test_clock) : null;
    let clock = null;
    if (clockId) {
      clock = await stripe.testHelpers.testClocks.retrieve(clockId);
      if (clock.status === "advancing") {
        return res.status(200).json({
          status: true,
          ok: true,
          stripe: {
            subscription_id: id,
            test_clock_id: clockId,
            clock_status: "advancing",
            frozen_time: toIso(Number(clock.frozen_time)),
          },
          note: "The clock is still advancing from an earlier call — wait a minute, then check the DB.",
        });
      }
    } else {
      clock = await stripe.testHelpers.testClocks.create({
        frozen_time: Math.floor(Date.now() / 1000),
        customer: customerId,
        name: `renewal test ${id}`,
      });
      clockId = clock.id;
    }

    // Two hours past period end: Stripe creates the renewal invoice at period
    // end but finalizes and pays it about an hour later, so one hour can leave
    // it unpaid. Note period_end is re-read per call — once a renewal has
    // landed, calling again advances the NEXT cycle.
    const target = periodEnd + 2 * 3600;
    if (Number(clock.frozen_time) >= target) {
      return res.status(409).json({
        status: false,
        ok: false,
        message: `Clock is already at ${toIso(Number(clock.frozen_time))}, past this period end — if the renewal still hasn't landed, check webhook_events for errors.`,
      });
    }
    clock = await stripe.testHelpers.testClocks.advance(clockId, { frozen_time: target });

    await H.writeAuthLogSafe(req, {
      eventType: "simulate_renewal",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: rows[0].purchaser_email || id,
      success: true,
      failureReason: `sub=${id} clock=${clockId}`,
    });

    return res.status(200).json({
      status: true,
      ok: true,
      stripe: {
        subscription_id: id,
        customer_id: customerId,
        test_clock_id: clockId,
        clock_status: clock.status, // "advancing" until Stripe finishes
        advancing_to: toIso(target),
        period_end_before: toIso(periodEnd),
      },
      note:
        "Stripe is advancing the clock (can take up to a minute). Then check payment_transactions for a subscription_cycle row and referral_subscriptions for the new period dates.",
    });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, message: err.message });
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ status: false, ok: false, message: err.message });
    }
    console.error("SIMULATE_RENEWAL_ERROR:", { code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "simulate_renewal",
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

module.exports = { simulateRenewal };
