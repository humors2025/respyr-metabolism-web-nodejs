"use strict";

/**
 * POST /dietitian/api/web/cancel-order-subscription   (super_admin only)
 *
 * Cancels (or un-cancels) a website (/order) subscription in Stripe. Writes
 * nothing to the database itself: Stripe answers with the new subscription
 * state, then sends customer.subscription.updated / .deleted to the webhook,
 * which is what updates referral_subscriptions — so the row may lag this
 * response by a few seconds.
 *
 * Body: { stripe_subscription_id? , email? , mode? }
 *   stripe_subscription_id  sub_… (preferred)
 *   email                   purchaser_email lookup when no id is given; must
 *                           match exactly one non-canceled subscription
 *   mode                    "at_period_end" (default) — customer keeps access
 *                                 until current_period_end, then it ends
 *                           "immediately"   — ends now (no refund)
 *                           "resume"        — undo a pending at_period_end cancel
 */

const pool = require("../../../../config/db");
const { requireStripe } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");

const MODES = ["at_period_end", "immediately", "resume"];

const toIso = (unixSeconds) =>
  unixSeconds ? new Date(unixSeconds * 1000).toISOString().replace(".000Z", "Z") : null;

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

/** The referral_subscriptions row this acts on — only website purchases live there. */
async function findSubscription(body) {
  const id = String(body.stripe_subscription_id || "").trim();
  const email = String(body.email || "").trim().toLowerCase();
  if (id) {
    if (!/^sub_[A-Za-z0-9]+$/.test(id)) throw httpError(422, "stripe_subscription_id must look like sub_…");
    const [rows] = await pool.query(
      `SELECT stripe_subscription_id, stripe_schedule_id, purchaser_email, status, canceled_at
       FROM referral_subscriptions WHERE stripe_subscription_id = ?`,
      [id]
    );
    if (!rows.length) throw httpError(404, "No website subscription with that id");
    return rows[0];
  }
  if (!email) throw httpError(422, "Provide stripe_subscription_id or email");
  const [rows] = await pool.query(
    `SELECT stripe_subscription_id, stripe_schedule_id, purchaser_email, status, canceled_at
     FROM referral_subscriptions WHERE purchaser_email = ? AND status <> 'canceled'`,
    [email]
  );
  if (!rows.length) throw httpError(404, "No active website subscription for that email");
  if (rows.length > 1) {
    throw httpError(409, "Multiple subscriptions for that email — pass stripe_subscription_id");
  }
  return rows[0];
}

/**
 * Website subscriptions sit on a 12-month device-term schedule (end_behavior
 * "release"; see the webhook's applyTerm), and Stripe refuses cancellation
 * changes on a schedule-managed subscription. So while the schedule is still
 * attached, an immediate cancel goes through the schedule, and an
 * at-period-end cancel first releases the schedule (the subscription keeps
 * running unchanged, just unmanaged — the term cap is moot once it's ending).
 */
async function detachScheduleIfAny(stripe, subscription) {
  const scheduleId = subscription.schedule ? String(subscription.schedule) : null;
  if (!scheduleId) return;
  await stripe.subscriptionSchedules.release(scheduleId);
}

const cancelOrderSubscription = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const mode = String(body.mode || "at_period_end");
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    if (!MODES.includes(mode)) {
      return res.status(422).json({ status: false, ok: false, message: `mode must be one of ${MODES.join(", ")}` });
    }

    const row = await findSubscription(body);
    const subscriptionId = row.stripe_subscription_id;
    const stripe = requireStripe();

    const current = await stripe.subscriptions.retrieve(subscriptionId);

    let subscription;
    if (mode === "immediately" && current.schedule) {
      // Cancelling the schedule cancels the subscription with it.
      await stripe.subscriptionSchedules.cancel(String(current.schedule));
      subscription = await stripe.subscriptions.retrieve(subscriptionId);
    } else if (mode === "immediately") {
      subscription = await stripe.subscriptions.cancel(subscriptionId);
    } else {
      await detachScheduleIfAny(stripe, current);
      subscription = await stripe.subscriptions.update(subscriptionId, {
        cancel_at_period_end: mode === "at_period_end",
      });
    }

    // Cancelling ends a paying subscription: log who did it, to which sub.
    await H.writeAuthLogSafe(req, {
      eventType: "order_subscription_cancel",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: row.purchaser_email || subscriptionId,
      success: true,
      failureReason: `mode=${mode} sub=${subscriptionId}`,
    });

    const item = subscription.items?.data?.[0];
    return res.status(200).json({
      status: true,
      ok: true,
      mode,
      stripe: {
        subscription_id: subscription.id,
        status: subscription.status,
        cancel_at_period_end: Boolean(subscription.cancel_at_period_end),
        canceled_at: toIso(subscription.canceled_at),
        current_period_end: toIso(item?.current_period_end ?? subscription.current_period_end),
      },
      note: "referral_subscriptions updates when the webhook processes Stripe's event (a few seconds).",
    });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, message: err.message });
    // Stripe errors (e.g. already-canceled sub) carry statusCode + a safe message.
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ status: false, ok: false, message: err.message });
    }
    console.error("CANCEL_ORDER_SUBSCRIPTION_ERROR:", { mode, code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "order_subscription_cancel",
        userId: resolved.actorEmail,
        role: "super_admin",
        partnerCode: null,
        identifier: String(body.email || body.stripe_subscription_id || ""),
        success: false,
        failureReason: String(err?.code || "internal_error"),
      });
    }
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { cancelOrderSubscription };
