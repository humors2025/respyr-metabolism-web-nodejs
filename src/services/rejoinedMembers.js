"use strict";

// "Re-joined Again" members (user's rule, 27 Nov 2026).
//
// Once a plan is cancelled and over, Stripe cannot restart it: buying again
// (website or the app's Renew button) creates a NEW referral_subscriptions
// row. That member is treated as renewing, not as a new customer:
//   - the old plan is flagged "Re-joined Again" and leaves the Sales
//     Analytics cancellation numbers
//   - the new plan's first payment is a renewal payment, not a new sale
// Same member = same app profile, else same purchase email. The old plan must
// have been cancelled (or ended) before the new one was bought, so a second
// plan bought alongside a running one stays a new sale.
//
// Every helper returns a SQL fragment built from fixed table aliases only (no
// user input).

const { realSubscriptionSql } = require("./excludedSubscriptions");

const ALIAS = /^[a-z_][a-z0-9_]*$/i;
const check = (...aliases) => {
  for (const a of aliases) if (!ALIAS.test(a)) throw new Error(`rejoinedMembers: bad alias ${a}`);
};

const samePersonSql = (a, b) => `(
  (${a}.profile_id IS NOT NULL AND ${a}.profile_id <> '' AND ${a}.profile_id = ${b}.profile_id)
  OR (${a}.purchaser_email IS NOT NULL AND ${a}.purchaser_email <> '' AND LOWER(${a}.purchaser_email) = LOWER(${b}.purchaser_email))
)`;

/** SQL: subscription row `nw` is the member of row `od` re-joining. */
function cameBackSql(od, nw) {
  check(od, nw);
  return `(
    ${nw}.id <> ${od}.id
    AND ${nw}.created_at > ${od}.created_at
    AND ${samePersonSql(od, nw)}
    AND ${od}.status NOT IN ('incomplete', 'incomplete_expired')
    AND ${nw}.status NOT IN ('incomplete', 'incomplete_expired')
    AND ${realSubscriptionSql(`${od}.stripe_subscription_id`)}
    AND ${realSubscriptionSql(`${nw}.stripe_subscription_id`)}
    AND (
      ${od}.canceled_at <= ${nw}.created_at
      OR (${od}.status IN ('canceled', 'unpaid') AND ${od}.current_period_end <= DATE_ADD(${nw}.created_at, INTERVAL 1 DAY))
    )
  )`;
}

/** SQL: row `a` is a re-join purchase (a renewal, not a new sale). */
const isComebackSql = (a) => `EXISTS (SELECT 1 FROM referral_subscriptions cb_old WHERE ${cameBackSql("cb_old", a)})`;

/** SQL: the member of row `a` re-joined later on a new plan. */
const cameBackLaterSql = (a) => `EXISTS (SELECT 1 FROM referral_subscriptions cb_new WHERE ${cameBackSql(a, "cb_new")})`;

/** SQL: when the member of row `a` re-joined (first new plan), or NULL. */
const rejoinedAtSql = (a) => `(SELECT MIN(cb_new.created_at) FROM referral_subscriptions cb_new WHERE ${cameBackSql(a, "cb_new")})`;

/** SQL: payment `pt` (of subscription row `rs`) is a renewal payment. */
function renewalPaymentSql(pt, rs) {
  check(pt, rs);
  return `(${pt}.billing_reason = 'subscription_cycle' OR (${pt}.billing_reason = 'subscription_create' AND ${isComebackSql(rs)}))`;
}

/** SQL: payment `pt` is a genuine first payment (new customer). */
function firstPaymentSql(pt, rs) {
  check(pt, rs);
  return `(${pt}.billing_reason = 'subscription_create' AND NOT ${isComebackSql(rs)})`;
}

module.exports = { cameBackSql, isComebackSql, cameBackLaterSql, rejoinedAtSql, renewalPaymentSql, firstPaymentSql };
