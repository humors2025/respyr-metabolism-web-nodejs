"use strict";

/**
 * Breath-test credit: every breath test a member records earns $0.20 off the
 * next month's invoice, capped at $6.00 per billing month. Only subscriptions
 * bought through a partner code earn the credit (rule of 28 Oct 2026; before
 * that it was $0.20 per reading-day for every subscription).
 *
 * Mechanism: shortly before a subscription renews, count the member's breath
 * tests in the current billing period and post a negative Customer Balance
 * Transaction on the Stripe customer. Stripe applies the balance to the next
 * invoice automatically, so invoice.amount_paid — which the commission ledger
 * uses — is already net of the credit.
 *
 * Idempotent: one breath_credits row per (subscription, period_start); the
 * Stripe call carries an idempotency key derived from the same pair. The
 * row's reading_days column holds the test count.
 */

const pool = require("../config/db");
const {
  requireStripe,
  BREATH_CREDIT_PER_TEST_MINOR,
  BREATH_CREDIT_CAP_MINOR,
} = require("../config/stripe");

const RENEWAL_WINDOW_HOURS = 36;

function ymd(d) {
  return d.toISOString().slice(0, 10);
}

/** Whole days between two Date objects (UTC), minimum 1. */
function daysBetween(a, b) {
  return Math.max(1, Math.round((b.getTime() - a.getTime()) / 86400000));
}

/** Credit in minor units for `testCount` breath tests. Exported for tests. */
function creditForTests(testCount) {
  return Math.min(BREATH_CREDIT_CAP_MINOR, Math.max(0, testCount) * BREATH_CREDIT_PER_TEST_MINOR);
}

/** Link purchase code redemptions and unique email matches -> app profile. */
async function linkProfilesByEmail() {
  const r = await require("./purchaseCodes").linkProfiles();
  await require("./commissionLedger").rebuildHeldForActivatedPayees();
  return r.by_purchase_code + r.by_email;
}

async function countTests(profileId, periodStart, periodEndExclusive) {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(*) AS tests
      FROM table_test_data
      WHERE profile_id = ?
        AND date_time >= ?
        AND date_time <  ?
    `,
    [profileId, periodStart, periodEndExclusive]
  );
  return Number(rows[0]?.tests || 0);
}

/**
 * Run the credit pass. `now` is injectable for tests.
 * Returns a summary of what was credited / skipped.
 */
async function runBreathCredits({ now = new Date(), dryRun = false } = {}) {
  const stripe = dryRun ? null : requireStripe();
  const linked = await linkProfilesByEmail();

  const windowEnd = new Date(now.getTime() + RENEWAL_WINDOW_HOURS * 3600000);

  // Active partner-code subscriptions renewing inside the window (or already
  // past the end because a run was missed) with no credit for this period yet.
  // No-code purchases do not earn the credit.
  const [subs] = await pool.execute(
    `
      SELECT rs.id, rs.stripe_subscription_id, rs.stripe_customer_id, rs.profile_id,
             rs.currency, rs.current_period_start, rs.current_period_end
      FROM referral_subscriptions rs
      LEFT JOIN breath_credits bc
        ON bc.stripe_subscription_id = rs.stripe_subscription_id
       AND bc.period_start = DATE(rs.current_period_start)
      WHERE rs.status IN ('active','past_due')
        AND LEFT(rs.stripe_subscription_id, 5) <> 'test_'
        AND rs.attributed_partner_code IS NOT NULL
        AND rs.attributed_partner_code <> ''
        AND rs.current_period_start IS NOT NULL
        AND rs.current_period_end   IS NOT NULL
        AND rs.current_period_end <= ?
        AND bc.id IS NULL
    `,
    [windowEnd.toISOString().slice(0, 19).replace("T", " ")]
  );

  const summary = { linked_profiles: linked, considered: subs.length, credited: 0, zero: 0, unlinked: 0, errors: 0, items: [] };

  for (const sub of subs) {
    if (!sub.profile_id) {
      summary.unlinked += 1;
      continue;
    }

    const periodStart = new Date(sub.current_period_start + "Z");
    const periodEnd = new Date(sub.current_period_end + "Z");
    // Never count readings after the period ends; never count the future.
    const countUntil = new Date(Math.min(periodEnd.getTime(), now.getTime()));
    const daysInPeriod = daysBetween(periodStart, periodEnd);

    const testCount = await countTests(
      sub.profile_id,
      sub.current_period_start,
      countUntil.toISOString().slice(0, 19).replace("T", " ")
    );
    const creditMinor = creditForTests(testCount);

    const item = {
      subscription: sub.stripe_subscription_id,
      profile_id: sub.profile_id,
      period: `${ymd(periodStart)}..${ymd(periodEnd)}`,
      days_in_period: daysInPeriod,
      tests: testCount,
      credit_minor: creditMinor,
    };

    try {
      let txnId = null;
      if (creditMinor > 0 && !dryRun) {
        const txn = await stripe.customers.createBalanceTransaction(
          sub.stripe_customer_id,
          {
            amount: -creditMinor, // negative = credit to the customer
            currency: String(sub.currency || "usd").toLowerCase(),
            description: `Rysflo breath credit: ${testCount} breath test${testCount === 1 ? "" : "s"} (${ymd(periodStart)} – ${ymd(periodEnd)})`,
            metadata: {
              stripe_subscription_id: sub.stripe_subscription_id,
              period_start: ymd(periodStart),
              tests: String(testCount),
            },
          },
          { idempotencyKey: `breath-credit-${sub.stripe_subscription_id}-${ymd(periodStart)}` }
        );
        txnId = txn.id;
      }

      if (!dryRun) {
        await pool.execute(
          `
            INSERT IGNORE INTO breath_credits
              (stripe_subscription_id, profile_id, period_start, period_end,
               reading_days, days_in_period, credit_minor, stripe_balance_txn_id, applied_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, IF(? IS NULL, NULL, UTC_TIMESTAMP()))
          `,
          [
            sub.stripe_subscription_id,
            sub.profile_id,
            ymd(periodStart),
            ymd(periodEnd),
            testCount,
            daysInPeriod,
            creditMinor,
            txnId,
            txnId,
          ]
        );
      }

      if (creditMinor > 0) summary.credited += 1; else summary.zero += 1;
      item.stripe_balance_txn_id = txnId;
    } catch (err) {
      summary.errors += 1;
      item.error = err?.message;
      console.error("BREATH_CREDIT_ERROR:", { subscription: sub.stripe_subscription_id, message: err?.message });
    }

    summary.items.push(item);
  }

  return summary;
}

module.exports = { runBreathCredits, creditForTests, linkProfilesByEmail };
