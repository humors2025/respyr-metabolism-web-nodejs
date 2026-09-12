"use strict";

/**
 * Breath-test credit: every day a member records a reading earns $0.20 off
 * the next month's invoice, capped at $6.00. A full month always earns the
 * full $6.00 — so February (28 days) reaches the cap at 28 reading-days, and a
 * 31-day month is capped at 30 reading-days' worth.
 *
 * Mechanism: shortly before a subscription renews, count the member's
 * reading-days in the current billing period and post a negative Customer
 * Balance Transaction on the Stripe customer. Stripe applies the balance to
 * the next invoice automatically, so invoice.amount_paid — which the
 * commission ledger uses — is already net of the credit.
 *
 * Idempotent: one breath_credits row per (subscription, period_start); the
 * Stripe call carries an idempotency key derived from the same pair.
 */

const pool = require("../config/db");
const {
  requireStripe,
  BREATH_CREDIT_PER_DAY_MINOR,
  BREATH_CREDIT_CAP_MINOR,
  BREATH_CREDIT_FULL_DAYS,
} = require("../config/stripe");

const RENEWAL_WINDOW_HOURS = 36;

function ymd(d) {
  return d.toISOString().slice(0, 10);
}

/** Whole days between two Date objects (UTC), minimum 1. */
function daysBetween(a, b) {
  return Math.max(1, Math.round((b.getTime() - a.getTime()) / 86400000));
}

/**
 * Credit in minor units for `readingDays` in a period of `daysInPeriod` days.
 * Exported for tests.
 */
function creditForReadingDays(readingDays, daysInPeriod) {
  const fullMonthDays = Math.min(BREATH_CREDIT_FULL_DAYS, daysInPeriod);
  if (readingDays >= fullMonthDays) return BREATH_CREDIT_CAP_MINOR;
  return Math.min(BREATH_CREDIT_CAP_MINOR, readingDays * BREATH_CREDIT_PER_DAY_MINOR);
}

/** Link purchase code redemptions and unique email matches -> app profile. */
async function linkProfilesByEmail() {
  const r = await require("./purchaseCodes").linkProfiles();
  return r.by_purchase_code + r.by_email;
}

async function countReadingDays(profileId, periodStart, periodEndExclusive) {
  const [rows] = await pool.execute(
    `
      SELECT COUNT(DISTINCT DATE(date_time)) AS days
      FROM table_test_data
      WHERE profile_id = ?
        AND date_time >= ?
        AND date_time <  ?
    `,
    [profileId, periodStart, periodEndExclusive]
  );
  return Number(rows[0]?.days || 0);
}

/**
 * Run the credit pass. `now` is injectable for tests.
 * Returns a summary of what was credited / skipped.
 */
async function runBreathCredits({ now = new Date(), dryRun = false } = {}) {
  const stripe = dryRun ? null : requireStripe();
  const linked = await linkProfilesByEmail();

  const windowEnd = new Date(now.getTime() + RENEWAL_WINDOW_HOURS * 3600000);

  // Active subscriptions renewing inside the window (or already past the end
  // because a run was missed) that have no credit for this period yet.
  const [subs] = await pool.execute(
    `
      SELECT rs.id, rs.stripe_subscription_id, rs.stripe_customer_id, rs.profile_id,
             rs.currency, rs.current_period_start, rs.current_period_end
      FROM referral_subscriptions rs
      LEFT JOIN breath_credits bc
        ON bc.stripe_subscription_id = rs.stripe_subscription_id
       AND bc.period_start = DATE(rs.current_period_start)
      WHERE rs.status IN ('active','past_due')
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

    const readingDays = await countReadingDays(
      sub.profile_id,
      sub.current_period_start,
      countUntil.toISOString().slice(0, 19).replace("T", " ")
    );
    const creditMinor = creditForReadingDays(readingDays, daysInPeriod);

    const item = {
      subscription: sub.stripe_subscription_id,
      profile_id: sub.profile_id,
      period: `${ymd(periodStart)}..${ymd(periodEnd)}`,
      days_in_period: daysInPeriod,
      reading_days: readingDays,
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
            description: `Rysflo breath credit: ${readingDays} reading day${readingDays === 1 ? "" : "s"} (${ymd(periodStart)} – ${ymd(periodEnd)})`,
            metadata: {
              stripe_subscription_id: sub.stripe_subscription_id,
              period_start: ymd(periodStart),
              reading_days: String(readingDays),
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
            readingDays,
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

module.exports = { runBreathCredits, creditForReadingDays, linkProfilesByEmail };
