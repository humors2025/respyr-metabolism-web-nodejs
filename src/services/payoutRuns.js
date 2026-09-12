"use strict";

/**
 * Payout run: turn pending commission entries into Stripe Transfers to each
 * payee's connected account.
 *
 *  - Groups pending entries by payee; skips payees without payouts_enabled
 *    (their entries stay 'held'/'pending' and are picked up next run).
 *  - Nets fully-refunded-after-payment entries (reversed_by_invoice_id set on
 *    a paid entry) against the payee's next payout.
 *  - One payouts row + one Transfer per payee per run, idempotent on
 *    (payee, period_end) so a crashed run can be re-invoked safely.
 *  - A Transfer to a connected account settles synchronously; the entries are
 *    marked 'paid' in the same transaction the transfer id is stored.
 *  - Minimum payout threshold avoids sending $0.40 transfers.
 */

const pool = require("../config/db");
const { requireStripe } = require("../config/stripe");
const connect = require("./stripeConnectAccounts");

const MIN_PAYOUT_MINOR = Math.max(0, parseInt(process.env.PAYOUT_MIN_MINOR, 10) || 2500); // $25

function ymd(d) {
  return d.toISOString().slice(0, 10);
}

/**
 * Run payouts for entries with invoice_paid_at < periodEnd (exclusive).
 * Default period: the calendar month before `now`.
 */
async function runPayouts({ now = new Date(), periodEnd = null, initiatedBy = "scheduler", dryRun = false } = {}) {
  const stripe = dryRun ? null : requireStripe();

  const end = periodEnd
    ? new Date(periodEnd)
    : new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1)); // first of this month → pays last month
  const endStr = end.toISOString().slice(0, 19).replace("T", " ");

  // Candidates: pending entries before the cut-off, grouped by payee, only for
  // payees whose Connect account can receive transfers.
  const [groups] = await pool.execute(
    `
      SELECT
        ce.payee_user_id,
        ce.currency,
        ppa.stripe_account_id,
        COUNT(*)            AS entry_count,
        SUM(ce.amount_minor) AS gross_minor,
        MIN(ce.invoice_paid_at) AS first_paid_at
      FROM commission_entries ce
      JOIN partner_payout_accounts ppa
        ON LOWER(ppa.user_id) = LOWER(ce.payee_user_id)
       AND ppa.payouts_enabled = 1
      WHERE ce.status = 'pending'
        AND ce.invoice_paid_at < ?
      GROUP BY ce.payee_user_id, ce.currency, ppa.stripe_account_id
    `,
    [endStr]
  );

  const summary = { period_end: ymd(end), payees: groups.length, paid: 0, skipped_below_min: 0, errors: 0, items: [] };

  for (const g of groups) {
    const payee = String(g.payee_user_id).toLowerCase();
    const currency = String(g.currency).toUpperCase();

    // Clawbacks: entries paid earlier whose invoice was later refunded.
    const [claw] = await pool.execute(
      `
        SELECT COALESCE(SUM(amount_minor), 0) AS minor, COUNT(*) AS n
        FROM commission_entries
        WHERE LOWER(payee_user_id) = ? AND currency = ?
          AND status = 'paid' AND reversed_by_invoice_id IS NOT NULL AND payout_id IS NOT NULL
          AND hold_reason IS NULL
      `,
      [payee, currency]
    );
    const clawMinor = Number(claw[0].minor);
    const netMinor = Number(g.gross_minor) - clawMinor;

    const item = {
      payee,
      currency,
      entries: Number(g.entry_count),
      gross_minor: Number(g.gross_minor),
      clawback_minor: clawMinor,
      net_minor: netMinor,
    };

    if (netMinor < MIN_PAYOUT_MINOR) {
      summary.skipped_below_min += 1;
      item.skipped = `below minimum ${MIN_PAYOUT_MINOR}`;
      summary.items.push(item);
      continue;
    }

    if (dryRun) {
      item.dry_run = true;
      summary.items.push(item);
      continue;
    }

    // Our copy of the capability can be stale (v2 accounts push thin events we
    // do not consume yet). Re-check with Stripe before moving money.
    if (!(await connect.canReceiveTransfers(g.stripe_account_id))) {
      await connect.syncAccount(payee, g.stripe_account_id);
      item.skipped = "stripe_transfers capability not active";
      summary.items.push(item);
      continue;
    }

    const idem = `payout-${payee}-${currency}-${ymd(end)}`;
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Create (or reuse, on re-run) the payout row.
      await conn.execute(
        `
          INSERT IGNORE INTO payouts
            (payee_user_id, stripe_account_id, period_start, period_end, entry_count,
             amount_minor, currency, status, idempotency_key, initiated_by)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'processing', ?, ?)
        `,
        [payee, g.stripe_account_id, ymd(new Date(g.first_paid_at)), ymd(end), item.entries, netMinor, currency, idem, initiatedBy]
      );
      const [prow] = await conn.execute(
        `SELECT id, stripe_transfer_id, status FROM payouts WHERE idempotency_key = ? FOR UPDATE`,
        [idem]
      );
      const payout = prow[0];

      if (payout.status === "paid" && payout.stripe_transfer_id) {
        await conn.commit();
        item.skipped = "already paid";
        summary.items.push(item);
        continue;
      }

      // Attach entries to this payout before calling Stripe so a crash between
      // the transfer and the commit is recoverable by the idempotency key.
      await conn.execute(
        `
          UPDATE commission_entries
          SET status = 'scheduled', payout_id = ?, updated_at = UTC_TIMESTAMP()
          WHERE LOWER(payee_user_id) = ? AND currency = ? AND status = 'pending' AND invoice_paid_at < ?
        `,
        [payout.id, payee, currency, endStr]
      );
      await conn.execute(
        `
          UPDATE commission_entries
          SET hold_reason = CONCAT('netted in payout ', ?), updated_at = UTC_TIMESTAMP()
          WHERE LOWER(payee_user_id) = ? AND currency = ?
            AND status = 'paid' AND reversed_by_invoice_id IS NOT NULL AND payout_id IS NOT NULL
            AND hold_reason IS NULL
        `,
        [String(payout.id), payee, currency]
      );

      const transfer = await stripe.transfers.create(
        {
          amount: netMinor,
          currency: currency.toLowerCase(),
          destination: g.stripe_account_id,
          description: `Rysflo referral commission through ${ymd(end)}`,
          transfer_group: `payout_${payout.id}`,
          metadata: { payout_id: String(payout.id), payee_user_id: payee, period_end: ymd(end) },
        },
        { idempotencyKey: idem }
      );

      await conn.execute(
        `
          UPDATE payouts
          SET stripe_transfer_id = ?, status = 'paid', paid_at = UTC_TIMESTAMP(), updated_at = UTC_TIMESTAMP()
          WHERE id = ?
        `,
        [transfer.id, payout.id]
      );
      await conn.execute(
        `UPDATE commission_entries SET status = 'paid', updated_at = UTC_TIMESTAMP() WHERE payout_id = ? AND status = 'scheduled'`,
        [payout.id]
      );

      await conn.commit();
      summary.paid += 1;
      item.payout_id = payout.id;
      item.stripe_transfer_id = transfer.id;
    } catch (err) {
      await conn.rollback();
      // Leave the payout row (if any) as 'failed' so the super_admin sees it.
      await pool.execute(
        `UPDATE payouts SET status = 'failed', failure_reason = ?, updated_at = UTC_TIMESTAMP() WHERE idempotency_key = ? AND status = 'processing'`,
        [String(err?.message || "transfer failed").slice(0, 500), idem]
      );
      await pool.execute(
        `UPDATE commission_entries ce JOIN payouts p ON p.id = ce.payout_id
         SET ce.status = 'pending', ce.payout_id = NULL WHERE p.idempotency_key = ? AND ce.status = 'scheduled'`,
        [idem]
      );
      summary.errors += 1;
      item.error = err?.message;
      console.error("PAYOUT_RUN_ERROR:", { payee, message: err?.message });
    } finally {
      conn.release();
    }

    summary.items.push(item);
  }

  return summary;
}

module.exports = { runPayouts, MIN_PAYOUT_MINOR };
