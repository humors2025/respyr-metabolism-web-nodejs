"use strict";

/**
 * Commission ledger.
 *
 * For every paid Stripe invoice on a referral subscription:
 *
 *   gym_commission = invoice.amount_paid x platform_rate      (rate at that time)
 *   trainer share  = gym_commission x trainer.split_pct / 100 (if attributed to a trainer)
 *   owner share    = gym_commission - trainer share
 *
 * amount_paid is what Stripe actually collected — i.e. after the breath-test
 * credit — which is the agreed commission base.
 *
 * Attribution is read from referral_subscriptions at invoice time, so a
 * trainer's removal (which re-keys nothing here) is handled by resolving the
 * attributed user's *current* standing: a removed trainer's share goes to
 * their parent, matching remove-user.js.
 *
 * Every write is append-only; reversals add status='reversed' to existing
 * rows rather than deleting them. All money is integer minor units.
 */

const pool = require("../config/db");
const { resolvePartnerCode } = require("../utils/partnerCodeResolver");

function lower(v) {
  return typeof v === "string" ? v.trim().toLowerCase() : "";
}

/** Platform rate in force at `at` (MySQL datetime string). */
async function rateAt(conn, at) {
  const [rows] = await conn.execute(
    `
      SELECT rate_pct
      FROM commission_rates
      WHERE effective_from <= ?
      ORDER BY effective_from DESC, id DESC
      LIMIT 1
    `,
    [at]
  );
  if (!rows.length) {
    const err = new Error("No commission rate configured");
    err.code = "NO_COMMISSION_RATE";
    throw err;
  }
  return Number(rows[0].rate_pct);
}

/**
 * Current standing of the attributed user. Walks up to the parent when the
 * attributed account is no longer active (same rule as trainer removal).
 */
async function resolvePayees(conn, sub) {
  const [rows] = await conn.execute(
    `
      SELECT user_id, role, status, parent_user_id, facility_id, commission_split_pct
      FROM app_user_roles
      WHERE LOWER(user_id) = ?
      LIMIT 1
    `,
    [lower(sub.attributed_user_id)]
  );
  let row = rows[0] || null;
  let hops = 0;

  while (row && String(row.status) !== "active" && row.parent_user_id && hops < 4) {
    const [p] = await conn.execute(
      `
        SELECT user_id, role, status, parent_user_id, facility_id, commission_split_pct
        FROM app_user_roles
        WHERE LOWER(user_id) = ?
        LIMIT 1
      `,
      [lower(row.parent_user_id)]
    );
    row = p[0] || null;
    hops += 1;
  }

  if (!row || String(row.status) !== "active") return [];

  const role = String(row.role);

  // Trainer with a facility: split between trainer and facility admin.
  if (role === "trainer" && row.facility_id != null) {
    const [fa] = await conn.execute(
      `
        SELECT user_id, role, status
        FROM app_user_roles
        WHERE role = 'facility_admin' AND facility_id = ? AND status = 'active'
        LIMIT 1
      `,
      [Number(row.facility_id)]
    );
    const owner = fa[0] || null;
    const split = Math.min(100, Math.max(0, Number(row.commission_split_pct || 0)));

    const payees = [];
    if (split > 0) {
      payees.push({ user_id: lower(row.user_id), role: "trainer", share_pct: split, facility_id: Number(row.facility_id) });
    }
    if (owner && split < 100) {
      payees.push({ user_id: lower(owner.user_id), role: "facility_admin", share_pct: 100 - split, facility_id: Number(row.facility_id) });
    }
    return payees;
  }

  // Facility admin (wall QR) or admin (Rysflo-managed trainer / admin code): 100%.
  // A trainer directly under an admin (no facility) is paid 100% to that
  // trainer's parent admin — phase 1 pays gyms, not individuals.
  if (role === "trainer") {
    const [p] = await conn.execute(
      `SELECT user_id, role FROM app_user_roles WHERE LOWER(user_id) = ? AND status = 'active' LIMIT 1`,
      [lower(row.parent_user_id)]
    );
    if (!p[0]) return [];
    return [{ user_id: lower(p[0].user_id), role: String(p[0].role), share_pct: 100, facility_id: null }];
  }

  return [{ user_id: lower(row.user_id), role, share_pct: 100, facility_id: row.facility_id == null ? null : Number(row.facility_id) }];
}

/** Whether a payee can currently be paid (verified Connect account). */
async function payeeCanBePaid(conn, userId) {
  const [rows] = await conn.execute(
    `SELECT payouts_enabled FROM partner_payout_accounts WHERE LOWER(user_id) = ? LIMIT 1`,
    [userId]
  );
  return rows.length > 0 && Number(rows[0].payouts_enabled) === 1;
}

/**
 * Split an integer amount by percentage shares so the parts sum exactly to the
 * whole (largest-remainder). Shares are [{share_pct}], returns [minor].
 */
function allocate(totalMinor, shares) {
  const raw = shares.map((s) => (totalMinor * Number(s.share_pct)) / 100);
  const floors = raw.map((r) => Math.floor(r));
  let remainder = totalMinor - floors.reduce((a, b) => a + b, 0);
  const order = raw
    .map((r, i) => ({ i, frac: r - Math.floor(r) }))
    .sort((a, b) => b.frac - a.frac);
  for (const { i } of order) {
    if (remainder <= 0) break;
    floors[i] += 1;
    remainder -= 1;
  }
  return floors;
}

async function recordInvoicePaid({ stripeInvoiceId, stripeSubscriptionId, amountPaidMinor, currency, paidAt }) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [subs] = await conn.execute(
      `SELECT * FROM referral_subscriptions WHERE stripe_subscription_id = ? LIMIT 1 FOR UPDATE`,
      [stripeSubscriptionId]
    );
    let sub = subs[0];

    // Attribution rule (b): no code at purchase, but the member has since
    // linked a gym/trainer in the app -> that code earns from this invoice on.
    if (sub && !sub.attributed_user_id && sub.profile_id) {
      const [tc] = await conn.execute(
        `SELECT dietician_id FROM table_clients WHERE profile_id = ? ORDER BY id DESC LIMIT 1`,
        [sub.profile_id]
      );
      const appCode = tc[0]?.dietician_id ? String(tc[0].dietician_id) : "";
      const resolved = appCode ? await resolvePartnerCode(appCode) : null;
      if (resolved) {
        await conn.execute(
          `UPDATE referral_subscriptions
           SET attributed_partner_code = ?, attributed_user_id = ?, attributed_role = ?, facility_id = ?
           WHERE id = ? AND attributed_user_id IS NULL`,
          [resolved.partner_code, resolved.user_id, resolved.role, resolved.facility_id, sub.id]
        );
        sub = { ...sub, attributed_partner_code: resolved.partner_code, attributed_user_id: resolved.user_id, attributed_role: resolved.role, facility_id: resolved.facility_id };
      }
    }

    // Not a referral sale (or the checkout event has not arrived yet — Stripe
    // can deliver invoice.paid first). Nothing to attribute; the entry can be
    // built later by the reconcile job.
    if (!sub || !sub.attributed_user_id || amountPaidMinor <= 0) {
      await conn.commit();
      return { recorded: 0, reason: !sub ? "unknown_subscription" : !sub.attributed_user_id ? "unattributed" : "zero_amount" };
    }

    const rate = await rateAt(conn, paidAt);
    const gymCommission = Math.round((amountPaidMinor * rate) / 100);
    let payees = await resolvePayees(conn, sub);

    // Payee invited via a sticker but not yet active: hold the whole gym
    // commission against the invited email; rebuilt on activation.
    let awaitingActivation = false;
    if (!payees.length) {
      const [inv] = await conn.execute(
        `SELECT invited_email, invited_role, facility_id FROM app_user_invitations
         WHERE UPPER(partner_code) = ? AND status = 'pending' ORDER BY id DESC LIMIT 1`,
        [String(sub.attributed_partner_code || "").toUpperCase()]
      );
      if (inv[0]) {
        awaitingActivation = true;
        payees = [{ user_id: lower(inv[0].invited_email), role: String(inv[0].invited_role), share_pct: 100, facility_id: inv[0].facility_id == null ? null : Number(inv[0].facility_id) }];
      }
    }

    if (!payees.length) {
      await conn.commit();
      return { recorded: 0, reason: "no_active_payee" };
    }

    const amounts = allocate(gymCommission, payees);
    let recorded = 0;

    for (let i = 0; i < payees.length; i++) {
      const p = payees[i];
      const canPay = !awaitingActivation && (await payeeCanBePaid(conn, p.user_id));
      const [res] = await conn.execute(
        `
          INSERT IGNORE INTO commission_entries (
            stripe_invoice_id, stripe_subscription_id, referral_subscription_id,
            payee_user_id, payee_role, facility_id, attributed_partner_code,
            invoice_paid_at, invoice_net_minor, commission_rate_pct, gym_commission_minor,
            share_pct, amount_minor, currency, status, hold_reason
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          stripeInvoiceId,
          stripeSubscriptionId,
          Number(sub.id),
          p.user_id,
          p.role,
          p.facility_id,
          sub.attributed_partner_code || "",
          paidAt,
          amountPaidMinor,
          rate.toFixed(2),
          gymCommission,
          Number(p.share_pct).toFixed(2),
          amounts[i],
          currency,
          canPay ? "pending" : "held",
          canPay ? null : awaitingActivation ? "awaiting account activation" : "payee has not completed Stripe payout setup",
        ]
      );
      recorded += res.affectedRows;
    }

    await conn.commit();
    return { recorded, gym_commission_minor: gymCommission, rate_pct: rate };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

async function reverseInvoice({ stripeInvoiceId, reason }) {
  const [res] = await pool.execute(
    `
      UPDATE commission_entries
      SET status = 'reversed', hold_reason = ?, updated_at = UTC_TIMESTAMP()
      WHERE stripe_invoice_id = ?
        AND status IN ('pending','held','scheduled')
    `,
    [String(reason).slice(0, 255), stripeInvoiceId]
  );
  // Already-paid entries cannot be pulled back from a transfer that has
  // settled; they are flagged for netting against the payee's next payout.
  await pool.execute(
    `
      UPDATE commission_entries
      SET reversed_by_invoice_id = ?, updated_at = UTC_TIMESTAMP()
      WHERE stripe_invoice_id = ? AND status = 'paid' AND reversed_by_invoice_id IS NULL
    `,
    [stripeInvoiceId, stripeInvoiceId]
  );
  return { reversed: res.affectedRows };
}

/**
 * Entries held for a payee who has since accepted their invite: rebuild them
 * with the real split (facility admin / trainer) now that the account exists.
 */
async function rebuildHeldForActivatedPayees() {
  const [rows] = await pool.execute(
    `
      SELECT DISTINCT ce.stripe_invoice_id, ce.stripe_subscription_id, ce.invoice_net_minor, ce.currency, ce.invoice_paid_at
      FROM commission_entries ce
      JOIN app_user_roles aur ON LOWER(aur.user_id) = LOWER(ce.payee_user_id) AND aur.status = 'active'
      WHERE ce.status = 'held' AND ce.hold_reason = 'awaiting account activation'
    `
  );
  let rebuilt = 0;
  for (const r of rows) {
    await pool.execute(
      `DELETE FROM commission_entries WHERE stripe_invoice_id = ? AND status = 'held' AND hold_reason = 'awaiting account activation'`,
      [r.stripe_invoice_id]
    );
    await recordInvoicePaid({
      stripeInvoiceId: r.stripe_invoice_id,
      stripeSubscriptionId: r.stripe_subscription_id,
      amountPaidMinor: Number(r.invoice_net_minor),
      currency: r.currency,
      paidAt: r.invoice_paid_at instanceof Date ? r.invoice_paid_at.toISOString().slice(0, 19).replace("T", " ") : r.invoice_paid_at,
    });
    rebuilt += 1;
  }
  return { rebuilt };
}

/** Held entries become pending once the payee's Connect account is verified. */
async function releaseHeldForPayee(userId) {
  const [res] = await pool.execute(
    `
      UPDATE commission_entries
      SET status = 'pending', hold_reason = NULL, updated_at = UTC_TIMESTAMP()
      WHERE LOWER(payee_user_id) = ? AND status = 'held'
        AND (hold_reason IS NULL OR hold_reason <> 'awaiting account activation')
    `,
    [lower(userId)]
  );
  return { released: res.affectedRows };
}

module.exports = { recordInvoicePaid, reverseInvoice, releaseHeldForPayee, rebuildHeldForActivatedPayees, allocate, resolvePayees };
