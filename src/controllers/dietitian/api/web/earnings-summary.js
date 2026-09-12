"use strict";

/**
 * POST /dietitian/api/web/earnings-summary        (admin, facility_admin, trainer)
 *
 * Everything the Earnings > Overview page shows, for the authenticated payee:
 *  {
 *    ok, currency,
 *    this_month_minor, last_month_minor, lifetime_paid_minor,
 *    pending_minor, held_minor, scheduled_minor,
 *    next_payout_date,                       // first of next month (UTC)
 *    active_subscriptions,                   // subs attributed to codes that pay this user
 *    rate_pct, split_pct | null,             // trainer's own split, if any
 *    payout_account: { onboarding_status, payouts_enabled } | null,
 *    facility: { id, name, partner_code } | null,
 *    trainers: [ { user_id, name, partner_code, split_pct, this_month_minor, pending_minor } ]  // FA only
 *    recent: [ { invoice_paid_at, amount_minor, status, attributed_partner_code, payee_role } ]
 *  }
 * Money is integer minor units (cents). No PHI: nothing about members is
 * returned beyond counts.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const ROLES = ["admin", "facility_admin", "trainer"];

function monthStart(d) {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1));
}
function addMonths(d, n) {
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + n, 1));
}
function sqlDt(d) {
  return d.toISOString().slice(0, 19).replace("T", " ");
}

const earningsSummary = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await H.resolveActorFromToken(req, ROLES);
    if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
    const { actor, actorEmail } = resolved;
    const role = String(actor.role);

    const now = new Date();
    const thisStart = monthStart(now);
    const nextStart = addMonths(thisStart, 1);
    const lastStart = addMonths(thisStart, -1);

    const [[sums]] = await pool.execute(
      `
        SELECT
          COALESCE(SUM(CASE WHEN invoice_paid_at >= ? AND invoice_paid_at < ? AND status <> 'reversed' THEN amount_minor END), 0) AS this_month_minor,
          COALESCE(SUM(CASE WHEN invoice_paid_at >= ? AND invoice_paid_at < ? AND status <> 'reversed' THEN amount_minor END), 0) AS last_month_minor,
          COALESCE(SUM(CASE WHEN status = 'paid'      THEN amount_minor END), 0) AS lifetime_paid_minor,
          COALESCE(SUM(CASE WHEN status = 'pending'   THEN amount_minor END), 0) AS pending_minor,
          COALESCE(SUM(CASE WHEN status = 'held'      THEN amount_minor END), 0) AS held_minor,
          COALESCE(SUM(CASE WHEN status = 'scheduled' THEN amount_minor END), 0) AS scheduled_minor,
          MAX(currency) AS currency
        FROM commission_entries
        WHERE LOWER(payee_user_id) = ?
      `,
      [sqlDt(thisStart), sqlDt(nextStart), sqlDt(lastStart), sqlDt(thisStart), actorEmail]
    );

    // Active subscriptions that pay this user: attributed to their own code, or
    // (facility admin) to any active trainer in their facility.
    let codes = [String(actor.partner_code || "").toUpperCase()].filter(Boolean);
    if (role === "facility_admin" && actor.facility_id != null) {
      const [tr] = await pool.execute(
        `SELECT partner_code FROM app_user_roles WHERE role = 'trainer' AND facility_id = ? AND status = 'active' AND partner_code IS NOT NULL`,
        [Number(actor.facility_id)]
      );
      codes = codes.concat(tr.map((r) => String(r.partner_code).toUpperCase()));
    }
    let activeSubs = 0;
    if (codes.length) {
      const [[a]] = await pool.query(
        `SELECT COUNT(*) AS n FROM referral_subscriptions WHERE status IN ('active','trialing','past_due') AND UPPER(attributed_partner_code) IN (?)`,
        [codes]
      );
      activeSubs = Number(a.n);
    }

    const [[rate]] = await pool.execute(
      `SELECT rate_pct FROM commission_rates WHERE effective_from <= UTC_TIMESTAMP() ORDER BY effective_from DESC, id DESC LIMIT 1`
    );

    const [[acct]] = await pool.execute(
      `SELECT onboarding_status, payouts_enabled FROM partner_payout_accounts WHERE LOWER(user_id) = ? LIMIT 1`,
      [actorEmail]
    ).then((r) => (r[0].length ? r : [[null]]));

    let facility = null;
    if (actor.facility_id != null) {
      const [[f]] = await pool.execute(
        `SELECT id, name, partner_code FROM facilities WHERE id = ? LIMIT 1`,
        [Number(actor.facility_id)]
      ).then((r) => (r[0].length ? r : [[null]]));
      facility = f;
    }

    let trainers;
    if (role === "facility_admin" && actor.facility_id != null) {
      const [rows] = await pool.execute(
        `
          SELECT aur.user_id, td.name, aur.partner_code, aur.commission_split_pct,
                 COALESCE(SUM(CASE WHEN ce.invoice_paid_at >= ? AND ce.invoice_paid_at < ? AND ce.status <> 'reversed' THEN ce.amount_minor END), 0) AS this_month_minor,
                 COALESCE(SUM(CASE WHEN ce.status IN ('pending','held','scheduled') THEN ce.amount_minor END), 0) AS pending_minor
          FROM app_user_roles aur
          LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
          LEFT JOIN commission_entries ce ON LOWER(ce.payee_user_id) = LOWER(aur.user_id)
          WHERE aur.role = 'trainer' AND aur.facility_id = ? AND aur.status = 'active'
          GROUP BY aur.user_id, td.name, aur.partner_code, aur.commission_split_pct
          ORDER BY td.name
        `,
        [sqlDt(thisStart), sqlDt(nextStart), Number(actor.facility_id)]
      );
      trainers = rows.map((r) => ({
        user_id: String(r.user_id).toLowerCase(),
        name: r.name || null,
        partner_code: r.partner_code,
        split_pct: Number(r.commission_split_pct || 0),
        this_month_minor: Number(r.this_month_minor),
        pending_minor: Number(r.pending_minor),
      }));
    }

    const [recent] = await pool.execute(
      `
        SELECT invoice_paid_at, amount_minor, status, attributed_partner_code, payee_role, share_pct
        FROM commission_entries
        WHERE LOWER(payee_user_id) = ?
        ORDER BY invoice_paid_at DESC, id DESC
        LIMIT 20
      `,
      [actorEmail]
    );

    return res.status(200).json({
      ok: true,
      role,
      partner_code: actor.partner_code || null,
      currency: sums.currency || "USD",
      this_month_minor: Number(sums.this_month_minor),
      last_month_minor: Number(sums.last_month_minor),
      lifetime_paid_minor: Number(sums.lifetime_paid_minor),
      pending_minor: Number(sums.pending_minor),
      held_minor: Number(sums.held_minor),
      scheduled_minor: Number(sums.scheduled_minor),
      next_payout_date: nextStart.toISOString().slice(0, 10),
      active_subscriptions: activeSubs,
      rate_pct: rate ? Number(rate.rate_pct) : null,
      split_pct: role === "trainer" ? Number(actor.commission_split_pct ?? 0) : null,
      payout_account: acct
        ? { onboarding_status: acct.onboarding_status, payouts_enabled: Number(acct.payouts_enabled) === 1 }
        : null,
      facility,
      ...(trainers && { trainers }),
      recent: recent.map((r) => ({ ...r, amount_minor: Number(r.amount_minor), share_pct: Number(r.share_pct) })),
    });
  } catch (err) {
    console.error("EARNINGS_SUMMARY_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { earningsSummary };
