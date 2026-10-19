"use strict";

/**
 * POST /dietitian/api/web/super-admin-orders
 *   (super_admin, plus trainer admins listed in ORDERS_VIEWER_EMAILS)
 *
 * Website (/order) purchases as recorded by the Stripe webhook. Read-only.
 * Listed trainer admins see the same rows as a super admin (every buyer, not
 * just their network); test codes and cancelling stay super_admin only.
 *
 *   view=shipping  subscription_shipping_addresses, one row per purchase:
 *                  who to ship the device to (name, phone, address)
 *   view=payments  payment_transactions, one row per Stripe invoice: the first
 *                  payment, each renewal, failed payments and refunds.
 *                  type=renewal keeps renewal invoices only (billing_reason
 *                  subscription_cycle) for the Renewals tab, and the summary
 *                  then counts renewals only. Each row carries renewal_number
 *                  (1 = first renewal; null for other invoices), the plan as it
 *                  stands now and the facility behind the partner code.
 *                  paid_only=true drops invoices that never went through
 *                  (failed / open): the Renewals tab lists members who did
 *                  renew. Refunds stay, since the renewal was paid first.
 *   view=upcoming_renewals
 *                  referral_subscriptions still set to renew (active or
 *                  trialing, not cancelled) whose current_period_end falls in
 *                  the next `days` days (default 7), soonest first. Each row
 *                  carries the renewals paid so far and the last payment.
 *                  Super-admin test codes (test_… rows) are left out.
 *
 * Both join referral_subscriptions (by stripe_subscription_id) for the buyer's
 * email / name and the partner code used. Shipping rows also carry the plan's
 * current_period_start / current_period_end and a derived subscription_status:
 * a Stripe "active" plan whose period end has passed is reported as "expired".
 * Shipping rows also carry the facility behind the partner code (the gym and
 * its facility admin, same lookup as Sales Analytics' top_trainers), or null
 * for a website purchase / a trainer outside any facility.
 *
 * Body: { view: "shipping" | "payments" | "upcoming_renewals", search?, page?, limit?,
 *         payments only: status? ("all" | open | paid | failed | refunded | partially_refunded),
 *                        type? ("all" | first_payment | renewal), paid_only? (boolean),
 *         upcoming_renewals only: days? (1-31, default 7) }
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");
const { trainerHierarchy } = require("./super-admin-sales-analytics");

const SEARCH_MIN_LENGTH = 3;
const MAX_LIMIT = 100;
const PAYMENT_STATUSES = ["open", "paid", "failed", "refunded", "partially_refunded"];
// Invoices that were paid (a refund came later, if at all).
const PAID_STATUSES = ["paid", "partially_refunded", "refunded"];
// Payment type filter -> Stripe invoice billing_reason.
const PAYMENT_TYPES = { first_payment: "subscription_create", renewal: "subscription_cycle" };
const UPCOMING_DAYS = 7;
const UPCOMING_MAX_DAYS = 31;

// Trainer admins (app_user_roles role "admin") who may also read orders.
// Comma-separated; override with ORDERS_VIEWER_EMAILS=a@x.com,b@y.com.
// Mirrored in the frontend's src/lib/ordersAccess.js for the menu link.
const ORDERS_VIEWER_EMAILS = String(
  process.env.ORDERS_VIEWER_EMAILS || "evan.gaudet@gmail.com,derek.lopez88@gmail.com,sagar@respyr.in"
)
  .split(",")
  .map((email) => email.trim().toLowerCase())
  .filter(Boolean);

const minorToMajor = (v) => (v == null ? null : Math.round(Number(v)) / 100);

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toIso(v) {
  if (!v) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().replace(".000Z", "Z");
}

// Stripe status → what the page shows. "expired" is derived: Stripe keeps the
// last status it sent (usually "active") once a plan's period is over and no
// renewal invoice was paid, so the end date decides.
const SUB_STATUS_LABEL = { canceled: "cancelled", incomplete_expired: "expired" };
const RUNNING_SUB_STATUSES = new Set(["active", "trialing", "past_due"]);

function deriveSubscriptionStatus(row, now = Date.now()) {
  const raw = row.subscription_status ? String(row.subscription_status).toLowerCase() : null;
  if (!raw) return null;
  if (row.canceled_at || raw === "canceled") return "cancelled";
  const endIso = toIso(row.current_period_end);
  if (RUNNING_SUB_STATUSES.has(raw) && endIso && Date.parse(endIso) < now) return "expired";
  return SUB_STATUS_LABEL[raw] || raw;
}

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function parsePaging(body) {
  const page = Math.max(1, parseInt(body.page, 10) || 1);
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(body.limit, 10) || 20));
  return { page, limit, offset: (page - 1) * limit };
}

function parseSearch(body) {
  const search = String(body.search || "").trim().slice(0, 100);
  if (search && search.length < SEARCH_MIN_LENGTH) {
    throw httpError(422, `search must be at least ${SEARCH_MIN_LENGTH} characters`);
  }
  return search;
}

const like = (s) => `%${s.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

// Partner code → { id, name, partner_code, status, admin_user_id, admin_name }
// for the codes on this page. Only names a column, so a failed lookup leaves
// the facility empty instead of failing the shipping list.
async function facilityByCode(rows, codeOf) {
  const codes = [...new Set(rows.map(codeOf).filter(Boolean))];
  const out = new Map();
  if (!codes.length) return out;
  try {
    const items = rows.filter((r) => codeOf(r)).map((r) => ({ code: codeOf(r), linkedCode: null, raw: r }));
    const hierarchy = await trainerHierarchy(codes, items);
    for (const [code, h] of hierarchy) if (h.facility) out.set(code, h.facility);
  } catch (err) {
    console.error("SUPER_ADMIN_ORDERS_FACILITY_LOOKUP_ERROR:", { code: err?.code, message: err?.message });
  }
  return out;
}

async function shipping(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);

  const where = [];
  const params = [];
  if (search) {
    where.push(`(
      rs.purchaser_email LIKE ? OR rs.purchaser_name LIKE ? OR sa.name LIKE ? OR sa.phone LIKE ?
      OR sa.city LIKE ? OR sa.postal_code LIKE ? OR rs.attributed_partner_code LIKE ?
    )`);
    params.push(...Array(7).fill(like(search)));
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const from = `
    FROM subscription_shipping_addresses sa
    LEFT JOIN referral_subscriptions rs ON rs.stripe_subscription_id = sa.stripe_subscription_id
  `;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total ${from} ${whereSql}`, params);
  const [rows] = await pool.query(
    `
      SELECT
        sa.id, sa.stripe_subscription_id, sa.name, sa.phone, sa.line1, sa.line2, sa.city,
        sa.state, sa.postal_code, sa.country, sa.created_at,
        rs.purchaser_email, rs.purchaser_name, rs.attributed_partner_code, rs.status AS subscription_status,
        rs.attributed_user_id, rs.attributed_role, rs.facility_id,
        rs.current_period_start, rs.current_period_end, rs.canceled_at,
        rs.created_at AS purchased_at
      ${from} ${whereSql}
      ORDER BY sa.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  const now = Date.now();
  return {
    filters: { search, search_min_length: SEARCH_MIN_LENGTH },
    addresses: rows.map((r) => ({
      id: Number(r.id),
      purchased_at: toIso(r.purchased_at || r.created_at),
      customer: { name: r.purchaser_name || null, email: r.purchaser_email || null },
      ship_to: {
        name: r.name || null,
        phone: r.phone || null,
        line1: r.line1 || null,
        line2: r.line2 || null,
        city: r.city || null,
        state: r.state || null,
        postal_code: r.postal_code || null,
        country: r.country || null,
      },
      partner_code: r.attributed_partner_code || null,
      facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
      subscription_status: deriveSubscriptionStatus(r, now),
      stripe_status: r.subscription_status || null,
      current_period_start: toIso(r.current_period_start),
      current_period_end: toIso(r.current_period_end),
      canceled_at: toIso(r.canceled_at),
      stripe_subscription_id: r.stripe_subscription_id,
    })),
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
  };
}

async function payments(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);
  const paidOnly = body.paid_only === true || body.paid_only === "true";
  const statusOptions = paidOnly ? PAID_STATUSES : PAYMENT_STATUSES;
  const status = String(body.status || "all").toLowerCase();
  if (status !== "all" && !statusOptions.includes(status)) {
    throw httpError(422, `status must be all or one of ${statusOptions.join(", ")}`);
  }
  const type = String(body.type || "all").toLowerCase();
  if (type !== "all" && !PAYMENT_TYPES[type]) {
    throw httpError(422, `type must be all or one of ${Object.keys(PAYMENT_TYPES).join(", ")}`);
  }
  const billingReason = type === "all" ? null : PAYMENT_TYPES[type];

  // Type and paid-only scope both the list and the summary chips.
  const scope = [];
  const scopeParams = [];
  if (billingReason) {
    scope.push("pt.billing_reason = ?");
    scopeParams.push(billingReason);
  }
  if (paidOnly) {
    scope.push(`pt.status IN (${PAID_STATUSES.map(() => "?").join(", ")})`);
    scopeParams.push(...PAID_STATUSES);
  }

  const where = [];
  const params = [];
  if (status !== "all") {
    where.push("pt.status = ?");
    params.push(status);
  }
  where.push(...scope);
  params.push(...scopeParams);
  if (search) {
    where.push(`(
      rs.purchaser_email LIKE ? OR rs.purchaser_name LIKE ? OR pt.stripe_invoice_id LIKE ?
      OR pt.stripe_subscription_id LIKE ? OR rs.attributed_partner_code LIKE ?
    )`);
    params.push(...Array(5).fill(like(search)));
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const from = `
    FROM payment_transactions pt
    LEFT JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id
  `;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total ${from} ${whereSql}`, params);
  const [rows] = await pool.query(
    `
      SELECT
        pt.id, pt.stripe_subscription_id, pt.stripe_invoice_id, pt.stripe_payment_intent_id, pt.stripe_charge_id,
        pt.billing_reason, pt.period_start, pt.period_end, pt.amount_paid_minor, pt.amount_refunded_minor,
        pt.currency, pt.fee_minor, pt.net_minor, pt.status, pt.failure_message, pt.payment_method_type,
        pt.card_last4, pt.paid_at, pt.created_at,
        rs.purchaser_email, rs.purchaser_name, rs.attributed_partner_code,
        rs.status AS subscription_status, rs.current_period_start, rs.current_period_end, rs.canceled_at,
        -- Which renewal of its subscription this invoice is (rows are written
        -- in billing order, so earlier renewals have lower ids).
        CASE WHEN pt.billing_reason = 'subscription_cycle' THEN (
          SELECT COUNT(*) FROM payment_transactions p2
          WHERE p2.stripe_subscription_id = pt.stripe_subscription_id
            AND p2.billing_reason = 'subscription_cycle'
            AND p2.id <= pt.id
        ) END AS renewal_number
      ${from} ${whereSql}
      ORDER BY COALESCE(pt.paid_at, pt.created_at) DESC, pt.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  // Totals per status and currency across every payment of this type (not
  // just this page, and ignoring the status and search filters).
  const [counts] = await pool.query(
    `SELECT status, currency, COUNT(*) AS n, SUM(amount_paid_minor) AS paid, SUM(amount_refunded_minor) AS refunded
     FROM payment_transactions pt ${scope.length ? `WHERE ${scope.join(" AND ")}` : ""} GROUP BY status, currency`,
    scopeParams
  );

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  const now = Date.now();
  return {
    filters: { status, type, paid_only: paidOnly, search, search_min_length: SEARCH_MIN_LENGTH },
    payments: rows.map((r) => ({
      id: Number(r.id),
      date: toIso(r.paid_at || r.created_at),
      customer: { name: r.purchaser_name || null, email: r.purchaser_email || null },
      partner_code: r.attributed_partner_code || null,
      facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
      type: r.billing_reason === "subscription_create" ? "first_payment" : r.billing_reason === "subscription_cycle" ? "renewal" : r.billing_reason || null,
      renewal_number: r.renewal_number == null ? null : Number(r.renewal_number),
      period_start: toIso(r.period_start),
      period_end: toIso(r.period_end),
      currency: r.currency,
      amount_paid: minorToMajor(r.amount_paid_minor),
      amount_refunded: minorToMajor(r.amount_refunded_minor),
      fee: minorToMajor(r.fee_minor),
      net: minorToMajor(r.net_minor),
      status: r.status,
      failure_message: r.failure_message || null,
      payment_method: { type: r.payment_method_type || null, last4: r.card_last4 || null },
      stripe: {
        subscription_id: r.stripe_subscription_id || null,
        invoice_id: r.stripe_invoice_id,
        payment_intent_id: r.stripe_payment_intent_id || null,
        charge_id: r.stripe_charge_id || null,
      },
      // The subscription as it stands now (same fields as a shipping row).
      plan: {
        subscription_status: deriveSubscriptionStatus(r, now),
        stripe_status: r.subscription_status || null,
        current_period_start: toIso(r.current_period_start),
        current_period_end: toIso(r.current_period_end),
        canceled_at: toIso(r.canceled_at),
      },
    })),
    summary: counts.map((c) => ({
      status: c.status,
      currency: c.currency,
      count: Number(c.n),
      amount_paid: minorToMajor(c.paid),
      amount_refunded: minorToMajor(c.refunded),
    })),
    status_options: statusOptions,
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
  };
}

async function upcomingRenewals(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);
  const days = Math.min(UPCOMING_MAX_DAYS, Math.max(1, parseInt(body.days, 10) || UPCOMING_DAYS));

  // Still set to renew: running, not cancelled (cancel at period end sets
  // canceled_at too), and the period ends within the window. Test-code rows
  // (test_…) have no Stripe subscription behind them.
  const where = [
    "rs.status IN ('active', 'trialing')",
    "rs.canceled_at IS NULL",
    "rs.current_period_end > UTC_TIMESTAMP()",
    "rs.current_period_end <= UTC_TIMESTAMP() + INTERVAL ? DAY",
    "LEFT(rs.stripe_subscription_id, 5) <> 'test_'",
  ];
  const params = [days];
  if (search) {
    where.push(`(
      rs.purchaser_email LIKE ? OR rs.purchaser_name LIKE ? OR rs.attributed_partner_code LIKE ?
      OR rs.stripe_subscription_id LIKE ?
    )`);
    params.push(...Array(4).fill(like(search)));
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM referral_subscriptions rs ${whereSql}`, params);
  const [rows] = await pool.query(
    `
      SELECT
        rs.id, rs.stripe_subscription_id, rs.purchaser_email, rs.purchaser_name, rs.attributed_partner_code,
        rs.status AS subscription_status, rs.current_period_start, rs.current_period_end, rs.canceled_at,
        rs.currency, rs.unit_amount_minor, rs.created_at AS purchased_at
      FROM referral_subscriptions rs
      ${whereSql}
      ORDER BY rs.current_period_end ASC, rs.id ASC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  // Paid invoices of these subscriptions: renewals so far and the last payment.
  const subIds = rows.map((r) => r.stripe_subscription_id);
  const history = new Map();
  if (subIds.length) {
    const [paid] = await pool.query(
      `
        SELECT stripe_subscription_id, billing_reason, amount_paid_minor, currency, paid_at, created_at
        FROM payment_transactions
        WHERE stripe_subscription_id IN (?) AND status IN (?)
        ORDER BY COALESCE(paid_at, created_at) ASC, id ASC
      `,
      [subIds, PAID_STATUSES]
    );
    for (const p of paid) {
      const h = history.get(p.stripe_subscription_id) || { renewals: 0, last: null };
      if (p.billing_reason === "subscription_cycle") h.renewals += 1;
      h.last = p;
      history.set(p.stripe_subscription_id, h);
    }
  }

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  const now = Date.now();
  return {
    filters: { days, search, search_min_length: SEARCH_MIN_LENGTH },
    upcoming: rows.map((r) => {
      const h = history.get(r.stripe_subscription_id) || { renewals: 0, last: null };
      return {
        id: Number(r.id),
        renews_at: toIso(r.current_period_end),
        customer: { name: r.purchaser_name || null, email: r.purchaser_email || null },
        partner_code: r.attributed_partner_code || null,
        facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
        purchased_at: toIso(r.purchased_at),
        // This coming renewal is renewals_so_far + 1.
        renewals_so_far: h.renewals,
        last_payment: h.last
          ? {
              amount_paid: minorToMajor(h.last.amount_paid_minor),
              currency: h.last.currency,
              date: toIso(h.last.paid_at || h.last.created_at),
              type: h.last.billing_reason === "subscription_create" ? "first_payment" : h.last.billing_reason === "subscription_cycle" ? "renewal" : h.last.billing_reason || null,
            }
          : null,
        plan_price: { amount: minorToMajor(r.unit_amount_minor), currency: r.currency },
        subscription_status: deriveSubscriptionStatus(r, now),
        stripe_status: r.subscription_status || null,
        current_period_start: toIso(r.current_period_start),
        current_period_end: toIso(r.current_period_end),
        stripe_subscription_id: r.stripe_subscription_id,
      };
    }),
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

const superAdminOrders = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const view = String(body.view || "shipping");
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, ["super_admin", "admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });
    const actorRole = String(resolved.actor.role);
    if (actorRole !== "super_admin" && !ORDERS_VIEWER_EMAILS.includes(resolved.actorEmail)) {
      return res.status(403).json({ status: false, ok: false, message: "You are not allowed to perform this action" });
    }

    let payload;
    if (view === "shipping") payload = await shipping(body);
    else if (view === "payments") payload = await payments(body);
    else if (view === "upcoming_renewals") payload = await upcomingRenewals(body);
    else return res.status(422).json({ status: false, ok: false, message: "view must be shipping, payments or upcoming_renewals" });

    // Shipping rows carry buyers' home addresses and phones: log every read.
    await H.writeAuthLogSafe(req, {
      eventType: "super_admin_orders_viewed",
      userId: resolved.actorEmail,
      role: resolved.actor.role,
      partnerCode: null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: `view=${view}`,
    });

    return res.status(200).json({ status: true, ok: true, view, ...payload });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, message: err.message });
    console.error("SUPER_ADMIN_ORDERS_ERROR:", { view, code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "super_admin_orders_error",
        userId: resolved.actorEmail,
        role: resolved.actor.role,
        partnerCode: null,
        identifier: resolved.actorEmail,
        success: false,
        failureReason: String(err?.code || "internal_error"),
      });
    }
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { superAdminOrders };
