"use strict";

/**
 * POST /dietitian/api/web/super-admin-orders   (super_admin only)
 *
 * Website (/order) purchases as recorded by the Stripe webhook. Read-only.
 *
 *   view=shipping  subscription_shipping_addresses, one row per purchase:
 *                  who to ship the device to (name, phone, address)
 *   view=payments  payment_transactions, one row per Stripe invoice: the first
 *                  payment, each renewal, failed payments and refunds
 *
 * Both join referral_subscriptions (by stripe_subscription_id) for the buyer's
 * email / name and the partner code used.
 *
 * Body: { view: "shipping" | "payments", search?, page?, limit?,
 *         payments only: status? ("all" | open | paid | failed | refunded | partially_refunded) }
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const SEARCH_MIN_LENGTH = 3;
const MAX_LIMIT = 100;
const PAYMENT_STATUSES = ["open", "paid", "failed", "refunded", "partially_refunded"];

const minorToMajor = (v) => (v == null ? null : Math.round(Number(v)) / 100);

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toIso(v) {
  if (!v) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().replace(".000Z", "Z");
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
        rs.created_at AS purchased_at
      ${from} ${whereSql}
      ORDER BY sa.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

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
      subscription_status: r.subscription_status || null,
      stripe_subscription_id: r.stripe_subscription_id,
    })),
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
  };
}

async function payments(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);
  const status = String(body.status || "all").toLowerCase();
  if (status !== "all" && !PAYMENT_STATUSES.includes(status)) {
    throw httpError(422, `status must be all or one of ${PAYMENT_STATUSES.join(", ")}`);
  }

  const where = [];
  const params = [];
  if (status !== "all") {
    where.push("pt.status = ?");
    params.push(status);
  }
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
        rs.purchaser_email, rs.purchaser_name, rs.attributed_partner_code
      ${from} ${whereSql}
      ORDER BY COALESCE(pt.paid_at, pt.created_at) DESC, pt.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  // Totals per status and currency across every payment (not just this page).
  const [counts] = await pool.query(
    `SELECT status, currency, COUNT(*) AS n, SUM(amount_paid_minor) AS paid, SUM(amount_refunded_minor) AS refunded
     FROM payment_transactions GROUP BY status, currency`
  );

  return {
    filters: { status, search, search_min_length: SEARCH_MIN_LENGTH },
    payments: rows.map((r) => ({
      id: Number(r.id),
      date: toIso(r.paid_at || r.created_at),
      customer: { name: r.purchaser_name || null, email: r.purchaser_email || null },
      partner_code: r.attributed_partner_code || null,
      type: r.billing_reason === "subscription_create" ? "first_payment" : r.billing_reason === "subscription_cycle" ? "renewal" : r.billing_reason || null,
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
    })),
    summary: counts.map((c) => ({
      status: c.status,
      currency: c.currency,
      count: Number(c.n),
      amount_paid: minorToMajor(c.paid),
      amount_refunded: minorToMajor(c.refunded),
    })),
    status_options: PAYMENT_STATUSES,
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
    resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    let payload;
    if (view === "shipping") payload = await shipping(body);
    else if (view === "payments") payload = await payments(body);
    else return res.status(422).json({ status: false, ok: false, message: "view must be shipping or payments" });

    // Shipping rows carry buyers' home addresses and phones: log every read.
    await H.writeAuthLogSafe(req, {
      eventType: "super_admin_orders_viewed",
      userId: resolved.actorEmail,
      role: "super_admin",
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
        role: "super_admin",
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
