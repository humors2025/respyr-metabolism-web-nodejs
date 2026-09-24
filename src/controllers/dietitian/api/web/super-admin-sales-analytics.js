"use strict";

/**
 * POST /dietitian/api/web/super-admin-sales-analytics   (super_admin only)
 *
 * Network-wide sales for the Rysflo membership, split into website purchases
 * (no trainer attribution) and trainer-code purchases.
 *
 * Data:
 *   referral_subscriptions  one row per purchase (Checkout on the order page):
 *                           buyer, attribution, purchase code, subscription status
 *   sales_invoices          every paid / failed / refunded invoice (first payment
 *                           and renewals) — migration 006, filled by the Stripe
 *                           webhook and by view=sync
 *
 * Definitions:
 *   Source         trainer_code when referral_subscriptions.attributed_partner_code
 *                  is set (same attribution the commission ledger uses), else website.
 *   Purchase       the first invoice of a subscription (billing_reason =
 *                  subscription_create); dated by its paid_at. A fully refunded
 *                  first payment is not counted as a purchase.
 *   Sales          all paid invoices in the period (first payments + renewals):
 *                  gross = subtotal, discounts = coupon/referral discount,
 *                  net = amount paid - amount refunded.
 *   AOV            net of first payments / purchases.
 *
 * Body (all views): { view, period: week|month|year, date_from, date_to (YYYY-MM-DD,
 *                     inclusive, in the viewer's calendar), tz_offset_minutes }
 *   view=overview   → summary, source_breakdown, trend, top_trainers
 *   view=purchases  → + source, subscription_status, payment_status, search, page, limit
 *   view=sync       → { offset } backfills sales_invoices from Stripe in batches
 */

const pool = require("../../../../config/db");
const { requireStripe, PLAN_CODE } = require("../../../../config/stripe");
const salesInvoices = require("../../../../services/salesInvoices");
const { _helpers: H } = require("./admin-invite-trainer");

const YMD = /^\d{4}-\d{2}-\d{2}$/;
const PERIODS = new Set(["week", "month", "year"]);
const SOURCES = new Set(["all", "website", "trainer_code"]);
const PAID_STATUSES = "('paid', 'partially_refunded', 'refunded')";
const SEARCH_MIN_LENGTH = 3;
const TOP_TRAINERS_MAX = 50;
const PLAN_NAMES = { [PLAN_CODE]: "Rysflo Membership" };

// Stripe subscription statuses shown with the spelling the dashboard uses.
const SUB_STATUS_LABEL = { canceled: "cancelled", incomplete_expired: "expired" };
const SUB_STATUS_RAW = { cancelled: ["canceled"], expired: ["incomplete_expired"] };

const minorToMajor = (v) => Math.round(Number(v) || 0) / 100;
const pad = (n) => String(n).padStart(2, "0");

function fmtUtc(ms) {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

function escapeLike(value) {
  return value.replace(/[\\%_]/g, (ch) => `\\${ch}`);
}

function httpError(status, message, extra) {
  const e = new Error(message);
  e.status = status;
  e.extra = extra;
  return e;
}

/** Validates the shared period fields and converts them to a UTC window. */
function parsePeriod(body) {
  const period = String(body.period || "month").toLowerCase();
  if (!PERIODS.has(period)) throw httpError(422, "period must be week, month or year");

  const dateFrom = String(body.date_from || "");
  const dateTo = String(body.date_to || "");
  if (!YMD.test(dateFrom) || !YMD.test(dateTo)) throw httpError(422, "date_from and date_to must be YYYY-MM-DD");

  const offset = body.tz_offset_minutes == null || body.tz_offset_minutes === "" ? 0 : Number(body.tz_offset_minutes);
  if (!Number.isInteger(offset) || offset < -840 || offset > 840) {
    throw httpError(422, "tz_offset_minutes must be an integer between -840 and 840");
  }

  const [fy, fm, fd] = dateFrom.split("-").map(Number);
  const [ty, tm, td] = dateTo.split("-").map(Number);
  const startLocal = Date.UTC(fy, fm - 1, fd);
  const endLocal = Date.UTC(ty, tm - 1, td + 1);
  if (!Number.isFinite(startLocal) || !Number.isFinite(endLocal) || endLocal <= startLocal) {
    throw httpError(422, "date_to must be on or after date_from");
  }
  if (endLocal - startLocal > 367 * 86400000) throw httpError(422, "The date range can be at most one year");

  return {
    period,
    dateFrom,
    dateTo,
    offset,
    granularity: period === "year" ? "month" : "day",
    startUtc: fmtUtc(startLocal - offset * 60000),
    endUtc: fmtUtc(endLocal - offset * 60000),
  };
}

async function trainerDirectory(codes) {
  if (!codes.length) return new Map();
  const [rows] = await pool.query(
    `
      SELECT UPPER(aur.partner_code) AS code, td.dietician_id, COALESCE(NULLIF(td.name, ''), aur.user_id) AS name
      FROM app_user_roles aur
      LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE UPPER(aur.partner_code) IN (?)
    `,
    [codes]
  );
  const map = new Map();
  for (const r of rows) if (!map.has(r.code)) map.set(r.code, { trainer_id: r.dietician_id || null, name: r.name || null });
  return map;
}

// ─── view=overview ───────────────────────────────────────────────────────────

async function overview(p) {
  const fmt = p.granularity === "month" ? "%Y-%m" : "%Y-%m-%d";
  // offset is a validated integer and fmt a constant — safe to inline.
  const [rows] = await pool.query(
    `
      SELECT
        DATE_FORMAT(DATE_ADD(si.paid_at, INTERVAL ${p.offset} MINUTE), '${fmt}') AS bucket,
        UPPER(COALESCE(rs.attributed_partner_code, '')) AS code,
        si.currency,
        SUM(si.subtotal_minor) AS gross_minor,
        SUM(si.discount_minor) AS discount_minor,
        SUM(si.amount_refunded_minor) AS refunded_minor,
        SUM(si.amount_paid_minor - si.amount_refunded_minor) AS net_minor,
        SUM(CASE WHEN si.billing_reason = 'subscription_create' AND si.status <> 'refunded' THEN 1 ELSE 0 END) AS purchases,
        SUM(CASE WHEN si.billing_reason = 'subscription_create'
                 THEN si.amount_paid_minor - si.amount_refunded_minor ELSE 0 END) AS new_net_minor
      FROM sales_invoices si
      INNER JOIN referral_subscriptions rs ON rs.stripe_subscription_id = si.stripe_subscription_id
      WHERE si.status IN ${PAID_STATUSES}
        AND si.paid_at >= ? AND si.paid_at < ?
      GROUP BY bucket, code, si.currency
    `,
    [p.startUtc, p.endUtc]
  );

  // One currency is reported (the one carrying the most revenue); anything in
  // another currency is listed in other_currencies rather than summed.
  const byCurrency = new Map();
  for (const r of rows) byCurrency.set(r.currency, (byCurrency.get(r.currency) || 0) + Number(r.net_minor));
  const [pr] = await pool.query(`SELECT currency FROM pricing_settings ORDER BY effective_from DESC, id DESC LIMIT 1`).catch(() => [[]]);
  const fallbackCurrency = String(pr?.[0]?.currency || "USD").toUpperCase();
  const currency = [...byCurrency.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || fallbackCurrency;
  const inCurrency = rows.filter((r) => r.currency === currency);

  const blank = () => ({ purchases: 0, gross: 0, discount: 0, refunded: 0, net: 0, newNet: 0 });
  const add = (acc, r) => {
    acc.purchases += Number(r.purchases);
    acc.gross += Number(r.gross_minor);
    acc.discount += Number(r.discount_minor);
    acc.refunded += Number(r.refunded_minor);
    acc.net += Number(r.net_minor);
    acc.newNet += Number(r.new_net_minor);
  };

  const total = blank();
  const website = blank();
  const trainer = blank();
  const trend = new Map();
  const trainers = new Map();

  for (const r of inCurrency) {
    const isTrainer = r.code !== "";
    add(total, r);
    add(isTrainer ? trainer : website, r);

    const b = trend.get(r.bucket) || { website: blank(), trainer: blank() };
    add(isTrainer ? b.trainer : b.website, r);
    trend.set(r.bucket, b);

    if (isTrainer) {
      const t = trainers.get(r.code) || blank();
      add(t, r);
      trainers.set(r.code, t);
    }
  }

  const ranked = [...trainers.entries()].sort((a, b) => b[1].net - a[1].net);
  const directory = await trainerDirectory(ranked.slice(0, TOP_TRAINERS_MAX).map(([code]) => code));

  const [[active]] = await pool.query(`SELECT COUNT(*) AS n FROM referral_subscriptions WHERE status = 'active'`);

  const channel = (c) => ({
    purchases: c.purchases,
    gross_sales: minorToMajor(c.gross),
    net_sales: minorToMajor(c.net),
    new_net_sales: minorToMajor(c.newNet),
  });

  return {
    filters: { period: p.period, date_from: p.dateFrom, date_to: p.dateTo, granularity: p.granularity, tz_offset_minutes: p.offset },
    summary: {
      currency,
      other_currencies: [...byCurrency.keys()].filter((c) => c !== currency),
      gross_sales: minorToMajor(total.gross),
      discounts: minorToMajor(total.discount),
      refunds: minorToMajor(total.refunded),
      net_sales: minorToMajor(total.net),
      new_purchase_net_sales: minorToMajor(total.newNet),
      renewal_net_sales: minorToMajor(total.net - total.newNet),
      total_purchases: total.purchases,
      website_purchases: website.purchases,
      trainer_code_purchases: trainer.purchases,
      average_order_value: total.purchases ? minorToMajor(total.newNet / total.purchases) : 0,
      active_paid_subscribers: Number(active.n),
    },
    source_breakdown: { website: channel(website), trainer_code: channel(trainer) },
    trend: [...trend.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([bucket, b]) => ({
        bucket,
        website_sales: minorToMajor(b.website.net),
        trainer_sales: minorToMajor(b.trainer.net),
        total_sales: minorToMajor(b.website.net + b.trainer.net),
        website_purchases: b.website.purchases,
        trainer_purchases: b.trainer.purchases,
      })),
    top_trainers: ranked.slice(0, TOP_TRAINERS_MAX).map(([code, t]) => ({
      trainer_id: directory.get(code)?.trainer_id || null,
      trainer_name: directory.get(code)?.name || null,
      partner_code: code,
      purchases: t.purchases,
      gross_sales: minorToMajor(t.gross),
      net_sales: minorToMajor(t.net),
    })),
    top_trainers_total: ranked.length,
  };
}

// ─── view=purchases ──────────────────────────────────────────────────────────

async function purchases(p, body) {
  const source = String(body.source || "all");
  if (!SOURCES.has(source)) throw httpError(422, "source must be all, website or trainer_code");

  const search = String(body.search || "").trim();
  if (search && search.length < SEARCH_MIN_LENGTH) {
    throw httpError(422, `Search must be at least ${SEARCH_MIN_LENGTH} characters`, { search_min_length: SEARCH_MIN_LENGTH });
  }
  if (search.length > 100) throw httpError(422, "Search is too long");

  const subStatus = String(body.subscription_status || "all").toLowerCase();
  const payStatus = String(body.payment_status || "all").toLowerCase();
  if (!/^[a-z_]{1,32}$/.test(subStatus) || !/^[a-z_]{1,32}$/.test(payStatus)) throw httpError(422, "Invalid status filter");

  let page = Math.trunc(Number(body.page) || 1);
  let limit = Math.trunc(Number(body.limit) || 10);
  if (page < 1) page = 1;
  if (limit < 1) limit = 10;
  if (limit > 100) limit = 100;

  const purchasedAt = "COALESCE(fi.paid_at, fi.failed_at, rs.created_at)";
  const where = [`${purchasedAt} >= ?`, `${purchasedAt} < ?`];
  const params = [p.startUtc, p.endUtc];

  if (source === "website") where.push("(rs.attributed_partner_code IS NULL OR rs.attributed_partner_code = '')");
  if (source === "trainer_code") where.push("(rs.attributed_partner_code IS NOT NULL AND rs.attributed_partner_code <> '')");
  if (subStatus !== "all") {
    const raw = SUB_STATUS_RAW[subStatus] || [subStatus];
    where.push(`rs.status IN (${raw.map(() => "?").join(", ")})`);
    params.push(...raw);
  }
  if (payStatus !== "all") {
    where.push("fi.status = ?");
    params.push(payStatus);
  }
  if (search) {
    const like = `%${escapeLike(search)}%`;
    where.push("(rs.purchaser_name LIKE ? OR rs.purchaser_email LIKE ? OR rs.purchase_code LIKE ? OR rs.attributed_partner_code LIKE ?)");
    params.push(like, like, like, like);
  }

  const from = `
    FROM referral_subscriptions rs
    LEFT JOIN sales_invoices fi
      ON fi.stripe_subscription_id = rs.stripe_subscription_id
     AND fi.billing_reason = 'subscription_create'
    WHERE ${where.join(" AND ")}
  `;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total ${from}`, params);
  const offset = (page - 1) * limit;
  // limit/offset are validated integers — inlined (bound LIMIT is rejected on some MySQL builds).
  const [rows] = await pool.query(
    `
      SELECT
        rs.stripe_subscription_id, rs.stripe_checkout_session_id, rs.purchaser_email, rs.purchaser_name,
        rs.profile_id, rs.attributed_partner_code, rs.purchase_code, rs.stripe_promotion_code_id,
        rs.plan_code, rs.currency AS sub_currency, rs.unit_amount_minor, rs.status AS sub_status,
        rs.current_period_start, rs.current_period_end, rs.canceled_at, rs.created_at,
        fi.stripe_invoice_id, fi.stripe_payment_intent_id, fi.status AS pay_status, fi.currency,
        fi.subtotal_minor, fi.discount_minor, fi.amount_paid_minor, fi.amount_refunded_minor,
        ${purchasedAt} AS purchased_at,
        (SELECT tc.profile_name FROM table_clients tc
          WHERE rs.profile_id IS NOT NULL AND tc.profile_id = rs.profile_id
          ORDER BY tc.id DESC LIMIT 1) AS profile_name
      ${from}
      ORDER BY purchased_at DESC, rs.id DESC
      LIMIT ${limit} OFFSET ${offset}
    `,
    params
  );

  const directory = await trainerDirectory([
    ...new Set(rows.map((r) => String(r.attributed_partner_code || "").toUpperCase()).filter(Boolean)),
  ]);

  const toIso = (v) => {
    if (!v) return null;
    if (v instanceof Date) return fmtUtc(v.getTime()).replace(" ", "T") + "Z";
    return String(v).replace(" ", "T") + "Z";
  };

  const data = rows.map((r) => {
    const code = String(r.attributed_partner_code || "").toUpperCase();
    const hasInvoice = !!r.stripe_invoice_id;
    const discount = hasInvoice ? Number(r.discount_minor) : null;
    return {
      purchase_id: r.stripe_subscription_id,
      purchased_at: toIso(r.purchased_at),
      customer: {
        name: r.purchaser_name || r.profile_name || null,
        email: r.purchaser_email || null,
        profile_id: r.profile_id || null,
      },
      plan: { code: r.plan_code, name: PLAN_NAMES[r.plan_code] || r.plan_code },
      purchase_source: code ? "trainer_code" : "website",
      trainer: code ? { trainer_id: directory.get(code)?.trainer_id || null, name: directory.get(code)?.name || null } : null,
      attributed_partner_code: code || null,
      purchase_code: r.purchase_code || null,
      coupon_code: discount ? code || r.stripe_promotion_code_id || null : null,
      currency: r.currency || r.sub_currency,
      gross_amount: hasInvoice ? minorToMajor(r.subtotal_minor) : null,
      discount_amount: hasInvoice ? minorToMajor(discount) : null,
      net_amount: hasInvoice ? minorToMajor(Number(r.amount_paid_minor) - Number(r.amount_refunded_minor)) : null,
      subscription_status: SUB_STATUS_LABEL[r.sub_status] || r.sub_status || null,
      subscription_start: toIso(r.created_at),
      // Cancelled: when it was cancelled; otherwise the next renewal date.
      subscription_end: toIso(r.canceled_at || r.current_period_end),
      payment_status: r.pay_status || null,
      stripe: {
        checkout_session_id: r.stripe_checkout_session_id || null,
        payment_intent_id: r.stripe_payment_intent_id || null,
        subscription_id: r.stripe_subscription_id,
        invoice_id: r.stripe_invoice_id || null,
      },
    };
  });

  const [subStatuses] = await pool.query(`SELECT DISTINCT status FROM referral_subscriptions WHERE status IS NOT NULL`);
  const [payStatuses] = await pool.query(`SELECT DISTINCT status FROM sales_invoices`);

  return {
    filters: {
      period: p.period, date_from: p.dateFrom, date_to: p.dateTo, tz_offset_minutes: p.offset,
      source, subscription_status: subStatus, payment_status: payStatus, search, search_min_length: SEARCH_MIN_LENGTH,
    },
    purchases: data,
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
    filter_options: {
      subscription_status: [...new Set(subStatuses.map((s) => SUB_STATUS_LABEL[s.status] || s.status))].sort(),
      payment_status: payStatuses.map((s) => s.status).sort(),
    },
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

const superAdminSalesAnalytics = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const view = String(body.view || "overview");
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    let payload;
    if (view === "overview") {
      payload = await overview(parsePeriod(body));
    } else if (view === "purchases") {
      payload = await purchases(parsePeriod(body), body);
    } else if (view === "sync") {
      let stripe;
      try {
        stripe = requireStripe();
      } catch {
        return res.status(503).json({ status: false, ok: false, message: "Stripe is not configured" });
      }
      payload = await salesInvoices.syncFromStripe(stripe, { offset: body.offset });
    } else {
      return res.status(422).json({ status: false, ok: false, message: "view must be overview, purchases or sync" });
    }

    await H.writeAuthLogSafe(req, {
      eventType: view === "sync" ? "sales_invoices_synced" : "super_admin_sales_analytics_viewed",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: view === "sync" ? `sync offset=${body.offset || 0} next=${payload.next_offset}` : `view=${view}`,
    });

    return res.status(200).json({ status: true, ok: true, view, ...payload });
  } catch (err) {
    if (err?.status) {
      return res.status(err.status).json({ status: false, ok: false, message: err.message, ...(err.extra || {}) });
    }
    if (err?.code === "ER_NO_SUCH_TABLE") {
      return res.status(503).json({
        status: false,
        ok: false,
        code: "sales_table_missing",
        message: "Sales data is not set up on this environment yet (sales_invoices table missing).",
      });
    }
    console.error("SUPER_ADMIN_SALES_ANALYTICS_ERROR:", { view, code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "super_admin_sales_analytics_error",
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

module.exports = { superAdminSalesAnalytics };
