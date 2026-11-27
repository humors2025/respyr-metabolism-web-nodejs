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
 *   facility_id    (optional, every view except facility_options) narrows the
 *                  list, summary and counts to one facility's network: the
 *                  facility's and its facility admin's codes plus its trainers
 *                  (see facilityFilter). view=facility_options lists the
 *                  facilities with their facility admin for the picker.
 *   view=upcoming_renewals
 *                  referral_subscriptions still set to renew (active or
 *                  trialing, not cancelled) whose current_period_end falls in
 *                  the next `days` days (default 10), soonest first. Each row
 *                  carries the renewals paid so far and the last payment.
 *                  Super-admin test codes (test_… rows) are left out.
 *   view=cancellations
 *                  referral_subscriptions the member cancelled (canceled_at
 *                  set, or status canceled), newest cancellation first.
 *                  state=scheduled keeps those still inside their paid
 *                  period, state=ended those whose plan is over. Each row
 *                  carries what they paid, the phone from Checkout and
 *                  Stripe's cancellation_details (reason / feedback / comment).
 *   view=failed_renewals
 *                  renewal invoices (subscription_cycle) that failed, or are
 *                  still unpaid a day after Stripe created them, newest first.
 *                  state=failed | pending. Each row carries the reason in plain
 *                  words (Stripe decline code looked up live), the card, the
 *                  attempt count and Stripe's next retry date.
 *
 * Both join referral_subscriptions (by stripe_subscription_id) for the buyer's
 * email / name and the partner code used. Shipping rows also carry the plan's
 * current_period_start / current_period_end and a derived subscription_status:
 * a Stripe "active" plan whose period end has passed is reported as "expired".
 * Shipping rows also carry the facility behind the partner code (the gym and
 * its facility admin, same lookup as Sales Analytics' top_trainers), or null
 * for a website purchase / a trainer outside any facility. They also carry
 * paid_period (the latest paid invoice's period) and renewal_pending (Stripe
 * started a newer period whose invoice is not paid yet), and tracking: the
 * FedEx number and latest status saved via shipment-tracking.js, or null.
 *
 * Body: { view: "shipping" | "payments" | "upcoming_renewals" | "cancellations" | "failed_renewals", search?, page?, limit?,
 *         payments only: status? ("all" | open | paid | failed | refunded | partially_refunded),
 *                        type? ("all" | first_payment | renewal), paid_only? (boolean),
 *         upcoming_renewals only: days? (1-31, default 10),
 *         cancellations only: state? ("all" | scheduled | ended) }
 */

const pool = require("../../../../config/db");
const { notHiddenOnOrdersSql } = require("../../../../services/excludedSubscriptions");
const { isComebackSql, rejoinedAtSql, renewalPaymentSql, firstPaymentSql } = require("../../../../services/rejoinedMembers");
const { requireStripe } = require("../../../../config/stripe");
const { creditForReadingDays } = require("../../../../services/breathCredits");
const { BREATH_CREDIT_EXCLUDE_PROFILES } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");
const { trainerHierarchy } = require("./super-admin-sales-analytics");
const { trackingFor } = require("../../../../services/shipmentTracking");

const SEARCH_MIN_LENGTH = 3;
const MAX_LIMIT = 100;
const PAYMENT_STATUSES = ["open", "paid", "failed", "refunded", "partially_refunded"];
// Invoices that were paid (a refund came later, if at all).
const PAID_STATUSES = ["paid", "partially_refunded", "refunded"];
// Payment type filter -> Stripe invoice billing_reason.
const PAYMENT_TYPES = { first_payment: "subscription_create", renewal: "subscription_cycle" };
const UPCOMING_DAYS = 10;
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

// Optional facility filter (body.facility_id): the sales of one facility's
// network, the same people the Facility column names. A sale belongs to the
// facility when the subscription was stamped with it (rs.facility_id) or its
// partner code is one of: the facility's own code, its facility admin's code,
// any account or invitation tied to the facility, or a trainer the facility
// admin invited (as on the admin's own Sales & Payments page).
// Returns null (no filter) or { facility, sql, params } where sql uses `rs.`.
async function facilityFilter(body) {
  const raw = body.facility_id;
  if (raw == null || raw === "" || String(raw).toLowerCase() === "all") return null;
  const id = Number(raw);
  if (!Number.isInteger(id) || id <= 0) throw httpError(422, "facility_id must be all or a facility id");

  const [[f]] = await pool.query(
    `SELECT f.id, f.name, UPPER(TRIM(f.partner_code)) AS partner_code, LOWER(f.facility_admin_user_id) AS admin_user_id,
            NULLIF(TRIM(td.name), '') AS admin_name
     FROM facilities f
     LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(f.facility_admin_user_id)
     WHERE f.id = ? LIMIT 1`,
    [id]
  );
  if (!f) throw httpError(404, "Facility not found");

  const admin = f.admin_user_id || "";
  const [roleCodes] = await pool.query(
    `SELECT DISTINCT UPPER(TRIM(partner_code)) AS code FROM app_user_roles
     WHERE partner_code IS NOT NULL AND TRIM(partner_code) <> ''
       AND (facility_id = ? OR LOWER(user_id) = ? OR (role = 'trainer' AND LOWER(parent_user_id) = ?))`,
    [id, admin, admin]
  );
  const [inviteCodes] = await pool.query(
    `SELECT DISTINCT UPPER(TRIM(partner_code)) AS code FROM app_user_invitations
     WHERE partner_code IS NOT NULL AND TRIM(partner_code) <> '' AND facility_id = ?`,
    [id]
  );
  const codes = [...new Set([f.partner_code, ...roleCodes.map((r) => r.code), ...inviteCodes.map((r) => r.code)].filter(Boolean))];

  return {
    facility: { id: Number(f.id), name: f.name, partner_code: f.partner_code || null, admin_user_id: f.admin_user_id || null, admin_name: f.admin_name || null },
    sql: codes.length ? "(rs.facility_id = ? OR UPPER(rs.attributed_partner_code) IN (?))" : "rs.facility_id = ?",
    params: codes.length ? [id, codes] : [id],
  };
}

// Facilities for the Orders filter, with their facility admin, by name.
async function facilityOptions() {
  const [rows] = await pool.query(
    `SELECT f.id, f.name, UPPER(TRIM(f.partner_code)) AS partner_code, f.status,
            LOWER(f.facility_admin_user_id) AS admin_user_id, NULLIF(TRIM(td.name), '') AS admin_name
     FROM facilities f
     LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(f.facility_admin_user_id)
     ORDER BY f.name, f.id`
  );
  // table_dietician can hold the same email twice: keep one row per facility.
  const seen = new Set();
  const facilities = [];
  for (const r of rows) {
    if (seen.has(r.id)) continue;
    seen.add(r.id);
    facilities.push({
      id: Number(r.id),
      name: r.name,
      partner_code: r.partner_code || null,
      status: r.status || null,
      admin_user_id: r.admin_user_id || null,
      admin_name: r.admin_name || null,
    });
  }
  return { facilities };
}

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

// Stripe moves current_period_* to the next month as soon as it creates the
// renewal invoice, before that invoice is paid. The latest paid invoice per
// subscription says how far the plan is actually paid.
async function lastPaidPeriods(subIds) {
  const out = new Map();
  const ids = [...new Set(subIds.filter(Boolean))];
  if (!ids.length) return out;
  try {
    const [rows] = await pool.query(
      `
        SELECT stripe_subscription_id, MAX(period_start) AS period_start, MAX(period_end) AS period_end
        FROM payment_transactions
        WHERE stripe_subscription_id IN (${ids.map(() => "?").join(", ")})
          AND status IN (${PAID_STATUSES.map(() => "?").join(", ")})
        GROUP BY stripe_subscription_id
      `,
      [...ids, ...PAID_STATUSES]
    );
    for (const r of rows) out.set(r.stripe_subscription_id, { start: toIso(r.period_start), end: toIso(r.period_end) });
  } catch (err) {
    console.error("SUPER_ADMIN_ORDERS_PAID_PERIOD_ERROR:", { code: err?.code, message: err?.message });
  }
  return out;
}

// paid_period: the period covered by the latest paid invoice (null when none
// is recorded). renewal_pending: Stripe already started a newer period whose
// invoice is not paid yet (still processing, or failed and being retried).
// A day of slack absorbs small clock differences between the two dates.
function renewalState(row, paid) {
  const currentEnd = Date.parse(toIso(row.current_period_end) || "");
  const paidEnd = Date.parse(paid?.end || "");
  const pending = Number.isFinite(currentEnd) && Number.isFinite(paidEnd) && paidEnd < currentEnd - DAY_MS;
  return { paid_period: paid?.end ? paid : null, renewal_pending: pending };
}

const DAY_MS = 24 * 60 * 60 * 1000;

async function shipping(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);

  // Internal test subscriptions stay off the Orders page.
  const where = [notHiddenOnOrdersSql("sa.stripe_subscription_id")];
  const params = [];
  const fac = await facilityFilter(body);
  if (fac) {
    where.push(fac.sql);
    params.push(...fac.params);
  }
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
        rs.purchaser_email, rs.purchaser_name, rs.attributed_partner_code, rs.qr_id, rs.status AS subscription_status,
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
  const paidPeriods = await lastPaidPeriods(rows.map((r) => r.stripe_subscription_id));
  const tracking = await trackingFor(rows.map((r) => r.stripe_subscription_id));

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
      qr_id: r.qr_id || null, // set = bought by scanning this QR sticker
      facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
      subscription_status: deriveSubscriptionStatus(r, now),
      stripe_status: r.subscription_status || null,
      current_period_start: toIso(r.current_period_start),
      current_period_end: toIso(r.current_period_end),
      canceled_at: toIso(r.canceled_at),
      stripe_subscription_id: r.stripe_subscription_id,
      // FedEx tracking saved on the Shipping tab (shipment-tracking.js), or null.
      tracking: tracking.get(r.stripe_subscription_id) || null,
      ...renewalState(r, paidPeriods.get(r.stripe_subscription_id)),
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

  // Type and paid-only scope both the list and the summary chips; internal
  // test subscriptions are always left out.
  const scope = [notHiddenOnOrdersSql("pt.stripe_subscription_id")];
  const scopeParams = [];
  // A member who re-joined after cancelling ("Re-joined Again") pays a new
  // plan's first invoice, but it counts as a renewal (services/rejoinedMembers).
  if (type === "renewal") scope.push(renewalPaymentSql("pt", "rs"));
  else if (type === "first_payment") scope.push(firstPaymentSql("pt", "rs"));
  if (paidOnly) {
    scope.push(`pt.status IN (${PAID_STATUSES.map(() => "?").join(", ")})`);
    scopeParams.push(...PAID_STATUSES);
  }
  const fac = await facilityFilter(body);
  if (fac) {
    scope.push(fac.sql);
    scopeParams.push(...fac.params);
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
        rs.purchaser_email, rs.purchaser_name, rs.profile_id, rs.attributed_partner_code, rs.qr_id,
        rs.status AS subscription_status, rs.current_period_start, rs.current_period_end, rs.canceled_at,
        rs.unit_amount_minor, rs.currency AS plan_currency,
        (pt.billing_reason = 'subscription_create' AND ${isComebackSql("rs")}) AS rejoined,
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
    `SELECT pt.status, pt.currency, COUNT(*) AS n, SUM(pt.amount_paid_minor) AS paid, SUM(pt.amount_refunded_minor) AS refunded
     FROM payment_transactions pt
     ${fac || type !== "all" ? "LEFT JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id" : ""}
     WHERE ${scope.join(" AND ")} GROUP BY pt.status, pt.currency`,
    scopeParams
  );

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  // A failed or still-open invoice collected nothing, so amount_paid is 0.
  // What Stripe tried to charge (invoice.amount_due) is not stored, so it is
  // read from Stripe for those rows only. Best-effort: on a Stripe hiccup
  // amount_due falls back to the plan price, or stays null.
  const amountDue = new Map();
  const unpaid = rows.filter((r) => r.status === "failed" || r.status === "open");
  if (unpaid.length) {
    try {
      const stripe = requireStripe();
      const CHUNK = 8;
      for (let i = 0; i < unpaid.length; i += CHUNK) {
        await Promise.all(
          unpaid.slice(i, i + CHUNK).map(async (r) => {
            try {
              const inv = await stripe.invoices.retrieve(r.stripe_invoice_id);
              amountDue.set(r.id, {
                amount: minorToMajor(inv.amount_due ?? inv.total ?? 0),
                currency: String(inv.currency || r.currency || "usd").toUpperCase(),
              });
            } catch (err) {
              console.warn("PAYMENTS_AMOUNT_DUE_LOOKUP_FAILED:", { invoice: r.stripe_invoice_id, code: err?.code, message: err?.message });
            }
          })
        );
      }
    } catch {
      // No Stripe key configured: fall back to the plan price below.
    }
  }
  const planPrice = (r) =>
    r.unit_amount_minor != null
      ? { amount: minorToMajor(r.unit_amount_minor), currency: String(r.plan_currency || r.currency || "usd").toUpperCase() }
      : null;

  const now = Date.now();
  return {
    filters: { status, type, paid_only: paidOnly, search, search_min_length: SEARCH_MIN_LENGTH },
    payments: rows.map((r) => ({
      id: Number(r.id),
      date: toIso(r.paid_at || r.created_at),
      customer: {
        name: r.purchaser_name || null,
        email: r.purchaser_email || null,
        // The linked app profile (null until the buyer redeems their code).
        profile_id: r.profile_id || null,
      },
      partner_code: r.attributed_partner_code || null,
      qr_id: r.qr_id || null, // set = bought by scanning this QR sticker
      facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
      type: Number(r.rejoined)
        ? "renewal"
        : r.billing_reason === "subscription_create" ? "first_payment" : r.billing_reason === "subscription_cycle" ? "renewal" : r.billing_reason || null,
      // "Re-joined Again": first payment of a new plan after the member's
      // earlier plan was cancelled and ended; counted as a renewal.
      rejoined: Boolean(Number(r.rejoined)),
      renewal_number: r.renewal_number == null ? null : Number(r.renewal_number),
      period_start: toIso(r.period_start),
      period_end: toIso(r.period_end),
      currency: r.currency,
      amount_paid: minorToMajor(r.amount_paid_minor),
      amount_refunded: minorToMajor(r.amount_refunded_minor),
      // Failed / open invoices only: what Stripe tried to charge (null for
      // paid ones, whose amount_paid already says it).
      amount_due:
        r.status === "failed" || r.status === "open" ? amountDue.get(r.id) || planPrice(r) : null,
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
    notHiddenOnOrdersSql("rs.stripe_subscription_id"),
  ];
  const params = [days];
  const fac = await facilityFilter(body);
  if (fac) {
    where.push(fac.sql);
    params.push(...fac.params);
  }
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
        rs.id, rs.stripe_subscription_id, rs.purchaser_email, rs.purchaser_name, rs.profile_id,
        rs.attributed_partner_code, rs.qr_id,
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
      const h = history.get(p.stripe_subscription_id) || { renewals: 0, last: null, first: null };
      if (p.billing_reason === "subscription_cycle") h.renewals += 1;
      if (p.billing_reason === "subscription_create" && !h.first) h.first = p;
      h.last = p;
      history.set(p.stripe_subscription_id, h);
    }
  }

  // Breath-test DAYS per calendar month (current and previous, UTC) by the
  // linked app profile — several readings on one day count as 1. A purchase
  // whose code is not redeemed yet has no profile, so no tests.
  const monthKeyOf = (d) => d.toISOString().slice(0, 7);
  const nowDate = new Date();
  const curMonth = monthKeyOf(nowDate);
  const prevMonth = monthKeyOf(new Date(Date.UTC(nowDate.getUTCFullYear(), nowDate.getUTCMonth() - 1, 1)));
  const testsByProfile = new Map();
  const profileIds = [...new Set(rows.map((r) => r.profile_id).filter(Boolean))];
  if (profileIds.length) {
    const [tests] = await pool.query(
      `
        SELECT profile_id,
               COUNT(DISTINCT CASE WHEN DATE_FORMAT(date_time, '%Y-%m') = ? THEN DATE(date_time) END) AS cur_count,
               COUNT(DISTINCT CASE WHEN DATE_FORMAT(date_time, '%Y-%m') = ? THEN DATE(date_time) END) AS prev_count,
               COUNT(DISTINCT DATE(date_time)) AS total_count
        FROM table_test_data
        WHERE profile_id IN (?)
        GROUP BY profile_id
      `,
      [curMonth, prevMonth, profileIds]
    );
    for (const t of tests) testsByProfile.set(t.profile_id, t);
  }

  // Projected breath credit on the next invoice: $0.20 per reading-day so
  // far in the current billing period, capped — every subscription with a
  // linked app profile earns it, matching services/breathCredits.js (which
  // posts the actual balance credit shortly before renewal). Null when the
  // purchase code is not redeemed yet (no profile, so no readings) and for
  // the excluded internal test profiles, which never earn the credit.
  const breathCredits = new Map();
  await Promise.all(
    rows
      .filter((r) => r.profile_id && !BREATH_CREDIT_EXCLUDE_PROFILES.includes(String(r.profile_id)))
      .map(async (r) => {
        try {
          const [[t]] = await pool.query(
            `
              SELECT COUNT(DISTINCT DATE(date_time)) AS days
              FROM table_test_data
              WHERE profile_id = ?
                AND date_time >= ?
                AND date_time <  LEAST(UTC_TIMESTAMP(), ?)
            `,
            [r.profile_id, r.current_period_start, r.current_period_end]
          );
          const readingDays = Number(t?.days || 0);
          const startMs = Date.parse(toIso(r.current_period_start));
          const endMs = Date.parse(toIso(r.current_period_end));
          const daysInPeriod = Math.max(1, Math.round((endMs - startMs) / 86400000));
          breathCredits.set(r.stripe_subscription_id, {
            days: readingDays,
            credit_minor: creditForReadingDays(readingDays, daysInPeriod),
          });
        } catch (err) {
          console.warn("UPCOMING_RENEWAL_BREATH_CREDIT_FAILED:", {
            sub: r.stripe_subscription_id,
            message: err?.message,
          });
        }
      })
  );

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  // What Stripe will actually bill next: the price minus whatever discounts
  // are still on the subscription/schedule. The DB cannot know this (the
  // pre-5-Oct schedule rewrite dropped referral coupons on some subs), so
  // each row's next invoice is previewed. Best-effort: a Stripe hiccup
  // leaves next_charge null and the page falls back to the plan price.
  const nextCharge = new Map();
  try {
    const stripe = requireStripe();
    const CHUNK = 8;
    for (let i = 0; i < rows.length; i += CHUNK) {
      await Promise.all(
        rows.slice(i, i + CHUNK).map(async (r) => {
          try {
            const inv = await stripe.invoices.createPreview({ subscription: r.stripe_subscription_id });
            const discountMinor = (inv.total_discount_amounts || []).reduce(
              (sum, d) => sum + Number(d.amount || 0),
              0
            );
            nextCharge.set(r.stripe_subscription_id, {
              amount_minor: Number(inv.amount_due ?? inv.total ?? 0),
              discount_minor: discountMinor,
              currency: String(inv.currency || r.currency || "usd").toUpperCase(),
            });
          } catch (err) {
            console.warn("UPCOMING_RENEWAL_PREVIEW_FAILED:", {
              sub: r.stripe_subscription_id,
              code: err?.code,
              message: err?.message,
            });
          }
        })
      );
    }
  } catch {
    // No Stripe key configured: every next_charge stays null.
  }

  const now = Date.now();
  return {
    filters: { days, search, search_min_length: SEARCH_MIN_LENGTH },
    upcoming: rows.map((r) => {
      const h = history.get(r.stripe_subscription_id) || { renewals: 0, last: null, first: null };
      const nc = nextCharge.get(r.stripe_subscription_id) || null;
      const bc = breathCredits.get(r.stripe_subscription_id) || null;
      // The price the member is entitled to renew at: a partner-code purchase
      // keeps its referred (discounted) price — what they paid on day one —
      // while a no-code purchase renews at list price.
      const discounted = Boolean(r.attributed_partner_code && h.first);
      const expected = discounted
        ? { amount_minor: Number(h.first.amount_paid_minor), currency: h.first.currency || r.currency }
        : r.unit_amount_minor != null
          ? { amount_minor: Number(r.unit_amount_minor), currency: r.currency }
          : null;
      return {
        id: Number(r.id),
        renews_at: toIso(r.current_period_end),
        customer: {
          name: r.purchaser_name || null,
          email: r.purchaser_email || null,
          // The linked app profile (null until the buyer redeems their code).
          profile_id: r.profile_id || null,
        },
        partner_code: r.attributed_partner_code || null,
        qr_id: r.qr_id || null, // set = bought by scanning this QR sticker
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
        // Breath-test days this month and last month (plus lifetime total of
        // test days) — one per day however many readings that day; zeros when
        // the code is not redeemed yet.
        tests_monthly: [
          { month: curMonth, count: Number(testsByProfile.get(r.profile_id)?.cur_count || 0) },
          { month: prevMonth, count: Number(testsByProfile.get(r.profile_id)?.prev_count || 0) },
        ],
        total_test_taken: Number(testsByProfile.get(r.profile_id)?.total_count || 0),
        // Projected breath credit on the coming renewal: reading-days so far
        // in the current billing period × the per-day rate, capped. Null when
        // the purchase code is not redeemed yet (no profile, no readings).
        breath_credit: bc
          ? { amount: minorToMajor(bc.credit_minor), currency: r.currency, days: bc.days }
          : null,
        // The entitled renewal price (see above); discounted says whether it
        // is the partner-code referral price or plain list price.
        expected_charge: expected
          ? { amount: minorToMajor(expected.amount_minor), currency: expected.currency, discounted }
          : null,
        // The amount Stripe will charge at renews_at, discounts included
        // (previewed above); null when the preview was unavailable.
        next_charge: nc
          ? {
              amount: minorToMajor(nc.amount_minor),
              discount: minorToMajor(nc.discount_minor),
              currency: nc.currency,
            }
          : null,
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

// Members who cancelled: the webhook stamps referral_subscriptions.canceled_at
// on a cancel at period end (Stripe status stays "active" until the paid
// period runs out) and flips status to "canceled" when the plan ends.
//   scheduled  still has access: running, period end in the future
//   ended      the plan is over
const CANCEL_STATES = ["scheduled", "ended"];
const SCHEDULED_SQL =
  "(rs.status IN ('active', 'trialing', 'past_due') AND rs.current_period_end > UTC_TIMESTAMP())";

async function cancellations(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);
  const state = String(body.state || body.status || "all").toLowerCase();
  if (state !== "all" && !CANCEL_STATES.includes(state)) {
    throw httpError(422, `state must be all or one of ${CANCEL_STATES.join(", ")}`);
  }

  // Test-code rows (test_…) have no Stripe subscription behind them.
  const scope = [
    "(rs.canceled_at IS NOT NULL OR rs.status = 'canceled')",
    "LEFT(rs.stripe_subscription_id, 5) <> 'test_'",
    notHiddenOnOrdersSql("rs.stripe_subscription_id"),
  ];
  const scopeParams = [];
  const fac = await facilityFilter(body);
  if (fac) {
    scope.push(fac.sql);
    scopeParams.push(...fac.params);
  }
  const where = [...scope];
  const params = [...scopeParams];
  if (state === "scheduled") where.push(SCHEDULED_SQL);
  else if (state === "ended") where.push(`NOT ${SCHEDULED_SQL}`);
  if (search) {
    where.push(`(
      rs.purchaser_email LIKE ? OR rs.purchaser_name LIKE ? OR rs.attributed_partner_code LIKE ?
      OR rs.stripe_subscription_id LIKE ? OR rs.profile_id LIKE ?
    )`);
    params.push(...Array(5).fill(like(search)));
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total FROM referral_subscriptions rs ${whereSql}`, params);
  const [rows] = await pool.query(
    `
      SELECT
        rs.id, rs.stripe_subscription_id, rs.purchaser_email, rs.purchaser_name, rs.profile_id,
        rs.attributed_partner_code, rs.qr_id,
        rs.status AS subscription_status, rs.current_period_start, rs.current_period_end, rs.canceled_at,
        rs.currency, rs.created_at AS purchased_at,
        ${SCHEDULED_SQL} AS still_active,
        ${rejoinedAtSql("rs")} AS rejoined_at
      FROM referral_subscriptions rs
      ${whereSql}
      ORDER BY COALESCE(rs.canceled_at, rs.created_at) DESC, rs.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  // Counts across every cancellation (ignoring the search and state filter).
  const [[counts]] = await pool.query(
    `SELECT COUNT(*) AS total, COALESCE(SUM(${SCHEDULED_SQL}), 0) AS scheduled,
            COALESCE(SUM(rs.canceled_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY), 0) AS last_30_days
     FROM referral_subscriptions rs WHERE ${scope.join(" AND ")}`,
    scopeParams
  );

  const subIds = rows.map((r) => r.stripe_subscription_id).filter(Boolean);

  // What each member paid before cancelling.
  const paidBySub = new Map();
  if (subIds.length) {
    const [paid] = await pool.query(
      `
        SELECT stripe_subscription_id, billing_reason, amount_paid_minor, amount_refunded_minor, currency, paid_at, created_at
        FROM payment_transactions
        WHERE stripe_subscription_id IN (?) AND status IN (?)
        ORDER BY COALESCE(paid_at, created_at) ASC, id ASC
      `,
      [subIds, PAID_STATUSES]
    );
    for (const p of paid) {
      const h = paidBySub.get(p.stripe_subscription_id) || { count: 0, renewals: 0, paid: 0, refunded: 0, currency: p.currency, last: null };
      h.count += 1;
      if (p.billing_reason === "subscription_cycle") h.renewals += 1;
      h.paid += Number(p.amount_paid_minor || 0);
      h.refunded += Number(p.amount_refunded_minor || 0);
      h.last = p;
      paidBySub.set(p.stripe_subscription_id, h);
    }
  }

  // Phone from Checkout, for a follow-up call.
  const phoneBySub = new Map();
  if (subIds.length) {
    try {
      const [ship] = await pool.query(
        "SELECT stripe_subscription_id, phone, state FROM subscription_shipping_addresses WHERE stripe_subscription_id IN (?)",
        [subIds]
      );
      for (const s of ship) phoneBySub.set(s.stripe_subscription_id, { phone: s.phone || null, state: s.state || null });
    } catch (err) {
      console.error("SUPER_ADMIN_ORDERS_CANCEL_SHIPPING_ERROR:", { code: err?.code, message: err?.message });
    }
  }

  // Why it was cancelled lives only in Stripe (cancellation_details: reason,
  // plus the feedback / comment the member gave in the customer portal).
  // Best-effort: a Stripe hiccup leaves it null.
  const stripeInfo = new Map();
  try {
    const stripe = requireStripe();
    const CHUNK = 8;
    for (let i = 0; i < subIds.length; i += CHUNK) {
      await Promise.all(
        subIds.slice(i, i + CHUNK).map(async (id) => {
          try {
            const sub = await stripe.subscriptions.retrieve(id);
            const d = sub.cancellation_details || {};
            stripeInfo.set(id, {
              reason: d.reason || null,
              feedback: d.feedback || null,
              comment: d.comment || null,
              cancel_at: sub.cancel_at ? new Date(sub.cancel_at * 1000).toISOString().replace(".000Z", "Z") : null,
              ended_at: sub.ended_at ? new Date(sub.ended_at * 1000).toISOString().replace(".000Z", "Z") : null,
            });
          } catch (err) {
            console.warn("CANCELLATION_STRIPE_LOOKUP_FAILED:", { sub: id, code: err?.code, message: err?.message });
          }
        })
      );
    }
  } catch {
    // No Stripe key configured: reasons stay null.
  }

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  const now = Date.now();
  return {
    filters: { state, search, search_min_length: SEARCH_MIN_LENGTH },
    cancellations: rows.map((r) => {
      const h = paidBySub.get(r.stripe_subscription_id) || null;
      const s = stripeInfo.get(r.stripe_subscription_id) || null;
      const stillActive = Boolean(Number(r.still_active));
      return {
        id: Number(r.id),
        canceled_at: toIso(r.canceled_at),
        customer: {
          name: r.purchaser_name || null,
          email: r.purchaser_email || null,
          phone: phoneBySub.get(r.stripe_subscription_id)?.phone || null,
          // The linked app profile (null until the buyer redeems their code).
          profile_id: r.profile_id || null,
        },
        partner_code: r.attributed_partner_code || null,
        qr_id: r.qr_id || null, // set = bought by scanning this QR sticker
        facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
        purchased_at: toIso(r.purchased_at),
        // scheduled = cancelled but still has access until access_ends;
        // ended = the plan is over.
        cancel_state: stillActive ? "scheduled" : "ended",
        // "Re-joined Again": when the member bought a new plan after this one
        // (null = has not come back).
        rejoined_at: toIso(r.rejoined_at),
        access_ends: s?.ended_at || toIso(r.current_period_end),
        payments: h
          ? {
              count: h.count,
              renewals: h.renewals,
              total_paid: minorToMajor(h.paid),
              total_refunded: minorToMajor(h.refunded),
              currency: h.currency || r.currency,
              last_payment: {
                amount_paid: minorToMajor(h.last.amount_paid_minor),
                date: toIso(h.last.paid_at || h.last.created_at),
              },
            }
          : null,
        // From Stripe; null when the lookup failed.
        cancellation: s ? { reason: s.reason, feedback: s.feedback, comment: s.comment } : null,
        subscription_status: deriveSubscriptionStatus(r, now),
        stripe_status: r.subscription_status || null,
        current_period_start: toIso(r.current_period_start),
        current_period_end: toIso(r.current_period_end),
        stripe_subscription_id: r.stripe_subscription_id,
      };
    }),
    summary: {
      total: Number(counts.total || 0),
      scheduled: Number(counts.scheduled || 0),
      ended: Number(counts.total || 0) - Number(counts.scheduled || 0),
      last_30_days: Number(counts.last_30_days || 0),
    },
    state_options: CANCEL_STATES,
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
  };
}

// Renewal invoices that did not go through:
//   failed   Stripe reported the charge failed (invoice.payment_failed, or the
//            invoice was marked uncollectible). A retry that later succeeds
//            turns the row into "paid", so it leaves this list by itself.
//   pending  still "open" a day after Stripe created it: no success and no
//            failure yet (e.g. a card payment stuck in processing).
const FAILED_RENEWAL_STATES = ["failed", "pending"];
const FAILED_RENEWAL_SQL = `(
  pt.status = 'failed'
  OR (pt.status = 'open' AND pt.created_at < UTC_TIMESTAMP() - INTERVAL 1 DAY)
)`;

// Stripe decline / error codes in plain words for the Reason column.
const DECLINE_LABEL = {
  insufficient_funds: "Not enough money on the card",
  expired_card: "Card has expired",
  card_declined: "Card declined by the bank",
  generic_decline: "Card declined by the bank (no reason given)",
  do_not_honor: "Card declined by the bank (no reason given)",
  call_issuer: "Card declined: customer must call their bank",
  lost_card: "Card reported lost",
  stolen_card: "Card reported stolen",
  pickup_card: "Card blocked by the bank",
  restricted_card: "Card blocked by the bank",
  incorrect_cvc: "Wrong security code (CVC)",
  invalid_cvc: "Wrong security code (CVC)",
  incorrect_number: "Wrong card number",
  invalid_number: "Wrong card number",
  invalid_expiry_month: "Wrong expiry date",
  invalid_expiry_year: "Wrong expiry date",
  authentication_required: "Bank asked the customer to approve the payment (3-D Secure)",
  approve_with_id: "Bank could not approve the payment, retry may work",
  processing_error: "Card processing error, retry may work",
  issuer_not_available: "Customer's bank could not be reached, retry may work",
  try_again_later: "Bank asked to try again later",
  card_velocity_exceeded: "Card limit reached",
  withdrawal_count_limit_exceeded: "Card limit reached",
  card_not_supported: "Card does not allow this kind of payment",
  transaction_not_allowed: "Card does not allow this kind of payment",
  not_permitted: "Card does not allow this kind of payment",
  service_not_allowed: "Card does not allow this kind of payment",
  currency_not_supported: "Card cannot pay in this currency",
  fraudulent: "Bank flagged the payment as possible fraud",
  merchant_blacklist: "Blocked by Stripe's fraud check",
  invalid_account: "Card account is closed or invalid",
  new_account_information_available: "Card details changed, customer must update their card",
  revocation_of_authorization: "Customer cancelled the payment authorisation with their bank",
  revocation_of_all_authorizations: "Customer cancelled the payment authorisation with their bank",
  stop_payment_order: "Customer asked their bank to stop the payment",
  payment_intent_authentication_failure: "Customer did not complete the bank approval (3-D Secure)",
  card_decline_rate_limit_exceeded: "Too many declined attempts on this card",
};

const secsToIso = (s) => (s ? new Date(s * 1000).toISOString().replace(".000Z", "Z") : null);

// What Stripe knows about one failed renewal invoice: the decline reason,
// the card, how many attempts were made and when Stripe will try again.
async function failedRenewalDetails(stripe, row) {
  const invoice = await stripe.invoices.retrieve(row.stripe_invoice_id, { expand: ["payments"] });
  const payments = invoice.payments?.data || [];
  const invoicePayment = payments.find((p) => p.is_default) || payments[0] || null;
  const piRef = invoicePayment?.payment?.payment_intent || row.stripe_payment_intent_id || null;
  const piId = piRef && typeof piRef === "object" ? piRef.id : piRef;

  let pi = null;
  if (piId) {
    try {
      pi = await stripe.paymentIntents.retrieve(piId, { expand: ["latest_charge"] });
    } catch (err) {
      console.warn("FAILED_RENEWAL_PI_LOOKUP_FAILED:", { invoice: row.stripe_invoice_id, code: err?.code, message: err?.message });
    }
  }
  const err = pi?.last_payment_error || null;
  const charge = pi?.latest_charge && typeof pi.latest_charge === "object" ? pi.latest_charge : null;
  const outcome = charge?.outcome || null;
  const card =
    err?.payment_method?.card ||
    charge?.payment_method_details?.card ||
    null;

  const declineCode = err?.decline_code || charge?.outcome?.reason || null;
  const code = err?.code || charge?.failure_code || null;
  let label =
    (declineCode && DECLINE_LABEL[declineCode]) ||
    (code && DECLINE_LABEL[code]) ||
    null;
  if (!label && outcome?.type === "blocked") label = "Blocked by Stripe's fraud check";
  if (!label && !piId && invoice.status === "open" && !invoice.default_payment_method) label = "No card on file to charge";
  if (!label && pi?.status === "processing") label = "Payment still processing at the bank";
  if (!label && pi?.status === "requires_action") label = "Bank asked the customer to approve the payment (3-D Secure)";

  return {
    invoice_status: invoice.status || null,
    amount_due: { amount: minorToMajor(invoice.amount_due), currency: String(invoice.currency || "usd").toUpperCase() },
    attempt_count: Number(invoice.attempt_count || 0),
    next_retry_at: secsToIso(invoice.next_payment_attempt),
    payment_status: pi?.status || null,
    reason: {
      label,
      message: err?.message || charge?.failure_message || outcome?.seller_message || null,
      code,
      decline_code: declineCode,
      network_advice: outcome?.advice_code || err?.advice_code || null,
    },
    card: card
      ? {
          brand: card.brand || null,
          last4: card.last4 || null,
          exp_month: card.exp_month || null,
          exp_year: card.exp_year || null,
        }
      : null,
  };
}

async function failedRenewals(body) {
  const { page, limit, offset } = parsePaging(body);
  const search = parseSearch(body);
  const state = String(body.state || body.status || "all").toLowerCase();
  if (state !== "all" && !FAILED_RENEWAL_STATES.includes(state)) {
    throw httpError(422, `state must be all or one of ${FAILED_RENEWAL_STATES.join(", ")}`);
  }

  const scope = [
    "pt.billing_reason = 'subscription_cycle'",
    FAILED_RENEWAL_SQL,
    notHiddenOnOrdersSql("pt.stripe_subscription_id"),
  ];
  const scopeParams = [];
  const fac = await facilityFilter(body);
  if (fac) {
    scope.push(fac.sql);
    scopeParams.push(...fac.params);
  }
  const where = [...scope];
  const params = [...scopeParams];
  if (state === "failed") where.push("pt.status = 'failed'");
  else if (state === "pending") where.push("pt.status = 'open'");
  if (search) {
    where.push(`(
      rs.purchaser_email LIKE ? OR rs.purchaser_name LIKE ? OR rs.attributed_partner_code LIKE ?
      OR pt.stripe_invoice_id LIKE ? OR pt.stripe_subscription_id LIKE ? OR rs.profile_id LIKE ?
    )`);
    params.push(...Array(6).fill(like(search)));
  }
  const whereSql = `WHERE ${where.join(" AND ")}`;
  const from = `
    FROM payment_transactions pt
    LEFT JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id
  `;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total ${from} ${whereSql}`, params);
  const [rows] = await pool.query(
    `
      SELECT
        pt.id, pt.stripe_subscription_id, pt.stripe_invoice_id, pt.stripe_payment_intent_id,
        pt.period_start, pt.period_end, pt.currency, pt.status, pt.failure_message,
        pt.payment_method_type, pt.card_last4, pt.created_at,
        rs.purchaser_email, rs.purchaser_name, rs.profile_id, rs.attributed_partner_code, rs.qr_id,
        rs.status AS subscription_status, rs.current_period_start, rs.current_period_end, rs.canceled_at,
        rs.unit_amount_minor, rs.currency AS plan_currency, rs.created_at AS purchased_at,
        (
          SELECT COUNT(*) FROM payment_transactions p2
          WHERE p2.stripe_subscription_id = pt.stripe_subscription_id
            AND p2.billing_reason = 'subscription_cycle'
            AND p2.id <= pt.id
        ) AS renewal_number
      ${from} ${whereSql}
      ORDER BY pt.created_at DESC, pt.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  // Counts across every failed renewal (ignoring the search and state filter).
  const [[counts]] = await pool.query(
    `SELECT COUNT(*) AS total,
            COALESCE(SUM(pt.status = 'failed'), 0) AS failed,
            COALESCE(SUM(pt.created_at >= UTC_TIMESTAMP() - INTERVAL 30 DAY), 0) AS last_30_days
     FROM payment_transactions pt
     ${fac ? "LEFT JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id" : ""}
     WHERE ${scope.join(" AND ")}`,
    scopeParams
  );

  const subIds = [...new Set(rows.map((r) => r.stripe_subscription_id).filter(Boolean))];

  // Phone from Checkout, for a follow-up call.
  const phoneBySub = new Map();
  if (subIds.length) {
    try {
      const [ship] = await pool.query(
        "SELECT stripe_subscription_id, phone FROM subscription_shipping_addresses WHERE stripe_subscription_id IN (?)",
        [subIds]
      );
      for (const s of ship) phoneBySub.set(s.stripe_subscription_id, s.phone || null);
    } catch (err) {
      console.error("SUPER_ADMIN_ORDERS_FAILED_RENEWAL_SHIPPING_ERROR:", { code: err?.code, message: err?.message });
    }
  }

  // Paid since? A later renewal of the same subscription that went through
  // means the member is back on track even though this invoice failed.
  const paidLater = new Map();
  if (subIds.length) {
    const [paid] = await pool.query(
      `
        SELECT stripe_subscription_id, MAX(COALESCE(paid_at, created_at)) AS last_paid_at
        FROM payment_transactions
        WHERE stripe_subscription_id IN (?) AND status IN (?)
        GROUP BY stripe_subscription_id
      `,
      [subIds, PAID_STATUSES]
    );
    for (const p of paid) paidLater.set(p.stripe_subscription_id, toIso(p.last_paid_at));
  }

  // The decline reason, card and retry schedule live in Stripe. Best-effort:
  // a Stripe hiccup leaves `stripe` null and the page falls back to the
  // message saved by the webhook.
  const details = new Map();
  try {
    const stripe = requireStripe();
    const CHUNK = 8;
    for (let i = 0; i < rows.length; i += CHUNK) {
      await Promise.all(
        rows.slice(i, i + CHUNK).map(async (r) => {
          try {
            details.set(r.id, await failedRenewalDetails(stripe, r));
          } catch (err) {
            console.warn("FAILED_RENEWAL_STRIPE_LOOKUP_FAILED:", { invoice: r.stripe_invoice_id, code: err?.code, message: err?.message });
          }
        })
      );
    }
  } catch {
    // No Stripe key configured: details stay null.
  }

  const codeOf = (r) => String(r.attributed_partner_code || "").toUpperCase() || null;
  const facilities = await facilityByCode(rows, codeOf);

  const now = Date.now();
  return {
    filters: { state, search, search_min_length: SEARCH_MIN_LENGTH },
    failed_renewals: rows.map((r) => {
      const d = details.get(r.id) || null;
      const lastPaid = paidLater.get(r.stripe_subscription_id) || null;
      const createdIso = toIso(r.created_at);
      return {
        id: Number(r.id),
        failed_at: createdIso,
        // failed = Stripe reported a failure; pending = no outcome after a day.
        state: r.status === "failed" ? "failed" : "pending",
        customer: {
          name: r.purchaser_name || null,
          email: r.purchaser_email || null,
          phone: phoneBySub.get(r.stripe_subscription_id) || null,
          // The linked app profile (null until the buyer redeems their code).
          profile_id: r.profile_id || null,
        },
        partner_code: r.attributed_partner_code || null,
        qr_id: r.qr_id || null,
        facility: (codeOf(r) && facilities.get(codeOf(r))) || null,
        purchased_at: toIso(r.purchased_at),
        renewal_number: r.renewal_number == null ? null : Number(r.renewal_number),
        period_start: toIso(r.period_start),
        period_end: toIso(r.period_end),
        // Amount Stripe tried to charge (from Stripe; plan price as fallback).
        amount_due:
          d?.amount_due ||
          (r.unit_amount_minor != null
            ? { amount: minorToMajor(r.unit_amount_minor), currency: String(r.plan_currency || r.currency || "usd").toUpperCase() }
            : null),
        // Why it failed: the webhook's saved message, plus Stripe's detail.
        failure_message: r.failure_message || null,
        reason: d?.reason || null,
        card: d?.card || (r.card_last4 ? { brand: null, last4: r.card_last4, exp_month: null, exp_year: null } : null),
        attempt_count: d?.attempt_count ?? null,
        next_retry_at: d?.next_retry_at || null,
        invoice_status: d?.invoice_status || null,
        payment_status: d?.payment_status || null,
        // A paid invoice of this subscription newer than this failure.
        paid_since: lastPaid && createdIso && Date.parse(lastPaid) > Date.parse(createdIso) ? lastPaid : null,
        plan: {
          subscription_status: deriveSubscriptionStatus(r, now),
          stripe_status: r.subscription_status || null,
          current_period_start: toIso(r.current_period_start),
          current_period_end: toIso(r.current_period_end),
          canceled_at: toIso(r.canceled_at),
        },
        stripe_subscription_id: r.stripe_subscription_id,
        stripe_invoice_id: r.stripe_invoice_id,
      };
    }),
    summary: {
      total: Number(counts.total || 0),
      failed: Number(counts.failed || 0),
      pending: Number(counts.total || 0) - Number(counts.failed || 0),
      last_30_days: Number(counts.last_30_days || 0),
    },
    state_options: FAILED_RENEWAL_STATES,
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
    else if (view === "cancellations") payload = await cancellations(body);
    else if (view === "failed_renewals") payload = await failedRenewals(body);
    else if (view === "facility_options") payload = await facilityOptions();
    else return res.status(422).json({ status: false, ok: false, message: "view must be shipping, payments, upcoming_renewals, cancellations, failed_renewals or facility_options" });

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

module.exports = {
  superAdminOrders,
  // Shared with facility-admin-payments.js (a facility admin's own payments).
  _helpers: {
    ORDERS_VIEWER_EMAILS,
    SEARCH_MIN_LENGTH,
    PAYMENT_STATUSES,
    PAYMENT_TYPES,
    minorToMajor,
    toIso,
    deriveSubscriptionStatus,
    httpError,
    parsePaging,
    parseSearch,
    like,
  },
};
