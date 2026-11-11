"use strict";

/**
 * POST /dietitian/api/web/super-admin-sales-analytics   (super_admin only)
 *
 * Network-wide Rysflo membership sales, split into website purchases and
 * trainer-code purchases. Read-only; uses existing tables only:
 *
 *   referral_subscriptions   one row per completed Checkout (rysflo.com/buy and
 *                            the dashboard /order page both land here)
 *   partner_promotion_codes  promo code used at Checkout -> its Stripe coupon
 *   pricing_settings         list / referred price of that coupon (the discount)
 *   commission_entries       actual amount paid on the first invoice, and
 *                            reversals (refunds), for commission-earning sales
 *   app_user_roles, table_dietician, table_clients   names
 *
 * Definitions
 *   Purchase      a referral_subscriptions row, dated by created_at (UTC).
 *   Source        trainer_code whenever the purchase carries a trainer/gym code
 *                 (attributed_partner_code is set), website when it is empty.
 *                 A promotion code is not required: with list price = referred
 *                 price there is no coupon, so a code used at Checkout leaves
 *                 no promotion code behind (29 Sep 2026, user's rule).
 *   Amounts       first payment only. gross = list price charged
 *                 (unit_amount_minor); discount = the coupon of the promotion
 *                 code used; net = first invoice amount from commission_entries
 *                 when present, else gross - discount. Renewals are not
 *                 included: website renewals are not stored in the database.
 *   Payment       refunded when every ledger entry of the first invoice is
 *                 reversed; unpaid when the subscription never became payable
 *                 (incomplete*); otherwise paid. Refunded/unpaid purchases are
 *                 listed but excluded from sales and purchase counts.
 *
 * Trainer Admin views: pass trainer_admin (the TA's email) with overview or
 * purchases to limit every number to that TA's network (see
 * trainerAdminNetwork). view=trainer_admins lists the TAs to choose from.
 *
 * Body: { view: "overview" | "purchases" | "trainer_admins", trainer_admin?, period: week|month|year,
 *         date_from, date_to (YYYY-MM-DD, inclusive, viewer's calendar),
 *         tz_offset_minutes,
 *         purchases only: source, partner_code, subscription_status, payment_status, search, page, limit }
 */

const pool = require("../../../../config/db");
const { PLAN_CODE } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");
const { FIRST_PAYMENT_COLUMNS, firstPaymentAmounts } = require("../../../../services/firstPaymentAmount");
const { realSubscriptionSql } = require("../../../../services/excludedSubscriptions");

const YMD = /^\d{4}-\d{2}-\d{2}$/;
const PERIODS = new Set(["week", "month", "year"]);
const SOURCES = new Set(["all", "website", "trainer_code"]);
const SEARCH_MIN_LENGTH = 3;
const PLAN_NAMES = { [PLAN_CODE]: "Rysflo Membership" };
const UNPAID_SUB_STATUSES = new Set(["incomplete", "incomplete_expired"]);

// Stripe subscription statuses, spelled the way the dashboard shows them.
const SUB_STATUS_LABEL = { canceled: "cancelled", incomplete_expired: "expired" };

const minorToMajor = (v) => (v == null ? null : Math.round(Number(v)) / 100);
const pad = (n) => String(n).padStart(2, "0");

function fmtUtc(ms) {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toMs(v) {
  if (!v) return null;
  if (v instanceof Date) return v.getTime();
  const t = Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(t) ? null : t;
}

const toIso = (v) => {
  const ms = toMs(v);
  return ms == null ? null : new Date(ms).toISOString().replace(".000Z", "Z");
};

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

/**
 * Every purchase in the window with the columns the page needs. Volume is one
 * row per membership sold, so the period is aggregated here in JS.
 */
async function loadPurchases(p) {
  const [rows] = await pool.query(
    `
      SELECT
        rs.id, rs.stripe_subscription_id, rs.stripe_checkout_session_id, rs.stripe_customer_id,
        rs.purchaser_email, rs.purchaser_name, rs.profile_id,
        rs.attributed_partner_code, rs.attributed_user_id, rs.attributed_role, rs.facility_id,
        rs.stripe_promotion_code_id, rs.qr_id,
        rs.purchase_code, rs.plan_code, rs.currency, rs.unit_amount_minor,
        rs.status, rs.current_period_end, rs.canceled_at, rs.created_at,
        ${FIRST_PAYMENT_COLUMNS},
        (
          SELECT tc.profile_name
          FROM table_clients tc
          WHERE rs.profile_id IS NOT NULL AND tc.profile_id = rs.profile_id
          ORDER BY tc.id DESC
          LIMIT 1
        ) AS profile_name
      FROM referral_subscriptions rs
      WHERE rs.created_at >= ? AND rs.created_at < ?
        AND ${realSubscriptionSql("rs.stripe_subscription_id")}
      ORDER BY rs.created_at DESC, rs.id DESC
    `,
    [p.startUtc, p.endUtc]
  );

  // Refund state of each first invoice: refunded when all its entries are reversed.
  const invoiceIds = [...new Set(rows.map((r) => r.first_invoice_id).filter(Boolean))];
  const reversed = new Set();
  if (invoiceIds.length) {
    const [rev] = await pool.query(
      `
        SELECT stripe_invoice_id
        FROM commission_entries
        WHERE stripe_invoice_id IN (?)
        GROUP BY stripe_invoice_id
        HAVING SUM(status <> 'reversed') = 0
      `,
      [invoiceIds]
    );
    for (const r of rev) reversed.add(r.stripe_invoice_id);
  }

  return rows.map((r) => {
    const code = String(r.attributed_partner_code || "").toUpperCase();
    // Trainer-code sale = a code is on the purchase (see "Source" above).
    const usedCodeAtCheckout = !!code;
    const createdMs = toMs(r.created_at);
    // Gross / discount / net, shared with the Facilities Active members list.
    const { gross, discount, net, amountSource, firstInvoiceId } = firstPaymentAmounts(r);

    let paymentStatus = "paid";
    if (UNPAID_SUB_STATUSES.has(String(r.status))) paymentStatus = "unpaid";
    else if (firstInvoiceId && reversed.has(firstInvoiceId)) paymentStatus = "refunded";

    return {
      raw: r,
      createdMs,
      firstInvoiceId,
      source: usedCodeAtCheckout ? "trainer_code" : "website",
      code: usedCodeAtCheckout ? code : null,
      linkedCode: !usedCodeAtCheckout && code ? code : null,
      currency: String(r.currency || "USD").toUpperCase(),
      gross,
      discount,
      net,
      amountSource,
      paymentStatus,
      counts: paymentStatus === "paid",
      // A live plan with canceled_at set is a cancel-at-period-end request:
      // the buyer keeps access until current_period_end, then it ends.
      subStatus:
        r.canceled_at && String(r.status) !== "canceled"
          ? "cancellation_scheduled"
          : SUB_STATUS_LABEL[r.status] || r.status || null,
    };
  });
}

/**
 * Trainer name per partner code. Codes can belong to an active role row, to a
 * user who has since been removed (name still found through the purchase's
 * attributed_user_id), or to a pending invitation.
 */
async function trainerDirectory(codes, emailByCode = new Map()) {
  const map = new Map();
  if (!codes.length) return map;

  const [rows] = await pool.query(
    `
      SELECT UPPER(aur.partner_code) AS code, td.dietician_id, NULLIF(td.name, '') AS name, LOWER(aur.user_id) AS email
      FROM app_user_roles aur
      LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE UPPER(aur.partner_code) IN (?)
    `,
    [codes]
  );
  for (const r of rows) if (!map.has(r.code) && r.name) map.set(r.code, { trainer_id: r.dietician_id || null, name: r.name, email: r.email || null });

  const byEmail = codes.filter((c) => !map.has(c) && emailByCode.get(c));
  if (byEmail.length) {
    const [tds] = await pool.query(
      `SELECT LOWER(email) AS email, dietician_id, NULLIF(name, '') AS name FROM table_dietician WHERE LOWER(email) IN (?)`,
      [byEmail.map((c) => emailByCode.get(c))]
    );
    const tdByEmail = new Map(tds.map((t) => [t.email, t]));
    for (const c of byEmail) {
      const t = tdByEmail.get(emailByCode.get(c));
      if (t?.name) map.set(c, { trainer_id: t.dietician_id || null, name: t.name, email: t.email });
    }
  }

  const rest = codes.filter((c) => !map.has(c));
  if (rest.length) {
    const [inv] = await pool.query(
      `
        SELECT UPPER(partner_code) AS code,
               NULLIF(TRIM(CONCAT_WS(' ', invited_first_name, invited_last_name)), '') AS name,
               facility_name, LOWER(invited_email) AS email
        FROM app_user_invitations
        WHERE UPPER(partner_code) IN (?)
        ORDER BY id DESC
      `,
      [rest]
    );
    for (const r of inv) if (!map.has(r.code) && (r.name || r.facility_name)) map.set(r.code, { trainer_id: null, name: r.name || r.facility_name, email: r.email || null });
  }
  // Still unnamed: at least show the account the sale was attributed to.
  for (const c of codes) if (!map.has(c) && emailByCode.get(c)) map.set(c, { trainer_id: null, name: null, email: emailByCode.get(c) });
  for (const [c, v] of map) if (!v.email && emailByCode.get(c)) v.email = emailByCode.get(c);
  return map;
}

/**
 * Where each code sits in the network: its role, the user who onboarded it
 * (app_user_roles.parent_user_id) and its facility with the facility admin.
 * Falls back to the pending invitation, then to what was stamped on the
 * purchase (attributed_role / facility_id) for codes with no role row.
 * Also used by super-admin-orders for the shipping rows' facility.
 */
async function trainerHierarchy(codes, items) {
  const map = new Map();
  if (!codes.length) return map;

  const [roles] = await pool.query(
    `
      SELECT UPPER(partner_code) AS code, role, LOWER(parent_user_id) AS parent_user_id, facility_id
      FROM app_user_roles
      WHERE UPPER(partner_code) IN (?)
    `,
    [codes]
  );
  for (const r of roles) {
    if (!map.has(r.code)) map.set(r.code, { role: r.role, parent_user_id: r.parent_user_id || null, facility_id: r.facility_id });
  }

  const missing = codes.filter((c) => !map.has(c));
  if (missing.length) {
    const [inv] = await pool.query(
      `
        SELECT UPPER(partner_code) AS code, invited_role AS role, LOWER(parent_user_id) AS parent_user_id,
               facility_id, NULLIF(facility_name, '') AS facility_name
        FROM app_user_invitations
        WHERE UPPER(partner_code) IN (?)
        ORDER BY id DESC
      `,
      [missing]
    );
    for (const r of inv) {
      if (!map.has(r.code)) {
        map.set(r.code, {
          role: r.role,
          parent_user_id: r.parent_user_id || null,
          facility_id: r.facility_id,
          invited_facility_name: r.facility_name || null,
        });
      }
    }
  }

  // A code the account no longer holds (re-issued code, removed role row):
  // fall back to the account the sale was attributed to, by email.
  const emailByCode = new Map();
  for (const i of items) {
    const code = i.code || i.linkedCode;
    if (code && i.raw.attributed_user_id && !emailByCode.has(code)) emailByCode.set(code, String(i.raw.attributed_user_id).toLowerCase());
  }
  const needAccount = codes.filter((c) => !map.get(c)?.parent_user_id && emailByCode.get(c));
  if (needAccount.length) {
    const [acc] = await pool.query(
      `
        SELECT LOWER(user_id) AS email, role, LOWER(parent_user_id) AS parent_user_id, facility_id
        FROM app_user_roles
        WHERE LOWER(user_id) IN (?)
      `,
      [[...new Set(needAccount.map((c) => emailByCode.get(c)))]]
    );
    const byEmail = new Map(acc.map((a) => [a.email, a]));
    for (const c of needAccount) {
      const a = byEmail.get(emailByCode.get(c));
      if (!a) continue;
      const h = map.get(c) || {};
      map.set(c, {
        ...h,
        role: h.role || a.role,
        parent_user_id: h.parent_user_id || a.parent_user_id || null,
        facility_id: h.facility_id ?? a.facility_id,
      });
    }
  }

  for (const i of items) {
    const code = i.code || i.linkedCode;
    if (!code || !codes.includes(code)) continue;
    const h = map.get(code) || { role: null, parent_user_id: null, facility_id: null };
    if (!h.role && i.raw.attributed_role) h.role = i.raw.attributed_role;
    if (h.facility_id == null && i.raw.facility_id != null) h.facility_id = i.raw.facility_id;
    map.set(code, h);
  }

  // Facilities by id, plus by the code itself / the owner's email for facility
  // admins whose role row has no facility_id.
  const facilityIds = [...new Set([...map.values()].map((h) => h.facility_id).filter((v) => v != null).map(Number))];
  const ownerEmails = [...new Set(codes.map((c) => emailByCode.get(c)).filter(Boolean))];
  const facilities = new Map();
  const [fs] = await pool.query(
    `
      SELECT id, name, UPPER(partner_code) AS partner_code, LOWER(facility_admin_user_id) AS admin_user_id, status
      FROM facilities
      WHERE id IN (?) OR UPPER(partner_code) IN (?) OR LOWER(facility_admin_user_id) IN (?)
    `,
    [facilityIds.length ? facilityIds : [0], codes, ownerEmails.length ? ownerEmails : [""]]
  );
  for (const f of fs) facilities.set(Number(f.id), f);
  for (const [code, h] of map) {
    if (h.facility_id != null) continue;
    const f = fs.find((x) => x.partner_code === code || (emailByCode.get(code) && x.admin_user_id === emailByCode.get(code)));
    if (f) h.facility_id = f.id;
  }

  const emails = [
    ...new Set(
      [...map.values()].map((h) => h.parent_user_id).concat([...facilities.values()].map((f) => f.admin_user_id)).filter(Boolean)
    ),
  ];
  const names = new Map();
  if (emails.length) {
    const [tds] = await pool.query(`SELECT LOWER(email) AS email, NULLIF(name, '') AS name FROM table_dietician WHERE LOWER(email) IN (?)`, [emails]);
    for (const t of tds) if (t.name && !names.has(t.email)) names.set(t.email, t.name);
  }

  const out = new Map();
  for (const [code, h] of map) {
    const f = h.facility_id != null ? facilities.get(Number(h.facility_id)) : null;
    out.set(code, {
      role: h.role || null,
      parent_user_id: h.parent_user_id || null,
      parent_name: h.parent_user_id ? names.get(h.parent_user_id) || null : null,
      facility: f
        ? {
            id: Number(f.id),
            name: f.name,
            partner_code: f.partner_code,
            status: f.status,
            admin_user_id: f.admin_user_id,
            admin_name: names.get(f.admin_user_id) || null,
          }
        : h.invited_facility_name
          ? // Invited but never set up: only the name typed on the invitation exists.
            { id: null, name: h.invited_facility_name, partner_code: null, status: "invited", admin_user_id: null, admin_name: null }
          : null,
    });
  }
  return out;
}

function emailsByCode(items) {
  const m = new Map();
  for (const i of items) {
    const code = i.code || i.linkedCode;
    if (code && i.raw.attributed_user_id && !m.has(code)) m.set(code, String(i.raw.attributed_user_id).toLowerCase());
  }
  return m;
}

// Chooses the currency to report: the one carrying the most revenue.
function primaryCurrency(items) {
  const byCurrency = new Map();
  for (const i of items) if (i.counts) byCurrency.set(i.currency, (byCurrency.get(i.currency) || 0) + i.net);
  const top = [...byCurrency.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  return { currency: top || "USD", others: [...byCurrency.keys()].filter((c) => c !== top) };
}

// ─── Trainer Admin scope ─────────────────────────────────────────────────────

/**
 * Trainer Admins offered in the page's view switcher: the active members of
 * the admin groups (ta_admin_groups), the same list TA Analytics shows.
 */
async function trainerAdmins() {
  const [rows] = await pool.query(
    `
      SELECT g.group_name, UPPER(g.dietician_id) AS code,
             LOWER(COALESCE(NULLIF(td.email, ''), aur.user_id)) AS email,
             NULLIF(td.name, '') AS name, aur.role
      FROM ta_admin_groups g
      LEFT JOIN table_dietician td ON UPPER(td.dietician_id) = UPPER(g.dietician_id)
      LEFT JOIN app_user_roles aur ON UPPER(aur.partner_code) = UPPER(g.dietician_id)
      WHERE g.status = 'active'
      ORDER BY g.added_at ASC, g.id ASC
    `
  );
  const byEmail = new Map();
  for (const r of rows) {
    if (!r.email) continue;
    const ta = byEmail.get(r.email) || { user_id: r.email, name: r.name || r.email, partner_code: r.code, role: r.role || null, groups: [] };
    if (!ta.groups.includes(r.group_name)) ta.groups.push(r.group_name);
    byEmail.set(r.email, ta);
  }
  return [...byEmail.values()];
}

/**
 * Everything that belongs to a Trainer Admin's network: their own code, users
 * they onboarded (parent_user_id), facilities they onboarded
 * (facilities.parent_admin_user_id) and those facilities' trainers, walked a
 * few levels down, plus pending invitations sent by anyone in the network.
 */
async function trainerAdminNetwork(taEmail) {
  const [[ta]] = await pool.query(
    `SELECT LOWER(user_id) AS email, UPPER(partner_code) AS code, role FROM app_user_roles WHERE LOWER(user_id) = ? LIMIT 1`,
    [taEmail]
  );
  if (!ta) throw httpError(404, "Trainer admin not found");

  const emails = new Set([ta.email]);
  const codes = new Set(ta.code ? [ta.code] : []);
  const facilityIds = new Set();

  const [fs] = await pool.query(
    `SELECT id, UPPER(partner_code) AS code, LOWER(facility_admin_user_id) AS admin FROM facilities WHERE LOWER(parent_admin_user_id) = ?`,
    [ta.email]
  );
  for (const f of fs) {
    facilityIds.add(Number(f.id));
    if (f.code) codes.add(f.code);
    if (f.admin) emails.add(f.admin);
  }

  for (let depth = 0; depth < 4; depth++) {
    const before = emails.size + facilityIds.size;
    const [rows] = await pool.query(
      `
        SELECT LOWER(user_id) AS email, UPPER(partner_code) AS code, facility_id
        FROM app_user_roles
        WHERE LOWER(parent_user_id) IN (?) OR facility_id IN (?)
      `,
      [[...emails], facilityIds.size ? [...facilityIds] : [0]]
    );
    for (const r of rows) {
      emails.add(r.email);
      if (r.code) codes.add(r.code);
      if (r.facility_id != null) facilityIds.add(Number(r.facility_id));
    }
    if (emails.size + facilityIds.size === before) break;
  }

  const [inv] = await pool.query(
    `
      SELECT UPPER(partner_code) AS code, LOWER(invited_email) AS email
      FROM app_user_invitations
      WHERE LOWER(parent_user_id) IN (?) OR facility_id IN (?)
    `,
    [[...emails], facilityIds.size ? [...facilityIds] : [0]]
  );
  for (const r of inv) {
    if (r.code) codes.add(r.code);
    if (r.email) emails.add(r.email);
  }

  return {
    email: ta.email,
    codes,
    emails,
    facilityIds,
    has(i) {
      const code = i.code || i.linkedCode;
      if (code && codes.has(code)) return true;
      const attributedTo = String(i.raw.attributed_user_id || "").toLowerCase();
      if (attributedTo && emails.has(attributedTo)) return true;
      return i.raw.facility_id != null && facilityIds.has(Number(i.raw.facility_id));
    },
  };
}

async function scopeFor(body) {
  const email = String(body.trainer_admin || "").trim().toLowerCase();
  if (!email) return null;
  if (email.length > 191 || !/^[^\s@]+@[^\s@]+$/.test(email)) throw httpError(422, "Invalid trainer_admin");
  return trainerAdminNetwork(email);
}

// ─── Renewals & retention (part of view=overview) ────────────────────────────

// Stripe statuses after which a membership is over for good.
const ENDED_STATUSES = new Set(["canceled", "cancelled", "incomplete_expired", "expired", "unpaid"]);
const PAID_INVOICE = "('paid','partially_refunded','refunded')";

const pct = (part, whole) => (whole ? Math.round((part / whole) * 1000) / 10 : null);

// Minimal purchase-shaped object so scope.has() works on plain SQL rows.
const scopeItem = (r) => ({
  code: String(r.attributed_partner_code || "").toUpperCase() || null,
  linkedCode: null,
  raw: { attributed_user_id: r.attributed_user_id, facility_id: r.facility_id },
});

// Buckets a membership by its subscription status (same labels as the table).
function memberState(status, canceledAt) {
  const s = String(status || "");
  if (ENDED_STATUSES.has(s)) return "ended";
  if (canceledAt) return "cancellation_scheduled";
  if (s === "active" || s === "trialing") return "active";
  return "at_risk"; // past_due and anything Stripe is still retrying
}

/**
 * Renewal and retention numbers for the window, all with percentages.
 *
 *   renewals   paid renewal invoices (payment_transactions, billing_reason
 *              subscription_cycle) collected in the window, and the renewal
 *              rate: of the paid billing periods that ENDED in the window (up to
 *              now), how many were followed by a paid renewal, are still
 *              pending (plan live, renewal not paid yet) or lapsed (plan ended).
 *   cohort     purchases made in the window and what state they are in today.
 *   members    every paid membership ever sold (in scope): still active vs ended.
 *   cancellations  members whose canceled_at falls in the window: still has
 *              access (scheduled) vs ended, plus the newest 50 by name.
 *
 * payment_transactions is optional (production may not have migration 006):
 * without it renewals is null and the page says renewal data is unavailable.
 */
async function renewalsAndRetention(p, scope, currency, counted, firstPaymentNet) {
  const inScope = (r) => !scope || scope.has(scopeItem(r));

  let renewals = null;
  try {
    const [paidRows] = await pool.query(
      `
        SELECT pt.amount_paid_minor, pt.amount_refunded_minor, pt.currency,
               rs.attributed_partner_code, rs.attributed_user_id, rs.facility_id
        FROM payment_transactions pt
        JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id
        WHERE pt.billing_reason = 'subscription_cycle'
          AND pt.status IN ${PAID_INVOICE}
          AND COALESCE(pt.paid_at, pt.created_at) >= ? AND COALESCE(pt.paid_at, pt.created_at) < ?
          AND ${realSubscriptionSql("rs.stripe_subscription_id")}
      `,
      [p.startUtc, p.endUtc]
    );
    const [dueRows] = await pool.query(
      `
        SELECT pt.id, rs.status, rs.canceled_at, (pt.period_end > UTC_TIMESTAMP()) AS not_ended,
               rs.attributed_partner_code, rs.attributed_user_id, rs.facility_id,
               EXISTS (
                 SELECT 1 FROM payment_transactions n
                 WHERE n.stripe_subscription_id = pt.stripe_subscription_id
                   AND n.id <> pt.id
                   AND n.billing_reason = 'subscription_cycle'
                   AND n.status IN ${PAID_INVOICE}
                   AND n.period_start >= DATE_SUB(pt.period_end, INTERVAL 1 DAY)
               ) AS renewed
        FROM payment_transactions pt
        JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id
        WHERE pt.billing_reason IN ('subscription_create', 'subscription_cycle')
          AND pt.status IN ('paid', 'partially_refunded')
          AND pt.period_end >= ? AND pt.period_end < ?
          AND ${realSubscriptionSql("rs.stripe_subscription_id")}
      `,
      [p.startUtc, p.endUtc]
    );
    // dueRows also carries periods that end later in the window; only the ones
    // already cancelled count (they will not renew), the rest are not due yet.

    const paid = paidRows.filter((r) => inScope(r) && String(r.currency || "").toUpperCase() === currency);
    const net = paid.reduce((s, r) => s + Number(r.amount_paid_minor || 0) - Number(r.amount_refunded_minor || 0), 0);

    // renewed    a paid renewal followed
    // cancelled  month not over yet, but they already cancelled: will not renew
    // lapsed     month over, plan ended without renewing
    // pending    month over, plan still live, renewal not paid yet
    const due = { total: 0, renewed: 0, pending: 0, lapsed: 0, cancelled: 0 };
    for (const r of dueRows) {
      if (!inScope(r)) continue;
      const renewed = Number(r.renewed);
      const ended = memberState(r.status, null) === "ended";
      if (Number(r.not_ended)) {
        if (renewed) due.renewed += 1;
        else if (r.canceled_at || ended) due.cancelled += 1;
        else continue; // not due yet
      } else if (renewed) due.renewed += 1;
      else if (ended) due.lapsed += 1;
      else due.pending += 1;
      due.total += 1;
    }

    renewals = {
      payments: paid.length,
      net_sales: minorToMajor(net),
      // Renewal money as a share of everything collected (first payments + renewals).
      share_of_sales: pct(net, net + firstPaymentNet),
      due: due.total,
      renewed: due.renewed,
      pending: due.pending,
      lapsed: due.lapsed,
      cancelled: due.cancelled,
      cancelled_rate: pct(due.cancelled, due.total),
      renewal_rate: pct(due.renewed, due.total),
      pending_rate: pct(due.pending, due.total),
      lapse_rate: pct(due.lapsed, due.total),
    };
  } catch (err) {
    if (err?.code !== "ER_NO_SUCH_TABLE" && err?.errno !== 1146) throw err;
  }

  // Purchases made in this window, by where they stand today.
  const cohort = { purchases: counted.length, active: 0, cancellation_scheduled: 0, at_risk: 0, ended: 0 };
  for (const i of counted) cohort[memberState(i.raw.status, i.raw.canceled_at)] += 1;

  // Every paid membership ever sold in scope.
  const [memberRows] = await pool.query(
    `
      SELECT status, canceled_at, attributed_partner_code, attributed_user_id, facility_id
      FROM referral_subscriptions
      WHERE ${realSubscriptionSql()}
        AND status NOT IN ('incomplete', 'incomplete_expired')
    `
  );
  const members = { total: 0, active: 0, cancellation_scheduled: 0, at_risk: 0, ended: 0 };
  for (const r of memberRows) {
    if (!inScope(r)) continue;
    members.total += 1;
    members[memberState(r.status, r.canceled_at)] += 1;
  }

  // Members who cancelled during the window (Stripe canceled_at = when they asked
  // to cancel). "scheduled" still have access until their paid month ends.
  const [cancelRows] = await pool.query(
    `
      SELECT rs.id, rs.purchaser_name, rs.purchaser_email, rs.profile_id,
             rs.attributed_partner_code, rs.attributed_user_id, rs.facility_id,
             rs.canceled_at, rs.current_period_end, rs.created_at,
             (rs.status IN ('active', 'trialing', 'past_due') AND rs.current_period_end > UTC_TIMESTAMP()) AS still_active
      FROM referral_subscriptions rs
      WHERE rs.canceled_at >= ? AND rs.canceled_at < ?
        AND ${realSubscriptionSql("rs.stripe_subscription_id")}
        AND rs.status NOT IN ('incomplete', 'incomplete_expired')
      ORDER BY rs.canceled_at DESC, rs.id DESC
    `,
    [p.startUtc, p.endUtc]
  );
  const cancelled = cancelRows.filter(inScope);
  const cancelScheduled = cancelled.filter((r) => Number(r.still_active)).length;
  const CANCEL_LIST_MAX = 50;
  const cancellations = {
    total: cancelled.length,
    scheduled: cancelScheduled,
    ended: cancelled.length - cancelScheduled,
    list_limit: CANCEL_LIST_MAX,
    list: cancelled.slice(0, CANCEL_LIST_MAX).map((r) => ({
      id: Number(r.id),
      name: r.purchaser_name || null,
      email: r.purchaser_email || null,
      profile_id: r.profile_id || null,
      partner_code: r.attributed_partner_code || null,
      purchased_at: toIso(r.created_at),
      canceled_at: toIso(r.canceled_at),
      access_ends: toIso(r.current_period_end),
      state: Number(r.still_active) ? "scheduled" : "ended",
    })),
  };

  const rates = (o, whole) => ({
    active_rate: pct(o.active, whole),
    cancellation_scheduled_rate: pct(o.cancellation_scheduled, whole),
    at_risk_rate: pct(o.at_risk, whole),
    ended_rate: pct(o.ended, whole),
  });

  return {
    renewals,
    cohort: { ...cohort, ...rates(cohort, cohort.purchases) },
    cancellations,
    members: {
      ...members,
      ...rates(members, members.total),
      // Retained = still has access (active + cancelling at period end + payment retrying).
      retention_rate: pct(members.total - members.ended, members.total),
      churn_rate: pct(members.ended, members.total),
    },
  };
}

// ─── view=overview ───────────────────────────────────────────────────────────

async function overview(p, body) {
  const scope = await scopeFor(body);
  const all = await loadPurchases(p);
  const items = scope ? all.filter((i) => scope.has(i)) : all;
  const { currency, others } = primaryCurrency(items);
  const counted = items.filter((i) => i.counts && i.currency === currency);

  const blank = () => ({ purchases: 0, gross: 0, discount: 0, net: 0 });
  const add = (acc, i) => {
    acc.purchases += 1;
    acc.gross += i.gross;
    acc.discount += i.discount;
    acc.net += i.net;
  };

  const total = blank();
  const bySource = { website: blank(), trainer_code: blank() };
  const trend = new Map();
  const trainers = new Map();

  for (const i of counted) {
    add(total, i);
    add(bySource[i.source], i);

    const local = new Date(i.createdMs + p.offset * 60000);
    const bucket =
      p.granularity === "month"
        ? `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}`
        : `${local.getUTCFullYear()}-${pad(local.getUTCMonth() + 1)}-${pad(local.getUTCDate())}`;
    const b = trend.get(bucket) || { website: blank(), trainer_code: blank() };
    add(b[i.source], i);
    trend.set(bucket, b);

    if (i.source === "trainer_code") {
      const t = trainers.get(i.code) || blank();
      add(t, i);
      trainers.set(i.code, t);
    }
  }

  const ranked = [...trainers.entries()].sort((a, b) => b[1].net - a[1].net || b[1].purchases - a[1].purchases);
  const directory = await trainerDirectory(ranked.map(([code]) => code), emailsByCode(counted));
  const hierarchy = await trainerHierarchy(ranked.map(([code]) => code), counted);
  const [[active]] = scope
    ? await pool.query(
        `
          SELECT COUNT(*) AS n
          FROM referral_subscriptions
          WHERE status = 'active'
            AND ${realSubscriptionSql()}
            AND (UPPER(attributed_partner_code) IN (?) OR LOWER(attributed_user_id) IN (?) OR facility_id IN (?))
        `,
        [scope.codes.size ? [...scope.codes] : [""], [...scope.emails], scope.facilityIds.size ? [...scope.facilityIds] : [0]]
      )
    : await pool.query(`SELECT COUNT(*) AS n FROM referral_subscriptions WHERE status = 'active' AND ${realSubscriptionSql()}`);

  const retention = await renewalsAndRetention(p, scope, currency, counted, total.net);

  const channel = (c) => ({
    purchases: c.purchases,
    gross_sales: minorToMajor(c.gross),
    net_sales: minorToMajor(c.net),
    new_net_sales: minorToMajor(c.net),
  });

  return {
    filters: { period: p.period, date_from: p.dateFrom, date_to: p.dateTo, granularity: p.granularity, tz_offset_minutes: p.offset },
    summary: {
      currency,
      other_currencies: others,
      gross_sales: minorToMajor(total.gross),
      discounts: minorToMajor(total.discount),
      net_sales: minorToMajor(total.net),
      new_purchase_net_sales: minorToMajor(total.net),
      renewal_net_sales: retention.renewals ? retention.renewals.net_sales : 0,
      total_purchases: total.purchases,
      website_purchases: bySource.website.purchases,
      trainer_code_purchases: bySource.trainer_code.purchases,
      average_order_value: total.purchases ? minorToMajor(total.net / total.purchases) : 0,
      active_paid_subscribers: Number(active.n),
      ...(scope ? { trainer_admin: scope.email, network_codes: scope.codes.size } : {}),
      excluded_purchases: items.length - items.filter((i) => i.counts).length,
    },
    source_breakdown: { website: channel(bySource.website), trainer_code: channel(bySource.trainer_code) },
    trend: [...trend.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([bucket, b]) => ({
        bucket,
        website_sales: minorToMajor(b.website.net),
        trainer_sales: minorToMajor(b.trainer_code.net),
        total_sales: minorToMajor(b.website.net + b.trainer_code.net),
        website_purchases: b.website.purchases,
        trainer_purchases: b.trainer_code.purchases,
      })),
    top_trainers: ranked.map(([code, t]) => ({
      ...(hierarchy.get(code) || { role: null, parent_user_id: null, parent_name: null, facility: null }),
      trainer_id: directory.get(code)?.trainer_id || null,
      trainer_email: directory.get(code)?.email || null,
      trainer_name: directory.get(code)?.name || null,
      partner_code: code,
      purchases: t.purchases,
      gross_sales: minorToMajor(t.gross),
      net_sales: minorToMajor(t.net),
    })),
    top_trainers_total: ranked.length,
    retention,
  };
}

// ─── view=engagement ─────────────────────────────────────────────────────────

const ENGAGEMENT_GROUPS = new Set(["all", "purchased", "renewed"]);
const COHORT_TIERS = [90, 70, 50, 25, 10];
const cohortOf = (rate) => {
  for (const t of COHORT_TIERS) if (rate >= t) return `${t}%+`;
  return "<10%";
};
const DAY_MS = 86400000;
const utcDay = (ms) => Math.floor(ms / DAY_MS);

/**
 * Client Engagement (same idea as TA Analytics) for paying customers only:
 * profiles that bought in the window, renewed in the window, or both.
 *
 *   member_since   the profile's first paid membership (earliest purchase)
 *   days           days from member_since to today, inclusive
 *   reading_days   distinct days with a breath test (table_test_data) since member_since
 *   rate           reading_days / days, capped at 100 (TA Analytics' "Rate")
 *
 * Body: overview's period fields + trainer_admin?, group?: all | purchased | renewed.
 * Rows carry customer names and emails (super_admin only, logged like the other views).
 */
async function engagement(p, body) {
  const group = String(body.group || "all");
  if (!ENGAGEMENT_GROUPS.has(group)) throw httpError(422, "group must be all, purchased or renewed");
  const scope = await scopeFor(body);
  const inScope = (r) => !scope || scope.has(scopeItem(r));

  // profile_id -> { purchased, renewed, sub row (latest seen) }
  const people = new Map();
  const note = (pid, row, kind) => {
    if (!pid) return;
    const cur = people.get(pid) || { purchased: false, renewed: false, row };
    cur[kind] = true;
    if (toMs(row.created_at) > toMs(cur.row.created_at)) cur.row = row;
    people.set(pid, cur);
  };

  if (group !== "renewed") {
    const bought = (await loadPurchases(p)).filter((i) => i.counts && (!scope || scope.has(i)));
    for (const i of bought) note(i.raw.profile_id, i.raw, "purchased");
  }

  let renewalsAvailable = true;
  if (group !== "purchased") {
    try {
      const [rows] = await pool.query(
        `
          SELECT rs.profile_id, rs.purchaser_name, rs.purchaser_email, rs.attributed_partner_code,
                 rs.attributed_user_id, rs.facility_id, rs.status, rs.canceled_at, rs.created_at
          FROM payment_transactions pt
          JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id
          WHERE pt.billing_reason = 'subscription_cycle'
            AND pt.status IN ${PAID_INVOICE}
            AND COALESCE(pt.paid_at, pt.created_at) >= ? AND COALESCE(pt.paid_at, pt.created_at) < ?
            AND ${realSubscriptionSql("rs.stripe_subscription_id")}
            AND rs.profile_id IS NOT NULL
        `,
        [p.startUtc, p.endUtc]
      );
      for (const r of rows) if (inScope(r)) note(r.profile_id, r, "renewed");
    } catch (err) {
      if (err?.code !== "ER_NO_SUCH_TABLE" && err?.errno !== 1146) throw err;
      renewalsAvailable = false;
    }
  }

  const ids = [...people.keys()];
  const nowMs = Date.now();
  const today = utcDay(nowMs + p.offset * 60000);
  const empty = {
    filters: { period: p.period, date_from: p.dateFrom, date_to: p.dateTo, group },
    renewals_available: renewalsAvailable,
    summary: {
      clients: 0, purchased: 0, renewed: 0, both: 0, avg_rate: 0, high_rate: 0, low_rate: 0,
      never_tested: 0, never_tested_rate: null, readings_this_week: 0, readings_last_week: 0,
      readings_week_change: null, goals: { fat_loss: 0, muscle_gain: 0, weight_loss: 0, other: 0 },
      cohorts: COHORT_TIERS.map((t) => ({ tier: `${t}%+`, count: 0, rate: null })).concat({ tier: "<10%", count: 0, rate: null }),
    },
    clients: [],
  };
  if (!ids.length) return empty;

  // First paid membership per profile, client name, goal, tests.
  const [since] = await pool.query(
    `
      SELECT profile_id, MIN(created_at) AS first_purchase
      FROM referral_subscriptions
      WHERE profile_id IN (?) AND ${realSubscriptionSql()}
        AND status NOT IN ('incomplete', 'incomplete_expired')
      GROUP BY profile_id
    `,
    [ids]
  );
  const [names] = await pool.query(
    `
      SELECT tc.profile_id, tc.profile_name, tc.email
      FROM table_clients tc
      JOIN (SELECT profile_id, MAX(id) AS id FROM table_clients WHERE profile_id IN (?) GROUP BY profile_id) x ON x.id = tc.id
    `,
    [ids]
  );
  const [goals] = await pool.query(
    `
      SELECT uh.profile_id, uh.goal
      FROM user_habits uh
      JOIN (SELECT profile_id, MAX(id) AS id FROM user_habits WHERE profile_id IN (?) GROUP BY profile_id) x ON x.id = uh.id
    `,
    [ids]
  );
  const [tests] = await pool.query(
    `
      SELECT profile_id, DATE_FORMAT(date_time, '%Y-%m-%d') AS day, COUNT(*) AS n,
             MAX(date_time) AS last_at,
             SUBSTRING_INDEX(GROUP_CONCAT(fat_loss_metabolism_score ORDER BY date_time DESC, test_id DESC), ',', 1) AS day_score
      FROM table_test_data
      WHERE profile_id IN (?)
      GROUP BY profile_id, DATE_FORMAT(date_time, '%Y-%m-%d')
    `,
    [ids]
  );

  const sinceBy = new Map(since.map((r) => [r.profile_id, toMs(r.first_purchase)]));
  const nameBy = new Map(names.map((r) => [r.profile_id, r]));
  const goalBy = new Map(goals.map((r) => [r.profile_id, String(r.goal || "").trim()]));
  const testsBy = new Map();
  for (const t of tests) {
    const list = testsBy.get(t.profile_id) || [];
    list.push({ day: utcDay(Date.parse(`${t.day}T00:00:00Z`)), n: Number(t.n) || 0, lastMs: toMs(t.last_at), score: t.day_score });
    testsBy.set(t.profile_id, list);
  }

  const codes = [...new Set([...people.values()].map((v) => String(v.row.attributed_partner_code || "").toUpperCase()).filter(Boolean))];
  const directory = await trainerDirectory(codes);

  const weekStart = today - 6;
  const prevWeekStart = today - 13;
  let thisWeek = 0;
  let lastWeek = 0;

  const clients = ids.map((pid) => {
    const v = people.get(pid);
    const startMs = sinceBy.get(pid) ?? toMs(v.row.created_at);
    const startDay = utcDay(startMs + p.offset * 60000);
    const days = Math.max(1, today - startDay + 1);
    const list = (testsBy.get(pid) || []).filter((t) => t.day >= startDay);
    const readingDays = list.length;
    const readings = list.reduce((s, t) => s + t.n, 0);
    for (const t of list) {
      if (t.day >= weekStart && t.day <= today) thisWeek += t.n;
      else if (t.day >= prevWeekStart && t.day < weekStart) lastWeek += t.n;
    }
    const latest = list.reduce((a, t) => (!a || t.lastMs > a.lastMs ? t : a), null);
    const rate = Math.min(100, Math.round((readingDays / days) * 100));
    const code = String(v.row.attributed_partner_code || "").toUpperCase() || null;
    const n = nameBy.get(pid);
    const score = latest?.score != null && latest.score !== "" ? Number(latest.score) : null;
    return {
      profile_id: pid,
      name: n?.profile_name || v.row.profile_name || v.row.purchaser_name || null,
      email: n?.email || v.row.purchaser_email || null,
      purchased: v.purchased,
      renewed: v.renewed,
      trainer_code: code,
      trainer_name: code ? directory.get(code)?.name || null : null,
      subscription_status: memberState(v.row.status, v.row.canceled_at),
      fitness_goal: goalBy.get(pid) || null,
      member_since: startMs == null ? null : toIso(new Date(startMs)),
      days,
      reading_days: readingDays,
      readings,
      last_reading: latest?.lastMs != null ? toIso(new Date(latest.lastMs)) : null,
      metabolism_score: Number.isFinite(score) ? score : null,
      rate,
      cohort: cohortOf(rate),
    };
  });
  clients.sort((a, b) => b.rate - a.rate || b.reading_days - a.reading_days);

  const total = clients.length;
  const goalCounts = { fat_loss: 0, muscle_gain: 0, weight_loss: 0, other: 0 };
  for (const c of clients) {
    const g = String(c.fitness_goal || "").toLowerCase();
    if (g.includes("fat")) goalCounts.fat_loss += 1;
    else if (g.includes("weight")) goalCounts.weight_loss += 1;
    else if (g.includes("muscle") || g.includes("gain")) goalCounts.muscle_gain += 1;
    else goalCounts.other += 1;
  }
  const neverTested = clients.filter((c) => c.reading_days === 0).length;
  const tiers = [...COHORT_TIERS.map((t) => `${t}%+`), "<10%"];

  return {
    ...empty,
    summary: {
      clients: total,
      purchased: clients.filter((c) => c.purchased).length,
      renewed: clients.filter((c) => c.renewed).length,
      both: clients.filter((c) => c.purchased && c.renewed).length,
      avg_rate: Math.round(clients.reduce((s, c) => s + c.rate, 0) / total),
      high_rate: Math.max(...clients.map((c) => c.rate)),
      low_rate: Math.min(...clients.map((c) => c.rate)),
      never_tested: neverTested,
      never_tested_rate: pct(neverTested, total),
      readings_this_week: thisWeek,
      readings_last_week: lastWeek,
      readings_week_change: lastWeek ? Math.round(((thisWeek - lastWeek) / lastWeek) * 1000) / 10 : null,
      goals: goalCounts,
      cohorts: tiers.map((tier) => {
        const count = clients.filter((c) => c.cohort === tier).length;
        return { tier, count, rate: pct(count, total) };
      }),
    },
    clients,
  };
}

// ─── view=purchases ──────────────────────────────────────────────────────────

async function purchases(p, body) {
  const source = String(body.source || "all");
  if (!SOURCES.has(source)) throw httpError(422, "source must be all, website or trainer_code");

  const search = String(body.search || "").trim().toLowerCase();
  if (search && search.length < SEARCH_MIN_LENGTH) {
    throw httpError(422, `Search must be at least ${SEARCH_MIN_LENGTH} characters`, { search_min_length: SEARCH_MIN_LENGTH });
  }
  if (search.length > 100) throw httpError(422, "Search is too long");

  const partnerCode = String(body.partner_code || "").trim().toUpperCase();
  if (partnerCode.length > 50) throw httpError(422, "Invalid partner_code");
  const subStatus = String(body.subscription_status || "all").toLowerCase();
  const payStatus = String(body.payment_status || "all").toLowerCase();

  let page = Math.trunc(Number(body.page) || 1);
  let limit = Math.trunc(Number(body.limit) || 10);
  if (page < 1) page = 1;
  if (limit < 1) limit = 10;
  if (limit > 100) limit = 100;

  const scope = await scopeFor(body);
  const all = await loadPurchases(p);
  const items = scope ? all.filter((i) => scope.has(i)) : all;

  const filtered = items.filter((i) => {
    if (source !== "all" && i.source !== source) return false;
    if (partnerCode && i.code !== partnerCode) return false;
    if (subStatus !== "all" && i.subStatus !== subStatus) return false;
    if (payStatus !== "all" && i.paymentStatus !== payStatus) return false;
    if (search) {
      const r = i.raw;
      const hay = [r.purchaser_name, r.profile_name, r.purchaser_email, r.purchase_code, i.code, i.linkedCode]
        .filter(Boolean)
        .map((v) => String(v).toLowerCase());
      if (!hay.some((v) => v.includes(search))) return false;
    }
    return true;
  });

  const total = filtered.length;
  const pageItems = filtered.slice((page - 1) * limit, page * limit);
  const directory = await trainerDirectory(
    [...new Set(pageItems.flatMap((i) => [i.code, i.linkedCode]).filter(Boolean))],
    emailsByCode(pageItems)
  );

  const data = pageItems.map((i) => {
    const r = i.raw;
    return {
      purchase_id: r.stripe_subscription_id,
      purchased_at: toIso(r.created_at),
      customer: {
        name: r.purchaser_name || r.profile_name || null,
        email: r.purchaser_email || null,
        profile_id: r.profile_id || null,
      },
      plan: { code: r.plan_code, name: PLAN_NAMES[r.plan_code] || r.plan_code },
      purchase_source: i.source,
      trainer: i.code
        ? {
            trainer_id: directory.get(i.code)?.trainer_id || null,
            name: directory.get(i.code)?.name || null,
            email: directory.get(i.code)?.email || null,
          }
        : null,
      attributed_partner_code: i.code,
      linked_partner_code: i.linkedCode,
      linked_trainer_name: i.linkedCode ? directory.get(i.linkedCode)?.name || null : null,
      linked_trainer_email: i.linkedCode ? directory.get(i.linkedCode)?.email || null : null,
      purchase_code: r.purchase_code || null,
      coupon_code: i.discount > 0 ? i.code || r.stripe_promotion_code_id || null : null,
      currency: i.currency,
      gross_amount: minorToMajor(i.gross),
      discount_amount: minorToMajor(i.discount),
      net_amount: minorToMajor(i.net),
      amount_source: i.amountSource,
      subscription_status: i.subStatus,
      subscription_start: toIso(r.created_at),
      canceled_at: toIso(r.canceled_at),
      // Cancelled: when access ended. A scheduled cancel (canceled_at set,
      // status still active) runs until period end, so show that date.
      subscription_end: toIso(
        String(r.status) === "canceled" ? r.canceled_at || r.current_period_end : r.current_period_end
      ),
      payment_status: i.paymentStatus,
      stripe: {
        checkout_session_id: r.stripe_checkout_session_id || null,
        payment_intent_id: null,
        subscription_id: r.stripe_subscription_id,
        invoice_id: i.firstInvoiceId || null,
      },
    };
  });

  return {
    filters: {
      period: p.period, date_from: p.dateFrom, date_to: p.dateTo, tz_offset_minutes: p.offset,
      source, partner_code: partnerCode || null, subscription_status: subStatus, payment_status: payStatus, search, search_min_length: SEARCH_MIN_LENGTH,
    },
    purchases: data,
    pagination: { page, limit, total, total_pages: Math.max(1, Math.ceil(total / limit)) },
    filter_options: {
      subscription_status: [...new Set(items.map((i) => i.subStatus).filter(Boolean))].sort(),
      payment_status: [...new Set(items.map((i) => i.paymentStatus))].sort(),
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
    if (view === "overview") payload = await overview(parsePeriod(body), body);
    else if (view === "purchases") payload = await purchases(parsePeriod(body), body);
    else if (view === "engagement") payload = await engagement(parsePeriod(body), body);
    else if (view === "trainer_admins") payload = { trainer_admins: await trainerAdmins() };
    else return res.status(422).json({ status: false, ok: false, message: "view must be overview, purchases, engagement or trainer_admins" });

    await H.writeAuthLogSafe(req, {
      eventType: "super_admin_sales_analytics_viewed",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: `view=${view}`,
    });

    return res.status(200).json({ status: true, ok: true, view, ...payload });
  } catch (err) {
    if (err?.status) {
      return res.status(err.status).json({ status: false, ok: false, message: err.message, ...(err.extra || {}) });
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

module.exports = { superAdminSalesAnalytics, trainerHierarchy };
