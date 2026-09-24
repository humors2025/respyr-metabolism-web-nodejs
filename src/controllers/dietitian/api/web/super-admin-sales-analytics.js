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
 *   Source        trainer_code when a trainer/gym code was used at Checkout:
 *                 attributed_partner_code is set AND a promotion code or QR
 *                 sticker was applied. A member who bought without a code and
 *                 linked a trainer later in the app stays "website" (shown as
 *                 linked_partner_code).
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
        (
          SELECT ps.list_price_minor - ps.referred_price_minor
          FROM partner_promotion_codes ppc
          JOIN pricing_settings ps ON ps.stripe_coupon_id = ppc.stripe_coupon_id
          WHERE ppc.stripe_promotion_code_id = rs.stripe_promotion_code_id
          ORDER BY ps.id DESC
          LIMIT 1
        ) AS coupon_off_minor,
        (
          -- Fallback when the coupon was replaced (pricing re-saved, e.g. after a
          -- Stripe account change): the referral discount in effect that day.
          SELECT ps.list_price_minor - ps.referred_price_minor
          FROM pricing_settings ps
          WHERE ps.effective_from <= rs.created_at
          ORDER BY ps.effective_from DESC, ps.id DESC
          LIMIT 1
        ) AS pricing_off_minor,
        (
          SELECT ce.stripe_invoice_id
          FROM commission_entries ce
          WHERE ce.stripe_subscription_id = rs.stripe_subscription_id
          ORDER BY ce.invoice_paid_at ASC, ce.id ASC
          LIMIT 1
        ) AS first_invoice_id,
        (
          SELECT ce.invoice_net_minor
          FROM commission_entries ce
          WHERE ce.stripe_subscription_id = rs.stripe_subscription_id
          ORDER BY ce.invoice_paid_at ASC, ce.id ASC
          LIMIT 1
        ) AS first_invoice_net_minor,
        (
          SELECT ce.invoice_paid_at
          FROM commission_entries ce
          WHERE ce.stripe_subscription_id = rs.stripe_subscription_id
          ORDER BY ce.invoice_paid_at ASC, ce.id ASC
          LIMIT 1
        ) AS first_invoice_paid_at,
        (
          SELECT tc.profile_name
          FROM table_clients tc
          WHERE rs.profile_id IS NOT NULL AND tc.profile_id = rs.profile_id
          ORDER BY tc.id DESC
          LIMIT 1
        ) AS profile_name
      FROM referral_subscriptions rs
      WHERE rs.created_at >= ? AND rs.created_at < ?
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
    const usedCodeAtCheckout = !!code && !!(r.stripe_promotion_code_id || r.qr_id);
    const gross = Number(r.unit_amount_minor) || 0;
    const couponOff =
      r.coupon_off_minor != null ? Math.max(0, Number(r.coupon_off_minor))
      : r.pricing_off_minor != null ? Math.max(0, Number(r.pricing_off_minor))
      : null;
    // The earliest ledger invoice is the purchase itself only if it was paid
    // at checkout time; a member attributed later has ledger rows for renewals only.
    const createdMs = toMs(r.created_at);
    const invoiceMs = toMs(r.first_invoice_paid_at);
    const isFirstPayment = invoiceMs != null && createdMs != null && Math.abs(invoiceMs - createdMs) <= 2 * 86400000;
    const invoiceNet = isFirstPayment && r.first_invoice_net_minor != null ? Number(r.first_invoice_net_minor) : null;
    const firstInvoiceId = isFirstPayment ? r.first_invoice_id : null;

    let net;
    let discount;
    if (invoiceNet != null) {
      net = invoiceNet;
      discount = Math.max(0, gross - invoiceNet);
    } else {
      // A code or sticker at checkout always applies the referral coupon.
      discount = usedCodeAtCheckout || r.stripe_promotion_code_id ? Math.min(gross, couponOff ?? 0) : 0;
      net = Math.max(0, gross - discount);
    }

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
      amountSource: invoiceNet != null ? "invoice" : "price",
      paymentStatus,
      counts: paymentStatus === "paid",
      subStatus: SUB_STATUS_LABEL[r.status] || r.status || null,
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
            AND (UPPER(attributed_partner_code) IN (?) OR LOWER(attributed_user_id) IN (?) OR facility_id IN (?))
        `,
        [scope.codes.size ? [...scope.codes] : [""], [...scope.emails], scope.facilityIds.size ? [...scope.facilityIds] : [0]]
      )
    : await pool.query(`SELECT COUNT(*) AS n FROM referral_subscriptions WHERE status = 'active'`);

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
      renewal_net_sales: 0,
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
      // Cancelled: when it was cancelled; otherwise the next renewal date.
      subscription_end: toIso(r.canceled_at || r.current_period_end),
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
    else if (view === "trainer_admins") payload = { trainer_admins: await trainerAdmins() };
    else return res.status(422).json({ status: false, ok: false, message: "view must be overview, purchases or trainer_admins" });

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

module.exports = { superAdminSalesAnalytics };
