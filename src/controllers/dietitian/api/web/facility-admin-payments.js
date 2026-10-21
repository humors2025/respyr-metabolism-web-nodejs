"use strict";

/**
 * POST /dietitian/api/web/facility-admin-payments   (facility_admin)
 *
 * Super Admin › Orders › Payments, narrowed to one facility: one row per
 * Stripe invoice (first payment, each renewal, failed payments, refunds) for
 * the members who bought through the signed-in facility admin's network.
 *
 * Network (looked up from the token's user_id): the facility admin's own code
 * (wall QR) plus every trainer in their facility or invited by them, including
 * removed trainers so their past sales still show. Same members as
 * Referrals › Members (referred-members).
 *
 * Rysflo-side detail stays out: no Stripe fee / net, card digits or Stripe ids.
 *
 * Body: { search?, page?, limit?,
 *         status? ("all" | open | paid | failed | refunded | partially_refunded),
 *         type? ("all" | first_payment | renewal),
 *         code? ("all" | one of the `sources` codes),
 *         date_from?, date_to? (YYYY-MM-DD, inclusive, viewer's calendar; either
 *           may be left out), tz_offset_minutes? (viewer's minutes ahead of UTC) }
 *   The date is the payment date (paid_at, or created_at for unpaid invoices).
 *
 * Response: { payments: [ { id, date, customer: { name, email }, partner_code,
 *               referred_by: { kind: "facility" | "trainer", name, user_id, status } | null,
 *               type, renewal_number, period_start, period_end, currency,
 *               amount_paid, amount_refunded, status, failure_message,
 *               plan: { subscription_status, current_period_start, current_period_end, canceled_at } } ],
 *             summary: [ { status, currency, count, amount_paid, amount_refunded } ]
 *               (every payment of this type, code and date range, ignoring status and search),
 *             sources: [ { code, kind, name, user_id, status } ], status_options, filters, pagination }
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");
const { _helpers: O } = require("./super-admin-orders");

const OWN_CODE_NAME = "Facility QR (direct)";
const YMD = /^\d{4}-\d{2}-\d{2}$/;

const pad = (n) => String(n).padStart(2, "0");

function fmtUtc(ms) {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
}

// Midnight UTC of a YYYY-MM-DD day; 422 when it is not a real date.
function dayMs(ymd, field) {
  if (!YMD.test(ymd)) throw O.httpError(422, `${field} must be YYYY-MM-DD`);
  const [y, m, d] = ymd.split("-").map(Number);
  const ms = Date.UTC(y, m - 1, d);
  if (fmtUtc(ms).slice(0, 10) !== ymd) throw O.httpError(422, `${field} is not a valid date`);
  return ms;
}

// date_from / date_to (inclusive days in the viewer's calendar) → a UTC
// window [startUtc, endUtc) on the payment date. Same convention as Sales
// Analytics (super-admin-sales-analytics parsePeriod), but either end may be open.
function parseDateRange(body) {
  const dateFrom = String(body.date_from || "").trim() || null;
  const dateTo = String(body.date_to || "").trim() || null;
  const offset = body.tz_offset_minutes == null || body.tz_offset_minutes === "" ? 0 : Number(body.tz_offset_minutes);
  if (!Number.isInteger(offset) || offset < -840 || offset > 840) {
    throw O.httpError(422, "tz_offset_minutes must be an integer between -840 and 840");
  }
  const start = dateFrom ? dayMs(dateFrom, "date_from") : null;
  const end = dateTo ? dayMs(dateTo, "date_to") + 86400000 : null;
  if (start != null && end != null && end <= start) {
    throw O.httpError(422, "The end date must be on or after the start date");
  }
  return {
    dateFrom,
    dateTo,
    offset,
    startUtc: start == null ? null : fmtUtc(start - offset * 60000),
    endUtc: end == null ? null : fmtUtc(end - offset * 60000),
  };
}

// Codes whose sales belong to this facility admin, own code first.
async function facilitySources(actor, actorEmail) {
  const sources = [];
  const own = String(actor.partner_code || "").trim().toUpperCase();
  if (own) sources.push({ code: own, kind: "facility", name: OWN_CODE_NAME, user_id: actorEmail, status: "active" });

  const facilityId = actor.facility_id == null ? null : Number(actor.facility_id);
  const [rows] = await pool.query(
    `
      SELECT UPPER(TRIM(aur.partner_code)) AS code, LOWER(aur.user_id) AS user_id, aur.status,
             COALESCE(NULLIF(TRIM(td.name), ''), aur.user_id) AS name
      FROM app_user_roles aur
      LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE aur.role = 'trainer' AND aur.partner_code IS NOT NULL AND TRIM(aur.partner_code) <> ''
        AND (aur.facility_id = ? OR LOWER(aur.parent_user_id) = ?)
      ORDER BY name
    `,
    [facilityId, actorEmail]
  );
  const seen = new Set(sources.map((s) => s.code));
  for (const r of rows) {
    if (seen.has(r.code)) continue;
    seen.add(r.code);
    sources.push({ code: r.code, kind: "trainer", name: r.name, user_id: r.user_id, status: r.status });
  }
  return sources;
}

async function payments(body, sources) {
  const { page, limit, offset } = O.parsePaging(body);
  const search = O.parseSearch(body);
  const status = String(body.status || "all").toLowerCase();
  if (status !== "all" && !O.PAYMENT_STATUSES.includes(status)) {
    throw O.httpError(422, `status must be all or one of ${O.PAYMENT_STATUSES.join(", ")}`);
  }
  const type = String(body.type || "all").toLowerCase();
  if (type !== "all" && !O.PAYMENT_TYPES[type]) {
    throw O.httpError(422, `type must be all or one of ${Object.keys(O.PAYMENT_TYPES).join(", ")}`);
  }
  const billingReason = type === "all" ? null : O.PAYMENT_TYPES[type];
  const rawCode = String(body.code || "all").trim();
  const code = rawCode.toLowerCase() === "all" ? null : rawCode.toUpperCase();
  const allCodes = sources.map((s) => s.code);
  if (code && !allCodes.includes(code)) throw O.httpError(422, "code must be all or one of your facility's codes");
  const codes = code ? [code] : allCodes;
  const range = parseDateRange(body);

  const filters = {
    status,
    type,
    code: code || "all",
    date_from: range.dateFrom,
    date_to: range.dateTo,
    tz_offset_minutes: range.offset,
    search,
    search_min_length: O.SEARCH_MIN_LENGTH,
  };
  const pagination = (total) => ({ page, limit, total, total_pages: Math.max(1, Math.ceil(total / limit)) });
  const base = { filters, sources, status_options: O.PAYMENT_STATUSES };
  if (!codes.length) return { ...base, payments: [], summary: [], pagination: pagination(0) };

  // The facility's codes, and the type, code and date filters: list and summary chips.
  const scope = ["UPPER(rs.attributed_partner_code) IN (?)"];
  const scopeParams = [codes];
  if (billingReason) {
    scope.push("pt.billing_reason = ?");
    scopeParams.push(billingReason);
  }
  if (range.startUtc) {
    scope.push("COALESCE(pt.paid_at, pt.created_at) >= ?");
    scopeParams.push(range.startUtc);
  }
  if (range.endUtc) {
    scope.push("COALESCE(pt.paid_at, pt.created_at) < ?");
    scopeParams.push(range.endUtc);
  }

  const where = [...scope];
  const params = [...scopeParams];
  if (status !== "all") {
    where.push("pt.status = ?");
    params.push(status);
  }
  if (search) {
    where.push("(rs.purchaser_email LIKE ? OR rs.purchaser_name LIKE ? OR rs.attributed_partner_code LIKE ?)");
    params.push(...Array(3).fill(O.like(search)));
  }

  const from = `
    FROM payment_transactions pt
    INNER JOIN referral_subscriptions rs ON rs.stripe_subscription_id = pt.stripe_subscription_id
  `;

  const [[{ total }]] = await pool.query(`SELECT COUNT(*) AS total ${from} WHERE ${where.join(" AND ")}`, params);
  const [rows] = await pool.query(
    `
      SELECT
        pt.id, pt.billing_reason, pt.period_start, pt.period_end, pt.amount_paid_minor, pt.amount_refunded_minor,
        pt.currency, pt.status, pt.failure_message, pt.paid_at, pt.created_at,
        rs.purchaser_email, rs.purchaser_name, rs.attributed_partner_code,
        rs.status AS subscription_status, rs.current_period_start, rs.current_period_end, rs.canceled_at,
        -- Which renewal of its subscription this invoice is (same rule as super-admin-orders).
        CASE WHEN pt.billing_reason = 'subscription_cycle' THEN (
          SELECT COUNT(*) FROM payment_transactions p2
          WHERE p2.stripe_subscription_id = pt.stripe_subscription_id
            AND p2.billing_reason = 'subscription_cycle'
            AND p2.id <= pt.id
        ) END AS renewal_number
      ${from} WHERE ${where.join(" AND ")}
      ORDER BY COALESCE(pt.paid_at, pt.created_at) DESC, pt.id DESC
      LIMIT ? OFFSET ?
    `,
    [...params, limit, offset]
  );

  const [counts] = await pool.query(
    `
      SELECT pt.status, pt.currency, COUNT(*) AS n,
             SUM(pt.amount_paid_minor) AS paid, SUM(pt.amount_refunded_minor) AS refunded
      ${from} WHERE ${scope.join(" AND ")}
      GROUP BY pt.status, pt.currency
    `,
    scopeParams
  );

  const sourceByCode = new Map(sources.map((s) => [s.code, s]));
  const now = Date.now();
  return {
    ...base,
    payments: rows.map((r) => {
      const src = sourceByCode.get(String(r.attributed_partner_code || "").toUpperCase());
      return {
        id: Number(r.id),
        date: O.toIso(r.paid_at || r.created_at),
        customer: { name: r.purchaser_name || null, email: r.purchaser_email || null },
        partner_code: r.attributed_partner_code || null,
        referred_by: src ? { kind: src.kind, name: src.name, user_id: src.user_id, status: src.status } : null,
        type: r.billing_reason === "subscription_create" ? "first_payment" : r.billing_reason === "subscription_cycle" ? "renewal" : r.billing_reason || null,
        renewal_number: r.renewal_number == null ? null : Number(r.renewal_number),
        period_start: O.toIso(r.period_start),
        period_end: O.toIso(r.period_end),
        currency: r.currency,
        amount_paid: O.minorToMajor(r.amount_paid_minor),
        amount_refunded: O.minorToMajor(r.amount_refunded_minor),
        status: r.status,
        failure_message: r.failure_message || null,
        // The membership as it stands now.
        plan: {
          subscription_status: O.deriveSubscriptionStatus(r, now),
          current_period_start: O.toIso(r.current_period_start),
          current_period_end: O.toIso(r.current_period_end),
          canceled_at: O.toIso(r.canceled_at),
        },
      };
    }),
    summary: counts.map((c) => ({
      status: c.status,
      currency: c.currency,
      count: Number(c.n),
      amount_paid: O.minorToMajor(c.paid),
      amount_refunded: O.minorToMajor(c.refunded),
    })),
    pagination: pagination(Number(total)),
  };
}

// ─── Controller ──────────────────────────────────────────────────────────────

const facilityAdminPayments = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, ["facility_admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    const sources = await facilitySources(resolved.actor, resolved.actorEmail);
    const payload = await payments(body, sources);

    await H.writeAuthLogSafe(req, {
      eventType: "facility_admin_payments_viewed",
      userId: resolved.actorEmail,
      role: resolved.actor.role,
      partnerCode: resolved.actor.partner_code || null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: null,
    });

    return res.status(200).json({ status: true, ok: true, ...payload });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, message: err.message });
    console.error("FACILITY_ADMIN_PAYMENTS_ERROR:", { code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "facility_admin_payments_error",
        userId: resolved.actorEmail,
        role: resolved.actor.role,
        partnerCode: resolved.actor.partner_code || null,
        identifier: resolved.actorEmail,
        success: false,
        failureReason: String(err?.code || "internal_error"),
      });
    }
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { facilityAdminPayments, _helpers: { facilitySources, payments } };
