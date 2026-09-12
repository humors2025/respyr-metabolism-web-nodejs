"use strict";

/**
 * Referral programme operations (v0.3).
 *
 *  Public (no JWT):
 *   POST /dietitian/api/web/order-page-context   { partner_code?, qr_id? }
 *        -> pricing + resolved code for the order page (never reveals whether
 *           a code exists beyond "discount applies")
 *   POST /dietitian/api/web/order-session-status { session_id }
 *        -> { paid, purchase_code, email } for the success page
 *
 *  Authenticated:
 *   POST /dietitian/api/web/referred-members     (admin, facility_admin, trainer)
 *        -> subscriptions attributed to the caller's code(s), linked or not
 *   POST /dietitian/api/web/resend-purchase-code { stripe_subscription_id }
 *   POST /dietitian/api/web/qr-generate          (super_admin) { count }
 *   POST /dietitian/api/web/qr-link              (super_admin, admin) { qr_id, target_user_id | null }
 *   POST /dietitian/api/web/qr-list              (super_admin, admin) { status?, facility_id? }
 *   POST /dietitian/api/web/get-pricing          (any role)
 *   POST /dietitian/api/web/set-pricing          (super_admin) { list_price, referred_price, note? }
 */

const pool = require("../../../../config/db");
const { requireStripe } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");
const pricing = require("../../../../services/pricing");
const qr = require("../../../../services/qrCodes");
const purchaseCodes = require("../../../../services/purchaseCodes");
const { resolvePartnerCode, normalizeCode } = require("../../../../utils/partnerCodeResolver");

const ALL_ROLES = ["super_admin", "admin", "facility_admin", "trainer"];
const PAYEES = ["admin", "facility_admin", "trainer"];

function guard(fn) {
  return async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
    try {
      return await fn(req, res);
    } catch (err) {
      console.error("REFERRAL_OPS_ERROR:", { path: req.path, code: err?.code, message: err?.message });
      return res.status(err?.status || 500).json({ ok: false, message: err?.status ? err.message : "Internal server error" });
    }
  };
}

async function actor(req, res, roles) {
  const r = await H.resolveActorFromToken(req, roles);
  if (r.error) {
    res.status(r.error.status).json(r.error.body);
    return null;
  }
  return r;
}

// ── Public ───────────────────────────────────────────────────────────────────

const orderPageContext = guard(async (req, res) => {
  const p = await pricing.publicPricing();
  let code = normalizeCode(req.body?.partner_code);
  let qrId = null;
  if (typeof req.body?.qr_id === "string" && req.body.qr_id.trim()) {
    const st = await qr.resolve(req.body.qr_id);
    if (st) {
      qrId = st.id;
      if (st.partner_code) code = st.partner_code;
    }
  }
  const resolved = code ? await resolvePartnerCode(code) : null;
  let facilityName = null;
  if (resolved?.facility_id != null) {
    const [f] = await pool.execute(`SELECT name FROM facilities WHERE id = ? LIMIT 1`, [resolved.facility_id]);
    facilityName = f[0]?.name || null;
  }
  return res.status(200).json({
    ok: true,
    pricing: p,
    qr_id: qrId,
    referral: resolved ? { partner_code: resolved.partner_code, role: resolved.role, facility_name: facilityName } : null,
  });
});

const orderSessionStatus = guard(async (req, res) => {
  const sid = typeof req.body?.session_id === "string" ? req.body.session_id.trim() : "";
  if (!/^cs_(test|live)_[A-Za-z0-9]+$/.test(sid)) return res.status(422).json({ ok: false, message: "Invalid session" });
  const [rows] = await pool.execute(
    `SELECT purchaser_email, purchase_code, profile_id FROM referral_subscriptions WHERE stripe_checkout_session_id = ? LIMIT 1`,
    [sid]
  );
  if (rows[0]) {
    return res.status(200).json({
      ok: true,
      paid: true,
      email: rows[0].purchaser_email,
      purchase_code: rows[0].profile_id ? null : rows[0].purchase_code, // already linked -> nothing to enter
      already_linked: !!rows[0].profile_id,
    });
  }
  // Webhook may lag a few seconds; ask Stripe whether the session is paid.
  const session = await requireStripe().checkout.sessions.retrieve(sid);
  return res.status(200).json({
    ok: true,
    paid: session.payment_status === "paid",
    email: session.customer_details?.email || null,
    purchase_code: null,
    pending: true,
  });
});

// ── Referred members ─────────────────────────────────────────────────────────

const referredMembers = guard(async (req, res) => {
  const a = await actor(req, res, PAYEES);
  if (!a) return;
  const role = String(a.actor.role);
  let codes = [String(a.actor.partner_code || "").toUpperCase()].filter(Boolean);
  if (role === "facility_admin" && a.actor.facility_id != null) {
    const [tr] = await pool.execute(
      `SELECT partner_code FROM app_user_roles WHERE role = 'trainer' AND facility_id = ? AND partner_code IS NOT NULL`,
      [Number(a.actor.facility_id)]
    );
    codes = codes.concat(tr.map((r) => String(r.partner_code).toUpperCase()));
  }
  if (!codes.length) return res.status(200).json({ ok: true, items: [], totals: { total: 0, linked: 0, unlinked: 0 } });

  const [rows] = await pool.query(
    `
      SELECT rs.stripe_subscription_id, rs.purchaser_email, rs.profile_id, rs.linked_via, rs.linked_at,
             rs.attributed_partner_code, rs.attributed_role, rs.qr_id, rs.status,
             rs.purchase_code, rs.purchase_code_email_sent_at, rs.created_at, rs.current_period_end,
             td.name AS trainer_name,
             (SELECT COALESCE(SUM(ce.invoice_net_minor),0) FROM commission_entries ce
               WHERE ce.stripe_subscription_id = rs.stripe_subscription_id AND ce.payee_user_id = ? AND ce.status <> 'reversed') AS net_sales_minor
      FROM referral_subscriptions rs
      LEFT JOIN app_user_roles aur ON UPPER(aur.partner_code) = UPPER(rs.attributed_partner_code)
      LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE UPPER(rs.attributed_partner_code) IN (?)
      ORDER BY rs.created_at DESC
      LIMIT 500
    `,
    [a.actorEmail, codes]
  );
  const items = rows.map((r) => ({
    stripe_subscription_id: r.stripe_subscription_id,
    email: r.purchaser_email,
    linked: !!r.profile_id,
    linked_via: r.linked_via,
    linked_at: r.linked_at,
    code: r.attributed_partner_code,
    via_trainer: r.attributed_role === "trainer" ? r.trainer_name || r.attributed_partner_code : null,
    qr_id: r.qr_id,
    status: r.status,
    purchase_code: r.profile_id ? null : r.purchase_code,
    code_email_sent_at: r.purchase_code_email_sent_at,
    since: r.created_at,
    renews: r.current_period_end,
  }));
  return res.status(200).json({
    ok: true,
    items,
    totals: { total: items.length, linked: items.filter((i) => i.linked).length, unlinked: items.filter((i) => !i.linked).length },
  });
});

const resendPurchaseCode = guard(async (req, res) => {
  const a = await actor(req, res, PAYEES);
  if (!a) return;
  const sid = typeof req.body?.stripe_subscription_id === "string" ? req.body.stripe_subscription_id.trim() : "";
  if (!sid) return res.status(422).json({ ok: false, message: "stripe_subscription_id is required" });
  // Scope: only subscriptions attributed to the caller (or their facility's trainers).
  const [rows] = await pool.execute(
    `SELECT rs.attributed_partner_code, rs.facility_id, rs.profile_id FROM referral_subscriptions rs WHERE rs.stripe_subscription_id = ? LIMIT 1`,
    [sid]
  );
  const sub = rows[0];
  const own = sub && String(sub.attributed_partner_code || "").toUpperCase() === String(a.actor.partner_code || "").toUpperCase();
  const inFacility = sub && String(a.actor.role) === "facility_admin" && a.actor.facility_id != null && Number(sub.facility_id) === Number(a.actor.facility_id);
  if (!sub || !(own || inFacility)) return res.status(404).json({ ok: false, message: "Subscription not found" });
  if (sub.profile_id) return res.status(409).json({ ok: false, message: "This member is already linked" });
  await purchaseCodes.ensurePurchaseCode({ stripeSubscriptionId: sid });
  const r = await purchaseCodes.sendPurchaseCodeEmail({ stripeSubscriptionId: sid, force: true });
  if (!r.ok) return res.status(502).json({ ok: false, message: r.reason || "Email could not be sent" });
  return res.status(200).json({ ok: true, message: "Code re-sent" });
});

// ── QR stickers ──────────────────────────────────────────────────────────────

const qrGenerate = guard(async (req, res) => {
  const a = await actor(req, res, "super_admin");
  if (!a) return;
  const count = Math.max(1, Math.min(1000, parseInt(req.body?.count, 10) || 0));
  if (!count) return res.status(422).json({ ok: false, message: "count must be 1–1000" });
  const out = await qr.generateBatch({ count, createdBy: a.actorEmail });
  await H.writeAuthLogSafe(req, { eventType: "qr_batch_generated", userId: a.actorEmail, role: "super_admin", partnerCode: null, identifier: a.actorEmail, success: true, failureReason: `${out.ids.length} stickers, batch ${out.batch_id}` });
  return res.status(201).json({ ok: true, ...out });
});

const qrLink = guard(async (req, res) => {
  const a = await actor(req, res, ["super_admin", "admin"]);
  if (!a) return;
  const id = qr.normalizeId(req.body?.qr_id);
  if (!id) return res.status(422).json({ ok: false, message: "qr_id is required" });
  const targetUser = H.normalizeEmail(req.body?.target_user_id);

  let target = null;
  if (targetUser) {
    const [rows] = await pool.execute(
      `SELECT user_id, role, partner_code, parent_user_id, facility_id, status FROM app_user_roles
       WHERE LOWER(user_id) = ? AND role IN ('facility_admin','trainer') AND status = 'active' LIMIT 1`,
      [targetUser]
    );
    target = rows[0] || null;
    if (!target || !target.partner_code) return res.status(404).json({ ok: false, message: "Target not found" });
    // An admin may only link stickers to facilities they onboarded (or their trainers).
    if (String(a.actor.role) === "admin") {
      const [f] = await pool.execute(`SELECT parent_admin_user_id FROM facilities WHERE id = ? LIMIT 1`, [target.facility_id == null ? -1 : Number(target.facility_id)]);
      if (!f[0] || String(f[0].parent_admin_user_id).toLowerCase() !== a.actorEmail) {
        return res.status(403).json({ ok: false, message: "You can only link stickers to your own facilities" });
      }
    }
  }
  const row = await qr.link({ id, target, actorUserId: a.actorEmail });
  await H.writeAuthLogSafe(req, { eventType: "qr_linked", userId: a.actorEmail, role: String(a.actor.role), partnerCode: null, identifier: id, success: true, failureReason: target ? `-> ${target.partner_code}` : "unlinked" });
  return res.status(200).json({ ok: true, qr: row });
});

const qrList = guard(async (req, res) => {
  const a = await actor(req, res, ["super_admin", "admin"]);
  if (!a) return;
  const status = ["unassigned", "assigned", "retired"].includes(req.body?.status) ? req.body.status : null;
  const facilityId = req.body?.facility_id != null && req.body.facility_id !== "" ? Number(req.body.facility_id) : null;
  const where = [];
  const params = [];
  if (status) { where.push("q.status = ?"); params.push(status); }
  if (facilityId != null) { where.push("q.facility_id = ?"); params.push(facilityId); }
  if (String(a.actor.role) === "admin") {
    where.push("(q.status = 'unassigned' OR f.parent_admin_user_id = ?)");
    params.push(a.actorEmail);
  }
  const [rows] = await pool.execute(
    `
      SELECT q.id, q.batch_id, q.status, q.partner_code, q.facility_id, f.name AS facility_name, q.linked_user_id, q.linked_at, q.scans, q.created_at
      FROM qr_codes q
      LEFT JOIN facilities f ON f.id = q.facility_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY q.created_at DESC, q.id
      LIMIT 500
    `,
    params
  );
  return res.status(200).json({ ok: true, items: rows });
});

// ── Pricing ──────────────────────────────────────────────────────────────────

const getPricing = guard(async (req, res) => {
  const a = await actor(req, res, ALL_ROLES);
  if (!a) return;
  const row = await pricing.currentPricing({ fresh: true });
  const [history] = await pool.execute(`SELECT currency, list_price_minor, referred_price_minor, effective_from, set_by_user_id, note FROM pricing_settings ORDER BY effective_from DESC, id DESC LIMIT 20`);
  return res.status(200).json({
    ok: true,
    current: row ? { currency: row.currency, list_price_minor: Number(row.list_price_minor), referred_price_minor: Number(row.referred_price_minor), effective_from: row.effective_from } : null,
    history: String(a.actor.role) === "super_admin" ? history : undefined,
  });
});

const setPricingEndpoint = guard(async (req, res) => {
  const a = await actor(req, res, "super_admin");
  if (!a) return;
  const list = Math.round(Number(req.body?.list_price) * 100);
  const referred = Math.round(Number(req.body?.referred_price) * 100);
  if (!Number.isFinite(list) || !Number.isFinite(referred) || list <= 0 || referred <= 0 || referred > list) {
    return res.status(422).json({ ok: false, message: "list_price and referred_price must be positive and referred <= list" });
  }
  const note = typeof req.body?.note === "string" ? req.body.note.trim().slice(0, 255) : null;
  const row = await pricing.setPricing({ listMinor: list, referredMinor: referred, setBy: a.actorEmail, note });
  await H.writeAuthLogSafe(req, { eventType: "pricing_set", userId: a.actorEmail, role: "super_admin", partnerCode: null, identifier: a.actorEmail, success: true, failureReason: `list ${list} referred ${referred}` });
  return res.status(200).json({ ok: true, current: { currency: row.currency, list_price_minor: Number(row.list_price_minor), referred_price_minor: Number(row.referred_price_minor) } });
});

module.exports = { orderPageContext, orderSessionStatus, referredMembers, resendPurchaseCode, qrGenerate, qrLink, qrList, getPricing, setPricingEndpoint };
