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
const crypto = require("crypto");
const { generateUniqueFacilityCode, validateFacilityName } = require("./admin-invite-facility-admin");
const { escapeHtml } = require("../../../../utils/securityValidation");
const { reserveEmailResendSlot } = require("../../../../utils/emailResendRateGuard");

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
  let facilityName = resolved?.facility_name || null;
  if (!facilityName && resolved?.facility_id != null) {
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
    `SELECT stripe_subscription_id, purchaser_email, purchase_code, purchase_code_email_sent_at, profile_id
     FROM referral_subscriptions WHERE stripe_checkout_session_id = ? LIMIT 1`,
    [sid]
  );
  if (rows[0]) {
    // The success page promises "we've emailed it". If the webhook's send
    // failed (Resend down, sender rejected…) retry here; the sent_at stamp
    // makes this a no-op once the email is out.
    if (rows[0].purchase_code && !rows[0].profile_id && !rows[0].purchase_code_email_sent_at) {
      try {
        const mail = await purchaseCodes.sendPurchaseCodeEmail({ stripeSubscriptionId: rows[0].stripe_subscription_id });
        if (!mail.ok) console.warn("PURCHASE_CODE_EMAIL_NOT_SENT:", { subscription: rows[0].stripe_subscription_id, reason: mail.reason });
      } catch (e) {
        console.warn("PURCHASE_CODE_EMAIL_NOT_SENT:", { subscription: rows[0].stripe_subscription_id, reason: e?.message });
      }
    }
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
  // Pick up any purchase codes redeemed in the app since the nightly
  // breath-credits job last ran, so "App linked" is current on every load
  // (two cheap UPDATEs, no-ops when nothing is pending).
  try {
    await purchaseCodes.linkProfiles();
  } catch (e) {
    console.warn("REFERRED_MEMBERS_LINK_SKIPPED:", e?.message);
  }
  const role = String(a.actor.role);
  const ownCode = String(a.actor.partner_code || "").toUpperCase();
  const isOwner = role === "facility_admin" && a.actor.facility_id != null;

  // Facility admin: own code (wall QR) + every trainer in the facility,
  // including removed trainers so their historical sales still show.
  let trainers = [];
  if (isOwner) {
    const [tr] = await pool.execute(
      `
        SELECT aur.user_id, aur.partner_code, aur.status,
               COALESCE(tcs.commission_split_pct, 0.00) AS commission_split_pct,
               COALESCE(td.name, aur.user_id) AS name
        FROM app_user_roles aur
        LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
        LEFT JOIN trainer_commission_splits tcs ON LOWER(tcs.user_id) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer' AND aur.facility_id = ? AND aur.partner_code IS NOT NULL
        ORDER BY name
      `,
      [Number(a.actor.facility_id)]
    );
    trainers = tr.map((r) => ({
      user_id: String(r.user_id).toLowerCase(),
      name: r.name,
      code: String(r.partner_code).toUpperCase(),
      status: r.status,
      split_pct: Number(r.commission_split_pct || 0),
    }));
  }
  const codes = [ownCode, ...trainers.map((t) => t.code)].filter(Boolean);
  const empty = { ok: true, items: [], groups: [], totals: { total: 0, linked: 0, unlinked: 0, active: 0, charged_minor: 0, breath_credit_minor: 0, commission_minor: 0, my_share_minor: 0 } };
  if (!codes.length) return res.status(200).json(empty);

  const [rows] = await pool.query(
    `
      SELECT rs.stripe_subscription_id, rs.purchaser_email, rs.purchaser_name, rs.profile_id, rs.linked_via, rs.linked_at,
             rs.attributed_partner_code, rs.attributed_role, rs.qr_id, rs.status, rs.currency, rs.unit_amount_minor,
             rs.purchase_code, rs.purchase_code_email_sent_at, rs.created_at, rs.current_period_start, rs.current_period_end,
             tc.profile_name
      FROM referral_subscriptions rs
      LEFT JOIN table_clients tc ON rs.profile_id IS NOT NULL AND tc.profile_id = rs.profile_id
      WHERE UPPER(rs.attributed_partner_code) IN (?)
      ORDER BY rs.created_at DESC
      LIMIT 500
    `,
    [codes]
  );
  if (!rows.length) return res.status(200).json(empty);
  const subIds = rows.map((r) => r.stripe_subscription_id);

  // One line per paid invoice: what the member was charged, the commission it
  // produced and how that commission was split. Reversed (refunded) entries
  // are shown but excluded from totals.
  const [entries] = await pool.query(
    `
      SELECT stripe_subscription_id, stripe_invoice_id, MIN(invoice_paid_at) AS paid_at,
             MAX(invoice_net_minor) AS net_minor, MAX(gym_commission_minor) AS commission_minor,
             MAX(commission_rate_pct) AS rate_pct,
             SUM(CASE WHEN payee_role = 'trainer' THEN amount_minor ELSE 0 END) AS trainer_minor,
             SUM(CASE WHEN payee_role <> 'trainer' THEN amount_minor ELSE 0 END) AS facility_minor,
             SUM(CASE WHEN LOWER(payee_user_id) = ? THEN amount_minor ELSE 0 END) AS my_minor,
             MIN(status) AS status
      FROM commission_entries
      WHERE stripe_subscription_id IN (?)
      GROUP BY stripe_subscription_id, stripe_invoice_id
      ORDER BY paid_at DESC
    `,
    [a.actorEmail, subIds]
  );
  const [credits] = await pool.query(
    `
      SELECT stripe_subscription_id, period_start, period_end, credit_minor, applied_at
      FROM breath_credits
      WHERE stripe_subscription_id IN (?) AND applied_at IS NOT NULL
    `,
    [subIds]
  );

  // A credit posted for period N is applied to the invoice paid at the start
  // of period N+1, i.e. on (or within a couple of days of) credit.period_end.
  const creditsBySub = new Map();
  for (const c of credits) {
    if (!creditsBySub.has(c.stripe_subscription_id)) creditsBySub.set(c.stripe_subscription_id, []);
    creditsBySub.get(c.stripe_subscription_id).push(c);
  }
  function creditFor(subId, paidAt) {
    const list = creditsBySub.get(subId) || [];
    const t = new Date(paidAt).getTime();
    let best = null;
    for (const c of list) {
      const diff = Math.abs(new Date(c.period_end + "T00:00:00Z").getTime() - t);
      if (diff <= 3 * 86400000 && (!best || diff < best.diff)) best = { diff, c };
    }
    return best ? Number(best.c.credit_minor) : 0;
  }

  const invoicesBySub = new Map();
  for (const e of entries) {
    if (!invoicesBySub.has(e.stripe_subscription_id)) invoicesBySub.set(e.stripe_subscription_id, []);
    invoicesBySub.get(e.stripe_subscription_id).push({
      invoice_id: e.stripe_invoice_id,
      paid_at: e.paid_at,
      charged_minor: Number(e.net_minor),
      breath_credit_minor: creditFor(e.stripe_subscription_id, e.paid_at),
      commission_minor: Number(e.commission_minor),
      rate_pct: Number(e.rate_pct),
      trainer_minor: Number(e.trainer_minor),
      facility_minor: Number(e.facility_minor),
      my_minor: Number(e.my_minor),
      status: e.status,
    });
  }

  const trainerByCode = new Map(trainers.map((t) => [t.code, t]));
  const totals = { total: 0, linked: 0, unlinked: 0, active: 0, charged_minor: 0, breath_credit_minor: 0, commission_minor: 0, my_share_minor: 0 };

  const items = rows.map((r) => {
    const code = String(r.attributed_partner_code || "").toUpperCase();
    const trainer = trainerByCode.get(code) || null;
    const invoices = invoicesBySub.get(r.stripe_subscription_id) || [];
    const live = invoices.filter((i) => i.status !== "reversed");
    const sum = (k) => live.reduce((acc, i) => acc + i[k], 0);
    const item = {
      stripe_subscription_id: r.stripe_subscription_id,
      name: r.profile_name || r.purchaser_name || null,
      email: r.purchaser_email,
      linked: !!r.profile_id,
      linked_via: r.linked_via,
      linked_at: r.linked_at,
      code,
      via_trainer: r.attributed_role === "trainer" ? (trainer ? trainer.name : code) : null,
      trainer_user_id: trainer ? trainer.user_id : null,
      qr_id: r.qr_id,
      status: r.status,
      currency: r.currency,
      list_price_minor: Number(r.unit_amount_minor || 0),
      purchase_code: r.profile_id ? null : r.purchase_code,
      code_email_sent_at: r.purchase_code_email_sent_at,
      since: r.created_at,
      period_start: r.current_period_start,
      renews: r.current_period_end,
      months_paid: live.length,
      charged_minor: sum("charged_minor"),
      breath_credit_minor: sum("breath_credit_minor"),
      commission_minor: sum("commission_minor"),
      my_share_minor: sum("my_minor"),
      last_charged_minor: live[0] ? live[0].charged_minor : null,
      invoices,
    };
    totals.total += 1;
    if (item.linked) totals.linked += 1; else totals.unlinked += 1;
    if (["active", "trialing", "past_due"].includes(String(item.status))) totals.active += 1;
    totals.charged_minor += item.charged_minor;
    totals.breath_credit_minor += item.breath_credit_minor;
    totals.commission_minor += item.commission_minor;
    totals.my_share_minor += item.my_share_minor;
    return item;
  });

  // Facility admin view: one group per trainer (accordion) + the wall QR.
  let groups = [];
  if (isOwner) {
    const groupOf = (key, meta, members) => ({
      key,
      ...meta,
      members,
      totals: {
        members: members.length,
        active: members.filter((m) => ["active", "trialing", "past_due"].includes(String(m.status))).length,
        charged_minor: members.reduce((s, m) => s + m.charged_minor, 0),
        breath_credit_minor: members.reduce((s, m) => s + m.breath_credit_minor, 0),
        commission_minor: members.reduce((s, m) => s + m.commission_minor, 0),
        my_share_minor: members.reduce((s, m) => s + m.my_share_minor, 0),
      },
    });
    groups.push(groupOf("facility", { kind: "facility", name: "Facility QR (direct)", code: ownCode, split_pct: 0, status: "active" }, items.filter((m) => m.code === ownCode)));
    for (const t of trainers) {
      groups.push(groupOf(t.user_id, { kind: "trainer", name: t.name, user_id: t.user_id, code: t.code, split_pct: t.split_pct, status: t.status }, items.filter((m) => m.code === t.code)));
    }
  }

  return res.status(200).json({ ok: true, items, groups, totals, rate_pct: entries[0] ? Number(entries[0].rate_pct) : null });
});

const resendPurchaseCode = guard(async (req, res) => {
  const a = await actor(req, res, PAYEES);
  if (!a) return;
  const sid = typeof req.body?.stripe_subscription_id === "string" ? req.body.stripe_subscription_id.trim() : "";
  if (!sid) return res.status(422).json({ ok: false, message: "stripe_subscription_id is required" });
  // Scope: only subscriptions attributed to the caller (or their facility's trainers).
  const [rows] = await pool.execute(
    `SELECT rs.attributed_partner_code, rs.facility_id, rs.profile_id, rs.purchaser_email FROM referral_subscriptions rs WHERE rs.stripe_subscription_id = ? LIMIT 1`,
    [sid]
  );
  const sub = rows[0];
  const own = sub && String(sub.attributed_partner_code || "").toUpperCase() === String(a.actor.partner_code || "").toUpperCase();
  const inFacility = sub && String(a.actor.role) === "facility_admin" && a.actor.facility_id != null && Number(sub.facility_id) === Number(a.actor.facility_id);
  if (!sub || !(own || inFacility)) return res.status(404).json({ ok: false, message: "Subscription not found" });
  if (sub.profile_id) return res.status(409).json({ ok: false, message: "This member is already linked" });
  if (!sub.purchaser_email) return res.status(409).json({ ok: false, message: "No email on file for this member" });

  // Email-bombing guard, same policy as the invite resends: per recipient a
  // cooldown and a per-hour cap, per actor a per-hour cap. The slot is
  // reserved inside a transaction (row locks) and committed BEFORE the email
  // goes out, so parallel clicks cannot all see a free slot.
  const conn = await pool.getConnection();
  let rateLimit;
  try {
    await conn.beginTransaction();
    rateLimit = await reserveEmailResendSlot(conn, { targetEmail: sub.purchaser_email, actorUserId: a.actorEmail });
    if (rateLimit.allowed) await conn.commit();
    else await conn.rollback();
  } catch (err) {
    await conn.rollback().catch(() => {});
    throw err;
  } finally {
    conn.release();
  }
  if (!rateLimit.allowed) {
    const retryAfterSeconds = Math.max(1, Number(rateLimit.retryAfterSeconds) || 1);
    res.setHeader("Retry-After", String(retryAfterSeconds));
    await H.writeAuthLogSafe(req, { eventType: "purchase_code_resend_rate_limited", userId: a.actorEmail, role: String(a.actor.role), partnerCode: a.actor.partner_code || null, identifier: sid, success: false, failureReason: rateLimit.reason || "email_resend_rate_limited" });
    return res.status(429).json({
      ok: false,
      message: rateLimit.reason === "recipient_cooldown" ? "Please wait before resending this code." : "Too many resend requests. Please try again later.",
      retry_after_seconds: retryAfterSeconds,
      rate_limit_reason: rateLimit.reason,
    });
  }

  await purchaseCodes.ensurePurchaseCode({ stripeSubscriptionId: sid });
  const r = await purchaseCodes.sendPurchaseCodeEmail({ stripeSubscriptionId: sid, force: true });
  if (!r.ok) return res.status(502).json({ ok: false, message: r.reason || "Email could not be sent" });
  await H.writeAuthLogSafe(req, { eventType: "purchase_code_resent", userId: a.actorEmail, role: String(a.actor.role), partnerCode: a.actor.partner_code || null, identifier: sid, success: true, failureReason: null });
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
    where.push("LOWER(q.assigned_to_user_id) = ?");
    params.push(a.actorEmail);
  }
  const [rows] = await pool.execute(
    `
      SELECT q.id, q.batch_id, q.status, q.assigned_to_user_id, q.assigned_at, q.partner_code, q.target_type, q.target_label,
             q.target_status, q.invitation_id, q.facility_id, f.name AS facility_name, q.linked_user_id, q.linked_at, q.scans, q.created_at,
             inv.invited_email, inv.status AS invitation_status,
             (SELECT COUNT(*) FROM referral_subscriptions rs WHERE rs.qr_id = q.id) AS signups
      FROM qr_codes q
      LEFT JOIN facilities f ON f.id = q.facility_id
      LEFT JOIN app_user_invitations inv ON inv.id = q.invitation_id
      ${where.length ? "WHERE " + where.join(" AND ") : ""}
      ORDER BY q.assigned_at DESC, q.created_at DESC, q.id
      LIMIT 1000
    `,
    params
  );
  // Per-TA counts for the super admin's allocation view.
  let allocation = undefined;
  if (String(a.actor.role) === "super_admin") {
    const [alloc] = await pool.execute(
      `
        SELECT COALESCE(q.assigned_to_user_id, '') AS ta, td.name AS ta_name,
               SUM(q.status = 'unassigned') AS unassigned, SUM(q.status = 'assigned') AS linked, COUNT(*) AS total
        FROM qr_codes q
        LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(q.assigned_to_user_id)
        WHERE q.status <> 'retired'
        GROUP BY q.assigned_to_user_id, td.name
      `
    );
    allocation = alloc.map((r) => ({ ta: r.ta || null, ta_name: r.ta_name || null, unassigned: Number(r.unassigned), linked: Number(r.linked), total: Number(r.total) }));
  }
  return res.status(200).json({ ok: true, items: rows, allocation });
});

/**
 * Super admin hands `count` unassigned stickers (oldest batch first, or a
 * specific batch) to a trainer admin.
 */
const qrAssign = guard(async (req, res) => {
  const a = await actor(req, res, "super_admin");
  if (!a) return;
  const to = H.normalizeEmail(req.body?.to_user_id);
  const count = Math.max(1, Math.min(1000, parseInt(req.body?.count, 10) || 0));
  const batch = typeof req.body?.batch_id === "string" && req.body.batch_id.trim() ? req.body.batch_id.trim() : null;
  if (!to || !count) return res.status(422).json({ ok: false, message: "to_user_id and count are required" });
  const [ta] = await pool.execute(`SELECT user_id FROM app_user_roles WHERE LOWER(user_id) = ? AND role = 'admin' AND status = 'active' LIMIT 1`, [to]);
  if (!ta[0]) return res.status(404).json({ ok: false, message: "Trainer admin not found" });
  const [pick] = await pool.query(
    `SELECT id FROM qr_codes WHERE status = 'unassigned' AND assigned_to_user_id IS NULL ${batch ? "AND batch_id = ?" : ""} ORDER BY created_at, id LIMIT ?`,
    batch ? [batch, count] : [count]
  );
  if (!pick.length) return res.status(409).json({ ok: false, message: "No unassigned stickers available" });
  const ids = pick.map((r) => r.id);
  await pool.query(`UPDATE qr_codes SET assigned_to_user_id = ?, assigned_at = UTC_TIMESTAMP() WHERE id IN (?)`, [to, ids]);
  await H.writeAuthLogSafe(req, { eventType: "qr_assigned", userId: a.actorEmail, role: "super_admin", partnerCode: null, identifier: to, success: true, failureReason: `${ids.length} stickers` });
  return res.status(200).json({ ok: true, assigned: ids.length, ids, to_user_id: to });
});

/** Trainer admins the super admin can assign stickers to. */
const listTrainerAdmins = guard(async (req, res) => {
  const a = await actor(req, res, "super_admin");
  if (!a) return;
  const [rows] = await pool.execute(
    `SELECT aur.user_id, td.name FROM app_user_roles aur LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
     WHERE aur.role = 'admin' AND aur.status = 'active' ORDER BY td.name, aur.user_id`
  );
  return res.status(200).json({ ok: true, items: rows.map((r) => ({ user_id: String(r.user_id).toLowerCase(), name: r.name || null })) });
});

/**
 * Field setup of one sticker by the TA holding it: invites the gym owner
 * (business) or a personal trainer under the TA, and binds the sticker to the
 * invitee's code right away — scans work before they accept; commission is
 * held until they do.
 *
 * body: { qr_id, target_type: 'facility'|'trainer', facility_name?, first_name, last_name, email, phone? }
 */
const qrSetup = guard(async (req, res) => {
  const a = await actor(req, res, ["super_admin", "admin"]);
  if (!a) return;
  const id = qr.normalizeId(req.body?.qr_id);
  const type = req.body?.target_type === "trainer" ? "trainer" : req.body?.target_type === "facility" ? "facility" : null;
  if (!id || !type) return res.status(422).json({ ok: false, message: "qr_id and target_type (facility|trainer) are required" });

  const sticker = await qr.get(id);
  if (!sticker) return res.status(404).json({ ok: false, message: "Unknown sticker" });
  const isSuper = String(a.actor.role) === "super_admin";
  if (!isSuper && String(sticker.assigned_to_user_id || "").toLowerCase() !== a.actorEmail) {
    return res.status(403).json({ ok: false, message: "This sticker is not assigned to you" });
  }
  if (sticker.status === "assigned" && sticker.partner_code) {
    return res.status(409).json({ ok: false, message: `Sticker already set up for ${sticker.target_label || sticker.partner_code}` });
  }

  const validation = H.validateInviteInput(req.body);
  if (!validation.ok) return res.status(validation.status).json({ ok: false, message: validation.message });
  const { first_name: firstName, last_name: lastName, email, phone } = validation.value;

  let facilityName = null;
  if (type === "facility") {
    const fn = validateFacilityName(req.body?.facility_name);
    if (!fn.ok) return res.status(422).json({ ok: false, message: fn.message });
    facilityName = fn.value;
  }

  const canCreate = await H.ensureInviteCanBeCreated(email);
  if (!canCreate.ok) return res.status(canCreate.status).json({ ok: false, message: canCreate.message });

  const partnerCode = type === "facility" ? await generateUniqueFacilityCode() : await H.generateUniquePartnerCode();
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = H.secureHash(rawToken);
  const inviteLink = `${H.FRONTEND_ACCEPT_INVITE_URL}?token=${encodeURIComponent(rawToken)}`;
  const expiresAt = H.toUtcMysqlDateTime(new Date(Date.now() + H.INVITE_EXPIRY_HOURS * 3600000));

  const invitationId = await H.createPendingInvite({
    email, firstName, lastName, phone: phone || null,
    invitedRole: type === "facility" ? "facility_admin" : "trainer",
    partnerCode,
    invitedByUserId: a.actorEmail,
    parentUserId: a.actorEmail,
    facilityId: null,
    facilityName,
    tokenHash,
    expiresAt,
  });

  const fullName = `${firstName} ${lastName}`.trim();
  const mail = await H.sendResendTemplateEmail(email, "You have been invited to Respyr", H.RESEND_INVITE_TEMPLATE_ID, {
    INVITED_NAME: escapeHtml(fullName),
    INVITER_EMAIL: escapeHtml(a.actorEmail),
    INVITED_EMAIL: escapeHtml(email),
    INVITED_ROLE: type === "facility" ? "facility_admin" : "trainer",
    ...(facilityName && { FACILITY_NAME: escapeHtml(facilityName) }),
    PARTNER_CODE: escapeHtml(partnerCode),
    EXPIRES_IN: escapeHtml(`${H.INVITE_EXPIRY_HOURS} hours`),
    INVITE_LINK: inviteLink,
  });
  if (!mail.ok) {
    await H.markInviteRevoked(invitationId);
    return res.status(502).json({ ok: false, message: "Invitation could not be emailed. Please try again." });
  }
  await H.markInviteSent(invitationId);

  // Bind the sticker now; the discount works immediately (promotion code
  // exists as soon as the pricing service sees the code).
  await pool.execute(
    `INSERT INTO qr_code_links (qr_id, from_partner_code, to_partner_code, actor_user_id) VALUES (?, ?, ?, ?)`,
    [id, sticker.partner_code || null, partnerCode, a.actorEmail]
  );
  await pool.execute(
    `UPDATE qr_codes
     SET status = 'assigned', partner_code = ?, target_type = ?, target_label = ?, invitation_id = ?, target_status = 'pending',
         linked_user_id = ?, linked_by = ?, linked_at = UTC_TIMESTAMP()
     WHERE id = ?`,
    [partnerCode, type, type === "facility" ? facilityName : fullName, invitationId, email, a.actorEmail, id]
  );
  try { await pricing.ensurePromotionCode(partnerCode); } catch (e) { console.warn("PROMO_CREATE_DEFERRED:", e?.message); }

  await H.writeAuthLogSafe(req, { eventType: "qr_setup", userId: a.actorEmail, role: String(a.actor.role), partnerCode: null, identifier: id, success: true, failureReason: `${type} ${partnerCode} -> ${email}` });

  const out = { ok: true, qr: await qr.get(id), invitation_id: invitationId, partner_code: partnerCode, invited_email: email };
  if (H.RETURN_INVITE_LINK_FOR_TESTING) out.debug_invite_link = inviteLink;
  return res.status(201).json(out);
});

/**
 * Undo a field setup while the invite is still pending: the invite is revoked
 * and the sticker goes back to "not set up" in the same TA's hands, so it
 * can be set up again. Once the invitee has accepted there is a real account
 * behind the code and the sticker stays live (409).
 *
 * body: { qr_id }
 */
const qrRevoke = guard(async (req, res) => {
  const a = await actor(req, res, ["super_admin", "admin"]);
  if (!a) return;
  const id = qr.normalizeId(req.body?.qr_id);
  if (!id) return res.status(422).json({ ok: false, message: "qr_id is required" });

  const sticker = await qr.get(id);
  if (!sticker) return res.status(404).json({ ok: false, message: "Unknown sticker" });
  const isSuper = String(a.actor.role) === "super_admin";
  if (!isSuper && String(sticker.assigned_to_user_id || "").toLowerCase() !== a.actorEmail) {
    return res.status(403).json({ ok: false, message: "This sticker is not assigned to you" });
  }
  if (sticker.status !== "assigned" || !sticker.partner_code || !sticker.invitation_id) {
    return res.status(409).json({ ok: false, message: "This sticker is not set up — nothing to revoke" });
  }
  if (sticker.target_status !== "pending") {
    return res.status(409).json({ ok: false, message: `${sticker.target_label || sticker.partner_code} has already accepted the invite — the sticker is live` });
  }

  // Guarded against a concurrent accept: if the invite is no longer pending the accept wins.
  if (!(await revokePendingInvitation(sticker.invitation_id))) {
    return res.status(409).json({ ok: false, message: "Invite is no longer pending — refresh and try again" });
  }
  await releaseSticker(sticker, a.actorEmail);

  await H.writeAuthLogSafe(req, { eventType: "qr_revoked", userId: a.actorEmail, role: String(a.actor.role), partnerCode: null, identifier: id, success: true, failureReason: `${sticker.partner_code} invite ${sticker.invitation_id} revoked` });
  return res.status(200).json({ ok: true, qr: await qr.get(id), partner_code: sticker.partner_code, invitation_id: sticker.invitation_id });
});

/** status pending → revoked; false when a concurrent accept got there first. */
async function revokePendingInvitation(invitationId) {
  const [rev] = await pool.execute(
    `UPDATE app_user_invitations SET status = 'revoked', updated_at = UTC_TIMESTAMP() WHERE id = ? AND status = 'pending' LIMIT 1`,
    [invitationId]
  );
  return rev.affectedRows > 0;
}

/** Put a sticker back to "not set up" in the same TA's hands, recording the unlink. */
async function releaseSticker(sticker, actorEmail) {
  await pool.execute(
    `INSERT INTO qr_code_links (qr_id, from_partner_code, to_partner_code, actor_user_id) VALUES (?, ?, NULL, ?)`,
    [sticker.id, sticker.partner_code, actorEmail]
  );
  await pool.execute(
    `UPDATE qr_codes
     SET status = 'unassigned', partner_code = NULL, target_type = NULL, target_label = NULL, invitation_id = NULL, target_status = NULL,
         facility_id = NULL, linked_user_id = NULL, linked_by = ?, linked_at = UTC_TIMESTAMP()
     WHERE id = ? AND invitation_id = ?`,
    [actorEmail, sticker.id, sticker.invitation_id]
  );
}

/**
 * Revoke a pending owner / trainer invite from the Facilities page — the
 * invite-first counterpart of qrRevoke. Works whether or not a sticker was
 * bound at invite time; a bound sticker is released back to "not set up".
 * Trainer admins may revoke invites parented to them; super admin any.
 *
 * body: { invite_id }
 */
const inviteRevoke = guard(async (req, res) => {
  const a = await actor(req, res, ["super_admin", "admin"]);
  if (!a) return;
  const inviteId = Number.parseInt(req.body?.invite_id, 10);
  if (!Number.isInteger(inviteId) || inviteId <= 0) return res.status(422).json({ ok: false, message: "invite_id is required" });

  const [[inv]] = await pool.execute(
    `SELECT id, invited_email, invited_role, partner_code, status, parent_user_id, invited_by_user_id
     FROM app_user_invitations WHERE id = ? LIMIT 1`,
    [inviteId]
  );
  if (!inv || !["facility_admin", "trainer"].includes(String(inv.invited_role))) {
    return res.status(404).json({ ok: false, message: "Unknown invite" });
  }
  const isSuper = String(a.actor.role) === "super_admin";
  const mine = [inv.parent_user_id, inv.invited_by_user_id].some((u) => String(u || "").toLowerCase() === a.actorEmail);
  if (!isSuper && !mine) return res.status(403).json({ ok: false, message: "This invite is not yours to revoke" });
  if (inv.status !== "pending") {
    return res.status(409).json({ ok: false, message: inv.status === "accepted" ? `${inv.invited_email} has already accepted the invite` : "Invite is already revoked" });
  }

  if (!(await revokePendingInvitation(inviteId))) {
    return res.status(409).json({ ok: false, message: "Invite is no longer pending — refresh and try again" });
  }
  const [stickers] = await pool.execute(`SELECT * FROM qr_codes WHERE invitation_id = ? AND status = 'assigned'`, [inviteId]);
  for (const s of stickers) await releaseSticker(s, a.actorEmail);

  await H.writeAuthLogSafe(req, { eventType: "invite_revoked", userId: a.actorEmail, role: String(a.actor.role), partnerCode: null, identifier: String(inviteId), success: true, failureReason: `${inv.partner_code || inv.invited_email} invite revoked; stickers released: ${stickers.map((s) => s.id).join(",") || "none"}` });
  return res.status(200).json({ ok: true, invitation_id: inviteId, partner_code: inv.partner_code, released_qr_ids: stickers.map((s) => s.id) });
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

module.exports = { orderPageContext, orderSessionStatus, referredMembers, resendPurchaseCode, qrGenerate, qrLink, qrList, qrAssign, qrSetup, qrRevoke, inviteRevoke, listTrainerAdmins, getPricing, setPricingEndpoint };
