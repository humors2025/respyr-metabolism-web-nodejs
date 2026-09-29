"use strict";

/**
 * POST /dietitian/api/web/super-admin-facility-details        (super_admin)
 *
 * Everything the Facilities page knows about one facility, for the detail
 * popup: the facility row, its owner and onboarding trainer admin, payout
 * setup, trainers (with split and member count), members (referred
 * subscriptions), QR stickers, commission totals + recent ledger entries and
 * pending trainer invites.
 *
 * Body: { facility_id }
 *
 * Reads existing tables only: facilities, app_user_roles, table_dietician,
 * partner_payout_accounts, referral_subscriptions, qr_codes,
 * commission_entries, app_user_invitations. Every read is written to
 * app_auth_logs because members carry buyers' emails.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const MEMBER_LIMIT = 200;
const LEDGER_LIMIT = 50;
const RUNNING_SUB_STATUSES = new Set(["active", "trialing", "past_due"]);

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toIso(v) {
  if (!v) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().replace(".000Z", "Z");
}

const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());

// Same rule as super-admin-orders: Stripe keeps "active" after a period ends
// without a paid renewal, so the end date decides "expired".
function deriveSubscriptionStatus(row, now = Date.now()) {
  const raw = row.status ? String(row.status).toLowerCase() : null;
  if (!raw) return null;
  if (row.canceled_at || raw === "canceled") return "cancelled";
  const endIso = toIso(row.current_period_end);
  if (RUNNING_SUB_STATUSES.has(raw) && endIso && Date.parse(endIso) < now) return "expired";
  if (raw === "incomplete_expired") return "expired";
  return raw;
}

async function loadDetails(facilityId) {
  const [[f]] = await pool.execute(
    `
      SELECT f.id, f.name, f.partner_code, f.status, f.created_at, f.updated_at,
             f.status_changed_at, f.status_changed_by, f.status_change_reason, f.created_by_user_id,
             f.facility_admin_user_id, f.parent_admin_user_id,
             o.name AS owner_name, o.phone_no AS owner_phone, o.location AS owner_location,
             oa.status AS owner_status, oa.created_at AS owner_joined_at,
             p.name AS parent_name, p.phone_no AS parent_phone,
             ppa.onboarding_status, ppa.details_submitted, ppa.charges_enabled, ppa.payouts_enabled,
             ppa.last_synced_at AS payout_synced_at
      FROM facilities f
      LEFT JOIN table_dietician o ON LOWER(o.email) = LOWER(f.facility_admin_user_id)
      LEFT JOIN app_user_roles oa ON LOWER(oa.user_id) = LOWER(f.facility_admin_user_id) AND oa.role = 'facility_admin'
      LEFT JOIN table_dietician p ON LOWER(p.email) = LOWER(f.parent_admin_user_id)
      LEFT JOIN partner_payout_accounts ppa ON LOWER(ppa.user_id) = LOWER(f.facility_admin_user_id)
      WHERE f.id = ?
      LIMIT 1
    `,
    [facilityId]
  );
  if (!f) return null;

  const [trainers, members, qrCodes, ledgerTotals, ledger, invites] = await Promise.all([
    pool.execute(
      `
        SELECT aur.user_id, aur.partner_code, aur.status, aur.commission_split_pct, aur.created_at,
               td.name, td.phone_no,
               (SELECT COUNT(*) FROM referral_subscriptions rs
                 WHERE rs.facility_id = aur.facility_id AND rs.attributed_partner_code = aur.partner_code
                   AND rs.status IN ('active','trialing','past_due')) AS active_subscriptions
        FROM app_user_roles aur
        LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
        WHERE aur.role = 'trainer' AND aur.facility_id = ?
        ORDER BY aur.status = 'active' DESC, aur.created_at DESC
      `,
      [facilityId]
    ),
    pool.execute(
      `
        SELECT rs.id, rs.purchaser_name, rs.purchaser_email, rs.plan_code, rs.currency, rs.unit_amount_minor,
               rs.status, rs.current_period_start, rs.current_period_end, rs.canceled_at, rs.created_at,
               rs.attributed_partner_code, rs.attributed_role, rs.qr_id, rs.profile_id
        FROM referral_subscriptions rs
        WHERE rs.facility_id = ?
        ORDER BY rs.created_at DESC
        LIMIT ${MEMBER_LIMIT}
      `,
      [facilityId]
    ),
    pool.execute(
      `
        SELECT q.id, q.status, q.partner_code, q.linked_user_id, q.linked_at, q.scans
        FROM qr_codes q
        WHERE q.facility_id = ?
        ORDER BY q.linked_at DESC, q.id
      `,
      [facilityId]
    ),
    pool.execute(
      `
        SELECT status, currency, COUNT(*) AS entries, COALESCE(SUM(amount_minor),0) AS amount_minor
        FROM commission_entries
        WHERE facility_id = ?
        GROUP BY status, currency
      `,
      [facilityId]
    ),
    pool.execute(
      `
        SELECT ce.id, ce.invoice_paid_at, ce.payee_user_id, ce.payee_role, ce.attributed_partner_code,
               ce.invoice_net_minor, ce.commission_rate_pct, ce.share_pct, ce.amount_minor, ce.currency,
               ce.status, ce.hold_reason
        FROM commission_entries ce
        WHERE ce.facility_id = ?
        ORDER BY ce.invoice_paid_at DESC, ce.id DESC
        LIMIT ${LEDGER_LIMIT}
      `,
      [facilityId]
    ),
    pool.execute(
      `
        SELECT i.id, i.invited_email, i.invited_first_name, i.invited_last_name, i.invited_role,
               i.partner_code, i.expires_at, i.sent_at
        FROM app_user_invitations i
        WHERE i.facility_id = ? AND i.status = 'pending'
        ORDER BY i.created_at DESC
      `,
      [facilityId]
    ),
  ]).then((all) => all.map(([rows]) => rows));

  const [[memberCount]] = await pool.execute(
    `SELECT COUNT(*) AS total,
            SUM(status IN ('active','trialing','past_due')) AS running
     FROM referral_subscriptions WHERE facility_id = ?`,
    [facilityId]
  );

  const commission = { pending: 0, held: 0, scheduled: 0, paid: 0, reversed: 0, entries: 0, currency: null };
  for (const r of ledgerTotals) {
    if (r.status in commission) commission[r.status] += Number(r.amount_minor);
    commission.entries += Number(r.entries);
    commission.currency = commission.currency || r.currency;
  }
  commission.owed = commission.pending + commission.held + commission.scheduled;

  return {
    facility: {
      id: Number(f.id),
      name: f.name,
      partner_code: f.partner_code,
      status: f.status,
      created_at: toIso(f.created_at),
      updated_at: toIso(f.updated_at),
      created_by_user_id: lower(f.created_by_user_id),
      status_changed_at: toIso(f.status_changed_at),
      status_changed_by: lower(f.status_changed_by),
      status_change_reason: f.status_change_reason || null,
    },
    owner: {
      user_id: lower(f.facility_admin_user_id),
      name: f.owner_name || null,
      phone: f.owner_phone || null,
      location: f.owner_location && f.owner_location !== "NA" ? f.owner_location : null,
      status: f.owner_status || null,
      joined_at: toIso(f.owner_joined_at),
    },
    parent_admin: {
      user_id: lower(f.parent_admin_user_id),
      name: f.parent_name || null,
      phone: f.parent_phone || null,
    },
    payout: {
      status: f.onboarding_status || "not_started",
      details_submitted: !!f.details_submitted,
      charges_enabled: !!f.charges_enabled,
      payouts_enabled: !!f.payouts_enabled,
      last_synced_at: toIso(f.payout_synced_at),
    },
    trainers: trainers.map((t) => ({
      user_id: lower(t.user_id),
      name: t.name || null,
      phone: t.phone_no || null,
      partner_code: t.partner_code || null,
      status: t.status,
      commission_split_pct: t.commission_split_pct == null ? null : Number(t.commission_split_pct),
      joined_at: toIso(t.created_at),
      active_subscriptions: Number(t.active_subscriptions),
    })),
    members: members.map((m) => ({
      id: Number(m.id),
      name: m.purchaser_name || null,
      email: lower(m.purchaser_email),
      plan_code: m.plan_code,
      amount_minor: Number(m.unit_amount_minor),
      currency: m.currency,
      status: deriveSubscriptionStatus(m),
      stripe_status: m.status,
      current_period_start: toIso(m.current_period_start),
      current_period_end: toIso(m.current_period_end),
      purchased_at: toIso(m.created_at),
      partner_code: m.attributed_partner_code || null,
      attributed_role: m.attributed_role || null,
      qr_id: m.qr_id || null,
      app_linked: !!m.profile_id,
    })),
    members_total: Number(memberCount?.total) || 0,
    members_running: Number(memberCount?.running) || 0,
    qr_codes: qrCodes.map((q) => ({
      id: q.id,
      status: q.status,
      partner_code: q.partner_code || null,
      linked_user_id: lower(q.linked_user_id),
      linked_at: toIso(q.linked_at),
      scans: Number(q.scans) || 0,
    })),
    commission,
    ledger: ledger.map((e) => ({
      id: Number(e.id),
      invoice_paid_at: toIso(e.invoice_paid_at),
      payee_user_id: lower(e.payee_user_id),
      payee_role: e.payee_role,
      partner_code: e.attributed_partner_code,
      invoice_net_minor: Number(e.invoice_net_minor),
      commission_rate_pct: Number(e.commission_rate_pct),
      share_pct: Number(e.share_pct),
      amount_minor: Number(e.amount_minor),
      currency: e.currency,
      status: e.status,
      hold_reason: e.hold_reason || null,
    })),
    pending_invites: invites.map((i) => ({
      id: Number(i.id),
      email: lower(i.invited_email),
      name: `${i.invited_first_name || ""} ${i.invited_last_name || ""}`.trim() || null,
      role: i.invited_role,
      partner_code: i.partner_code || null,
      sent_at: toIso(i.sent_at),
      expires_at: toIso(i.expires_at),
    })),
  };
}

const superAdminFacilityDetails = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const facilityId = parseInt(body.facility_id, 10);

  try {
    const resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    if (!Number.isInteger(facilityId) || facilityId <= 0) {
      return res.status(422).json({ status: false, ok: false, message: "facility_id is required" });
    }

    const details = await loadDetails(facilityId);
    if (!details) return res.status(404).json({ status: false, ok: false, message: "Facility not found" });

    await H.writeAuthLogSafe(req, {
      eventType: "super_admin_facility_viewed",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: details.facility.partner_code,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: `facility_id=${facilityId}`,
    });

    return res.status(200).json({ status: true, ok: true, ...details });
  } catch (err) {
    console.error("SUPER_ADMIN_FACILITY_DETAILS_ERROR:", { facilityId, code: err?.code, message: err?.message });
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { superAdminFacilityDetails };
