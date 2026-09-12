"use strict";

/**
 * POST /dietitian/api/web/list-facilities        (super_admin, admin)
 *
 * admin       -> facilities whose parent_admin_user_id is the actor, plus the
 *                actor's pending facility_admin invites.
 * super_admin -> every facility, plus every pending facility_admin invite.
 *
 * Each facility row carries the owner, trainer count, active subscriptions and
 * commission owed/paid to that facility's payees. No member data.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

function toMysqlDateTime(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 19).replace("T", " ");
}

const listFacilities = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await H.resolveActorFromToken(req, ["super_admin", "admin"]);
    if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
    const { actor, actorEmail } = resolved;
    const isSuper = String(actor.role) === "super_admin";

    const scope = isSuper ? "" : "WHERE LOWER(f.parent_admin_user_id) = ?";
    const params = isSuper ? [] : [actorEmail];

    const [rows] = await pool.execute(
      `
        SELECT
          f.id, f.name, f.partner_code, f.status, f.created_at,
          f.facility_admin_user_id, td.name AS owner_name, f.parent_admin_user_id,
          ppa.onboarding_status AS payout_status,
          (SELECT COUNT(*) FROM app_user_roles t WHERE t.role = 'trainer' AND t.facility_id = f.id AND t.status = 'active') AS trainers_count,
          (SELECT COUNT(*) FROM referral_subscriptions rs WHERE rs.facility_id = f.id AND rs.status IN ('active','trialing','past_due')) AS active_subscriptions,
          (SELECT COALESCE(SUM(ce.amount_minor),0) FROM commission_entries ce WHERE ce.facility_id = f.id AND ce.status IN ('pending','held','scheduled')) AS owed_minor,
          (SELECT COALESCE(SUM(ce.amount_minor),0) FROM commission_entries ce WHERE ce.facility_id = f.id AND ce.status = 'paid') AS paid_minor
        FROM facilities f
        LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(f.facility_admin_user_id)
        LEFT JOIN partner_payout_accounts ppa ON LOWER(ppa.user_id) = LOWER(f.facility_admin_user_id)
        ${scope}
        ORDER BY f.created_at DESC, f.id DESC
      `,
      params
    );

    const [pending] = await pool.execute(
      `
        SELECT id, invited_email, invited_first_name, invited_last_name, facility_name, partner_code,
               invited_by_user_id, parent_user_id, status, expires_at, sent_at, created_at
        FROM app_user_invitations
        WHERE invited_role = 'facility_admin' AND status = 'pending'
          ${isSuper ? "" : "AND LOWER(parent_user_id) = ?"}
        ORDER BY created_at DESC
      `,
      params
    );

    return res.status(200).json({
      ok: true,
      actor: { user_id: actorEmail, role: String(actor.role) },
      facilities: rows.map((r) => ({
        id: Number(r.id),
        name: r.name,
        partner_code: r.partner_code,
        status: r.status,
        created_at: toMysqlDateTime(r.created_at),
        owner_user_id: String(r.facility_admin_user_id).toLowerCase(),
        owner_name: r.owner_name || null,
        parent_admin_user_id: String(r.parent_admin_user_id || "").toLowerCase() || null,
        payout_status: r.payout_status || "not_started",
        trainers_count: Number(r.trainers_count),
        active_subscriptions: Number(r.active_subscriptions),
        owed_minor: Number(r.owed_minor),
        paid_minor: Number(r.paid_minor),
      })),
      pending_invites: pending.map((p) => ({
        id: Number(p.id),
        invited_email: String(p.invited_email).toLowerCase(),
        invited_name: `${p.invited_first_name || ""} ${p.invited_last_name || ""}`.trim(),
        facility_name: p.facility_name,
        partner_code: p.partner_code,
        invited_by_user_id: String(p.invited_by_user_id).toLowerCase(),
        status: p.status,
        expires_at: toMysqlDateTime(p.expires_at),
        sent_at: toMysqlDateTime(p.sent_at),
        created_at: toMysqlDateTime(p.created_at),
      })),
      totals: {
        facilities: rows.length,
        pending_invites: pending.length,
        trainers: rows.reduce((a, r) => a + Number(r.trainers_count), 0),
        active_subscriptions: rows.reduce((a, r) => a + Number(r.active_subscriptions), 0),
        owed_minor: rows.reduce((a, r) => a + Number(r.owed_minor), 0),
      },
    });
  } catch (err) {
    console.error("LIST_FACILITIES_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { listFacilities };
