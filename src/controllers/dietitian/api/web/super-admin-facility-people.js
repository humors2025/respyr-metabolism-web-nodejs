"use strict";

/**
 * POST /dietitian/api/web/super-admin-facility-people        (super_admin, admin)
 *
 * The rows behind the Trainers and Active members counts on the Facilities
 * page (list-facilities), for one facility — or, without facility_id, for
 * every facility in scope (the Trainers / Active members total cards):
 *
 * admin       -> only facilities whose parent_admin_user_id is the actor
 *                (same scope as list-facilities); a facility_id outside that
 *                scope is a 404.
 * super_admin -> every facility.
 *
 *   view=trainers  active trainers in the facility (same rule as
 *                  list-facilities.trainers_count)
 *   view=members   running referred subscriptions (same rule as
 *                  list-facilities.active_subscriptions)
 *
 * Body: { facility_id?, view, page?, limit? }   (facility_id omitted = all facilities)
 *
 * Pagination is opt-in, as on list-facilities: send page and/or limit
 * (1..100, default 10) for one page plus a `pagination` block; without them
 * every row is returned.
 *
 * Existing tables only. Member rows carry buyers' emails, so every read is
 * written to app_auth_logs.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toIso(v) {
  if (!v) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().replace(".000Z", "Z");
}

const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());

const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 100;

// null when the caller did not ask for a page (every row).
function parsePaging(body) {
  if (body.page == null && body.limit == null) return null;
  const page = Math.max(1, parseInt(body.page, 10) || 1);
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(body.limit, 10) || DEFAULT_LIMIT));
  return { page, limit, offset: (page - 1) * limit };
}

// LIMIT/OFFSET are validated integers, inlined because mysql2 execute()
// rejects them as placeholders on some server versions.
const pageSql = (paging) => (paging ? `LIMIT ${paging.limit} OFFSET ${paging.offset}` : "");

async function countRows(fromWhere, params) {
  const [[r]] = await pool.execute(`SELECT COUNT(*) AS total ${fromWhere}`, params);
  return Number(r.total) || 0;
}

// facilityId null = every facility in scope. parentEmail set (trainer admin)
// limits rows to facilities under that parent, as list-facilities does. Rows
// join facilities so the "all" list counts exactly what the totals count.
async function trainers(facilityId, parentEmail, paging) {
  const params = [...(facilityId ? [facilityId] : []), ...(parentEmail ? [parentEmail] : [])];
  const where = `WHERE aur.role = 'trainer' AND aur.status = 'active' ${facilityId ? "AND aur.facility_id = ?" : ""} ${parentEmail ? "AND LOWER(f.parent_admin_user_id) = ?" : ""}`;
  const fromWhere = `
      FROM app_user_roles aur
      INNER JOIN facilities f ON f.id = aur.facility_id
      ${where}`;
  const [rows] = await pool.execute(
    `
      SELECT aur.user_id, aur.partner_code, aur.status, aur.created_at,
             f.id AS facility_id, f.name AS facility_name,
             td.name, td.phone_no,
             COALESCE(tcs.commission_split_pct, 0.00) AS commission_split_pct,
             (SELECT COUNT(*) FROM referral_subscriptions rs
               WHERE rs.facility_id = aur.facility_id AND rs.attributed_partner_code = aur.partner_code
                 AND rs.status IN ('active','trialing','past_due')) AS active_members
      FROM app_user_roles aur
      INNER JOIN facilities f ON f.id = aur.facility_id
      LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      LEFT JOIN trainer_commission_splits tcs ON LOWER(tcs.user_id) = LOWER(aur.user_id)
      ${where}
      ORDER BY aur.created_at DESC, aur.user_id
      ${pageSql(paging)}
    `,
    params
  );
  const total = paging ? await countRows(fromWhere, params) : rows.length;
  const items = rows.map((t) => ({
    user_id: lower(t.user_id),
    name: t.name || null,
    phone: t.phone_no || null,
    partner_code: t.partner_code || null,
    facility_id: Number(t.facility_id),
    facility_name: t.facility_name,
    status: t.status,
    commission_split_pct: Number(t.commission_split_pct),
    active_members: Number(t.active_members),
    joined_at: toIso(t.created_at),
  }));
  return { items, total };
}

async function members(facilityId, parentEmail, paging) {
  const params = [...(facilityId ? [facilityId] : []), ...(parentEmail ? [parentEmail] : [])];
  const where = `WHERE rs.status IN ('active','trialing','past_due') ${facilityId ? "AND rs.facility_id = ?" : ""} ${parentEmail ? "AND LOWER(f.parent_admin_user_id) = ?" : ""}`;
  const fromWhere = `
      FROM referral_subscriptions rs
      INNER JOIN facilities f ON f.id = rs.facility_id
      ${where}`;
  const [rows] = await pool.execute(
    `
      SELECT rs.id, rs.purchaser_name, rs.purchaser_email, rs.plan_code, rs.unit_amount_minor, rs.currency,
             rs.status, rs.current_period_start, rs.current_period_end, rs.created_at,
             rs.attributed_partner_code, rs.qr_id, rs.profile_id,
             f.id AS facility_id, f.name AS facility_name,
             (SELECT td.name FROM table_dietician td WHERE LOWER(td.email) = LOWER(rs.attributed_user_id) LIMIT 1) AS code_owner_name
      FROM referral_subscriptions rs
      INNER JOIN facilities f ON f.id = rs.facility_id
      ${where}
      ORDER BY rs.created_at DESC, rs.id DESC
      ${pageSql(paging)}
    `,
    params
  );
  const total = paging ? await countRows(fromWhere, params) : rows.length;
  const items = rows.map((m) => ({
    id: Number(m.id),
    name: m.purchaser_name || null,
    email: lower(m.purchaser_email),
    plan_code: m.plan_code,
    amount_minor: Number(m.unit_amount_minor),
    currency: m.currency ? String(m.currency).toUpperCase() : "USD",
    status: m.status,
    current_period_start: toIso(m.current_period_start),
    current_period_end: toIso(m.current_period_end),
    purchased_at: toIso(m.created_at),
    partner_code: m.attributed_partner_code || null,
    facility_id: Number(m.facility_id),
    facility_name: m.facility_name,
    code_owner_name: m.code_owner_name || null,
    qr_id: m.qr_id || null,
    app_linked: !!m.profile_id,
  }));
  return { items, total };
}

const superAdminFacilityPeople = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const allFacilities = body.facility_id == null || body.facility_id === "" || body.facility_id === "all";
  const facilityId = allFacilities ? null : parseInt(body.facility_id, 10);
  const view = String(body.view || "");

  try {
    const resolved = await H.resolveActorFromToken(req, ["super_admin", "admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });
    const isSuper = String(resolved.actor.role) === "super_admin";
    // Trainer admin only ever sees facilities under them, as on list-facilities.
    const parentEmail = isSuper ? null : resolved.actorEmail;

    if (!allFacilities && (!Number.isInteger(facilityId) || facilityId <= 0)) {
      return res.status(422).json({ status: false, ok: false, message: "facility_id must be a positive integer or omitted" });
    }
    if (view !== "trainers" && view !== "members") {
      return res.status(422).json({ status: false, ok: false, message: "view must be trainers or members" });
    }

    let facility = null;
    if (!allFacilities) {
      [[facility]] = await pool.execute(
        `SELECT id, name, partner_code FROM facilities WHERE id = ? ${parentEmail ? "AND LOWER(parent_admin_user_id) = ?" : ""} LIMIT 1`,
        parentEmail ? [facilityId, parentEmail] : [facilityId]
      );
      if (!facility) return res.status(404).json({ status: false, ok: false, message: "Facility not found" });
    }

    const paging = parsePaging(body);
    const { items, total } = view === "trainers" ? await trainers(facilityId, parentEmail, paging) : await members(facilityId, parentEmail, paging);

    await H.writeAuthLogSafe(req, {
      eventType: "super_admin_facility_people_viewed",
      userId: resolved.actorEmail,
      role: String(resolved.actor.role),
      partnerCode: facility ? facility.partner_code : null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: `facility_id=${facilityId ?? "all"} view=${view}`,
    });

    return res.status(200).json({
      status: true,
      ok: true,
      view,
      facility: facility ? { id: Number(facility.id), name: facility.name, partner_code: facility.partner_code } : null,
      items,
      total,
      ...(paging && {
        pagination: {
          page: paging.page,
          limit: paging.limit,
          total,
          total_pages: Math.max(1, Math.ceil(total / paging.limit)),
        },
      }),
    });
  } catch (err) {
    console.error("SUPER_ADMIN_FACILITY_PEOPLE_ERROR:", { facilityId, view, code: err?.code, sqlMessage: err?.sqlMessage, message: err?.message });
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { superAdminFacilityPeople };
