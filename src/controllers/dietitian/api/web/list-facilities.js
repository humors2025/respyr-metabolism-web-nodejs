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
 *
 * Pagination is opt-in: send `page` and/or `limit` (1..100, default 10) to get
 * one page of facilities plus a `pagination` block. Without them every
 * facility is returned, as before. `totals` always covers all facilities in
 * scope; pending_invites are never paginated.
 *
 * Search is opt-in: `search` (trimmed, <=100 chars) keeps only facilities whose
 * name, partner code, owner name, owner email or parent admin email contains
 * the term (case-insensitive, "contains" match), and pending invites whose
 * facility name, code, invitee name / email or parent admin email contains it.
 * `pagination.total` counts the matching facilities; `totals` stays
 * whole-scope so the stat cards do not move while searching. The normalised
 * term is echoed back as `search` ("" when none was given).
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 100;
const SEARCH_MAX_LENGTH = 100;

// null when the caller did not ask for a page (old behaviour: all rows).
function parsePaging(body) {
  if (body.page == null && body.limit == null) return null;
  const page = Math.max(1, parseInt(body.page, 10) || 1);
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(body.limit, 10) || DEFAULT_LIMIT));
  return { page, limit, offset: (page - 1) * limit };
}

function parseSearch(body) {
  return typeof body.search === "string" ? body.search.trim().slice(0, SEARCH_MAX_LENGTH) : "";
}

// Literal "contains" LIKE term: escape the wildcards so "100%" or "a_b" match
// themselves (same helper as super-admin-orders).
const like = (s) => `%${s.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

const whereSql = (conds) => (conds.length ? `WHERE ${conds.join(" AND ")}` : "");

const FACILITY_SEARCH_SQL =
  "(f.name LIKE ? OR f.partner_code LIKE ? OR td.name LIKE ? OR f.facility_admin_user_id LIKE ? OR f.parent_admin_user_id LIKE ?)";
const INVITE_SEARCH_SQL =
  "(i.facility_name LIKE ? OR i.partner_code LIKE ? OR CONCAT_WS(' ', i.invited_first_name, i.invited_last_name) LIKE ? OR i.invited_email LIKE ? OR i.parent_user_id LIKE ?)";

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

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const paging = parsePaging(body);
    const search = parseSearch(body);

    // Scope (trainer admin: own facilities only) applies to every query. The
    // search term narrows the facility list, its count and the pending
    // invites, but not `totals`.
    const scopeConds = isSuper ? [] : ["LOWER(f.parent_admin_user_id) = ?"];
    const scopeParams = isSuper ? [] : [actorEmail];
    const searchParams = search ? Array(5).fill(like(search)) : [];
    const listWhere = whereSql([...scopeConds, ...(search ? [FACILITY_SEARCH_SQL] : [])]);
    const listParams = [...scopeParams, ...searchParams];
    // LIMIT/OFFSET are validated integers, inlined because mysql2 execute()
    // rejects them as placeholders on some server versions.
    const pageSql = paging ? `LIMIT ${paging.limit} OFFSET ${paging.offset}` : "";

    const [rows] = await pool.execute(
      `
        SELECT
          f.id, f.name, f.partner_code, f.status, f.created_at,
          f.facility_admin_user_id, td.name AS owner_name, f.parent_admin_user_id,
          ppa.onboarding_status AS payout_status,
          (SELECT COUNT(*) FROM app_user_roles t WHERE t.role = 'trainer' AND t.facility_id = f.id AND t.status = 'active') AS trainers_count,
          (SELECT COUNT(*) FROM referral_subscriptions rs WHERE rs.facility_id = f.id AND rs.status IN ('active','trialing','past_due')) AS active_subscriptions,
          (SELECT COALESCE(SUM(ce.amount_minor),0) FROM commission_entries ce WHERE ce.facility_id = f.id AND ce.status IN ('pending','held','scheduled')) AS owed_minor,
          (SELECT COALESCE(SUM(ce.amount_minor),0) FROM commission_entries ce WHERE ce.facility_id = f.id AND ce.status = 'paid') AS paid_minor,
          (SELECT COUNT(*) FROM facility_edit_logs l WHERE l.facility_id = f.id) AS edits_count,
          (SELECT l.edited_by FROM facility_edit_logs l WHERE l.facility_id = f.id ORDER BY l.id DESC LIMIT 1) AS last_edited_by,
          (SELECT l.edited_at FROM facility_edit_logs l WHERE l.facility_id = f.id ORDER BY l.id DESC LIMIT 1) AS last_edited_at
        FROM facilities f
        LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(f.facility_admin_user_id)
        LEFT JOIN partner_payout_accounts ppa ON LOWER(ppa.user_id) = LOWER(f.facility_admin_user_id)
        ${listWhere}
        ORDER BY f.created_at DESC, f.id DESC
        ${pageSql}
      `,
      listParams
    );

    // Totals over every facility in scope — not just this page, and not
    // narrowed by the search term.
    const [[agg]] = await pool.execute(
      `
        SELECT COUNT(*) AS facilities,
               COALESCE(SUM(x.trainers_count),0) AS trainers,
               COALESCE(SUM(x.active_subscriptions),0) AS active_subscriptions,
               COALESCE(SUM(x.owed_minor),0) AS owed_minor
        FROM (
          SELECT
            (SELECT COUNT(*) FROM app_user_roles t WHERE t.role = 'trainer' AND t.facility_id = f.id AND t.status = 'active') AS trainers_count,
            (SELECT COUNT(*) FROM referral_subscriptions rs WHERE rs.facility_id = f.id AND rs.status IN ('active','trialing','past_due')) AS active_subscriptions,
            (SELECT COALESCE(SUM(ce.amount_minor),0) FROM commission_entries ce WHERE ce.facility_id = f.id AND ce.status IN ('pending','held','scheduled')) AS owed_minor
          FROM facilities f
          ${whereSql(scopeConds)}
        ) x
      `,
      scopeParams
    );
    const totalFacilities = Number(agg.facilities) || 0;

    // How many facilities match the search — drives pagination.
    let matchingFacilities = totalFacilities;
    if (search) {
      const [[m]] = await pool.execute(
        `
          SELECT COUNT(*) AS n
          FROM facilities f
          LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(f.facility_admin_user_id)
          ${listWhere}
        `,
        listParams
      );
      matchingFacilities = Number(m.n) || 0;
    }

    const pendingBaseSql = `
        FROM app_user_invitations i
        WHERE i.invited_role IN ('facility_admin', 'trainer') AND i.status = 'pending'
          ${isSuper ? "" : "AND LOWER(i.parent_user_id) = ?"}
    `;
    const [pending] = await pool.execute(
      `
        SELECT i.id, i.invited_email, i.invited_first_name, i.invited_last_name, i.invited_role, i.facility_name, i.partner_code,
               i.invited_by_user_id, i.parent_user_id, i.status, i.expires_at, i.sent_at, i.created_at,
               (SELECT q.id FROM qr_codes q WHERE q.invitation_id = i.id AND q.status = 'assigned' LIMIT 1) AS qr_id
        ${pendingBaseSql}
          ${search ? `AND ${INVITE_SEARCH_SQL}` : ""}
        ORDER BY i.created_at DESC
      `,
      [...scopeParams, ...searchParams]
    );

    // totals.pending_invites is whole-scope too (the Facilities card hint).
    let totalPending = pending.length;
    if (search) {
      const [[pc]] = await pool.execute(`SELECT COUNT(*) AS n ${pendingBaseSql}`, scopeParams);
      totalPending = Number(pc.n) || 0;
    }

    return res.status(200).json({
      ok: true,
      actor: { user_id: actorEmail, role: String(actor.role) },
      search,
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
        // Edit history (facility_edit_logs) — drives the "Edited" tag.
        edits_count: Number(r.edits_count) || 0,
        last_edited_by: r.last_edited_by ? String(r.last_edited_by).toLowerCase() : null,
        last_edited_at: toMysqlDateTime(r.last_edited_at),
      })),
      pending_invites: pending.map((p) => ({
        id: Number(p.id),
        invited_email: String(p.invited_email).toLowerCase(),
        invited_name: `${p.invited_first_name || ""} ${p.invited_last_name || ""}`.trim(),
        invited_role: p.invited_role, // facility_admin (business owner) | trainer (personal trainer)
        facility_name: p.facility_name,
        partner_code: p.partner_code,
        qr_id: p.qr_id || null,
        invited_by_user_id: String(p.invited_by_user_id).toLowerCase(),
        status: p.status,
        expires_at: toMysqlDateTime(p.expires_at),
        sent_at: toMysqlDateTime(p.sent_at),
        created_at: toMysqlDateTime(p.created_at),
      })),
      totals: {
        facilities: totalFacilities,
        pending_invites: totalPending,
        trainers: Number(agg.trainers) || 0,
        active_subscriptions: Number(agg.active_subscriptions) || 0,
        owed_minor: Number(agg.owed_minor) || 0,
      },
      ...(paging && {
        pagination: {
          page: paging.page,
          limit: paging.limit,
          total: matchingFacilities,
          total_pages: Math.max(1, Math.ceil(matchingFacilities / paging.limit)),
        },
      }),
    });
  } catch (err) {
    console.error("LIST_FACILITIES_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { listFacilities };
