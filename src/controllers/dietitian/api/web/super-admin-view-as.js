"use strict";

/**
 * Super-admin "View as" (read-only impersonation).
 *
 * POST /dietitian/api/web/super-admin-view-as-list        (super_admin only)
 *   The users a super admin can view as: every active app_user_roles row with
 *   role admin | facility_admin | trainer that can actually log in (has a
 *   table_dietician account). Body: { role?, page?, limit?, search? }.
 *   role filters to one of the three ("" / "all" = everyone). Pagination and
 *   search follow super-admin-facility-people: page/limit opt into paging
 *   (1..100, default 10); search (3..100 chars) matches name, email, phone,
 *   partner code or facility name.
 *
 * POST /dietitian/api/web/super-admin-view-as             (super_admin only)
 *   Body: { target_user_id } (the target's login email). Mints an access
 *   token that carries the TARGET's identity — same claims a real login by
 *   that user would produce — plus:
 *     impersonated_by: the super admin's email
 *     view_only:       true
 *   authMiddleware rejects mutating endpoints when view_only is set, so the
 *   session can read everything the target sees but change nothing.
 *
 *   A dietician_refresh_tokens row is created for the target (authMiddleware
 *   requires a live session row for the token's dietician_id), with a short
 *   expiry (VIEW_AS_TTL) and a random token hash that is never returned —
 *   the view session cannot be refreshed, it simply expires.
 *
 *   No refresh token is issued. Both endpoints write app_auth_logs events
 *   (view_as_list_viewed / view_as_started), so every impersonation is
 *   auditable.
 */

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_ISS = process.env.JWT_ISS || process.env.JWT_ISSUER || "api.respyr.ai";
const JWT_AUD = process.env.JWT_AUD || process.env.JWT_AUDIENCE || "respyr-dietitian-app";

// View session lifetime (seconds). One token, no refresh — when it expires the
// frontend's silent refresh restores the super admin's own token.
const VIEW_AS_TTL = parseInt(process.env.VIEW_AS_TTL, 10) || 3600;

const LOGO_BASE_URL = (process.env.PUBLIC_API_BASE_URL || "https://api.respyr.ai").replace(/\/+$/, "");

const VIEWABLE_ROLES = ["admin", "facility_admin", "trainer"];

const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 100;
const SEARCH_MIN_LENGTH = 3;
const SEARCH_MAX_LENGTH = 100;

const lower = (v) => (v == null || v === "" ? null : String(v).toLowerCase());

function toIso(v) {
  if (!v) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().replace(".000Z", "Z");
}

// Mirrors loginController.buildDashboardRoute (not exported there).
function buildDashboardRoute(role) {
  if (role === "super_admin") return "/super-admin/overview";
  if (role === "admin") return "/trainer-admin/overview";
  if (role === "facility_admin") return "/facility-admin/overview";
  if (role === "trainer") return "/trainer/clients";
  return "/login";
}

function buildLogoUrl(dieticianId) {
  return (
    LOGO_BASE_URL +
    "/v1/dietitian/api/web/get_dietician_logo?dietician_id=" +
    encodeURIComponent(dieticianId)
  );
}

function getClientIp(req) {
  return String(req.ip || req.socket?.remoteAddress || "0.0.0.0").substring(0, 45);
}

// Literal "contains" LIKE term (same helper as super-admin-facility-people).
const like = (s) => `%${s.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;

function parsePaging(body) {
  if (body.page == null && body.limit == null) return null;
  const page = Math.max(1, parseInt(body.page, 10) || 1);
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(body.limit, 10) || DEFAULT_LIMIT));
  return { page, limit, offset: (page - 1) * limit };
}

const pageSql = (paging) => (paging ? `LIMIT ${paging.limit} OFFSET ${paging.offset}` : "");

/*
|--------------------------------------------------------------------------
| List the users a super admin can view as
|--------------------------------------------------------------------------
*/

const superAdminViewAsList = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};

  try {
    const resolved = await H.resolveActorFromToken(req, ["super_admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    const roleFilter = String(body.role || "").trim().toLowerCase();
    if (roleFilter && roleFilter !== "all" && !VIEWABLE_ROLES.includes(roleFilter)) {
      return res.status(422).json({ status: false, ok: false, message: "role must be admin, facility_admin or trainer" });
    }
    const role = VIEWABLE_ROLES.includes(roleFilter) ? roleFilter : null;

    const search = typeof body.search === "string" ? body.search.trim().slice(0, SEARCH_MAX_LENGTH) : "";
    if (search && search.length < SEARCH_MIN_LENGTH) {
      return res.status(422).json({ status: false, ok: false, message: `search must be at least ${SEARCH_MIN_LENGTH} characters` });
    }

    // INNER JOIN table_dietician: view-as reproduces a login, and login
    // requires the account row — role rows without one can't be viewed.
    const SEARCH_SQL = `(aur.user_id LIKE ? OR aur.partner_code LIKE ? OR td.name LIKE ? OR td.phone_no LIKE ? OR f.name LIKE ?)`;
    const where = `WHERE aur.role IN (${VIEWABLE_ROLES.map(() => "?").join(",")})
        AND aur.status = 'active'
        ${role ? "AND aur.role = ?" : ""}
        ${search ? `AND ${SEARCH_SQL}` : ""}`;
    const params = [
      ...VIEWABLE_ROLES,
      ...(role ? [role] : []),
      ...(search ? Array(5).fill(like(search)) : []),
    ];
    const fromWhere = `
      FROM app_user_roles aur
      INNER JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      LEFT JOIN facilities f ON f.id = aur.facility_id
      ${where}`;

    const paging = parsePaging(body);
    const [rows] = await pool.execute(
      `SELECT aur.user_id, aur.role, aur.partner_code, aur.parent_user_id, aur.facility_id, aur.created_at,
              td.name, td.phone_no,
              f.name AS facility_name
       ${fromWhere}
       ORDER BY FIELD(aur.role, ${VIEWABLE_ROLES.map(() => "?").join(",")}), td.name, aur.user_id
       ${pageSql(paging)}`,
      [...params, ...VIEWABLE_ROLES]
    );

    let total = rows.length;
    if (paging) {
      const [[r]] = await pool.execute(`SELECT COUNT(*) AS total ${fromWhere}`, params);
      total = Number(r.total) || 0;
    }

    const items = rows.map((u) => ({
      user_id: lower(u.user_id),
      name: u.name || null,
      phone: u.phone_no || null,
      role: String(u.role),
      partner_code: u.partner_code || null,
      parent_user_id: lower(u.parent_user_id),
      facility_id: u.facility_id == null ? null : Number(u.facility_id),
      facility_name: u.facility_name || null,
      joined_at: toIso(u.created_at),
    }));

    await H.writeAuthLogSafe(req, {
      eventType: "view_as_list_viewed",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: `role=${role || "all"}${search ? ` search=${search}` : ""}`,
    });

    return res.status(200).json({
      status: true,
      ok: true,
      role: role || "all",
      search,
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
    console.error("SUPER_ADMIN_VIEW_AS_LIST_ERROR:", { code: err?.code, sqlMessage: err?.sqlMessage, message: err?.message });
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

/*
|--------------------------------------------------------------------------
| Start a view-as session
|--------------------------------------------------------------------------
*/

const superAdminViewAsStart = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const targetUserId = String(body.target_user_id || "").trim().toLowerCase();

  try {
    const resolved = await H.resolveActorFromToken(req, ["super_admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    if (!targetUserId || targetUserId.length > 254 || !targetUserId.includes("@")) {
      return res.status(422).json({ status: false, ok: false, message: "target_user_id (email) is required" });
    }

    // Same lookup login runs, so the minted token matches a real login's claims.
    const [rows] = await pool.execute(
      `SELECT td.dietician_id, td.is_reset_password, td.name, td.phone_no, td.email, td.location,
              aur.role, aur.partner_code, aur.parent_user_id, aur.facility_id, aur.status
       FROM table_dietician td
       INNER JOIN app_user_roles aur ON LOWER(aur.user_id) = LOWER(td.email)
       WHERE LOWER(td.email) = LOWER(?)
       LIMIT 1`,
      [targetUserId]
    );
    const target = rows && rows.length ? rows[0] : null;

    const refuse = async (status, message) => {
      await H.writeAuthLogSafe(req, {
        eventType: "view_as_refused",
        userId: resolved.actorEmail,
        role: "super_admin",
        partnerCode: target?.partner_code || null,
        identifier: targetUserId,
        success: false,
        failureReason: message,
      });
      return res.status(status).json({ status: false, ok: false, message });
    };

    if (!target) return refuse(404, "User not found");
    const role = String(target.role);
    if (!VIEWABLE_ROLES.includes(role)) return refuse(403, "This user cannot be viewed");
    if (String(target.status) !== "active") return refuse(403, "Account is not active");

    /*
    | Server-side session row for the TARGET. authMiddleware requires a live
    | dietician_refresh_tokens row matching the token's dietician_id + sid.
    | The token hash is random and never returned, so this session cannot be
    | refreshed — it dies with VIEW_AS_TTL. user_agent records who viewed.
    */
    const expiresAt = new Date(Date.now() + VIEW_AS_TTL * 1000);
    const [insertResult] = await pool.execute(
      `INSERT INTO dietician_refresh_tokens (dietician_id, token_hash, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        String(target.dietician_id),
        crypto.createHash("sha256").update(crypto.randomBytes(64).toString("hex")).digest("hex"),
        expiresAt,
        getClientIp(req),
        `view-as by ${resolved.actorEmail}`.substring(0, 255),
      ]
    );
    const sessionId = String(insertResult.insertId);
    if (!insertResult.insertId || Number(insertResult.insertId) <= 0) {
      console.error("VIEW_AS_SESSION_CREATION_FAILED");
      return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
    }

    const partnerCode = target.partner_code == null ? null : String(target.partner_code);
    const parentUserId = target.parent_user_id == null ? null : String(target.parent_user_id).toLowerCase();
    const facilityId = target.facility_id == null ? null : Number(target.facility_id);
    const targetEmail = String(target.email).toLowerCase();
    const now = Math.floor(Date.now() / 1000);

    const dieticianPayload = {
      dietician_id: String(target.dietician_id),
      user_id: targetEmail,
      name: target.name,
      email: targetEmail,
      phone_no: target.phone_no,
      location: target.location,
      logo: buildLogoUrl(target.dietician_id),
      is_reset_password: parseInt(target.is_reset_password, 10) || 0,
      role,
      partner_code: partnerCode,
      parent_user_id: parentUserId,
      facility_id: facilityId,
    };

    const accessToken = jwt.sign(
      {
        iss: JWT_ISS,
        aud: JWT_AUD,
        iat: now,
        nbf: now,
        exp: now + VIEW_AS_TTL,
        sub: String(target.dietician_id),
        sid: sessionId,
        dietician_id: String(target.dietician_id),
        user_id: targetEmail,
        role,
        partner_code: partnerCode,
        parent_user_id: parentUserId,
        facility_id: facilityId,
        dashboard_route: buildDashboardRoute(role),
        dietician: dieticianPayload,
        // View-as markers. authMiddleware blocks mutating endpoints whenever
        // view_only is set; impersonated_by keeps the real actor auditable.
        view_only: true,
        impersonated_by: resolved.actorEmail,
      },
      JWT_SECRET,
      { algorithm: "HS256" }
    );

    await H.writeAuthLogSafe(req, {
      eventType: "view_as_started",
      userId: resolved.actorEmail,
      role: "super_admin",
      partnerCode,
      identifier: targetEmail,
      success: true,
      failureReason: `target=${targetEmail} role=${role} ttl=${VIEW_AS_TTL}s`,
    });

    return res.status(200).json({
      status: true,
      ok: true,
      token_type: "Bearer",
      access_token: accessToken,
      expires_in: VIEW_AS_TTL,
      target: {
        user_id: targetEmail,
        name: target.name || null,
        role,
        partner_code: partnerCode,
        dashboard_route: buildDashboardRoute(role),
      },
    });
  } catch (err) {
    console.error("SUPER_ADMIN_VIEW_AS_START_ERROR:", { targetUserId, code: err?.code, sqlMessage: err?.sqlMessage, message: err?.message });
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { superAdminViewAsList, superAdminViewAsStart };
