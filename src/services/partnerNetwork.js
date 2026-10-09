"use strict";

/**
 * partnerNetwork.js — which partner codes an admin-side actor may see.
 *
 * Dashboard data is keyed by partner code (table_clients.dietician_id and so
 * on). An actor's "network" is the set of active accounts under them in the
 * app_user_roles parent chain, and therefore the codes whose clients they may
 * see:
 *
 *   super_admin  admins          parented to the super admin
 *                facility admins parented to the super admin or to one of
 *                                those admins
 *                trainers        parented to the super admin, to one of those
 *                                admins, or to one of those facility admins
 *   admin        facility admins parented to the admin
 *                trainers        parented to the admin or to one of those
 *                                facility admins
 *
 * The PHP-era ports only followed admin → trainer, from before facility admins
 * (gym / studio owners) existed. A member scanning under a facility admin's
 * code, and the trainers a facility admin invites (parented to the facility
 * admin — see admin-invite-trainer), never showed up on All Clients or in the
 * overview counts. This module is the one place that rule lives now; callers:
 * super-admin-all-clients-overview(-newtest), super-admin-overview,
 * trainer-admin-overview, trainer-admin-clients-list-dir.
 *
 * Plain SQL without recursive CTEs (MySQL 5.7-safe); app_user_roles is small.
 * The actor's own code is NOT included — each caller adds it itself.
 */

const pool = require("../config/db");

// Active admins directly under a super admin. One `?` = the super admin email.
const ADMINS_UNDER_SUPER_ADMIN = `
  SELECT LOWER(a.user_id) FROM app_user_roles a
  WHERE a.role = 'admin' AND a.status = 'active' AND LOWER(a.parent_user_id) = LOWER(?)
`;

/**
 * Every active role account in `rootEmail`'s network (the root itself is not
 * included), one row each:
 *   { user_id, role, partner_code, dietician_id, code }
 * `code` is the upper-cased partner_code, falling back to
 * table_dietician.dietician_id for older trainers without one ("" if neither).
 *
 * @param {string} rootEmail  actor email, matched case-insensitively
 * @param {"super_admin"|"admin"} rootRole
 * @param {{ conn?: { execute: Function } }} [opts]  pool or transaction connection
 */
async function listNetworkAccounts(rootEmail, rootRole, { conn = pool } = {}) {
  const email = String(rootEmail || "").trim().toLowerCase();
  const role = String(rootRole || "");
  if (email === "" || (role !== "super_admin" && role !== "admin")) return [];

  let scopeSql;
  let params;
  if (role === "super_admin") {
    const facilityAdminsInScope = `
      SELECT LOWER(fa.user_id) FROM app_user_roles fa
      WHERE fa.role = 'facility_admin' AND fa.status = 'active'
        AND (LOWER(fa.parent_user_id) = LOWER(?) OR LOWER(fa.parent_user_id) IN (${ADMINS_UNDER_SUPER_ADMIN}))
    `;
    scopeSql = `
         (aur.role IN ('admin', 'facility_admin', 'trainer') AND LOWER(aur.parent_user_id) = LOWER(?))
      OR (aur.role IN ('facility_admin', 'trainer')          AND LOWER(aur.parent_user_id) IN (${ADMINS_UNDER_SUPER_ADMIN}))
      OR (aur.role = 'trainer'                               AND LOWER(aur.parent_user_id) IN (${facilityAdminsInScope}))
    `;
    params = [email, email, email, email];
  } else {
    const facilityAdminsInScope = `
      SELECT LOWER(fa.user_id) FROM app_user_roles fa
      WHERE fa.role = 'facility_admin' AND fa.status = 'active' AND LOWER(fa.parent_user_id) = LOWER(?)
    `;
    scopeSql = `
         (aur.role IN ('facility_admin', 'trainer') AND LOWER(aur.parent_user_id) = LOWER(?))
      OR (aur.role = 'trainer'                      AND LOWER(aur.parent_user_id) IN (${facilityAdminsInScope}))
    `;
    params = [email, email];
  }

  const [rows] = await conn.execute(
    `
      SELECT
        LOWER(aur.user_id) AS user_id,
        aur.role,
        aur.partner_code,
        td.dietician_id,
        UPPER(COALESCE(NULLIF(TRIM(aur.partner_code), ''), NULLIF(TRIM(td.dietician_id), ''), '')) AS code
      FROM app_user_roles aur
      LEFT JOIN table_dietician td ON LOWER(td.email) = LOWER(aur.user_id)
      WHERE aur.status = 'active'
        AND (${scopeSql})
    `,
    params
  );
  return rows;
}

/**
 * The network's partner codes: upper-cased, de-duplicated, empty ones dropped.
 * The actor's own code is not included — callers add it.
 */
async function listNetworkCodes(rootEmail, rootRole, opts) {
  const codes = new Set();
  for (const row of await listNetworkAccounts(rootEmail, rootRole, opts)) {
    if (row.code) codes.add(row.code);
  }
  return [...codes];
}

module.exports = { listNetworkAccounts, listNetworkCodes };
