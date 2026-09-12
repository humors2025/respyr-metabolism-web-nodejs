"use strict";

/**
 * Resolve a referral / partner code (the thing on a QR code or order link) to
 * the account that should be credited for a sale made through it.
 *
 * Rules:
 *  - An active admin / facility_admin / trainer code resolves to itself.
 *  - A removed / suspended trainer's code resolves to their parent (clients
 *    and their commission revert to the parent — same rule as remove-user.js),
 *    walking up at most a few levels.
 *  - Anything else resolves to null: the sale still happens, just without
 *    referral attribution.
 *
 * Returns { partner_code, user_id, role, facility_id, parent_user_id } or null.
 */

const pool = require("../config/db");

const CODE_RE = /^[A-Za-z0-9]{3,50}$/;
const MAX_HOPS = 4;

function normalizeCode(raw) {
  const c = typeof raw === "string" ? raw.trim().toUpperCase() : "";
  return CODE_RE.test(c) ? c : "";
}

async function lookupByCode(code) {
  const [rows] = await pool.execute(
    `
      SELECT user_id, role, partner_code, parent_user_id, facility_id, status
      FROM app_user_roles
      WHERE UPPER(partner_code) = ?
        AND role IN ('admin','facility_admin','trainer')
      LIMIT 1
    `,
    [code]
  );
  return rows[0] || null;
}

async function lookupByUserId(userId) {
  const [rows] = await pool.execute(
    `
      SELECT user_id, role, partner_code, parent_user_id, facility_id, status
      FROM app_user_roles
      WHERE LOWER(user_id) = LOWER(?)
        AND role IN ('admin','facility_admin','trainer')
      LIMIT 1
    `,
    [userId]
  );
  return rows[0] || null;
}

function shape(row) {
  return {
    partner_code: String(row.partner_code).toUpperCase(),
    user_id: String(row.user_id).toLowerCase(),
    role: String(row.role),
    facility_id: row.facility_id == null ? null : Number(row.facility_id),
    parent_user_id: row.parent_user_id ? String(row.parent_user_id).toLowerCase() : null,
  };
}

async function resolvePartnerCode(rawCode) {
  const code = normalizeCode(rawCode);
  if (code === "") return null;

  let row = await lookupByCode(code);
  let hops = 0;

  while (row && hops < MAX_HOPS) {
    if (String(row.status) === "active" && row.partner_code) {
      return shape(row);
    }
    if (!row.parent_user_id) return null;
    row = await lookupByUserId(row.parent_user_id);
    hops += 1;
  }

  return null;
}

module.exports = { resolvePartnerCode, normalizeCode };
