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

/**
 * A code on a *pending* invitation (sticker set up in the field before the
 * owner accepted). The sale is attributed to the invitee's email; commission
 * is held until the account is active.
 */
async function lookupPendingInvitation(code) {
  const [rows] = await pool.execute(
    `
      SELECT invited_email, invited_role, partner_code, parent_user_id, facility_id, facility_name
      FROM app_user_invitations
      WHERE UPPER(partner_code) = ? AND status = 'pending' AND expires_at > UTC_TIMESTAMP()
        AND invited_role IN ('facility_admin','trainer')
      ORDER BY id DESC LIMIT 1
    `,
    [code]
  );
  const r = rows[0];
  if (!r) return null;
  return {
    partner_code: String(r.partner_code).toUpperCase(),
    user_id: String(r.invited_email).toLowerCase(),
    role: String(r.invited_role),
    facility_id: r.facility_id == null ? null : Number(r.facility_id),
    parent_user_id: r.parent_user_id ? String(r.parent_user_id).toLowerCase() : null,
    pending: true,
    facility_name: r.facility_name || null,
  };
}

async function resolvePartnerCode(rawCode, { allowPending = true } = {}) {
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

  return allowPending ? lookupPendingInvitation(code) : null;
}

module.exports = { resolvePartnerCode, normalizeCode };
