"use strict";

/**
 * Checks shared by every endpoint that sends or resends an invitation.
 *
 * accept-invite.js creates (or updates) the table_dietician row for the invited
 * email under the invite's partner code. If table_dietician already has a row
 * for that email under a DIFFERENT dietician_id, the accept is refused with
 * 409 "email_code_conflict" — every time, because the invite's code never
 * changes. Such rows are left over from older accounts (e.g. the dietitian
 * platform) that have no app_user_roles row.
 *
 * New invites always get a freshly generated partner code, so any existing
 * table_dietician row for the email blocks them. A resend keeps the invite's
 * code, so it is only blocked when the old row is under another code.
 *
 * Checking before the email goes out turns a dead invite link into a clear
 * message for whoever is sending it.
 */

const pool = require("../config/db");

/**
 * The table_dietician row for this email, if any: { id, dietician_id } or null.
 */
async function findDieticianAccountByEmail(email) {
  const value = String(email || "").trim();
  if (value === "") return null;

  const [rows] = await pool.execute(
    `
      SELECT id, dietician_id
      FROM table_dietician
      WHERE LOWER(email) = LOWER(?)
      LIMIT 1
    `,
    [value]
  );

  return rows[0] || null;
}

/**
 * null when an invite for `email` can be accepted as far as table_dietician is
 * concerned; otherwise { ok: false, status: 409, message, reason }.
 *
 * partnerCode: the code the invite carries (resends). Omit for a new invite,
 * whose code has not been generated yet and will not match an old row.
 */
async function leftoverAccountBlock(email, { partnerCode = null } = {}) {
  const row = await findDieticianAccountByEmail(email);
  if (!row) return null;

  const oldCode = String(row.dietician_id || "").trim();
  if (partnerCode && oldCode.toUpperCase() === String(partnerCode).trim().toUpperCase()) {
    return null;
  }

  return {
    ok: false,
    status: 409,
    reason: "leftover_dietician_account",
    message:
      `This email is still linked to an old account (${oldCode || "no code"}), ` +
      "so the invitation could not be accepted. Ask Respyr support to remove the old account, then send the invitation again.",
  };
}

module.exports = { findDieticianAccountByEmail, leftoverAccountBlock };
