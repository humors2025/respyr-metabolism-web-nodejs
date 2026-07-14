"use strict";

/**
 * admin_group_visibility.js
 *
 * Converted from: admin_group_visibility.php
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Reusable helper for the ta_admin_groups single-table design.
 *
 * Two admins that share the SAME active group in ta_admin_groups can see each
 * other's data. This module expands an admin's own partner_code / dietician_id
 * into the full set of codes they may view. All codes are compared UPPER-cased,
 * exactly like the rest of the project (trainer-admin-clients-list-dir.js /
 * get_group_details.js).
 *
 * Usage from any controller (the shared mysql2 pool is used by default):
 *
 *     const { getAdminGroupPeerCodes } = require("./admin_group_visibility");
 *     const peerCodes = await getAdminGroupPeerCodes(actorCode); // includes actorCode
 *
 * The returned array is a de-duplicated, UPPER-cased list you can drop straight
 * into an IN (...) clause with `?` placeholders + bound params.
 *
 * ──────────────────────────────────────────────────────────────────────────
 *  KEY DIFFERENCES FROM THE PHP (intentional, required for Node + security)
 * ──────────────────────────────────────────────────────────────────────────
 *  1. ASYNC. Every function returns a Promise (mysql2 pool.execute is async).
 *     Callers must `await`.
 *  2. NO PDO ARGUMENT. The PHP took `$pdo` as the first parameter. Node uses the
 *     shared pool (config/db). An optional `executor` second argument is accepted
 *     so a caller inside a transaction can pass its own connection; it defaults
 *     to the pool. This keeps the shared-pool convention of the sibling modules.
 *  3. FULLY PARAMETERIZED. The named PDO placeholders become positional `?`
 *     placeholders bound via pool.execute(sql, params) — zero string
 *     interpolation. No value is ever concatenated into the SQL.
 *  4. FAIL-CLOSED, NON-LEAKY. Errors propagate to the caller (which owns the
 *     try/catch + audit + response), exactly like the PHP let PDO exceptions
 *     bubble. No PHI is logged here — this is a pure data-access utility.
 *
 * Tables touched (identical to the PHP — none added/removed): ta_admin_groups.
 */

const pool = require("../../../../config/db");

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** PHP normalizeCodeLocal(): upper-case + trim. Null/undefined → "". */
function normalizeCode(code) {
  return String(code ?? "").trim().toUpperCase();
}

// ─── Group visibility ────────────────────────────────────────────────────────

/**
 * Port of PHP getAdminGroupsForCode(): the distinct, active group names the given
 * admin code belongs to.
 *
 * @param {string}  code        Admin partner_code / dietician_id (any case).
 * @param {object} [executor]   mysql2 pool or connection; defaults to the shared pool.
 * @returns {Promise<string[]>} Active group names (may be empty).
 */
async function getAdminGroupsForCode(code, executor = pool) {
  const normalized = normalizeCode(code);

  if (normalized === "") return [];

  const [rows] = await executor.execute(
    `
      SELECT DISTINCT group_name
      FROM ta_admin_groups
      WHERE UPPER(dietician_id) = ?
        AND status = 'active'
    `,
    [normalized]
  );

  const groups = [];
  for (const row of rows) {
    if (row.group_name !== null && row.group_name !== undefined) {
      groups.push(row.group_name);
    }
  }
  return groups;
}

/**
 * Port of PHP getAdminGroupPeerCodes(): every admin code that shares at least one
 * active group with the given code. The given code itself is ALWAYS included
 * (even if it is in no group), so callers can use the result unconditionally.
 *
 * @param {string}  code        Admin partner_code / dietician_id (any case).
 * @param {object} [executor]   mysql2 pool or connection; defaults to the shared pool.
 * @returns {Promise<string[]>} De-duplicated, UPPER-cased codes including `code`.
 */
async function getAdminGroupPeerCodes(code, executor = pool) {
  const normalized = normalizeCode(code);

  // Map de-duplicates while preserving self-first insertion order.
  const codes = new Map();

  if (normalized === "") {
    return [];
  }

  // Self is always visible to self.
  codes.set(normalized, normalized);

  /*
   * Self-join on group_name: find everyone in any active group that "me" is in.
   * Both sides must be active. The single value is bound — no interpolation.
   */
  const [rows] = await executor.execute(
    `
      SELECT DISTINCT UPPER(peer.dietician_id) AS peer_code
      FROM ta_admin_groups AS me
      JOIN ta_admin_groups AS peer
        ON peer.group_name = me.group_name
       AND peer.status = 'active'
      WHERE UPPER(me.dietician_id) = ?
        AND me.status = 'active'
    `,
    [normalized]
  );

  for (const row of rows) {
    const peer = normalizeCode(row.peer_code);
    if (peer !== "") {
      codes.set(peer, peer);
    }
  }

  return [...codes.values()];
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  normalizeCode,
  getAdminGroupsForCode,
  getAdminGroupPeerCodes,
};
