"use strict";

/**
 * Pre-printed QR stickers. Each sticker encodes only its own id
 * (rysflo.com/q/K7M2P9); who it points at is decided later, on the
 * Facilities page, and can change. Scans resolve at scan time.
 */

const crypto = require("crypto");
const pool = require("../config/db");

// No 0/O/1/I so the printed id is unambiguous when typed.
const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const ID_LEN = 6;

function normalizeId(raw) {
  const v = typeof raw === "string" ? raw.trim().toUpperCase() : "";
  return /^[A-Z0-9]{4,12}$/.test(v) ? v : "";
}

function randomId() {
  const b = crypto.randomBytes(ID_LEN);
  let out = "";
  for (let i = 0; i < ID_LEN; i++) out += ALPHABET[b[i] % ALPHABET.length];
  return out;
}

/** Create `count` unassigned stickers in one batch. Returns the ids. */
async function generateBatch({ count, createdBy, batchId = null }) {
  const n = Math.max(1, Math.min(1000, Number(count) || 0));
  const batch = batchId || `B${new Date().toISOString().slice(0, 10).replace(/-/g, "")}-${randomId().slice(0, 4)}`;
  const ids = [];
  while (ids.length < n) {
    const id = randomId();
    const [r] = await pool.execute(
      `INSERT IGNORE INTO qr_codes (id, batch_id, status, created_by) VALUES (?, ?, 'unassigned', ?)`,
      [id, batch, createdBy]
    );
    if (r.affectedRows) ids.push(id);
  }
  return { batch_id: batch, ids };
}

/** Sticker row, or null. */
async function get(id) {
  const clean = normalizeId(id);
  if (!clean) return null;
  const [rows] = await pool.execute(`SELECT * FROM qr_codes WHERE id = ? LIMIT 1`, [clean]);
  return rows[0] || null;
}

/** For the order page: { id, partner_code|null }. Retired stickers resolve to nothing. */
async function resolve(id) {
  const row = await get(id);
  if (!row || row.status === "retired") return null;
  return { id: row.id, partner_code: row.partner_code || null, facility_id: row.facility_id == null ? null : Number(row.facility_id) };
}

async function recordScan(id) {
  await pool.execute(`UPDATE qr_codes SET scans = scans + 1 WHERE id = ?`, [id]);
}

/**
 * Point a sticker at a partner code (facility admin or trainer). `target` is
 * the app_user_roles row it should resolve to. Writes history.
 */
async function link({ id, target, actorUserId }) {
  const row = await get(id);
  if (!row) {
    const err = new Error("Unknown QR code");
    err.status = 404;
    throw err;
  }
  await pool.execute(
    `INSERT INTO qr_code_links (qr_id, from_partner_code, to_partner_code, actor_user_id) VALUES (?, ?, ?, ?)`,
    [row.id, row.partner_code || null, target ? target.partner_code : null, actorUserId]
  );
  await pool.execute(
    `
      UPDATE qr_codes
      SET status = ?, partner_code = ?, facility_id = ?, linked_user_id = ?, linked_by = ?, linked_at = UTC_TIMESTAMP()
      WHERE id = ?
    `,
    [
      target ? "assigned" : "unassigned",
      target ? String(target.partner_code).toUpperCase() : null,
      target && target.facility_id != null ? Number(target.facility_id) : null,
      target ? String(target.user_id).toLowerCase() : null,
      actorUserId,
      row.id,
    ]
  );
  return get(row.id);
}

async function retire({ id, actorUserId }) {
  const row = await get(id);
  if (!row) return null;
  await pool.execute(
    `INSERT INTO qr_code_links (qr_id, from_partner_code, to_partner_code, actor_user_id) VALUES (?, ?, NULL, ?)`,
    [row.id, row.partner_code || null, actorUserId]
  );
  await pool.execute(`UPDATE qr_codes SET status = 'retired', partner_code = NULL, facility_id = NULL, linked_user_id = NULL WHERE id = ?`, [row.id]);
  return get(row.id);
}

module.exports = { normalizeId, generateBatch, get, resolve, recordScan, link, retire };
