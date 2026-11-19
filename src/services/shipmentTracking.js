"use strict";

/**
 * Stored FedEx tracking for website purchases (shipment_tracking, migration 013).
 *
 *   trackingFor(subIds)        Map(stripe_subscription_id → row for the API), for
 *                              the Orders › Shipping rows. Empty when the table
 *                              is missing, so the tab keeps working.
 *   saveTrackingNumber(...)    store / replace a subscription's number, then
 *                              look it up at FedEx straight away
 *   removeTracking(subId)      forget a subscription's number
 *   refreshTracking(opts)      ask FedEx again for numbers not yet delivered,
 *                              skipping ones checked in the last 30 minutes
 *                              unless force is set
 */

const pool = require("../config/db");
const { trackNumbers, fedexTrackingUrl } = require("./fedex");

const TABLE = "shipment_tracking";
const REFRESH_MIN_AGE_MINUTES = 30;
const REFRESH_MAX_ROWS = 300;
const EVENTS_KEPT = 50;

function isMissingTable(err) {
  return err?.code === "ER_NO_SUCH_TABLE" || err?.errno === 1146;
}

function tableMissingError() {
  const e = new Error("Tracking is not set up yet: run database/migrations/013_shipment_tracking.sql");
  e.status = 503;
  e.code = "TRACKING_TABLE_MISSING";
  return e;
}

let missingWarned = false;
function warnMissingOnce() {
  if (missingWarned) return;
  missingWarned = true;
  console.warn("SHIPMENT_TRACKING_TABLE_MISSING:", { note: "run database/migrations/013_shipment_tracking.sql" });
}

const toIso = (v) => {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isFinite(d.getTime()) ? d.toISOString() : null;
};

// JS Date → "YYYY-MM-DD HH:MM:SS" in UTC for DATETIME columns.
const toSql = (d) => (d instanceof Date && Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 19).replace("T", " ") : null);

const clip = (s, n) => (s == null ? null : String(s).slice(0, n));

function parseEvents(json) {
  if (!json) return [];
  try {
    const list = JSON.parse(json);
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

/** DB row → the `tracking` object on a Shipping row. */
function present(row) {
  return {
    carrier: row.carrier,
    tracking_number: row.tracking_number,
    tracking_url: fedexTrackingUrl(row.tracking_number),
    status_code: row.status_code || null,
    status_text: row.status_text || null,
    delivered: row.status_code === "DL" || Boolean(row.delivered_at),
    estimated_delivery: toIso(row.estimated_delivery),
    delivered_at: toIso(row.delivered_at),
    last_event: row.last_event_text || row.last_event_at
      ? { at: toIso(row.last_event_at), text: row.last_event_text || null, location: row.last_event_location || null }
      : null,
    events: parseEvents(row.events_json),
    error: row.last_error || null,
    checked_at: toIso(row.checked_at),
    added_by: row.added_by || null,
    added_at: toIso(row.created_at),
  };
}

async function trackingFor(subscriptionIds) {
  const ids = [...new Set((subscriptionIds || []).filter(Boolean))];
  const out = new Map();
  if (!ids.length) return out;
  try {
    const [rows] = await pool.query(`SELECT * FROM ${TABLE} WHERE stripe_subscription_id IN (?)`, [ids]);
    for (const r of rows) out.set(r.stripe_subscription_id, present(r));
  } catch (err) {
    if (!isMissingTable(err)) throw err;
    warnMissingOnce();
  }
  return out;
}

/** Write one FedEx answer onto the row for `trackingNumber`. */
async function storeResult(stripeSubscriptionId, result) {
  if (!result?.ok) {
    await pool.query(`UPDATE ${TABLE} SET last_error = ?, checked_at = UTC_TIMESTAMP() WHERE stripe_subscription_id = ?`, [
      clip(result?.error || "FedEx lookup failed", 255),
      stripeSubscriptionId,
    ]);
    return;
  }
  const events = (result.events || []).slice(0, EVENTS_KEPT).map((e) => ({
    at: toIso(e.at),
    code: e.code || null,
    text: e.text || null,
    location: e.location || null,
  }));
  await pool.query(
    `UPDATE ${TABLE}
        SET status_code = ?, status_text = ?, estimated_delivery = ?, delivered_at = ?,
            last_event_at = ?, last_event_text = ?, last_event_location = ?,
            events_json = ?, last_error = NULL, checked_at = UTC_TIMESTAMP()
      WHERE stripe_subscription_id = ?`,
    [
      clip(result.status_code, 10),
      clip(result.status_text, 255),
      toSql(result.estimated_delivery),
      toSql(result.delivered_at),
      toSql(result.last_event?.at || null),
      clip(result.last_event?.text, 255),
      clip(result.last_event?.location, 150),
      JSON.stringify(events),
      stripeSubscriptionId,
    ]
  );
}

async function lookupAndStore(rows) {
  if (!rows.length) return { checked: 0, failed: 0 };
  const results = await trackNumbers(rows.map((r) => r.tracking_number));
  let failed = 0;
  for (const r of rows) {
    const result = results.get(String(r.tracking_number).trim());
    if (!result?.ok) failed += 1;
    await storeResult(r.stripe_subscription_id, result);
  }
  return { checked: rows.length, failed };
}

async function saveTrackingNumber({ stripeSubscriptionId, trackingNumber, addedBy }) {
  try {
    await pool.query(
      `INSERT INTO ${TABLE} (stripe_subscription_id, carrier, tracking_number, added_by)
       VALUES (?, 'fedex', ?, ?)
       ON DUPLICATE KEY UPDATE
         tracking_number = VALUES(tracking_number), carrier = VALUES(carrier), added_by = VALUES(added_by),
         status_code = NULL, status_text = NULL, estimated_delivery = NULL, delivered_at = NULL,
         last_event_at = NULL, last_event_text = NULL, last_event_location = NULL,
         events_json = NULL, last_error = NULL, checked_at = NULL`,
      [stripeSubscriptionId, trackingNumber, clip(addedBy, 150)]
    );
  } catch (err) {
    if (isMissingTable(err)) throw tableMissingError();
    throw err;
  }

  // The number is saved even when FedEx is down or does not know it yet
  // (labels can take a few hours to show up): the error is stored and shown.
  let lookupError = null;
  try {
    await lookupAndStore([{ stripe_subscription_id: stripeSubscriptionId, tracking_number: trackingNumber }]);
  } catch (err) {
    lookupError = err.message;
    await storeResult(stripeSubscriptionId, { ok: false, error: err.message });
  }
  const map = await trackingFor([stripeSubscriptionId]);
  return { tracking: map.get(stripeSubscriptionId) || null, lookup_error: lookupError };
}

async function removeTracking(stripeSubscriptionId) {
  try {
    const [res] = await pool.query(`DELETE FROM ${TABLE} WHERE stripe_subscription_id = ?`, [stripeSubscriptionId]);
    return res.affectedRows > 0;
  } catch (err) {
    if (isMissingTable(err)) throw tableMissingError();
    throw err;
  }
}

/**
 * Ask FedEx again for numbers that are not delivered yet. subscriptionIds
 * narrows to those rows (the page on screen); without it every undelivered
 * row is checked (nightly job). Rows checked less than 30 minutes ago are
 * skipped unless force.
 */
async function refreshTracking({ subscriptionIds = null, force = false } = {}) {
  const where = ["delivered_at IS NULL", "(status_code IS NULL OR status_code <> 'DL')"];
  const params = [];
  if (Array.isArray(subscriptionIds)) {
    const ids = subscriptionIds.filter(Boolean);
    if (!ids.length) return { checked: 0, failed: 0, skipped: 0 };
    where.push("stripe_subscription_id IN (?)");
    params.push(ids);
  }
  let rows;
  try {
    [rows] = await pool.query(
      `SELECT stripe_subscription_id, tracking_number, checked_at FROM ${TABLE}
        WHERE ${where.join(" AND ")} ORDER BY checked_at IS NULL DESC, checked_at ASC LIMIT ${REFRESH_MAX_ROWS}`,
      params
    );
  } catch (err) {
    if (isMissingTable(err)) {
      warnMissingOnce();
      return { checked: 0, failed: 0, skipped: 0, table_missing: true };
    }
    throw err;
  }

  const cutoff = Date.now() - REFRESH_MIN_AGE_MINUTES * 60 * 1000;
  const due = force
    ? rows
    : rows.filter((r) => {
        if (!r.checked_at) return true;
        const t = Date.parse(`${toIso(r.checked_at)}`);
        return !Number.isFinite(t) || t < cutoff;
      });
  const result = await lookupAndStore(due);
  return { ...result, skipped: rows.length - due.length };
}

module.exports = {
  trackingFor,
  saveTrackingNumber,
  removeTracking,
  refreshTracking,
  _test: { present, toSql },
};
