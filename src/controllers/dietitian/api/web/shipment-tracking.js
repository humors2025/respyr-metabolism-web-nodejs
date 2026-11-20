"use strict";

/**
 * POST /dietitian/api/web/shipment-tracking
 *
 * FedEx tracking for the devices sent to website buyers (Orders › Shipping).
 * Numbers are stored in shipment_tracking (migration 013); the latest FedEx
 * status is kept with them, and Orders › Shipping returns it on each row.
 *
 *   action=set      (super_admin) { stripe_subscription_id, tracking_number }
 *                   Saves or replaces the number and looks it up at FedEx at
 *                   once. The number stays saved when FedEx does not know it
 *                   yet; the FedEx message comes back as lookup_error.
 *   action=remove   (super_admin) { stripe_subscription_id }
 *   action=refresh  (super_admin + ORDERS_VIEWER_EMAILS) { stripe_subscription_ids?, force? }
 *                   Asks FedEx again for undelivered numbers, at most once per
 *                   30 minutes each unless force (super_admin only). Without
 *                   stripe_subscription_ids every undelivered number is checked.
 *
 * Env: FEDEX_API_BASE, FEDEX_CLIENT_ID, FEDEX_CLIENT_SECRET (see services/fedex.js).
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");
const { saveTrackingNumber, removeTracking, refreshTracking, trackingFor } = require("../../../../services/shipmentTracking");
const {
  _helpers: { ORDERS_VIEWER_EMAILS },
} = require("./super-admin-orders");

const SUB_ID_RE = /^sub_[A-Za-z0-9]+$/;
// FedEx numbers are 12, 15, 20 or 22 digits (some door tags carry letters).
const TRACKING_RE = /^[A-Za-z0-9]{8,34}$/;

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

function subscriptionId(value) {
  const id = String(value || "").trim();
  if (!id) throw httpError(422, "stripe_subscription_id is required");
  if (!SUB_ID_RE.test(id)) throw httpError(422, "stripe_subscription_id must look like sub_…");
  return id;
}

const shipmentTracking = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const action = String(body.action || "");
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, ["super_admin", "admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });
    const isSuperAdmin = String(resolved.actor.role) === "super_admin";
    const isViewer = ORDERS_VIEWER_EMAILS.includes(String(resolved.actorEmail || "").toLowerCase());
    if (!isSuperAdmin && !(action === "refresh" && isViewer)) {
      return res.status(403).json({ status: false, ok: false, message: "You are not allowed to perform this action" });
    }

    let payload;
    if (action === "set") {
      const id = subscriptionId(body.stripe_subscription_id);
      const number = String(body.tracking_number || "").replace(/\s+/g, "").toUpperCase();
      if (!TRACKING_RE.test(number)) throw httpError(422, "Enter a valid FedEx tracking number (letters and digits only)");

      const [[ship]] = await pool.query(
        "SELECT stripe_subscription_id FROM subscription_shipping_addresses WHERE stripe_subscription_id = ? LIMIT 1",
        [id]
      );
      if (!ship) throw httpError(404, "No shipping address for that subscription");

      payload = await saveTrackingNumber({ stripeSubscriptionId: id, trackingNumber: number, addedBy: resolved.actorEmail });
    } else if (action === "remove") {
      const id = subscriptionId(body.stripe_subscription_id);
      payload = { removed: await removeTracking(id) };
    } else if (action === "refresh") {
      let ids = null;
      if (Array.isArray(body.stripe_subscription_ids)) {
        ids = body.stripe_subscription_ids.map((v) => String(v || "").trim()).filter((v) => SUB_ID_RE.test(v)).slice(0, 100);
      }
      const summary = await refreshTracking({ subscriptionIds: ids, force: Boolean(body.force) && isSuperAdmin });
      const tracking = ids ? Object.fromEntries(await trackingFor(ids)) : undefined;
      payload = { summary, ...(tracking ? { tracking } : {}) };
    } else {
      return res.status(422).json({ status: false, ok: false, message: "action must be set, remove or refresh" });
    }

    if (action !== "refresh") {
      await H.writeAuthLogSafe(req, {
        eventType: `shipment_tracking_${action}`,
        userId: resolved.actorEmail,
        role: resolved.actor.role,
        partnerCode: null,
        identifier: String(body.stripe_subscription_id || ""),
        success: true,
        failureReason: null,
      });
    }

    return res.status(200).json({ status: true, ok: true, action, ...payload });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, code: err.code, message: err.message });
    console.error("SHIPMENT_TRACKING_ERROR:", { action, code: err?.code, message: err?.message });
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { shipmentTracking };
