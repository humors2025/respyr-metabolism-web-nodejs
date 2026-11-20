"use strict";

/**
 * FedEx Track API client (https://developer.fedex.com, "Track API").
 *
 * Env:
 *   FEDEX_API_BASE       https://apis-sandbox.fedex.com (test keys) or
 *                        https://apis.fedex.com (production keys). Defaults to
 *                        the sandbox.
 *   FEDEX_CLIENT_ID      the project's "API Key"
 *   FEDEX_CLIENT_SECRET  the project's "Secret Key"
 *
 * The sandbox only answers for FedEx's own test tracking numbers (e.g.
 * 123456789012); real parcels need the production base URL and keys.
 *
 * getToken() caches the OAuth token in memory until a minute before it
 * expires, so a warm Lambda reuses it. trackNumbers() asks for up to 30
 * numbers per FedEx call and returns a Map(trackingNumber → normalised result).
 */

const axios = require("axios");

const FEDEX_API_BASE = String(process.env.FEDEX_API_BASE || "https://apis-sandbox.fedex.com")
  .trim()
  .replace(/\/+$/, "");
const FEDEX_CLIENT_ID = String(process.env.FEDEX_CLIENT_ID || "").trim();
const FEDEX_CLIENT_SECRET = String(process.env.FEDEX_CLIENT_SECRET || "").trim();

const BATCH_SIZE = 30; // FedEx's limit per track request
const TIMEOUT_MS = 10000;

function fedexConfigured() {
  return Boolean(FEDEX_CLIENT_ID && FEDEX_CLIENT_SECRET);
}

function fedexError(status, message, code) {
  const e = new Error(message);
  e.status = status;
  e.code = code || "FEDEX_ERROR";
  return e;
}

// First FedEx error in a failed response, as "CODE: message".
function describeFedexFailure(err) {
  const data = err?.response?.data;
  const first = Array.isArray(data?.errors) ? data.errors[0] : null;
  if (first) return `${first.code || "ERROR"}: ${first.message || ""}`.trim();
  if (data?.error) return `${data.error}${data.error_description ? `: ${data.error_description}` : ""}`;
  return err?.code === "ECONNABORTED" ? "FedEx did not answer in time" : err?.message || "FedEx request failed";
}

let cachedToken = null; // { value, expiresAt }

async function getToken({ force = false } = {}) {
  if (!fedexConfigured()) {
    throw fedexError(503, "FedEx is not set up: FEDEX_CLIENT_ID and FEDEX_CLIENT_SECRET are missing", "FEDEX_NOT_CONFIGURED");
  }
  if (!force && cachedToken && cachedToken.expiresAt > Date.now()) return cachedToken.value;

  try {
    const res = await axios.post(
      `${FEDEX_API_BASE}/oauth/token`,
      new URLSearchParams({
        grant_type: "client_credentials",
        client_id: FEDEX_CLIENT_ID,
        client_secret: FEDEX_CLIENT_SECRET,
      }).toString(),
      { headers: { "Content-Type": "application/x-www-form-urlencoded" }, timeout: TIMEOUT_MS }
    );
    const value = res.data?.access_token;
    if (!value) throw new Error("FedEx returned no access_token");
    const seconds = Number(res.data?.expires_in) || 3600;
    cachedToken = { value, expiresAt: Date.now() + Math.max(60, seconds - 60) * 1000 };
    return value;
  } catch (err) {
    cachedToken = null;
    const status = err?.response?.status;
    console.error("FEDEX_TOKEN_ERROR:", { status, detail: describeFedexFailure(err) });
    throw fedexError(502, `FedEx sign-in failed (${describeFedexFailure(err)})`, "FEDEX_AUTH_FAILED");
  }
}

// ─── Response normalising ────────────────────────────────────────────────────

function toDate(value) {
  if (!value) return null;
  const t = Date.parse(value);
  return Number.isFinite(t) ? new Date(t) : null;
}

function placeOf(loc) {
  if (!loc) return null;
  const text = [loc.city, loc.stateOrProvinceCode, loc.countryCode].filter(Boolean).join(", ");
  return text || null;
}

function dateOfType(dateAndTimes, type) {
  const hit = (dateAndTimes || []).find((d) => d?.type === type);
  return toDate(hit?.dateTime);
}

/**
 * One trackResults[] entry → the fields we store:
 * { ok, error, status_code, status_text, estimated_delivery, delivered_at,
 *   last_event: { at, text, location } | null, events: [ { at, code, text, location } ] }
 */
function normaliseTrackResult(result) {
  if (!result) return { ok: false, error: "FedEx returned nothing for this number" };
  if (result.error) {
    return { ok: false, error: `${result.error.code || "ERROR"}: ${result.error.message || ""}`.trim() };
  }

  const latest = result.latestStatusDetail || {};
  const events = (Array.isArray(result.scanEvents) ? result.scanEvents : [])
    .map((e) => ({
      at: toDate(e.date),
      code: e.derivedStatusCode || e.eventType || null,
      text: e.eventDescription || e.derivedStatus || null,
      location: placeOf(e.scanLocation),
    }))
    .sort((a, b) => (b.at?.getTime() || 0) - (a.at?.getTime() || 0));

  const statusCode = latest.code || latest.derivedCode || null;
  const deliveredAt = dateOfType(result.dateAndTimes, "ACTUAL_DELIVERY") || (statusCode === "DL" ? events[0]?.at || null : null);
  const window = result.estimatedDeliveryTimeWindow?.window;
  const estimated =
    dateOfType(result.dateAndTimes, "ESTIMATED_DELIVERY") || toDate(window?.ends) || toDate(window?.begins) || null;

  return {
    ok: true,
    error: null,
    status_code: statusCode,
    status_text: latest.description || latest.statusByLocale || null,
    estimated_delivery: deliveredAt ? null : estimated,
    delivered_at: deliveredAt,
    last_event: events[0] ? { at: events[0].at, text: events[0].text, location: events[0].location } : latest.scanLocation ? { at: null, text: latest.description || null, location: placeOf(latest.scanLocation) } : null,
    events,
  };
}

/**
 * Track up to any number of FedEx tracking numbers (sent 30 per call).
 * Returns Map(trackingNumber → normaliseTrackResult()). A number FedEx does not
 * know comes back with ok:false and FedEx's message; a failed call throws.
 */
async function trackNumbers(numbers) {
  const unique = [...new Set((numbers || []).map((n) => String(n || "").trim()).filter(Boolean))];
  const out = new Map();
  if (!unique.length) return out;

  for (let i = 0; i < unique.length; i += BATCH_SIZE) {
    const batch = unique.slice(i, i + BATCH_SIZE);
    const body = {
      includeDetailedScans: true,
      trackingInfo: batch.map((trackingNumber) => ({ trackingNumberInfo: { trackingNumber } })),
    };

    let data;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const token = await getToken({ force: attempt > 0 });
      try {
        const res = await axios.post(`${FEDEX_API_BASE}/track/v1/trackingnumbers`, body, {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
            "X-locale": "en_US",
          },
          timeout: TIMEOUT_MS,
        });
        data = res.data;
        break;
      } catch (err) {
        // An expired / revoked token: fetch a fresh one once and retry.
        if (err?.response?.status === 401 && attempt === 0) continue;
        console.error("FEDEX_TRACK_ERROR:", { status: err?.response?.status, detail: describeFedexFailure(err) });
        throw fedexError(502, `FedEx tracking failed (${describeFedexFailure(err)})`, "FEDEX_TRACK_FAILED");
      }
    }

    const complete = Array.isArray(data?.output?.completeTrackResults) ? data.output.completeTrackResults : [];
    for (const c of complete) {
      const number = String(c?.trackingNumber || "").trim();
      const results = Array.isArray(c?.trackResults) ? c.trackResults : [];
      // A number can match several shipments; FedEx lists the latest first.
      if (number) out.set(number, normaliseTrackResult(results[0]));
    }
    for (const n of batch) {
      if (!out.has(n)) out.set(n, { ok: false, error: "FedEx returned nothing for this number" });
    }
  }
  return out;
}

/** Public FedEx tracking page for a number. */
function fedexTrackingUrl(trackingNumber) {
  return `https://www.fedex.com/fedextrack/?trknbr=${encodeURIComponent(String(trackingNumber || ""))}`;
}

module.exports = {
  FEDEX_API_BASE,
  fedexConfigured,
  getToken,
  trackNumbers,
  fedexTrackingUrl,
  _test: { normaliseTrackResult },
};
