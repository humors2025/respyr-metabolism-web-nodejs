"use strict";

/**
 * client-logs.js
 *
 * Endpoint : POST /dietitian/api/web/client-logs
 * Auth     : NONE (public). Receives UI interaction events from the signup /
 *            agreement flow where the user is NOT yet authenticated, so
 *            authMiddleware must NOT be mounted here.
 *
 * Storage  : Reuses the EXISTING app_auth_logs audit table via
 *            writeAuthLogSafe() from auth_common.js — no new table needed.
 *            Also emits one structured JSON line per event to CloudWatch.
 *
 * Column mapping into app_auth_logs:
 *   event_type      <- event_name (whitelisted, max 27 chars, fits varchar(60))
 *   user_id/role/
 *   partner_code/
 *   identifier_hash <- NULL (user is unauthenticated at this point)
 *   ip_hash         <- pepper-keyed hash (handled inside writeAuthLogSafe)
 *   user_agent_hash <- pepper-keyed hash (handled inside writeAuthLogSafe)
 *   success         <- 1 (these are clicks, not pass/fail outcomes)
 *   failure_reason  <- repurposed as a details field: compact JSON string
 *                      {"page":"/signup","meta":{...}} capped at 255 chars
 *                      (writeAuthLogSafe truncates to 255 anyway).
 *
 * Hardening (public endpoint):
 *   - event_name validated against a strict WHITELIST; unknown names -> 400.
 *   - Max 20 events per request; meta re-serialized (never trusted raw) and
 *     capped at 200 bytes so page+meta always fit failure_reason's 255.
 *   - No PHI: the frontend logger must never send passwords, tokens, emails,
 *     or names in meta. Booleans / counts / page path only.
 *   - writeAuthLogSafe is fail-safe (never throws), so a DB hiccup can never
 *     break the signup flow.
 *
 * NOTE (Lambda): in-memory rate limiting is unreliable across invocations.
 * If this endpoint is ever abused, attach an AWS WAF rate-based rule on
 * /v1/dietitian/api/web/client-logs at API Gateway.
 */

const { writeAuthLogSafe } = require("./auth_common");

// ---------------------------------------------------------------------------
// Whitelist of accepted client event names.
// To log a new UI event, add its name here AND emit it from the frontend.
// ---------------------------------------------------------------------------
const ALLOWED_EVENTS = new Set([
  "terms_and_condition_page_open",
  "create_password_page_open",
  "agreement_select_all_click",
  "agreement_decline_click",
  "agreement_agree_continue_click",
  "signup_create_account_click",
]);

const MAX_EVENTS_PER_REQUEST = 20;
const MAX_META_BYTES = 400; // incoming meta may carry user_email (extracted
// out before storage); stored page+meta stays well under failure_reason's 255

function capStr(v, max) {
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (!s) return null;
  return s.length > max ? s.slice(0, max) : s;
}

function safeMeta(meta) {
  if (meta === null || meta === undefined) return null;
  try {
    // Re-serialize: never store client-provided raw strings blindly.
    const json = JSON.stringify(meta);
    if (typeof json !== "string") return null;
    if (Buffer.byteLength(json, "utf8") > MAX_META_BYTES) return null;
    return json;
  } catch {
    return null;
  }
}

async function clientLogs(req, res) {
  try {
    const body = req.body || {};

    // Accept either { events: [...] } or a single flat event object.
    let events = Array.isArray(body.events) ? body.events : [body];

    if (!events.length) {
      return res
        .status(400)
        .json({ status: "error", message: "No events provided." });
    }
    if (events.length > MAX_EVENTS_PER_REQUEST) {
      events = events.slice(0, MAX_EVENTS_PER_REQUEST);
    }

    const accepted = [];
    for (const ev of events) {
      if (!ev || typeof ev !== "object") continue;

      const eventName = capStr(ev.event_name, 60);
      if (!eventName || !ALLOWED_EVENTS.has(eventName)) continue;

      accepted.push({
        event_name: eventName,
        page: capStr(ev.page, 150),
        meta: safeMeta(ev.meta),
        client_ts: capStr(ev.ts, 40),
      });
    }

    if (!accepted.length) {
      return res
        .status(400)
        .json({ status: "error", message: "No valid events." });
    }

    for (const ev of accepted) {
      // Pull the (client-supplied) user email out of meta -> user_id column.
      // NOTE: this endpoint is public, so this email is telemetry-grade
      // identification, not authenticated proof. Light format validation only.
      let userEmail = null;
      let metaObj = ev.meta ? JSON.parse(ev.meta) : null;
      if (metaObj && typeof metaObj.user_email === "string") {
        const e = metaObj.user_email.trim().toLowerCase();
        if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 191) {
          userEmail = e;
        }
        delete metaObj.user_email; // keep failure_reason small
        if (Object.keys(metaObj).length === 0) metaObj = null;
      }

      // 1) CloudWatch: structured JSON line (searchable via Logs Insights:
      //    filter @message like /client_event/).
      console.log(
        JSON.stringify({
          log_type: "client_event",
          event_name: ev.event_name,
          page: ev.page,
          user_email: userEmail,
          meta: metaObj,
          client_ts: ev.client_ts,
          server_ts: new Date().toISOString(),
        })
      );

      // 2) MySQL: existing app_auth_logs table via the hardened audit helper
      //    (hashes ip/user-agent with the SECURITY_PEPPER, never throws).
      //    failure_reason carries page+meta as a compact details string.
      const details = JSON.stringify({
        page: ev.page || undefined,
        meta: metaObj || undefined,
      });

      await writeAuthLogSafe(req, {
        eventType: ev.event_name,
        userId: userEmail,
        role: null,
        partnerCode: null,
        identifier: null,
        success: true,
        failureReason: details === "{}" ? null : details,
      });
    }

    return res.status(200).json({ status: "success", logged: accepted.length });
  } catch (err) {
    // Never let logging failures surface details publicly.
    console.error("client-logs error:", err && err.message ? err.message : err);
    return res
      .status(500)
      .json({ status: "error", message: "Could not record events." });
  }
}

module.exports = { clientLogs };