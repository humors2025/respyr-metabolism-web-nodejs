"use strict";

/**
 * App "Renew plan" button → rysflo.com/renewal
 *
 * POST /v1/renewal/link        (called by the mobile APP, with the app's login JWT)
 *   Header: Authorization: Bearer <app JWT>
 *   Body:   {}   (nothing about the user is accepted from the body)
 *   200 { ok: true, url, expires_at }                 → app opens url in the browser
 *   400 { ok: false, code: "PLAN_ACTIVE" }            → plan is still running
 *   401 { ok: false, code: "INVALID_TOKEN" }          → app refreshes its JWT / re-login
 *   404 { ok: false, code: "NO_SUBSCRIPTION" }        → no website subscription for this profile
 *   429 { ok: false, code: "TOO_MANY_LINKS" }
 *   503 { ok: false, code: "NOT_CONFIGURED" }         → APP_JWT_* env not set on this Lambda
 *
 * POST /v1/renewal/session     (called by the rysflo.com/renewal PAGE, no JWT)
 *   Body:   { t: "<renewal token from the URL>" }
 *   200 { ok: true, first_name, email_masked, plan: {...}, action: "renew" | "resume" }
 *   401 { ok: false, code: "LINK_EXPIRED" }           → expired, used or unknown token
 *   The token is sent in the body, not the query string, so it never lands
 *   in access logs.
 *
 * Who tapped: every link is a renewal_tokens row (profile_id + timestamps),
 * see database/migrations/014_renewal_tokens.sql.
 *
 * App JWT verification (env, set per Lambda):
 *   APP_JWT_SECRET         HS* shared secret of the APP backend (NOT the dashboard JWT_SECRET)
 *   APP_JWT_PUBLIC_KEY     or a PEM public key, for RS256 / ES256 tokens ("\n" escapes allowed)
 *   APP_JWT_ALGORITHMS     comma list, default "HS256"
 *   APP_JWT_PROFILE_FIELD  claim holding the profile id, default "profile_id"
 *   APP_JWT_ISSUER / APP_JWT_AUDIENCE   optional, checked when set
 *   RENEWAL_PAGE_URL       default https://rysflo.com/renewal/
 *   RENEWAL_LINK_TTL_MINUTES  default 30
 */

const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const pool = require("../../config/db");

const RENEWAL_PAGE_URL = process.env.RENEWAL_PAGE_URL || "https://rysflo.com/renewal/";
const TTL_MINUTES = Math.min(Math.max(parseInt(process.env.RENEWAL_LINK_TTL_MINUTES, 10) || 30, 5), 24 * 60);
const MAX_LINKS_PER_HOUR = 10;

// Subscription statuses where the member still has a running plan.
const LIVE_STATUSES = ["active", "trialing", "past_due"];

const TOKEN_RE = /^[A-Za-z0-9_-]{40,64}$/;

const sha256 = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");

function noStore(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}

function fail(res, status, code, message) {
  return res.status(status).json({ status: false, ok: false, code, message });
}

function bearer(req) {
  const h = String(req.headers.authorization || "");
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1].trim() : "";
}

function appJwtConfig() {
  const secret = process.env.APP_JWT_SECRET || "";
  const publicKey = (process.env.APP_JWT_PUBLIC_KEY || "").replace(/\\n/g, "\n");
  const key = publicKey || secret;
  if (!key) return null;
  const algorithms = String(process.env.APP_JWT_ALGORITHMS || (publicKey ? "RS256" : "HS256"))
    .split(",")
    .map((a) => a.trim())
    .filter(Boolean);
  const opts = { algorithms, clockTolerance: 5 };
  if (process.env.APP_JWT_ISSUER) opts.issuer = process.env.APP_JWT_ISSUER;
  if (process.env.APP_JWT_AUDIENCE) opts.audience = process.env.APP_JWT_AUDIENCE;
  return { key, opts, profileField: process.env.APP_JWT_PROFILE_FIELD || "profile_id" };
}

/** profile_id from a verified app JWT, or null. Supports nested claims like "user.profile_id". */
function profileIdFromAppJwt(token, cfg) {
  if (!token || token.length > 4096) return null;
  let decoded;
  try {
    decoded = jwt.verify(token, cfg.key, cfg.opts);
  } catch {
    return null;
  }
  const value = cfg.profileField.split(".").reduce((o, k) => (o == null ? o : o[k]), decoded);
  const id = value == null ? "" : String(value).trim();
  return id && id.length <= 64 ? id : null;
}

/** Latest website subscription for the profile, with whether it can be renewed. */
async function renewalState(profileId) {
  const [rows] = await pool.query(
    `SELECT stripe_subscription_id, stripe_customer_id, purchaser_name, purchaser_email,
            plan_code, price_id, currency, unit_amount_minor, status,
            current_period_end, canceled_at,
            (status IN (?) AND (current_period_end IS NULL OR current_period_end > UTC_TIMESTAMP())) AS running
       FROM referral_subscriptions
      WHERE profile_id = ?
      ORDER BY created_at DESC, id DESC
      LIMIT 1`,
    [LIVE_STATUSES, profileId]
  );
  const sub = rows[0];
  if (!sub) return { sub: null, action: null };

  // Compared in SQL (UTC) so the pool's time-zone handling can't skew it.
  const running = Number(sub.running) === 1;

  // Running with no cancellation → nothing to renew.
  if (running && !sub.canceled_at) return { sub, action: null };
  // Running but cancellation scheduled → undo the cancellation instead of a new purchase.
  if (running) return { sub, action: "resume" };
  // Cancelled / ended / unpaid → new checkout.
  return { sub, action: "renew" };
}

function maskEmail(email) {
  const e = String(email || "").trim();
  const at = e.indexOf("@");
  if (at < 1) return null;
  const user = e.slice(0, at);
  return `${user.slice(0, Math.min(2, user.length))}***${e.slice(at)}`;
}

/* ------------------------------------------------------------------ */
/* POST /renewal/link   (app)                                          */
/* ------------------------------------------------------------------ */
const createRenewalLink = async (req, res) => {
  noStore(res);
  try {
    const cfg = appJwtConfig();
    if (!cfg) {
      console.error("RENEWAL_LINK_NOT_CONFIGURED: set APP_JWT_SECRET or APP_JWT_PUBLIC_KEY");
      return fail(res, 503, "NOT_CONFIGURED", "Renewal is not available right now");
    }

    const profileId = profileIdFromAppJwt(bearer(req), cfg);
    if (!profileId) return fail(res, 401, "INVALID_TOKEN", "Invalid or expired token");

    const { sub, action } = await renewalState(profileId);
    if (!sub) return fail(res, 404, "NO_SUBSCRIPTION", "No subscription found to renew");
    if (!action) return fail(res, 400, "PLAN_ACTIVE", "Plan is still active");

    const [[{ recent }]] = await pool.query(
      `SELECT COUNT(*) AS recent FROM renewal_tokens
        WHERE profile_id = ? AND created_at > UTC_TIMESTAMP() - INTERVAL 1 HOUR`,
      [profileId]
    );
    if (Number(recent) >= MAX_LINKS_PER_HOUR) {
      return fail(res, 429, "TOO_MANY_LINKS", "Too many attempts. Please try again later.");
    }

    const token = crypto.randomBytes(32).toString("base64url"); // 43 chars
    const expiresAt = new Date(Date.now() + TTL_MINUTES * 60 * 1000);
    await pool.query(
      `INSERT INTO renewal_tokens (token_hash, profile_id, stripe_subscription_id, expires_at, created_at)
       VALUES (?, ?, ?, UTC_TIMESTAMP() + INTERVAL ? MINUTE, UTC_TIMESTAMP())`,
      [sha256(token), profileId, sub.stripe_subscription_id, TTL_MINUTES]
    );

    const url = new URL(RENEWAL_PAGE_URL);
    url.searchParams.set("t", token);
    return res.status(200).json({
      status: true,
      ok: true,
      url: url.toString(),
      expires_at: expiresAt.toISOString(),
    });
  } catch (err) {
    console.error("RENEWAL_LINK_ERROR:", err.message);
    return fail(res, 500, "SERVER_ERROR", "Could not start renewal");
  }
};

/* ------------------------------------------------------------------ */
/* POST /renewal/session   (rysflo.com/renewal page)                   */
/* ------------------------------------------------------------------ */

/** Unexpired, unused token row, or null. */
async function findValidToken(token) {
  const t = String(token || "").trim();
  if (!TOKEN_RE.test(t)) return null;
  const [rows] = await pool.query(
    `SELECT id, profile_id, stripe_subscription_id
       FROM renewal_tokens
      WHERE token_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP()
      LIMIT 1`,
    [sha256(t)]
  );
  return rows[0] || null;
}

const getRenewalSession = async (req, res) => {
  noStore(res);
  try {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    const row = await findValidToken(body.t);
    if (!row) return fail(res, 401, "LINK_EXPIRED", "This link has expired. Please tap Renew again in the app.");

    await pool.query(
      `UPDATE renewal_tokens
          SET opened_at = COALESCE(opened_at, UTC_TIMESTAMP()),
              open_count = open_count + 1,
              user_agent = COALESCE(user_agent, ?)
        WHERE id = ?`,
      [String(req.headers["user-agent"] || "").slice(0, 255) || null, row.id]
    );

    const { sub, action } = await renewalState(row.profile_id);
    if (!sub || !action) {
      return fail(res, 400, "PLAN_ACTIVE", "Your plan is already active.");
    }

    const firstName = String(sub.purchaser_name || "").trim().split(/\s+/)[0] || null;
    return res.status(200).json({
      status: true,
      ok: true,
      action, // "renew" → new checkout, "resume" → undo the scheduled cancellation
      first_name: firstName,
      email_masked: maskEmail(sub.purchaser_email),
      plan: {
        plan_code: sub.plan_code,
        currency: sub.currency,
        amount: sub.unit_amount_minor != null ? Number(sub.unit_amount_minor) / 100 : null,
        status: sub.status,
        current_period_end: sub.current_period_end ? new Date(sub.current_period_end).toISOString() : null,
      },
    });
  } catch (err) {
    console.error("RENEWAL_SESSION_ERROR:", err.message);
    return fail(res, 500, "SERVER_ERROR", "Could not load renewal details");
  }
};

module.exports = {
  createRenewalLink,
  getRenewalSession,
  _helpers: { findValidToken, renewalState, maskEmail, profileIdFromAppJwt, appJwtConfig, sha256 },
};
