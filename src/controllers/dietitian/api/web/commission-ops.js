"use strict";

/**
 * Super-admin operations for the commission programme.
 *
 *  POST /dietitian/api/web/run-breath-credits   { dry_run?: true }
 *  POST /dietitian/api/web/run-payouts          { dry_run?: true, period_end?: "YYYY-MM-DD" }
 *  POST /dietitian/api/web/list-payouts         { page?, limit?, status? }
 *  POST /dietitian/api/web/commission-overview  {}   network-wide totals
 *
 * The two run-* endpoints are the same code the scheduler calls
 * (src/tools/run-commission-jobs.js); exposing them lets a super_admin re-run
 * a missed night or preview with dry_run. Every invocation is audited.
 */

const pool = require("../../../../config/db");
const { runBreathCredits } = require("../../../../services/breathCredits");
const { runPayouts } = require("../../../../services/payoutRuns");
const { _helpers: H } = require("./admin-invite-trainer");

const YMD = /^\d{4}-\d{2}-\d{2}$/;

async function superAdminOnly(req, res) {
  const resolved = await H.resolveActorFromToken(req, "super_admin");
  if (resolved.error) {
    res.status(resolved.error.status).json(resolved.error.body);
    return null;
  }
  return resolved;
}

const runBreathCreditsEndpoint = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
  try {
    const resolved = await superAdminOnly(req, res);
    if (!resolved) return;
    const dryRun = req.body?.dry_run === true;
    const summary = await runBreathCredits({ dryRun });
    await H.writeAuthLogSafe(req, {
      eventType: "breath_credits_run",
      userId: resolved.actorEmail, role: "super_admin", partnerCode: null, identifier: resolved.actorEmail,
      success: summary.errors === 0,
      failureReason: `${dryRun ? "dry-run " : ""}credited=${summary.credited} zero=${summary.zero} unlinked=${summary.unlinked} errors=${summary.errors}`,
    });
    return res.status(200).json({ ok: true, dry_run: dryRun, summary });
  } catch (err) {
    console.error("RUN_BREATH_CREDITS_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

const runPayoutsEndpoint = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
  try {
    const resolved = await superAdminOnly(req, res);
    if (!resolved) return;
    const dryRun = req.body?.dry_run === true;
    let periodEnd = null;
    if (req.body?.period_end != null && req.body.period_end !== "") {
      if (typeof req.body.period_end !== "string" || !YMD.test(req.body.period_end)) {
        return res.status(422).json({ ok: false, message: "period_end must be YYYY-MM-DD" });
      }
      periodEnd = `${req.body.period_end}T00:00:00Z`;
    }
    const summary = await runPayouts({ dryRun, periodEnd, initiatedBy: resolved.actorEmail });
    await H.writeAuthLogSafe(req, {
      eventType: "payout_run",
      userId: resolved.actorEmail, role: "super_admin", partnerCode: null, identifier: resolved.actorEmail,
      success: summary.errors === 0,
      failureReason: `${dryRun ? "dry-run " : ""}period_end=${summary.period_end} paid=${summary.paid} skipped=${summary.skipped_below_min} errors=${summary.errors}`,
    });
    return res.status(200).json({ ok: true, dry_run: dryRun, summary });
  } catch (err) {
    console.error("RUN_PAYOUTS_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

const listPayouts = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
  try {
    const resolved = await superAdminOnly(req, res);
    if (!resolved) return;

    const page = Math.max(1, parseInt(req.body?.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.body?.limit, 10) || 25));
    const status = typeof req.body?.status === "string" && ["scheduled", "processing", "paid", "failed", "reversed"].includes(req.body.status)
      ? req.body.status : null;

    const where = status ? "WHERE p.status = ?" : "";
    const params = status ? [status] : [];

    const [[{ total }]] = await pool.execute(`SELECT COUNT(*) AS total FROM payouts p ${where}`, params);
    const [rows] = await pool.query(
      `
        SELECT p.id, p.payee_user_id, aur.role AS payee_role, f.name AS facility_name,
               p.period_start, p.period_end, p.entry_count, p.amount_minor, p.currency,
               p.status, p.stripe_transfer_id, p.failure_reason, p.initiated_by, p.created_at, p.paid_at
        FROM payouts p
        LEFT JOIN app_user_roles aur ON LOWER(aur.user_id) = LOWER(p.payee_user_id)
        LEFT JOIN facilities f ON f.id = aur.facility_id
        ${where}
        ORDER BY p.created_at DESC, p.id DESC
        LIMIT ? OFFSET ?
      `,
      [...params, limit, (page - 1) * limit]
    );

    return res.status(200).json({ ok: true, page, limit, total: Number(total), items: rows });
  } catch (err) {
    console.error("LIST_PAYOUTS_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

const commissionOverview = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });
  try {
    const resolved = await superAdminOnly(req, res);
    if (!resolved) return;

    const [[totals]] = await pool.execute(
      `
        SELECT
          COALESCE(SUM(CASE WHEN status='pending'   THEN amount_minor END),0) AS pending_minor,
          COALESCE(SUM(CASE WHEN status='held'      THEN amount_minor END),0) AS held_minor,
          COALESCE(SUM(CASE WHEN status='scheduled' THEN amount_minor END),0) AS scheduled_minor,
          COALESCE(SUM(CASE WHEN status='paid'      THEN amount_minor END),0) AS paid_minor,
          COALESCE(SUM(CASE WHEN status='reversed'  THEN amount_minor END),0) AS reversed_minor,
          COALESCE(SUM(CASE WHEN status IN ('pending','held','scheduled','paid') THEN invoice_net_minor END),0) AS attributed_net_sales_minor,
          COUNT(DISTINCT stripe_subscription_id) AS subscriptions
        FROM commission_entries
      `
    );
    const [byFacility] = await pool.execute(
      `
        SELECT f.id AS facility_id, f.name, f.partner_code,
               COUNT(DISTINCT ce.stripe_subscription_id) AS subscriptions,
               COALESCE(SUM(CASE WHEN ce.status IN ('pending','held','scheduled') THEN ce.amount_minor END),0) AS owed_minor,
               COALESCE(SUM(CASE WHEN ce.status='paid' THEN ce.amount_minor END),0) AS paid_minor
        FROM facilities f
        LEFT JOIN commission_entries ce ON ce.facility_id = f.id
        WHERE f.status = 'active'
        GROUP BY f.id, f.name, f.partner_code
        ORDER BY owed_minor DESC, f.name
        LIMIT 100
      `
    );
    return res.status(200).json({
      ok: true,
      totals: Object.fromEntries(Object.entries(totals).map(([k, v]) => [k, Number(v)])),
      facilities: byFacility.map((r) => ({ ...r, subscriptions: Number(r.subscriptions), owed_minor: Number(r.owed_minor), paid_minor: Number(r.paid_minor) })),
    });
  } catch (err) {
    console.error("COMMISSION_OVERVIEW_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { runBreathCreditsEndpoint, runPayoutsEndpoint, listPayouts, commissionOverview };
