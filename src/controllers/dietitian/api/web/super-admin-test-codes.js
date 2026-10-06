"use strict";

/**
 * POST /dietitian/api/web/super-admin-test-codes   (super_admin only)
 *
 * Free app-onboarding codes for testing. Each code is a
 * trainer_client_plan_subscriptions row in the exact shape a paid website
 * purchase produces (see services/purchaseCodes.js), so the app's existing
 * redemption accepts it unchanged — but no Stripe checkout, subscription or
 * referral_subscriptions row exists, so nothing reaches sales analytics,
 * commissions or payouts. The app enforces one redemption per code, so
 * "onboard n users" means generating n codes.
 *
 * Rows are tagged created_by_user_id = 'superadmin:test', which is also how
 * the list view finds them.
 *
 * Body: { action: "generate", count? (1–20, default 1) }
 *       { action: "list", page?, limit? }
 */

const pool = require("../../../../config/db");
const { HOUSE_TRAINER_CODE } = require("../../../../utils/partnerCodeResolver");
const csi = require("./client-subscription-action-common");
const { _helpers: H } = require("./admin-invite-trainer");

const CREATED_BY = "superadmin:test";
const MAX_PER_CALL = 20;
const MAX_LIMIT = 100;
const EXPIRY_DAYS = Math.max(1, parseInt(process.env.SUPER_ADMIN_TEST_CODE_EXPIRY_DAYS, 10) || 30);
// Same plan shape as a paid purchase so the app treats the code identically;
// only the price label says it was minted for testing.
const TEST_PLAN = { plan_code: "rysflo_monthly", plan_name: "Rysflo Membership", plan_price_label: "Test" };

function httpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}

// mysql2 returns DATETIME as a Date built from the UTC wall clock on Lambda.
function toIso(v) {
  if (!v) return null;
  const ms = v instanceof Date ? v.getTime() : Date.parse(String(v).replace(" ", "T") + "Z");
  return Number.isNaN(ms) ? null : new Date(ms).toISOString().replace(".000Z", "Z");
}

async function generate(body) {
  const count = Math.min(MAX_PER_CALL, Math.max(1, parseInt(body.count, 10) || 1));
  // Same fallback chain as purchaseCodes.js: without HOUSE_TRAINER_CODE the
  // row points at a trainer the app does not know and the code will not redeem.
  const trainerCode = HOUSE_TRAINER_CODE || "RYSFLO";
  const expiresAt = csi.istMysqlDateTime(new Date(Date.now() + EXPIRY_DAYS * 86400000));

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const codes = [];
    for (let i = 0; i < count; i++) {
      const code = await csi.uniqueRedeemCode(conn);
      await conn.execute(
        `
          INSERT INTO trainer_client_plan_subscriptions
            (source_invite_id, trainer_id, trainer_code, client_name, client_mobile, client_email,
             plan_code, plan_name, plan_price_label, redeem_code, code_expires_at,
             status, subscription_status, payment_status, email_status, resend_email_id,
             accepted_profile_id, accepted_at, error_message, created_by_user_id, created_at, updated_at)
          VALUES (NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 'sent', 'active', 'paid', 'sent', NULL, NULL, NULL, NULL, ?, NOW(), NOW())
        `,
        [trainerCode, trainerCode, "Test member", "", TEST_PLAN.plan_code, TEST_PLAN.plan_name, TEST_PLAN.plan_price_label, code, expiresAt, CREATED_BY]
      );
      codes.push(code);
    }
    await conn.commit();
    return {
      codes,
      expires_at: toIso(new Date(Date.now() + EXPIRY_DAYS * 86400000)),
      trainer_code: trainerCode,
      ...(HOUSE_TRAINER_CODE
        ? {}
        : { warning: "HOUSE_TRAINER_CODE is not set on this environment — these codes will not redeem in the app until it is." }),
    };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

async function list(body) {
  const page = Math.max(1, parseInt(body.page, 10) || 1);
  const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(body.limit, 10) || 20));
  const offset = (page - 1) * limit;

  const [[{ total }]] = await pool.query(
    `SELECT COUNT(*) AS total FROM trainer_client_plan_subscriptions WHERE created_by_user_id = ?`,
    [CREATED_BY]
  );
  // LIMIT/OFFSET are inlined (validated integers): mysql2 placeholders inside
  // LIMIT are rejected by some server versions in execute().
  const [rows] = await pool.query(
    `SELECT id, redeem_code, trainer_code, code_expires_at, created_at,
            accepted_profile_id, redeemed_profile_id, accepted_at
     FROM trainer_client_plan_subscriptions
     WHERE created_by_user_id = ?
     ORDER BY id DESC
     LIMIT ${limit} OFFSET ${offset}`,
    [CREATED_BY]
  );

  const now = Date.now();
  const codes = rows.map((r) => {
    const profileId = r.redeemed_profile_id ?? r.accepted_profile_id ?? null;
    const expiresIso = toIso(r.code_expires_at);
    let state = "unused";
    if (profileId || r.accepted_at) state = "redeemed";
    else if (expiresIso && Date.parse(expiresIso) < now) state = "expired";
    return {
      id: r.id,
      code: r.redeem_code,
      trainer_code: r.trainer_code,
      created_at: toIso(r.created_at),
      expires_at: expiresIso,
      state,
      redeemed_profile_id: profileId ? String(profileId) : null,
      redeemed_at: toIso(r.accepted_at),
    };
  });

  return { codes, pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) } };
}

const superAdminTestCodes = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const action = String(body.action || "list");
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    let payload;
    if (action === "generate") payload = await generate(body);
    else if (action === "list") payload = await list(body);
    else throw httpError(422, "action must be generate or list");

    if (action === "generate") {
      // Free onboarding codes bypass payment: log who minted how many.
      await H.writeAuthLogSafe(req, {
        eventType: "test_codes_generated",
        userId: resolved.actorEmail,
        role: "super_admin",
        partnerCode: null,
        identifier: resolved.actorEmail,
        success: true,
        failureReason: `count=${payload.codes.length}`,
      });
    }

    return res.status(200).json({ status: true, ok: true, action, ...payload });
  } catch (err) {
    if (err?.status) return res.status(err.status).json({ status: false, ok: false, message: err.message });
    console.error("SUPER_ADMIN_TEST_CODES_ERROR:", { action, code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "test_codes_error",
        userId: resolved.actorEmail,
        role: "super_admin",
        partnerCode: null,
        identifier: resolved.actorEmail,
        success: false,
        failureReason: String(err?.code || "internal_error"),
      });
    }
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = { superAdminTestCodes };
