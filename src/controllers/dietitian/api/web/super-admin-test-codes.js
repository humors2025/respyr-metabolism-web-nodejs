"use strict";

/**
 * POST /dietitian/api/web/super-admin-test-codes   (super_admin only)
 *
 * Free app-onboarding codes for testing. Each code is a
 * trainer_client_plan_subscriptions row plus a referral_subscriptions row, in
 * the exact shape a paid website purchase produces (see
 * services/purchaseCodes.js), so the app's existing redemption and its
 * subscription checks accept it unchanged. There is no Stripe checkout behind
 * it: the referral_subscriptions row is a $49, one-month 'active' plan whose
 * stripe_subscription_id starts with TEST_SUB_PREFIX, and it carries no
 * partner code, facility or QR, so commissions, payouts and trainer/facility
 * counts never see it; sales analytics and the breath-credit job skip the
 * prefix explicitly. The app enforces one redemption per code, so
 * "onboard n users" means generating n codes.
 *
 * Rows are tagged created_by_user_id = 'superadmin:test', which is also how
 * the list view finds them, and they are issued under one real trainer
 * account (SUPER_ADMIN_TEST_CODE_TRAINER_EMAIL, default connect@respyr.in) so
 * the members they onboard land in that trainer's client list.
 *
 * Body: { action: "generate", count? (1–20, default 1) }
 *       { action: "list", page?, limit? }
 */

const pool = require("../../../../config/db");
const csi = require("./client-subscription-action-common");
const { _helpers: H } = require("./admin-invite-trainer");

const CREATED_BY = "superadmin:test";
const MAX_PER_CALL = 20;
const MAX_LIMIT = 100;
const EXPIRY_DAYS = Math.max(1, parseInt(process.env.SUPER_ADMIN_TEST_CODE_EXPIRY_DAYS, 10) || 30);
// The trainer every test code is issued under. It has to be an account that
// exists in table_dietician: the app resolves a redeem code together with its
// trainer, so a code pointing at a trainer it cannot find never redeems.
const TRAINER_EMAIL = csi.email(process.env.SUPER_ADMIN_TEST_CODE_TRAINER_EMAIL || "connect@respyr.in");
// Same plan shape as a paid purchase so the app treats the code identically;
// only the price label says it was minted for testing.
const TEST_PLAN = { plan_code: "rysflo_monthly", plan_name: "Rysflo Membership", plan_price_label: "Test" };
// The referral_subscriptions side: what a real $49 monthly purchase stores.
const TEST_SUB_PREFIX = "test_";
const TEST_PRICE = { currency: "usd", unit_amount_minor: 4900, price_id: "test_price" };

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

/**
 * The trainer the codes hang off, as the trainer-invite flow writes the pair
 * (send_trainer_client_invite.js): trainer_id = table_dietician.dietician_id,
 * trainer_code = their partner code, or the dietician_id when they have none.
 * Returns null when the account is missing or deactivated.
 */
async function resolveTestTrainer() {
  // LEFT JOIN: a dietician row with no app_user_roles row is still a trainer
  // the app resolves, it just has no partner code of its own.
  const [rows] = await pool.execute(
    `SELECT td.dietician_id, td.name, td.email, aur.partner_code, aur.role, aur.status
     FROM table_dietician td
     LEFT JOIN app_user_roles aur ON LOWER(aur.user_id) = LOWER(td.email)
     WHERE LOWER(td.email) = ?
     LIMIT 1`,
    [TRAINER_EMAIL]
  );
  const row = rows[0];
  if (!row) return null;
  if (row.status && String(row.status) !== "active") return null;
  const trainerId = csi.clean(row.dietician_id);
  if (!trainerId) return null;
  return {
    email: csi.email(row.email) || TRAINER_EMAIL,
    name: csi.clean(row.name) || null,
    // effectiveCode(), not code(): keep the stored casing the app matches on.
    code: csi.clean(csi.effectiveCode(row)) || trainerId,
    trainer_id: trainerId,
  };
}

// What the UI shows above the table, resolved or not, so a misconfigured
// trainer is visible before anyone clicks Generate.
function trainerSummary(trainer) {
  return trainer
    ? { email: trainer.email, name: trainer.name, code: trainer.code, found: true }
    : { email: TRAINER_EMAIL, name: null, code: null, found: false };
}

/**
 * The referral_subscriptions row for one test code. profile_id stays NULL;
 * purchaseCodes.linkProfiles() fills it from purchase_code_row_id once the
 * app redeems the code, exactly as for a paid purchase.
 */
async function insertTestSubscription(conn, code, rowId) {
  await conn.execute(
    `
      INSERT INTO referral_subscriptions
        (stripe_subscription_id, stripe_customer_id, purchaser_name, purchase_code, purchase_code_row_id,
         plan_code, price_id, currency, unit_amount_minor, status,
         current_period_start, current_period_end, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', UTC_TIMESTAMP(), UTC_TIMESTAMP() + INTERVAL 1 MONTH, UTC_TIMESTAMP())
    `,
    [`${TEST_SUB_PREFIX}${code}`, `${TEST_SUB_PREFIX}customer`, "Test member", code, rowId,
     TEST_PLAN.plan_code, TEST_PRICE.price_id, TEST_PRICE.currency, TEST_PRICE.unit_amount_minor]
  );
}

async function generate(body) {
  const count = Math.min(MAX_PER_CALL, Math.max(1, parseInt(body.count, 10) || 1));
  const trainer = await resolveTestTrainer();
  // Minting codes under a trainer the app cannot resolve only produces dead
  // codes, so refuse rather than leave rows behind that never redeem.
  if (!trainer) {
    throw httpError(
      409,
      `No active trainer account found for ${TRAINER_EMAIL}. Test codes are issued under that trainer, and a code whose trainer the app cannot resolve never redeems. Create or reactivate the account, or point SUPER_ADMIN_TEST_CODE_TRAINER_EMAIL at another one.`
    );
  }
  const expiresAt = csi.istMysqlDateTime(new Date(Date.now() + EXPIRY_DAYS * 86400000));

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const codes = [];
    for (let i = 0; i < count; i++) {
      const code = await csi.uniqueRedeemCode(conn);
      const [ins] = await conn.execute(
        `
          INSERT INTO trainer_client_plan_subscriptions
            (source_invite_id, trainer_id, trainer_code, client_name, client_mobile, client_email,
             plan_code, plan_name, plan_price_label, redeem_code, code_expires_at,
             status, subscription_status, payment_status, email_status, resend_email_id,
             accepted_profile_id, accepted_at, error_message, created_by_user_id, created_at, updated_at)
          VALUES (NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 'sent', 'active', 'paid', 'sent', NULL, NULL, NULL, NULL, ?, NOW(), NOW())
        `,
        [trainer.trainer_id, trainer.code, "Test member", "", TEST_PLAN.plan_code, TEST_PLAN.plan_name, TEST_PLAN.plan_price_label, code, expiresAt, CREATED_BY]
      );
      await insertTestSubscription(conn, code, ins.insertId);
      codes.push(code);
    }
    await conn.commit();
    return {
      codes,
      expires_at: toIso(new Date(Date.now() + EXPIRY_DAYS * 86400000)),
      trainer_code: trainer.code,
      trainer: trainerSummary(trainer),
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

  return {
    codes,
    trainer: trainerSummary(await resolveTestTrainer()),
    pagination: { page, limit, total: Number(total), total_pages: Math.max(1, Math.ceil(Number(total) / limit)) },
  };
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
        failureReason: `count=${payload.codes.length} trainer=${payload.trainer_code}`,
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
