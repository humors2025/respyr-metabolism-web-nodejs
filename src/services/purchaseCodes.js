"use strict";

/**
 * Purchase codes: link a website purchase to the member's app account.
 *
 * After a website Checkout completes we create a row in
 * trainer_client_plan_subscriptions with a redeem code in the exact shape the
 * mobile app already redeems for trainer invites (RSP + 7 chars). The member
 * enters it once in the app; the app's existing redemption (PHP) stamps
 * accepted_profile_id / redeemed_profile_id on that row, and our link job
 * copies the profile onto referral_subscriptions. No app change needed.
 *
 * Attribution rule (c): redemption only fills an empty app link; it never
 * overwrites a member who already chose a trainer in the app — that is left
 * to the app's own logic, which we do not touch.
 */

const axios = require("axios");
const pool = require("../config/db");
const csi = require("../controllers/dietitian/api/web/client-subscription-action-common");
const { escapeHtml } = require("../utils/securityValidation");

const RESEND_API_KEY = process.env.RESEND_API_KEY || "";
const RESEND_FROM_EMAIL = process.env.RESEND_FROM_EMAIL || "Rysflo <no-reply@rysflo.com>";
const SKIP_OUTBOUND_EMAIL =
  process.env.NODE_ENV !== "production" && String(process.env.SKIP_OUTBOUND_EMAIL || "").toLowerCase() === "true";
const CODE_EXPIRY_DAYS = Math.max(1, parseInt(process.env.PURCHASE_CODE_EXPIRY_DAYS, 10) || 30);
const APP_STORE_URL = process.env.APP_STORE_URL || "https://apps.apple.com/app/rysflo";
const PLAY_STORE_URL = process.env.PLAY_STORE_URL || "https://play.google.com/store/apps/details?id=com.rysflo";

const PAID_PLAN = { plan_code: "rysflo_monthly", plan_name: "Rysflo Membership", plan_price_label: "Paid" };

/**
 * Create (once) the purchase code for a referral subscription. Idempotent on
 * stripe_subscription_id. Returns { code, row_id, created }.
 */
async function ensurePurchaseCode({ stripeSubscriptionId }) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [subs] = await conn.execute(
      `SELECT id, purchaser_email, attributed_partner_code, attributed_user_id, purchase_code, purchase_code_row_id
       FROM referral_subscriptions WHERE stripe_subscription_id = ? LIMIT 1 FOR UPDATE`,
      [stripeSubscriptionId]
    );
    const sub = subs[0];
    if (!sub) {
      await conn.rollback();
      return null;
    }
    if (sub.purchase_code) {
      await conn.commit();
      return { code: sub.purchase_code, row_id: Number(sub.purchase_code_row_id), created: false };
    }

    const code = await csi.uniqueRedeemCode(conn);
    const expiresAt = csi.istMysqlDateTime(new Date(Date.now() + CODE_EXPIRY_DAYS * 86400000));
    // trainer_id/trainer_code drive who becomes trainer-of-record when the app
    // redeems. With no referral there is nobody to link to, so use the
    // platform sentinel the app treats as "no trainer".
    const trainerCode = sub.attributed_partner_code || "RYSFLO";
    const email = sub.purchaser_email || "";

    const [ins] = await conn.execute(
      `
        INSERT INTO trainer_client_plan_subscriptions
          (source_invite_id, trainer_id, trainer_code, client_name, client_mobile, client_email,
           plan_code, plan_name, plan_price_label, redeem_code, code_expires_at,
           status, subscription_status, payment_status, email_status, resend_email_id,
           accepted_profile_id, accepted_at, error_message, created_by_user_id, created_at, updated_at)
        VALUES (NULL, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 'sent', 'active', 'paid', 'sent', NULL, NULL, NULL, NULL, ?, NOW(), NOW())
      `,
      [trainerCode, trainerCode, email.split("@")[0] || "Member", email, PAID_PLAN.plan_code, PAID_PLAN.plan_name, PAID_PLAN.plan_price_label, code, expiresAt, "stripe:checkout"]
    );

    await conn.execute(
      `UPDATE referral_subscriptions SET purchase_code = ?, purchase_code_row_id = ? WHERE id = ?`,
      [code, ins.insertId, sub.id]
    );
    await conn.commit();
    return { code, row_id: Number(ins.insertId), created: true };
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

/** Plain HTML email with the purchase code. Returns { ok, skipped? }. */
async function sendPurchaseCodeEmail({ stripeSubscriptionId, force = false }) {
  const [subs] = await pool.execute(
    `SELECT purchaser_email, purchase_code, purchase_code_email_sent_at, attributed_partner_code
     FROM referral_subscriptions WHERE stripe_subscription_id = ? LIMIT 1`,
    [stripeSubscriptionId]
  );
  const sub = subs[0];
  if (!sub || !sub.purchase_code || !sub.purchaser_email) return { ok: false, reason: "nothing to send" };
  if (sub.purchase_code_email_sent_at && !force) return { ok: true, skipped: true };

  const code = escapeHtml(sub.purchase_code);
  const html = `
    <div style="font-family:Poppins,Arial,sans-serif;max-width:560px;margin:0 auto;color:#252525">
      <h2 style="margin:0 0 8px">You're in. Here's your Rysflo code.</h2>
      <p style="color:#535359">Your membership is active and your device is on its way. One last step links your purchase to the app:</p>
      <ol style="color:#535359;line-height:1.6">
        <li>Download Rysflo — <a href="${APP_STORE_URL}">iPhone</a> · <a href="${PLAY_STORE_URL}">Android</a></li>
        <li>Create your account with <strong>this email address</strong></li>
        <li>When asked for a code, enter:</li>
      </ol>
      <div style="font-size:32px;font-weight:700;letter-spacing:3px;background:#EEF4FE;color:#1F4E8C;padding:16px;text-align:center;border-radius:10px;font-family:monospace">${code}</div>
      <p style="color:#535359;margin-top:16px">Every day you take a reading, 20¢ comes off next month's bill — up to $6.</p>
      <p style="color:#A1A1A1;font-size:12px">This code expires in ${CODE_EXPIRY_DAYS} days. If you've already used your gym's code in the app, that's fine — this one just links the purchase.</p>
    </div>`;

  if (SKIP_OUTBOUND_EMAIL) {
    await pool.execute(`UPDATE referral_subscriptions SET purchase_code_email_sent_at = UTC_TIMESTAMP() WHERE stripe_subscription_id = ?`, [stripeSubscriptionId]);
    return { ok: true, skipped: true, dev: true };
  }
  if (!RESEND_API_KEY) return { ok: false, reason: "RESEND_API_KEY not configured" };

  const res = await axios.post(
    "https://api.resend.com/emails",
    { from: RESEND_FROM_EMAIL, to: [sub.purchaser_email], subject: `Your Rysflo code: ${sub.purchase_code}`, html },
    { headers: { Authorization: `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" }, timeout: 15000, validateStatus: () => true }
  );
  if (res.status >= 200 && res.status < 300) {
    await pool.execute(`UPDATE referral_subscriptions SET purchase_code_email_sent_at = UTC_TIMESTAMP() WHERE stripe_subscription_id = ?`, [stripeSubscriptionId]);
    return { ok: true };
  }
  return { ok: false, reason: `resend ${res.status}` };
}

/**
 * Link job: copy the app profile onto referral_subscriptions once the app has
 * redeemed the purchase code (rows the PHP redemption stamped), then fall back
 * to a unique email match. Returns counts.
 */
async function linkProfiles() {
  const [byCode] = await pool.execute(
    `
      UPDATE referral_subscriptions rs
      JOIN trainer_client_plan_subscriptions t ON t.id = rs.purchase_code_row_id
      SET rs.profile_id = COALESCE(t.redeemed_profile_id, t.accepted_profile_id),
          rs.linked_via = 'purchase_code', rs.linked_at = UTC_TIMESTAMP()
      WHERE rs.profile_id IS NULL
        AND COALESCE(t.redeemed_profile_id, t.accepted_profile_id) IS NOT NULL
    `
  );
  // Email fallback only when exactly one profile has that email.
  const [byEmail] = await pool.execute(
    `
      UPDATE referral_subscriptions rs
      JOIN (
        SELECT LOWER(email) AS email, MIN(profile_id) AS profile_id, COUNT(*) AS n
        FROM table_clients GROUP BY LOWER(email) HAVING n = 1
      ) tc ON tc.email = LOWER(rs.purchaser_email)
      SET rs.profile_id = tc.profile_id, rs.linked_via = 'email', rs.linked_at = UTC_TIMESTAMP()
      WHERE rs.profile_id IS NULL AND rs.purchaser_email IS NOT NULL
    `
  );
  return { by_purchase_code: byCode.affectedRows, by_email: byEmail.affectedRows };
}

module.exports = { ensurePurchaseCode, sendPurchaseCodeEmail, linkProfiles };
