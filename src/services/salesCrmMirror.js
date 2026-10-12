"use strict";

/**
 * Mirror of Stripe payment rows into the sales team's database.
 *
 * `sales_crm` is served by its own Lambda but lives on the same MySQL server
 * as `dietician_db`, so the Stripe webhook writes to it with a cross-database
 * statement through its normal pool: no second connection, no second secret.
 * The target schema comes from SALES_CRM_DB_NAME; unset → mirroring is off,
 * which keeps production off until its table exists and the decision is made.
 * Table: database/migrations/008_sales_crm_stripe_payments.sql (run against
 * sales_crm). The backend's MySQL user needs SELECT, INSERT, UPDATE on it.
 *
 * Best-effort by design: a failure here (table missing, no GRANT, bad name)
 * is logged as SALES_CRM_MIRROR_FAILED and never fails the webhook, so the
 * dietician_db row, the buyer's emails and the commission ledger are
 * unaffected. The caller is paymentTransactions.syncInvoice, which runs for
 * every invoice event (paid, failed, refunded) and the checkout backfill, so
 * the mirror sees exactly what payment_transactions sees.
 */

const pool = require("../config/db");

const SALES_CRM_DB = String(process.env.SALES_CRM_DB_NAME || "").trim();
if (SALES_CRM_DB && !/^[A-Za-z0-9_]{1,64}$/.test(SALES_CRM_DB)) {
  throw new Error("SALES_CRM_DB_NAME must be a plain MySQL schema name (letters, digits, underscore)");
}
const TABLE = SALES_CRM_DB ? `\`${SALES_CRM_DB}\`.\`stripe_payments\`` : null;

const COLUMNS = [
  "stripe_invoice_id",
  "stripe_subscription_id",
  "stripe_customer_id",
  "stripe_payment_intent_id",
  "stripe_charge_id",
  "livemode",
  "purchaser_email",
  "purchaser_name",
  "partner_code",
  "billing_reason",
  "period_start",
  "period_end",
  "amount_paid_minor",
  "amount_refunded_minor",
  "currency",
  "fee_minor",
  "net_minor",
  "status",
  "failure_message",
  "payment_method_type",
  "card_last4",
  "paid_at",
];

// Values that can arrive on a later delivery (ids, fee/net, card, buyer) keep
// an earlier non-null value; everything else reflects Stripe's current state.
const KEEP_IF_NULL = new Set([
  "stripe_subscription_id",
  "stripe_customer_id",
  "stripe_payment_intent_id",
  "stripe_charge_id",
  "purchaser_email",
  "purchaser_name",
  "partner_code",
  "fee_minor",
  "net_minor",
  "payment_method_type",
  "card_last4",
  "paid_at",
]);

const UPSERT_SQL =
  TABLE &&
  `INSERT INTO ${TABLE} (${COLUMNS.map((c) => `\`${c}\``).join(", ")})
   VALUES (${COLUMNS.map(() => "?").join(", ")})
   ON DUPLICATE KEY UPDATE
     ${COLUMNS.filter((c) => c !== "stripe_invoice_id")
       .map((c) => (KEEP_IF_NULL.has(c) ? `\`${c}\` = COALESCE(VALUES(\`${c}\`), \`${c}\`)` : `\`${c}\` = VALUES(\`${c}\`)`))
       .join(",\n     ")}`;

function isEnabled() {
  return !!TABLE;
}

/**
 * Upsert one invoice row (keyed on stripe_invoice_id). `row` uses the column
 * names above; missing keys are stored as NULL, `livemode` as 0/1.
 * Returns { ok, skipped?, reason? } and never throws.
 */
async function upsertPayment(row) {
  if (!TABLE) return { ok: false, skipped: true, reason: "SALES_CRM_DB_NAME not set" };
  try {
    const values = COLUMNS.map((c) => {
      if (c === "livemode") return row.livemode ? 1 : 0;
      return row[c] === undefined ? null : row[c];
    });
    await pool.execute(UPSERT_SQL, values);
    return { ok: true };
  } catch (err) {
    console.warn("SALES_CRM_MIRROR_FAILED:", {
      invoice: row?.stripe_invoice_id,
      code: err?.code,
      message: err?.message,
    });
    return { ok: false, reason: err?.message || "mirror failed" };
  }
}

module.exports = { upsertPayment, isEnabled, COLUMNS };
