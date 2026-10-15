"use strict";

/**
 * Mirror of Stripe data into the sales team's database (migrations run
 * against sales_crm):
 *   sales_crm.stripe_payments         (008)  one row per invoice, with the
 *                                     buyer's shipping address and phone (010)
 *   sales_crm.stripe_payout_accounts  (009)  one row per Connect payout account
 *
 * Three ways to reach it, chosen by configuration (the first one set wins):
 *
 *   Sales CRM API (production): SALES_CRM_API_URL + SALES_CRM_API_KEY. The
 *   production Lambda's network cannot reach the sales_crm database, but it
 *   can reach the internet, so the row is posted to the sales_crm Lambda
 *   (rysflo-field-console-api, /v1/internal/stripe/*), which writes it.
 *   SALES_CRM_API_KEY must match that Lambda's INGEST_API_KEY;
 *   SALES_CRM_API_TIMEOUT_MS (default 5000) caps each call. No database
 *   settings are needed in this mode.
 *
 *   Shared server (UAT): SALES_CRM_DB_NAME only. sales_crm sits on the same
 *   MySQL server as dietician_db, so the row is written with a cross-database
 *   statement through the main pool. No second connection, no second secret.
 *
 *   Separate server: SALES_CRM_DB_HOST as well. When sales_crm lives on a
 *   different MySQL server that this Lambda can reach, the mirror opens its
 *   own small pool to it:
 *     SALES_CRM_DB_HOST, SALES_CRM_DB_PORT (3306), SALES_CRM_DB_USER,
 *     SALES_CRM_DB_PASSWORD, SALES_CRM_DB_NAME (sales_crm)
 *     SALES_CRM_DB_SSL_MODE  pinned (default, verifies the RDS certificate
 *                            against src/config/rds-global-bundle.pem or
 *                            SALES_CRM_DB_CA_PATH) | encrypted | disabled
 *   The Lambda's VPC must be able to reach the RDS; the connect timeout is
 *   short so an unreachable host cannot stall the webhook.
 *
 * All these keys may live in the Lambda's Secrets Manager secret
 * (secretsManager.js copies them into process.env) or as plain env vars.
 * None set → mirroring is off. The mode is logged once per cold start
 * ("sales_crm mirror: { mode }"). Best-effort by design: any failure here
 * (API down or refusing the key, table missing, no GRANT, host unreachable,
 * bad TLS) is logged as SALES_CRM_MIRROR_FAILED and never fails the webhook,
 * so the dietician_db row, the buyer's emails and the commission ledger are
 * unaffected. Callers:
 *   upsertPayment        paymentTransactions.syncInvoice, which runs for every
 *                        invoice event (paid, failed, refunded) and the
 *                        checkout backfill
 *   upsertPayoutAccount  stripeConnectAccounts.upsertFromAccount, which runs
 *                        whenever partner_payout_accounts is written
 */

const fs = require("fs");
const path = require("path");
const axios = require("axios");
const mysql = require("mysql2/promise");
const mainPool = require("../config/db");

const SALES_CRM_API_URL = String(process.env.SALES_CRM_API_URL || "").trim().replace(/\/+$/, "");
const SALES_CRM_API_KEY = String(process.env.SALES_CRM_API_KEY || "").trim();
const API_TIMEOUT_MS = Number(process.env.SALES_CRM_API_TIMEOUT_MS) > 0 ? Number(process.env.SALES_CRM_API_TIMEOUT_MS) : 5000;
// https only (plain http just for a local test server). A bad URL or a URL
// without its key turns the API off and says so at load (see the end of
// this file) rather than taking the whole Lambda down.
const API_URL_OK =
  /^https:\/\/[^/\s]+/.test(SALES_CRM_API_URL) || /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/.test(SALES_CRM_API_URL);
const API_ON = !!(SALES_CRM_API_URL && SALES_CRM_API_KEY && API_URL_OK);

const SALES_CRM_DB = String(process.env.SALES_CRM_DB_NAME || "").trim();
const SALES_CRM_HOST = String(process.env.SALES_CRM_DB_HOST || "").trim();
if (SALES_CRM_DB && !/^[A-Za-z0-9_]{1,64}$/.test(SALES_CRM_DB)) {
  throw new Error("SALES_CRM_DB_NAME must be a plain MySQL schema name (letters, digits, underscore)");
}
const TABLE = SALES_CRM_DB ? `\`${SALES_CRM_DB}\`.\`stripe_payments\`` : null;
const PAYOUT_TABLE = SALES_CRM_DB ? `\`${SALES_CRM_DB}\`.\`stripe_payout_accounts\`` : null;

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

// Added by migration 010. The address belongs to the subscription and is found
// only once Checkout has completed, so a later delivery without it keeps the
// one already stored.
const SHIPPING_COLUMNS = [
  "shipping_address",
  "shipping_name",
  "phone",
  "shipping_line1",
  "shipping_line2",
  "shipping_city",
  "shipping_state",
  "shipping_postal_code",
  "shipping_country",
];
for (const c of SHIPPING_COLUMNS) KEEP_IF_NULL.add(c);

function paymentUpsertSql(columns) {
  return `INSERT INTO ${TABLE} (${columns.map((c) => `\`${c}\``).join(", ")})
   VALUES (${columns.map(() => "?").join(", ")})
   ON DUPLICATE KEY UPDATE
     ${columns.filter((c) => c !== "stripe_invoice_id")
       .map((c) => (KEEP_IF_NULL.has(c) ? `\`${c}\` = COALESCE(VALUES(\`${c}\`), \`${c}\`)` : `\`${c}\` = VALUES(\`${c}\`)`))
       .join(",\n     ")}`;
}

const ALL_COLUMNS = [...COLUMNS, ...SHIPPING_COLUMNS];
const UPSERT_SQL = TABLE && paymentUpsertSql(ALL_COLUMNS);
// A sales_crm that has not had 010 yet still gets the payment, without the address.
const UPSERT_SQL_NO_SHIPPING = TABLE && paymentUpsertSql(COLUMNS);
let shippingColumnsMissing = false;

const PAYOUT_COLUMNS = [
  "stripe_account_id",
  "user_email",
  "user_name",
  "role",
  "partner_code",
  "facility_id",
  "facility_name",
  "livemode",
  "onboarding_status",
  "details_submitted",
  "payouts_enabled",
  "requirements_json",
  "setup_started_at",
  "last_synced_at",
];

// The payee's details come from a join that can miss (user row removed);
// keep what an earlier copy recorded rather than blanking it.
const PAYOUT_KEEP_IF_NULL = new Set([
  "user_name",
  "role",
  "partner_code",
  "facility_id",
  "facility_name",
  "setup_started_at",
]);

const PAYOUT_UPSERT_SQL =
  PAYOUT_TABLE &&
  `INSERT INTO ${PAYOUT_TABLE} (${PAYOUT_COLUMNS.map((c) => `\`${c}\``).join(", ")})
   VALUES (${PAYOUT_COLUMNS.map(() => "?").join(", ")})
   ON DUPLICATE KEY UPDATE
     ${PAYOUT_COLUMNS.filter((c) => c !== "stripe_account_id")
       .map((c) => (PAYOUT_KEEP_IF_NULL.has(c) ? `\`${c}\` = COALESCE(VALUES(\`${c}\`), \`${c}\`)` : `\`${c}\` = VALUES(\`${c}\`)`))
       .join(",\n     ")}`;

// Same column rules, for a row that must already exist (no insert).
const PAYOUT_UPDATE_SQL =
  PAYOUT_TABLE &&
  `UPDATE ${PAYOUT_TABLE} SET
     ${PAYOUT_COLUMNS.filter((c) => c !== "stripe_account_id")
       .map((c) => (PAYOUT_KEEP_IF_NULL.has(c) ? `\`${c}\` = COALESCE(?, \`${c}\`)` : `\`${c}\` = ?`))
       .join(",\n     ")}
   WHERE \`stripe_account_id\` = ?`;

// ── Dedicated pool for a sales_crm that the main database does not share ────

let ownPool = null;

/** TLS options for the RDS connection, same modes as the main pool. */
function sslOptions() {
  const mode = String(process.env.SALES_CRM_DB_SSL_MODE || "pinned").trim().toLowerCase();
  if (mode === "pinned") {
    const caFile = process.env.SALES_CRM_DB_CA_PATH || "rds-global-bundle.pem";
    const configDir = path.resolve(__dirname, "../config");
    const caPath = path.resolve(configDir, caFile);
    if (!caPath.startsWith(configDir + path.sep)) {
      throw new Error("SALES_CRM_DB_CA_PATH must be a file inside src/config");
    }
    if (!fs.existsSync(caPath)) {
      throw new Error(`sales_crm CA file not found: ${caFile}`);
    }
    // RDS certificates carry the endpoint hostname, so hostname verification
    // stays on; connect with the endpoint name, not an IP.
    return { rejectUnauthorized: true, ca: fs.readFileSync(caPath, "utf8") };
  }
  if (mode === "encrypted") return { rejectUnauthorized: false };
  if (mode === "disabled") return null;
  throw new Error(`Invalid SALES_CRM_DB_SSL_MODE "${mode}". Expected pinned, encrypted or disabled.`);
}

/** The pool to run the upsert on: the RDS pool when a host is configured, else the main one. */
function executor() {
  if (!SALES_CRM_HOST) return mainPool;
  if (!ownPool) {
    const ssl = sslOptions();
    ownPool = mysql.createPool({
      host: SALES_CRM_HOST,
      port: Number(process.env.SALES_CRM_DB_PORT || 3306),
      user: process.env.SALES_CRM_DB_USER,
      password: process.env.SALES_CRM_DB_PASSWORD,
      database: SALES_CRM_DB,
      waitForConnections: true,
      connectionLimit: 1,
      queueLimit: 0,
      maxIdle: 1,
      idleTimeout: 60000,
      // A host the Lambda cannot reach must fail fast: the webhook has to
      // answer Stripe well inside the API Gateway limit.
      connectTimeout: 5000,
      ...(ssl ? { ssl } : {}),
    });
    console.log("sales_crm mirror: dedicated connection", { host: SALES_CRM_HOST, database: SALES_CRM_DB });
  }
  return ownPool;
}

function isEnabled() {
  return API_ON || !!TABLE;
}

/**
 * "api" (post to the sales_crm Lambda), "shared" (cross-database through the
 * main pool), "dedicated" (own RDS pool) or "off".
 */
function mode() {
  if (API_ON) return "api";
  if (!TABLE) return "off";
  return SALES_CRM_HOST ? "dedicated" : "shared";
}

function isMissingColumn(err) {
  return err?.code === "ER_BAD_FIELD_ERROR" || err?.errno === 1054;
}

/**
 * Post one row to the sales_crm Lambda. The row's values go as JSON (dates as
 * ISO strings); that Lambda checks them and runs the same upsert as below.
 * Returns { ok, reason? } and never throws. `ref` only labels the log line.
 */
async function postToApi(route, body, ref) {
  try {
    const res = await axios.post(`${SALES_CRM_API_URL}${route}`, body, {
      headers: { "Content-Type": "application/json", "X-Sales-Crm-Key": SALES_CRM_API_KEY },
      timeout: API_TIMEOUT_MS,
      maxRedirects: 0,
      validateStatus: () => true,
    });
    if (res.status >= 200 && res.status < 300 && res.data?.ok === true) return { ok: true };
    const detail = res.data?.error || res.data?.code || "";
    const reason = `sales_crm api ${res.status}${detail ? `: ${detail}` : ""}`;
    console.warn("SALES_CRM_MIRROR_FAILED:", { ...ref, mode: "api", status: res.status, reason });
    return { ok: false, reason };
  } catch (err) {
    // A timeout or a network error; the key is in a header, never in the message.
    console.warn("SALES_CRM_MIRROR_FAILED:", { ...ref, mode: "api", code: err?.code, message: err?.message });
    return { ok: false, reason: err?.message || "mirror failed" };
  }
}

/**
 * Upsert one invoice row (keyed on stripe_invoice_id). `row` uses the column
 * names above (COLUMNS and SHIPPING_COLUMNS); missing keys are stored as NULL,
 * `livemode` as 0/1. Returns { ok, skipped?, reason? } and never throws.
 */
async function upsertPayment(row) {
  const valueOf = (c) => {
    if (c === "livemode") return row.livemode ? 1 : 0;
    return row[c] === undefined ? null : row[c];
  };
  if (API_ON) {
    const payment = Object.fromEntries(ALL_COLUMNS.map((c) => [c, valueOf(c)]));
    return postToApi("/v1/internal/stripe/payments", { payment }, { invoice: row?.stripe_invoice_id });
  }
  if (!TABLE) return { ok: false, skipped: true, reason: "SALES_CRM_DB_NAME not set" };
  const valuesFor = (columns) => columns.map(valueOf);
  try {
    if (!shippingColumnsMissing) {
      try {
        await executor().execute(UPSERT_SQL, valuesFor(ALL_COLUMNS));
        return { ok: true };
      } catch (err) {
        if (!isMissingColumn(err)) throw err;
        shippingColumnsMissing = true;
        console.warn("SALES_CRM_SHIPPING_COLUMNS_MISSING:", {
          mode: mode(),
          note: "payments copied without the address; run database/migrations/010 on sales_crm",
        });
      }
    }
    await executor().execute(UPSERT_SQL_NO_SHIPPING, valuesFor(COLUMNS));
    return { ok: true };
  } catch (err) {
    console.warn("SALES_CRM_MIRROR_FAILED:", {
      invoice: row?.stripe_invoice_id,
      mode: mode(),
      code: err?.code,
      message: err?.message,
    });
    return { ok: false, reason: err?.message || "mirror failed" };
  }
}

/**
 * Write one payout account row (keyed on stripe_account_id). `row` uses the
 * PAYOUT_COLUMNS names; `livemode`, `details_submitted` and `payouts_enabled`
 * are stored as 0/1, `requirements_json` as JSON text.
 * insertIfMissing = false only updates a row that is already there (an account
 * that has not been verified yet is not added).
 * Returns { ok, skipped?, reason? } and never throws.
 */
async function upsertPayoutAccount(row, { insertIfMissing = true } = {}) {
  const valueOf = (c) => {
    if (["livemode", "details_submitted", "payouts_enabled"].includes(c)) {
      return row[c] && Number(row[c]) !== 0 ? 1 : 0;
    }
    if (c === "requirements_json") {
      const v = row[c];
      if (v === undefined || v === null) return null;
      return typeof v === "string" ? v : JSON.stringify(v);
    }
    return row[c] === undefined ? null : row[c];
  };
  if (API_ON) {
    const account = Object.fromEntries(PAYOUT_COLUMNS.map((c) => [c, valueOf(c)]));
    return postToApi(
      "/v1/internal/stripe/payout-accounts",
      { account, insert_if_missing: insertIfMissing },
      { stripe_account: row?.stripe_account_id }
    );
  }
  if (!PAYOUT_TABLE) return { ok: false, skipped: true, reason: "SALES_CRM_DB_NAME not set" };
  try {
    const values = PAYOUT_COLUMNS.map(valueOf);
    if (insertIfMissing) {
      await executor().execute(PAYOUT_UPSERT_SQL, values);
    } else {
      // UPDATE takes the key last instead of first.
      await executor().execute(PAYOUT_UPDATE_SQL, [...values.slice(1), values[0]]);
    }
    return { ok: true };
  } catch (err) {
    console.warn("SALES_CRM_MIRROR_FAILED:", {
      stripe_account: row?.stripe_account_id,
      mode: mode(),
      code: err?.code,
      message: err?.message,
    });
    return { ok: false, reason: err?.message || "mirror failed" };
  }
}

// Once per cold start, so CloudWatch shows which way rows go (or that they
// go nowhere) without waiting for a payment.
if (SALES_CRM_API_URL && !API_URL_OK) {
  console.error("SALES_CRM_API_URL must be an https:// address; the sales_crm API is off");
} else if (SALES_CRM_API_URL && !SALES_CRM_API_KEY) {
  console.error("SALES_CRM_API_URL is set but SALES_CRM_API_KEY is empty; the sales_crm API is off");
}
console.log("sales_crm mirror:", { mode: mode(), ...(API_ON ? { url: SALES_CRM_API_URL } : {}) });

module.exports = { upsertPayment, upsertPayoutAccount, isEnabled, mode, COLUMNS, SHIPPING_COLUMNS, PAYOUT_COLUMNS };
