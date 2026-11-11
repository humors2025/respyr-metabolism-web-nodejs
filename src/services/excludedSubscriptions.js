// Subscriptions that are not real customers and must stay out of reporting
// (Sales Analytics). Two kinds:
//
//   1. Free test codes: stripe_subscription_id starts with "test_".
//   2. The internal test purchases made on 20–21 Sep 2026 on the OLD Stripe
//      account (before the switch to the current account on 29 Sep). That
//      account no longer sends webhooks, so these rows stay "active" forever
//      with a period that ended on 20–21 Oct and no payment rows.
//   3. Internal $1 test subscription on the current account (staff account,
//      29 Sep 2026, renewed at $1).
//
// The IDs only exist in the production database; elsewhere they match nothing.
// Rows are left untouched in referral_subscriptions — they are only skipped here.

const EXCLUDED_SUBSCRIPTION_IDS = Object.freeze([
  "sub_1UHibWHQhLpPZZsE571XBugW", // 2026-09-20
  "sub_1UHkwqHQhLpPZZsEYB786cZt", // 2026-09-20
  "sub_1UHl86HQhLpPZZsECLV0sUWv", // 2026-09-20
  "sub_1UHlC9HQhLpPZZsEnZ1O83Fr", // 2026-09-20
  "sub_1UHlPJHQhLpPZZsEO2F7zuPe", // 2026-09-20
  "sub_1UHlV0HQhLpPZZsET9L7bAYa", // 2026-09-20
  "sub_1UHldOHQhLpPZZsEP2OOmQPQ", // 2026-09-20
  "sub_1UHm5iHQhLpPZZsEJ4Gvqi0e", // 2026-09-20
  "sub_1UHmIUHQhLpPZZsE27HzjEEc", // 2026-09-20
  "sub_1UHmVfHQhLpPZZsEUzAq1MP5", // 2026-09-20
  "sub_1UHn6ZHQhLpPZZsExyWC0RJB", // 2026-09-20
  "sub_1UHpAEHQhLpPZZsEZA4Wbp8l", // 2026-09-20
  "sub_1UI0gYHQhLpPZZsEHWuIy2GX", // 2026-09-21
  "sub_1UI2kIHQhLpPZZsE9zJaJlLa", // 2026-09-21
  "sub_1UI3BnHQhLpPZZsEyeUUwoLR", // 2026-09-21
  "sub_1UI3GNHQhLpPZZsE7HsCWzDt", // 2026-09-21
  "sub_1UI3iyHQhLpPZZsEgS6P87sj", // 2026-09-21
  "sub_1UI3lfHQhLpPZZsECuxZrkNx", // 2026-09-21
  "sub_1UI3qKHQhLpPZZsEac6MCGz2", // 2026-09-21
  "sub_1UI59PHQhLpPZZsE6hM8uogz", // 2026-09-21
  "sub_1UI5IwHQhLpPZZsEze0xzhm2", // 2026-09-21
  "sub_1UI5QzHQhLpPZZsENuwUIzS8", // 2026-09-21
  "sub_1UI5TjHQhLpPZZsEQRlBu3hz", // 2026-09-21
  "sub_1UL11dHp3z0wKGvIMkxfY9If", // 2026-09-29, $1 internal test (current account)
]);

const SAFE_ID = /^sub_[A-Za-z0-9]+$/;
const SAFE_COLUMN = /^([a-z_][a-z0-9_]*\.)?stripe_subscription_id$/i;
for (const id of EXCLUDED_SUBSCRIPTION_IDS) {
  if (!SAFE_ID.test(id)) throw new Error(`excludedSubscriptions: bad id ${id}`);
}
const ID_LIST = EXCLUDED_SUBSCRIPTION_IDS.map((id) => `'${id}'`).join(", ");

/**
 * SQL condition that keeps only real customer subscriptions.
 * @param {string} column  e.g. "rs.stripe_subscription_id" (no user input).
 */
function realSubscriptionSql(column = "stripe_subscription_id") {
  if (!SAFE_COLUMN.test(column)) throw new Error(`excludedSubscriptions: bad column ${column}`);
  const parts = [`LEFT(${column}, 5) <> 'test_'`];
  if (ID_LIST) parts.push(`${column} NOT IN (${ID_LIST})`);
  return `(${parts.join(" AND ")})`;
}

// Internal test subscriptions that also stay off the Orders page (real Stripe
// money, but staff testing). The 23 old-account rows have no payments, so the
// Orders page keeps showing them as they are.
const ORDERS_HIDDEN_IDS = Object.freeze(["sub_1UL11dHp3z0wKGvIMkxfY9If"]);
for (const id of ORDERS_HIDDEN_IDS) {
  if (!SAFE_ID.test(id)) throw new Error(`excludedSubscriptions: bad id ${id}`);
}

/**
 * SQL condition for the Orders page: drops ORDERS_HIDDEN_IDS. NULL-safe, so
 * rows without a subscription id stay.
 * @param {string} column  e.g. "pt.stripe_subscription_id" (no user input).
 */
function notHiddenOnOrdersSql(column = "stripe_subscription_id") {
  if (!SAFE_COLUMN.test(column)) throw new Error(`excludedSubscriptions: bad column ${column}`);
  return `COALESCE(${column}, '') NOT IN (${ORDERS_HIDDEN_IDS.map((id) => `'${id}'`).join(", ")})`;
}

module.exports = { EXCLUDED_SUBSCRIPTION_IDS, ORDERS_HIDDEN_IDS, realSubscriptionSql, notHiddenOnOrdersSql };
