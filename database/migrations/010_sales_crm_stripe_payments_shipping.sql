-- 010: buyer's shipping address and phone on sales_crm.stripe_payments.
--
-- RUN THIS AGAINST THE `sales_crm` DATABASE, not dietician_db.
-- Already applied by hand to the production RDS (sales-crm-prod) on
-- 14 Oct 2026; run it on any other sales_crm (UAT) that does not have these
-- columns yet. Until then the webhook still copies payments there, just
-- without the address (logged once as SALES_CRM_SHIPPING_COLUMNS_MISSING).
--
-- Filled by the Stripe webhook (src/services/paymentTransactions.js,
-- shippingForSalesCrm) from the address the buyer entered on Checkout, which
-- dietician_db keeps in subscription_shipping_addresses. Renewal rows carry
-- the subscription's address too. `shipping_address` is the same address on
-- one line: "915 W Price Rd, A, Brownsville, TX 78520, US".

ALTER TABLE `stripe_payments`
  ADD COLUMN `shipping_address`     TEXT         NULL AFTER `purchaser_name`,
  ADD COLUMN `shipping_name`        VARCHAR(150) NULL AFTER `partner_code`,
  ADD COLUMN `phone`                VARCHAR(32)  NULL AFTER `shipping_name`,
  ADD COLUMN `shipping_line1`       VARCHAR(255) NULL AFTER `phone`,
  ADD COLUMN `shipping_line2`       VARCHAR(255) NULL AFTER `shipping_line1`,
  ADD COLUMN `shipping_city`        VARCHAR(100) NULL AFTER `shipping_line2`,
  ADD COLUMN `shipping_state`       VARCHAR(100) NULL AFTER `shipping_city`,
  ADD COLUMN `shipping_postal_code` VARCHAR(20)  NULL AFTER `shipping_state`,
  ADD COLUMN `shipping_country`     CHAR(2)      NULL AFTER `shipping_postal_code`;
