-- Reverts 010 (run against the `sales_crm` database).
ALTER TABLE `stripe_payments`
  DROP COLUMN `shipping_address`,
  DROP COLUMN `shipping_name`,
  DROP COLUMN `phone`,
  DROP COLUMN `shipping_line1`,
  DROP COLUMN `shipping_line2`,
  DROP COLUMN `shipping_city`,
  DROP COLUMN `shipping_state`,
  DROP COLUMN `shipping_postal_code`,
  DROP COLUMN `shipping_country`;
