-- Rollback for 006. Drops the new tables (their data is lost).
DROP TABLE IF EXISTS `payment_transactions`;
DROP TABLE IF EXISTS `subscription_shipping_addresses`;
