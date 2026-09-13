ALTER TABLE `referral_subscriptions`
  DROP COLUMN `purchase_code_email_sent_at`, DROP COLUMN `stripe_promotion_code_id`, DROP COLUMN `qr_id`,
  DROP COLUMN `linked_at`, DROP COLUMN `linked_via`, DROP COLUMN `purchase_code_row_id`, DROP COLUMN `purchase_code`;
DROP TABLE IF EXISTS `qr_code_links`;
DROP TABLE IF EXISTS `qr_codes`;
DROP TABLE IF EXISTS `partner_promotion_codes`;
DROP TABLE IF EXISTS `pricing_settings`;
