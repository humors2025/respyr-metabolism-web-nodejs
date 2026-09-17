-- Rollback for 002. webhook_events is left in place (pre-existing table).
DROP TABLE IF EXISTS `payouts`;
DROP TABLE IF EXISTS `commission_entries`;
DROP TABLE IF EXISTS `breath_credits`;
DROP TABLE IF EXISTS `referral_subscriptions`;
DROP TABLE IF EXISTS `partner_payout_accounts`;
