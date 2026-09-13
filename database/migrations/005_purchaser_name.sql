-- 005: buyer's name from Stripe Checkout, so referral dashboards can show who
-- bought without a round-trip to Stripe. Members later linked to an app
-- profile use table_clients.profile_name instead.
ALTER TABLE `referral_subscriptions`
  ADD COLUMN `purchaser_name` VARCHAR(150) NULL AFTER `purchaser_email`;
