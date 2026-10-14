-- 009: mirror of Stripe Connect payout setup for the sales team.
--
-- RUN THIS AGAINST THE `sales_crm` DATABASE, not dietician_db. Same writer and
-- connection as 008 (src/services/salesCrmMirror.js). Rows are built from
-- Stripe's data and written independently of dietician_db, so this table is
-- still updated when dietician_db is down (and the other way round). An
-- account is added here the first time Stripe verifies it (onboarding_status
-- = 'verified' and payouts_enabled = 1); payees who started setup but never
-- finished are not. After that, every save (the account.updated webhook, the
-- payee returning from Stripe, the pre-transfer check) updates the row, so a
-- later action_required or disabled still shows.
-- The MySQL user it connects as needs SELECT, INSERT, UPDATE on this table.
--
-- One row per Stripe Connect account. Carries the payee's role, referral code
-- and facility so the sales console never has to join across databases.
-- `livemode` = 0 are sandbox accounts (UAT); filter them out in any report.
-- The commission split is NOT copied: it lives in
-- dietician_db.trainer_commission_splits and changes independently.

CREATE TABLE IF NOT EXISTS `stripe_payout_accounts` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_account_id`   VARCHAR(64)     NOT NULL,                  -- acct_…
  `user_email`          VARCHAR(150)    NOT NULL,                  -- dietician_db app_user_roles.user_id
  `user_name`           VARCHAR(150)    NULL,
  `role`                VARCHAR(32)     NULL,                      -- trainer / facility_admin / admin
  `partner_code`        VARCHAR(50)     NULL,                      -- the payee's own referral code
  `facility_id`         BIGINT UNSIGNED NULL,                      -- dietician_db facilities.id
  `facility_name`       VARCHAR(150)    NULL,
  `livemode`            TINYINT(1)      NOT NULL DEFAULT 0,
  `onboarding_status`   ENUM('not_started','pending','verified','action_required','disabled')
                                        NOT NULL DEFAULT 'pending',
  `details_submitted`   TINYINT(1)      NOT NULL DEFAULT 0,
  `payouts_enabled`     TINYINT(1)      NOT NULL DEFAULT 0,        -- 1 = Stripe transfers active
  `requirements_json`   JSON            NULL,
  `setup_started_at`    DATETIME        NULL,                      -- partner_payout_accounts.created_at
  `last_synced_at`      DATETIME        NULL,                      -- last time the status was read from Stripe
  `created_at`          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`          DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_spa_account` (`stripe_account_id`),
  KEY `idx_spa_email` (`user_email`),
  KEY `idx_spa_partner` (`partner_code`),
  KEY `idx_spa_status` (`onboarding_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
