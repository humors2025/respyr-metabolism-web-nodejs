-- ============================================================================
-- 002_stripe_commission_ledger.sql
--
-- Money plumbing for the gym referral programme:
--   * Stripe Connect payout accounts (facility admins, trainers with a split)
--   * Breath-test credits applied to the next Stripe invoice
--   * Commission ledger, one row per paid invoice per payee
--   * Payout runs (Stripe Transfers)
--   * Stripe webhook event log (reuses the existing webhook_events table)
--
-- Additive only. Requires 001.
-- ============================================================================

SET NAMES utf8mb4;

-- ----------------------------------------------------------------------------
-- 1. Stripe Connect Express account per payee. No bank / tax data is stored;
--    Stripe holds W-9 / 1099 / bank details.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `partner_payout_accounts` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`             VARCHAR(150)    NOT NULL,                  -- app_user_roles.user_id
  `stripe_account_id`   VARCHAR(64)     NOT NULL,                  -- acct_…
  `onboarding_status`   ENUM('not_started','pending','verified','action_required','disabled')
                                        NOT NULL DEFAULT 'pending',
  `details_submitted`   TINYINT(1)      NOT NULL DEFAULT 0,
  `charges_enabled`     TINYINT(1)      NOT NULL DEFAULT 0,
  `payouts_enabled`     TINYINT(1)      NOT NULL DEFAULT 0,
  `requirements_json`   JSON            NULL,                      -- Stripe requirements.* for the UI
  `last_synced_at`      DATETIME        NULL,
  `created_at`          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`          DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ppa_user` (`user_id`),
  UNIQUE KEY `uq_ppa_account` (`stripe_account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 2. Subscriptions sold through /order/<code>. One row per Stripe subscription.
--    Keeps the referral attribution and the Stripe ids the ledger needs, without
--    overloading client_subscriptions (which the app links at code redemption).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `referral_subscriptions` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_subscription_id`  VARCHAR(64)     NOT NULL,
  `stripe_customer_id`      VARCHAR(64)     NOT NULL,
  `stripe_checkout_session_id` VARCHAR(255) NULL,
  `stripe_schedule_id`      VARCHAR(64)     NULL,
  `purchaser_email`         VARCHAR(255)    NULL,
  `profile_id`              VARCHAR(64)     NULL,                  -- set when the buyer redeems in the app
  `coupon_code`             VARCHAR(64)     NULL,                  -- coupon_codes.coupon_code handed to the buyer
  `attributed_partner_code` VARCHAR(50)     NULL,                  -- code on the QR / link at purchase
  `attributed_user_id`      VARCHAR(150)    NULL,                  -- owner of that code at purchase
  `attributed_role`         ENUM('admin','facility_admin','trainer') NULL,
  `facility_id`             BIGINT UNSIGNED NULL,
  `plan_code`               VARCHAR(64)     NOT NULL,
  `price_id`                VARCHAR(64)     NOT NULL,
  `currency`                CHAR(3)         NOT NULL,
  `unit_amount_minor`       INT             NOT NULL,
  `status`                  VARCHAR(32)     NOT NULL,              -- mirrors Stripe subscription.status
  `current_period_start`    DATETIME        NULL,
  `current_period_end`      DATETIME        NULL,
  `canceled_at`             DATETIME        NULL,
  `created_at`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`              DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rs_subscription` (`stripe_subscription_id`),
  KEY `idx_rs_customer` (`stripe_customer_id`),
  KEY `idx_rs_partner_code` (`attributed_partner_code`),
  KEY `idx_rs_profile` (`profile_id`),
  KEY `idx_rs_facility` (`facility_id`),
  KEY `idx_rs_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 3. Breath-test credits. One row per subscription per billing period, written
--    when the credit is applied to the Stripe customer balance. $0.20 per
--    reading-day, capped at $6.00 (30 days; 28 days reaches the cap in Feb).
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `breath_credits` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_subscription_id`  VARCHAR(64)     NOT NULL,
  `profile_id`              VARCHAR(64)     NOT NULL,
  `period_start`            DATE            NOT NULL,              -- billing period the readings fall in
  `period_end`              DATE            NOT NULL,
  `reading_days`            SMALLINT UNSIGNED NOT NULL,
  `days_in_period`          SMALLINT UNSIGNED NOT NULL,
  `credit_minor`            INT             NOT NULL,              -- cents credited
  `stripe_balance_txn_id`   VARCHAR(64)     NULL,                  -- cbtxn_…
  `applied_at`              DATETIME        NULL,
  `created_at`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_bc_sub_period` (`stripe_subscription_id`, `period_start`),
  KEY `idx_bc_profile` (`profile_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 4. Commission ledger. Append-only. One row per paid invoice per payee.
--    amount = invoice net (after breath credit) x platform rate x payee share.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `commission_entries` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_invoice_id`       VARCHAR(64)     NOT NULL,
  `stripe_subscription_id`  VARCHAR(64)     NOT NULL,
  `referral_subscription_id` BIGINT UNSIGNED NULL,
  `payee_user_id`           VARCHAR(150)    NOT NULL,
  `payee_role`              ENUM('admin','facility_admin','trainer') NOT NULL,
  `facility_id`             BIGINT UNSIGNED NULL,
  `attributed_partner_code` VARCHAR(50)     NOT NULL,
  `invoice_paid_at`         DATETIME        NOT NULL,
  `invoice_net_minor`       INT             NOT NULL,              -- amount_paid on the invoice
  `commission_rate_pct`     DECIMAL(5,2)    NOT NULL,              -- platform rate at invoice time
  `gym_commission_minor`    INT             NOT NULL,              -- net x rate, before split
  `share_pct`               DECIMAL(5,2)    NOT NULL,              -- this payee's share of gym commission
  `amount_minor`            INT             NOT NULL,
  `currency`                CHAR(3)         NOT NULL,
  `status`                  ENUM('pending','held','scheduled','paid','reversed') NOT NULL DEFAULT 'pending',
  `hold_reason`             VARCHAR(255)    NULL,
  `payout_id`               BIGINT UNSIGNED NULL,
  `reversed_by_invoice_id`  VARCHAR(64)     NULL,
  `created_at`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`              DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ce_invoice_payee` (`stripe_invoice_id`, `payee_user_id`),
  KEY `idx_ce_payee_status` (`payee_user_id`, `status`),
  KEY `idx_ce_facility` (`facility_id`),
  KEY `idx_ce_payout` (`payout_id`),
  KEY `idx_ce_paid_at` (`invoice_paid_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 5. Payout runs. One Stripe Transfer per payee per run.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `payouts` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `payee_user_id`       VARCHAR(150)    NOT NULL,
  `stripe_account_id`   VARCHAR(64)     NOT NULL,
  `stripe_transfer_id`  VARCHAR(64)     NULL,
  `period_start`        DATE            NOT NULL,
  `period_end`          DATE            NOT NULL,
  `entry_count`         INT             NOT NULL DEFAULT 0,
  `amount_minor`        INT             NOT NULL,
  `currency`            CHAR(3)         NOT NULL,
  `status`              ENUM('scheduled','processing','paid','failed','reversed') NOT NULL DEFAULT 'scheduled',
  `failure_reason`      VARCHAR(512)    NULL,
  `idempotency_key`     VARCHAR(64)     NOT NULL,
  `initiated_by`        VARCHAR(150)    NOT NULL,                  -- 'scheduler' or a super_admin email
  `created_at`          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `paid_at`             DATETIME        NULL,
  `updated_at`          DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_payouts_transfer` (`stripe_transfer_id`),
  UNIQUE KEY `uq_payouts_idem` (`idempotency_key`),
  KEY `idx_payouts_payee` (`payee_user_id`),
  KEY `idx_payouts_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 6. Webhook event log — already exists in the DEV dump as webhook_events.
--    Created here only if a target database lacks it.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `webhook_events` (
  `event_id`     VARCHAR(255) NOT NULL,
  `type`         VARCHAR(128) NOT NULL,
  `received_at`  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `processed_at` DATETIME NULL,
  `status`       ENUM('received','processed','error') NOT NULL DEFAULT 'received',
  `error`        TEXT NULL,
  PRIMARY KEY (`event_id`),
  KEY `idx_type` (`type`),
  KEY `idx_received_at` (`received_at`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
