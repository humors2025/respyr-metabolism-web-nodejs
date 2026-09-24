-- ============================================================================
-- 006_stripe_transactions_and_checkout_details.sql
--
-- Stores the Stripe data the webhook currently drops, in new tables only
-- (referral_subscriptions is left unchanged):
--   1. subscription_shipping_addresses: phone + shipping address collected on
--      Stripe Checkout, one row per website purchase
--   2. payment_transactions: one row per Stripe invoice (first payment,
--      renewals, failures, refunds)
--
-- Run once per database (UAT and production). Requires 002.
-- ============================================================================

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `subscription_shipping_addresses` (
  `id`                          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `referral_subscription_id`    BIGINT UNSIGNED NULL,                -- referral_subscriptions.id
  `stripe_subscription_id`      VARCHAR(64)     NOT NULL,
  `stripe_checkout_session_id`  VARCHAR(255)    NULL,
  `name`                        VARCHAR(150)    NULL,
  `phone`                       VARCHAR(32)     NULL,
  `line1`                       VARCHAR(255)    NULL,
  `line2`                       VARCHAR(255)    NULL,
  `city`                        VARCHAR(100)    NULL,
  `state`                       VARCHAR(100)    NULL,
  `postal_code`                 VARCHAR(20)     NULL,
  `country`                     CHAR(2)         NULL,
  `created_at`                  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`                  DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ssa_subscription` (`stripe_subscription_id`),
  KEY `idx_ssa_referral_sub` (`referral_subscription_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `payment_transactions` (
  `id`                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `referral_subscription_id`  BIGINT UNSIGNED NULL,
  `stripe_subscription_id`    VARCHAR(64)     NULL,
  `stripe_customer_id`        VARCHAR(64)     NULL,
  `stripe_invoice_id`         VARCHAR(64)     NOT NULL,
  `stripe_payment_intent_id`  VARCHAR(64)     NULL,
  `stripe_charge_id`          VARCHAR(64)     NULL,
  `billing_reason`            VARCHAR(32)     NULL,
  `period_start`              DATETIME        NULL,
  `period_end`                DATETIME        NULL,
  `amount_paid_minor`         INT             NOT NULL DEFAULT 0,
  `amount_refunded_minor`     INT             NOT NULL DEFAULT 0,
  `currency`                  CHAR(3)         NOT NULL,
  `fee_minor`                 INT             NULL,
  `net_minor`                 INT             NULL,
  `status`                    ENUM('open','paid','failed','refunded','partially_refunded') NOT NULL DEFAULT 'open',
  `failure_message`           VARCHAR(500)    NULL,
  `payment_method_type`       VARCHAR(32)     NULL,
  `card_last4`                CHAR(4)         NULL,
  `paid_at`                   DATETIME        NULL,
  `created_at`                DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`                DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_pt_invoice` (`stripe_invoice_id`),
  KEY `idx_pt_subscription` (`stripe_subscription_id`),
  KEY `idx_pt_charge` (`stripe_charge_id`),
  KEY `idx_pt_status` (`status`),
  KEY `idx_pt_paid_at` (`paid_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
