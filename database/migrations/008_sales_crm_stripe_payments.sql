-- 008: mirror of Stripe payment rows for the sales team.
--
-- RUN THIS AGAINST THE `sales_crm` DATABASE, not dietician_db. It is kept in
-- this repo because the writer is this backend's Stripe webhook
-- (src/services/salesCrmMirror.js), which inserts with a cross-database
-- statement (`sales_crm`.`stripe_payments`) through its normal connection.
-- The two databases live on the same MySQL server; the backend's MySQL user
-- needs SELECT, INSERT, UPDATE on this table.
--
-- One row per Stripe invoice, same shape as dietician_db.payment_transactions
-- plus the buyer, the referral code and the live/test flag, so the sales
-- console never has to join across databases. `livemode` = 0 are sandbox
-- payments (UAT); filter them out in any sales report.

CREATE TABLE IF NOT EXISTS `stripe_payments` (
  `id`                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_invoice_id`         VARCHAR(64)     NOT NULL,
  `stripe_subscription_id`    VARCHAR(64)     NULL,
  `stripe_customer_id`        VARCHAR(64)     NULL,
  `stripe_payment_intent_id`  VARCHAR(64)     NULL,
  `stripe_charge_id`          VARCHAR(64)     NULL,
  `livemode`                  TINYINT(1)      NOT NULL DEFAULT 0,
  `purchaser_email`           VARCHAR(255)    NULL,
  `purchaser_name`            VARCHAR(150)    NULL,
  `partner_code`              VARCHAR(50)     NULL,                  -- referral code the sale is attributed to
  `billing_reason`            VARCHAR(32)     NULL,                  -- subscription_create / subscription_cycle / …
  `period_start`              DATETIME        NULL,
  `period_end`                DATETIME        NULL,
  `amount_paid_minor`         INT             NOT NULL DEFAULT 0,    -- in `currency` minor units (cents / paise)
  `amount_refunded_minor`     INT             NOT NULL DEFAULT 0,
  `currency`                  CHAR(3)         NOT NULL,
  `fee_minor`                 INT             NULL,                  -- Stripe fee, only when settled in `currency`
  `net_minor`                 INT             NULL,
  `status`                    ENUM('open','paid','failed','refunded','partially_refunded') NOT NULL DEFAULT 'open',
  `failure_message`           VARCHAR(500)    NULL,
  `payment_method_type`       VARCHAR(32)     NULL,
  `card_last4`                CHAR(4)         NULL,
  `paid_at`                   DATETIME        NULL,
  `created_at`                DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`                DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_sp_invoice` (`stripe_invoice_id`),
  KEY `idx_sp_subscription` (`stripe_subscription_id`),
  KEY `idx_sp_email` (`purchaser_email`),
  KEY `idx_sp_partner` (`partner_code`),
  KEY `idx_sp_status` (`status`),
  KEY `idx_sp_paid_at` (`paid_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
