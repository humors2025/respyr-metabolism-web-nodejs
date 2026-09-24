-- ----------------------------------------------------------------------------
-- 006: sales_invoices — one row per Stripe invoice of a Rysflo membership.
--
-- Source of revenue for the Super Admin Sales Analytics page. Written by the
-- Stripe webhook (invoice.paid, invoice.payment_failed, charge.refunded) and by
-- the "Sync from Stripe" backfill (POST super-admin-sales-analytics, view=sync).
-- Attribution (website vs trainer code) is NOT stored here: it is read from
-- referral_subscriptions.attributed_partner_code through stripe_subscription_id.
--
-- Amounts are minor units (cents):
--   subtotal_minor         list price before discounts   (gross)
--   discount_minor         coupon / referral discount
--   amount_paid_minor      what Stripe collected          (after discount and
--                          any customer-balance breath credit)
--   amount_refunded_minor  refunded so far on that payment
-- Net revenue of an invoice = amount_paid_minor - amount_refunded_minor.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `sales_invoices` (
  `id`                       BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_invoice_id`        VARCHAR(64)     NOT NULL,
  `stripe_subscription_id`   VARCHAR(64)     NOT NULL,
  `stripe_customer_id`       VARCHAR(64)     NULL,
  `stripe_payment_intent_id` VARCHAR(255)    NULL,
  `billing_reason`           VARCHAR(40)     NULL,              -- subscription_create = the purchase, subscription_cycle = renewal
  `status`                   ENUM('paid','failed','refunded','partially_refunded') NOT NULL,
  `currency`                 CHAR(3)         NOT NULL,
  `subtotal_minor`           INT             NOT NULL DEFAULT 0,
  `discount_minor`           INT             NOT NULL DEFAULT 0,
  `amount_paid_minor`        INT             NOT NULL DEFAULT 0,
  `amount_refunded_minor`    INT             NOT NULL DEFAULT 0,
  `paid_at`                  DATETIME        NULL,              -- UTC
  `failed_at`                DATETIME        NULL,              -- UTC, last failed attempt
  `refunded_at`              DATETIME        NULL,              -- UTC
  `created_at`               DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`               DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_si_invoice` (`stripe_invoice_id`),
  KEY `idx_si_subscription` (`stripe_subscription_id`),
  KEY `idx_si_paid_at` (`paid_at`),
  KEY `idx_si_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
