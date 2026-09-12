-- ============================================================================
-- 003_pricing_qr_purchase_codes.sql
--
-- Referral flow v0.3: configurable list/referred pricing with derived Stripe
-- coupons, one Stripe promotion code per partner code, pre-printed QR
-- stickers linked to facilities/trainers at scan time, and purchase codes that
-- link a website purchase to the app account.
--
-- Additive only. Requires 001 + 002.
-- ============================================================================

SET NAMES utf8mb4;

-- 1. Pricing settings (append-only; latest effective row wins)
CREATE TABLE IF NOT EXISTS `pricing_settings` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `currency`              CHAR(3)         NOT NULL DEFAULT 'USD',
  `list_price_minor`      INT             NOT NULL,                  -- e.g. 4900
  `referred_price_minor`  INT             NOT NULL,                  -- e.g. 2900
  `stripe_list_price_id`  VARCHAR(64)     NULL,                      -- price_… for list_price_minor
  `stripe_coupon_id`      VARCHAR(64)     NULL,                      -- coupon for (list - referred), duration forever
  `effective_from`        DATETIME        NOT NULL,
  `set_by_user_id`        VARCHAR(150)    NOT NULL,
  `note`                  VARCHAR(255)    NULL,
  `created_at`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_pricing_effective` (`effective_from`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 2. Stripe promotion code per partner code (per coupon; re-issued when the coupon changes)
CREATE TABLE IF NOT EXISTS `partner_promotion_codes` (
  `id`                        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `partner_code`              VARCHAR(50)     NOT NULL,
  `stripe_coupon_id`          VARCHAR(64)     NOT NULL,
  `stripe_promotion_code_id`  VARCHAR(64)     NOT NULL,              -- promo_…
  `active`                    TINYINT(1)      NOT NULL DEFAULT 1,
  `created_at`                DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_ppc_code_coupon` (`partner_code`, `stripe_coupon_id`),
  UNIQUE KEY `uq_ppc_promo` (`stripe_promotion_code_id`),
  KEY `idx_ppc_partner` (`partner_code`, `active`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Pre-printed QR stickers
CREATE TABLE IF NOT EXISTS `qr_codes` (
  `id`              VARCHAR(12)     NOT NULL,                        -- printed ID, e.g. K7M2P9
  `batch_id`        VARCHAR(40)     NULL,
  `status`          ENUM('unassigned','assigned','retired') NOT NULL DEFAULT 'unassigned',
  `partner_code`    VARCHAR(50)     NULL,                            -- resolved target at scan time
  `facility_id`     BIGINT UNSIGNED NULL,
  `linked_user_id`  VARCHAR(150)    NULL,                            -- owner or trainer the sticker points at
  `linked_by`       VARCHAR(150)    NULL,
  `linked_at`       DATETIME        NULL,
  `scans`           INT UNSIGNED    NOT NULL DEFAULT 0,
  `created_by`      VARCHAR(150)    NOT NULL,
  `created_at`      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_qr_status` (`status`),
  KEY `idx_qr_partner` (`partner_code`),
  KEY `idx_qr_batch` (`batch_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `qr_code_links` (                         -- history of every (re)link
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `qr_id`           VARCHAR(12)     NOT NULL,
  `from_partner_code` VARCHAR(50)   NULL,
  `to_partner_code` VARCHAR(50)     NULL,
  `actor_user_id`   VARCHAR(150)    NOT NULL,
  `created_at`      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_qcl_qr` (`qr_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 4. Purchase code + link provenance on referral subscriptions
SET @c := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'referral_subscriptions' AND column_name = 'purchase_code');
SET @sql := IF(@c = 0,
  'ALTER TABLE `referral_subscriptions`
     ADD COLUMN `purchase_code` VARCHAR(20) NULL AFTER `coupon_code`,
     ADD COLUMN `purchase_code_row_id` BIGINT UNSIGNED NULL AFTER `purchase_code`,
     ADD COLUMN `linked_via` ENUM(''purchase_code'',''email'',''app_code'',''manual'') NULL AFTER `profile_id`,
     ADD COLUMN `linked_at` DATETIME NULL AFTER `linked_via`,
     ADD COLUMN `qr_id` VARCHAR(12) NULL AFTER `attributed_role`,
     ADD COLUMN `stripe_promotion_code_id` VARCHAR(64) NULL AFTER `qr_id`,
     ADD COLUMN `purchase_code_email_sent_at` DATETIME NULL AFTER `purchase_code_row_id`,
     ADD KEY `idx_rs_purchase_code` (`purchase_code`)',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;
