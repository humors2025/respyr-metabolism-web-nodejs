-- ============================================================================
-- 001_facilities_and_commission_split.sql
--
-- Gym referral commission — foundation.
--
-- Introduces the facility (gym / Pilates studio) as a first-class entity and
-- the facility_admin role that sits between admin (Rysflo US trainer-admin)
-- and trainer. Adds the per-trainer commission split the facility admin sets
-- and a super-admin-managed platform commission rate.
--
-- Additive only. Safe to run on a live database:
--   * ENUM extensions keep all existing values.
--   * New columns are nullable or defaulted.
--   * No data is rewritten.
--
-- Rollback: 001_facilities_and_commission_split.down.sql (valid only while no
-- facility_admin rows exist).
--
-- Requires MySQL 8.0+ (uses ADD COLUMN IF NOT EXISTS via information_schema
-- guards below so the file is re-runnable).
-- ============================================================================

SET NAMES utf8mb4;

-- ----------------------------------------------------------------------------
-- 1. Facilities
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `facilities` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`                  VARCHAR(150)    NOT NULL,
  `partner_code`          VARCHAR(50)     NOT NULL,                 -- the wall / front-desk QR code (e.g. TRX1234)
  `facility_admin_user_id` VARCHAR(150)   NOT NULL,                 -- app_user_roles.user_id of the owner (email)
  `parent_admin_user_id`  VARCHAR(150)    NOT NULL,                 -- the Rysflo admin (TA) who onboarded the facility
  `status`                ENUM('active','suspended','inactive','removed') NOT NULL DEFAULT 'active',
  `stripe_account_id`     VARCHAR(64)     NULL,                     -- Stripe Connect acct_… (added by 002, kept here for the FK-free shape)
  `created_by_user_id`    VARCHAR(150)    NOT NULL,
  `created_at`            DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`            DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  `status_changed_at`     DATETIME        NULL,
  `status_changed_by`     VARCHAR(150)    NULL,
  `status_change_reason`  TEXT            NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_facilities_partner_code` (`partner_code`),
  UNIQUE KEY `uq_facilities_facility_admin` (`facility_admin_user_id`),
  KEY `idx_facilities_parent_admin` (`parent_admin_user_id`),
  KEY `idx_facilities_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- 2. app_user_roles: new role value, facility link, commission split
-- ----------------------------------------------------------------------------
ALTER TABLE `app_user_roles`
  MODIFY COLUMN `role`
    ENUM('super_admin','admin','facility_admin','trainer')
    COLLATE utf8mb4_unicode_ci NOT NULL;

-- remove-user.js on branch `uat` writes status='removed'; the DEV dump's enum
-- lacks it. Adding it here so local matches what the code already does.
-- (No-op on UAT if the value is already present.)
ALTER TABLE `app_user_roles`
  MODIFY COLUMN `status`
    ENUM('active','suspended','inactive','offboarded','removed')
    COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'active';

SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'app_user_roles' AND column_name = 'facility_id');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE `app_user_roles`
     ADD COLUMN `facility_id` BIGINT UNSIGNED NULL AFTER `parent_user_id`,
     ADD KEY `idx_app_user_roles_facility_id` (`facility_id`)',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- Share (0.00–100.00) of the facility''s commission that this trainer receives.
-- Only meaningful on role=trainer rows with a facility_id. Set by the facility
-- admin. Changes apply to future invoices only — the ledger snapshots it.
SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'app_user_roles' AND column_name = 'commission_split_pct');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE `app_user_roles`
     ADD COLUMN `commission_split_pct` DECIMAL(5,2) NOT NULL DEFAULT 0.00 AFTER `facility_id`,
     ADD COLUMN `commission_split_updated_at` DATETIME NULL AFTER `commission_split_pct`,
     ADD COLUMN `commission_split_updated_by` VARCHAR(150) NULL AFTER `commission_split_updated_at`',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- ----------------------------------------------------------------------------
-- 3. app_user_invitations: allow inviting a facility_admin, carry facility
-- ----------------------------------------------------------------------------
ALTER TABLE `app_user_invitations`
  MODIFY COLUMN `invited_role`
    ENUM('admin','facility_admin','trainer')
    COLLATE utf8mb4_unicode_ci NOT NULL;

SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE() AND table_name = 'app_user_invitations' AND column_name = 'facility_id');
SET @sql := IF(@has_col = 0,
  'ALTER TABLE `app_user_invitations`
     ADD COLUMN `facility_id` BIGINT UNSIGNED NULL AFTER `parent_user_id`,
     ADD COLUMN `facility_name` VARCHAR(150) NULL AFTER `facility_id`,
     ADD KEY `idx_app_user_invitations_facility_id` (`facility_id`)',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- ----------------------------------------------------------------------------
-- 4. Platform commission rate (Rysflo -> facility), super-admin managed.
--    Append-only; the row with the latest effective_from <= NOW() is current.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `commission_rates` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `rate_pct`        DECIMAL(5,2)    NOT NULL,                       -- e.g. 20.00
  `effective_from`  DATETIME        NOT NULL,
  `set_by_user_id`  VARCHAR(150)    NOT NULL,
  `note`            VARCHAR(255)    NULL,
  `created_at`      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_commission_rates_effective_from` (`effective_from`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO `commission_rates` (`rate_pct`, `effective_from`, `set_by_user_id`, `note`)
SELECT 20.00, '2026-01-01 00:00:00', 'system', 'Initial platform rate'
WHERE NOT EXISTS (SELECT 1 FROM `commission_rates`);

-- ----------------------------------------------------------------------------
-- 5. Client reassignment audit (trainer removed -> clients revert to facility)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `client_reassignments` (
  `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `profile_id`         VARCHAR(100)    NOT NULL,
  `from_partner_code`  VARCHAR(50)     NOT NULL,
  `to_partner_code`    VARCHAR(50)     NOT NULL,
  `facility_id`        BIGINT UNSIGNED NULL,
  `reason`             ENUM('trainer_removed','manual') NOT NULL,
  `actor_user_id`      VARCHAR(150)    NOT NULL,
  `created_at`         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_client_reassignments_profile` (`profile_id`),
  KEY `idx_client_reassignments_from` (`from_partner_code`),
  KEY `idx_client_reassignments_facility` (`facility_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
