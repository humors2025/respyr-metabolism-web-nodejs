-- 005_trainer_commission_splits_table.sql
--
-- Moves the per-trainer commission split out of `app_user_roles` and into its
-- own table.
--
-- Why: the split is a facility/commission concern, not an identity concern.
-- Keeping it on app_user_roles meant every login and token refresh dragged
-- commission columns along with it.
--
-- What stays on app_user_roles: `facility_id`. Login reads it to route the
-- user to their dashboard, so it belongs with identity.
--
-- Safe to re-run. Backfills from the old columns when they are present, so it
-- works whether or not 001 has already been applied.

CREATE TABLE IF NOT EXISTS `trainer_commission_splits` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

  -- app_user_roles.user_id (the trainer's email). One row per trainer.
  `user_id` VARCHAR(150) COLLATE utf8mb4_unicode_ci NOT NULL,

  -- Denormalised for facility-scoped reads; authoritative value still lives
  -- on app_user_roles.facility_id.
  `facility_id` BIGINT UNSIGNED NULL,

  -- Share (0.00-100.00) of the facility's commission this trainer receives.
  -- The ledger snapshots this per invoice, so edits apply to future invoices.
  `commission_split_pct` DECIMAL(5,2) NOT NULL DEFAULT 0.00,

  `updated_at` DATETIME NULL,
  `updated_by` VARCHAR(150) COLLATE utf8mb4_unicode_ci NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_tcs_user` (`user_id`),
  KEY `idx_tcs_facility` (`facility_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


-- Backfill from app_user_roles, but only if 001 already added those columns.
SET @has_col := (SELECT COUNT(*) FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'app_user_roles'
    AND column_name = 'commission_split_pct');

SET @sql := IF(@has_col = 1,
  'INSERT IGNORE INTO `trainer_commission_splits`
     (`user_id`, `facility_id`, `commission_split_pct`, `updated_at`, `updated_by`)
   SELECT
     `user_id`,
     `facility_id`,
     COALESCE(`commission_split_pct`, 0.00),
     `commission_split_updated_at`,
     `commission_split_updated_by`
   FROM `app_user_roles`
   WHERE `role` = ''trainer''',
  'SELECT 1');

PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;


-- The old columns are intentionally NOT dropped here. Verify the new table
-- first, then run 005_trainer_commission_splits_table.down.sql's DROP section
-- (or the statements below) once you are satisfied:
--
--   ALTER TABLE `app_user_roles`
--     DROP COLUMN `commission_split_pct`,
--     DROP COLUMN `commission_split_updated_at`,
--     DROP COLUMN `commission_split_updated_by`;
