-- ----------------------------------------------------------------------------
-- 015: macro_overrides
--
-- Hand-edited macro targets for one client, set from the dashboard's
-- "Macros Analysis" tab. The test's own numbers (table_test_data.test_json →
-- final_macro_summary) are never changed; this table sits beside them.
--
-- An override is used between valid_from and valid_to (both inclusive, India
-- dates, the same calendar the weekly diet plan uses). While one covers the
-- week being planned, the diet-plan worker feed (get_latest_72hr_tests and
-- fetch-single-client-worker-job-test) sends these numbers as
-- final_macro_summary instead of the test's, and also sends the test's own
-- numbers as original_macro_summary.
--
-- When two overrides cover the same week, the most recently saved one wins.
-- Removing an override sets removed_at (soft delete), so the history stays.
--
-- base_* is a copy of the test's real macros at the moment of the edit, so the
-- dashboard can always show "real vs edited" even after newer tests arrive.
-- edited_by_* comes from the signed-in user's access token, never the request.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `macro_overrides` (
  `id`                     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `profile_id`             VARCHAR(64)     NOT NULL,
  `dietician_id`           VARCHAR(64)     NOT NULL,              -- the client's owning dietitian (table_clients)

  `protein_g`              DECIMAL(7,1)    NOT NULL,
  `carbs_g`                DECIMAL(7,1)    NOT NULL,
  `fat_g`                  DECIMAL(7,1)    NOT NULL,
  `fiber_g`                DECIMAL(7,1)    NOT NULL,
  `calories`               DECIMAL(8,1)    NOT NULL,              -- test calories moved by the change: 4·protein + 4·carbs + 9·fat + 2·fiber

  `valid_from`             DATE            NOT NULL,
  `valid_to`               DATE            NOT NULL,
  `note`                   VARCHAR(500)    NULL,

  `base_test_id`           BIGINT          NULL,                  -- test the real numbers came from
  `base_test_date`         DATETIME        NULL,
  `base_protein_g`         DECIMAL(7,1)    NULL,
  `base_carbs_g`           DECIMAL(7,1)    NULL,
  `base_fat_g`             DECIMAL(7,1)    NULL,
  `base_fiber_g`           DECIMAL(7,1)    NULL,
  `base_calories`          DECIMAL(8,1)    NULL,

  `edited_by_user_id`      VARCHAR(191)    NOT NULL,              -- access token user_id (login email)
  `edited_by_name`         VARCHAR(191)    NULL,                  -- access token dietician.name
  `edited_by_dietician_id` VARCHAR(64)     NULL,                  -- access token sub
  `edited_by_role`         VARCHAR(40)     NULL,

  `removed_at`             DATETIME        NULL,
  `removed_by_user_id`     VARCHAR(191)    NULL,
  `removed_by_name`        VARCHAR(191)    NULL,

  `created_at`             DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`             DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_mo_profile_range` (`profile_id`, `valid_from`, `valid_to`),
  KEY `idx_mo_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
