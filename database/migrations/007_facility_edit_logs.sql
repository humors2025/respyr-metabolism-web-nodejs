-- ============================================================================
-- 007_facility_edit_logs.sql
--
-- Edit history for facilities: one row per changed field each time a
-- super admin / trainer admin edits a facility's name or the owner's display
-- name from the Facilities page (update-facility endpoint). Drives the
-- "Edited" tag and the per-facility edit history in the dashboards.
--
-- Run once per database (UAT and production). Requires 001.
-- Must be applied BEFORE deploying the Lambda build that includes the
-- update-facility edit-log inserts and the list-facilities edit subqueries.
-- ============================================================================

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `facility_edit_logs` (
  `id`           BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `facility_id`  BIGINT UNSIGNED NOT NULL,                -- facilities.id
  `field`        ENUM('name','owner_name') NOT NULL,      -- what was edited
  `old_value`    VARCHAR(150)    NULL,
  `new_value`    VARCHAR(150)    NOT NULL,
  `edited_by`    VARCHAR(150)    NOT NULL,                -- actor email
  `edited_role`  VARCHAR(32)     NOT NULL,                -- super_admin | admin
  `edited_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_fel_facility` (`facility_id`, `edited_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
