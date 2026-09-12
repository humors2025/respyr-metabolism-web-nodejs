-- Rollback for 001. Only valid while no facility_admin rows / facilities exist.
ALTER TABLE `app_user_invitations`
  DROP COLUMN `facility_name`,
  DROP COLUMN `facility_id`,
  MODIFY COLUMN `invited_role` ENUM('admin','trainer') COLLATE utf8mb4_unicode_ci NOT NULL;
ALTER TABLE `app_user_roles`
  DROP COLUMN `commission_split_updated_by`,
  DROP COLUMN `commission_split_updated_at`,
  DROP COLUMN `commission_split_pct`,
  DROP COLUMN `facility_id`,
  MODIFY COLUMN `role` ENUM('super_admin','admin','trainer') COLLATE utf8mb4_unicode_ci NOT NULL;
DROP TABLE IF EXISTS `client_reassignments`;
DROP TABLE IF EXISTS `commission_rates`;
DROP TABLE IF EXISTS `facilities`;
