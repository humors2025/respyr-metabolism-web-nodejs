-- 004_qr_assignment.sql — stickers are assigned to a trainer admin, who sets
-- each one up in the field (business or personal trainer) which sends the
-- invite and binds the sticker to the invitee's code before they accept.
SET NAMES utf8mb4;

SET @c := (SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'qr_codes' AND column_name = 'assigned_to_user_id');
SET @sql := IF(@c = 0,
  'ALTER TABLE `qr_codes`
     ADD COLUMN `assigned_to_user_id` VARCHAR(150) NULL AFTER `batch_id`,          -- the TA holding the sticker
     ADD COLUMN `assigned_at`         DATETIME     NULL AFTER `assigned_to_user_id`,
     ADD COLUMN `target_type`         ENUM(''facility'',''trainer'') NULL AFTER `partner_code`,
     ADD COLUMN `target_label`        VARCHAR(150) NULL AFTER `target_type`,      -- gym / trainer name for the table
     ADD COLUMN `invitation_id`       BIGINT UNSIGNED NULL AFTER `target_label`,  -- pending invite created at setup
     ADD COLUMN `target_status`       ENUM(''pending'',''active'') NULL AFTER `invitation_id`,
     ADD KEY `idx_qr_assigned` (`assigned_to_user_id`, `status`)',
  'SELECT 1');
PREPARE s FROM @sql; EXECUTE s; DEALLOCATE PREPARE s;

-- Commission that cannot be paid yet because the payee has not accepted their
-- invite is held with this reason and rebuilt on activation.
ALTER TABLE `commission_entries`
  MODIFY COLUMN `status` ENUM('pending','held','scheduled','paid','reversed') NOT NULL DEFAULT 'pending';
