-- Undo 012: drop the sticker column. RUN AGAINST sales_crm.
ALTER TABLE `facility_admins`
  DROP KEY `idx_facility_admins_qr_code_id`,
  DROP COLUMN `qr_code_id`;
