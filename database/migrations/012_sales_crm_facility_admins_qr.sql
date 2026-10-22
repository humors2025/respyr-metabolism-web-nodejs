-- ============================================================================
-- 012: sales_crm.facility_admins.qr_code_id — the sticker pointing at the gym
--
-- RUN AGAINST THE sales_crm DATABASE, NOT dietician_db.
--
-- Filled by the mirror (src/services/salesCrmMirror.js upsertFacilityAdmin):
-- accept-invite.js sends the sticker bound to the invite (field flow), and
-- referral-ops.js qrLink keeps it current when a sticker is linked, re-pointed
-- or unlinked ('' clears the column via NULLIF). Backfill from dietician_db:
--   SELECT partner_code, id FROM qr_codes
--   WHERE partner_code LIKE 'FAC%' AND status = 'assigned';
-- then one UPDATE per row on sales_crm.
-- ============================================================================

ALTER TABLE `facility_admins`
  ADD COLUMN `qr_code_id` VARCHAR(12) NULL AFTER `partner_code`,
  ADD KEY `idx_facility_admins_qr_code_id` (`qr_code_id`);
