-- ============================================================================
-- 011: sales_crm.facility_admins — one row per gym owner (facility_admin)
--
-- RUN AGAINST THE sales_crm DATABASE, NOT dietician_db.
--
-- Filled by the main backend's sales_crm mirror (src/services/salesCrmMirror.js
-- upsertFacilityAdmin): accept-invite.js adds the row when a facility_admin
-- invite is accepted, update-facility.js refreshes facility_name on an edit.
-- Keyed on the FAC partner code (the facility's wall / front-desk QR code).
--
-- Production note: created by hand on the sales-crm-prod RDS on 22 Oct 2026,
-- and the 17 facility admins existing at that date were backfilled by hand.
-- ============================================================================

CREATE TABLE IF NOT EXISTS `facility_admins` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`         VARCHAR(150)    NOT NULL,            -- owner's email
  `first_name`      VARCHAR(100)    NULL,
  `last_name`       VARCHAR(100)    NULL,
  `phone`           VARCHAR(30)     NULL,
  `partner_code`    VARCHAR(50)     NOT NULL,            -- FAC... code
  `facility_name`   VARCHAR(150)    NULL,
  `parent_user_id`  VARCHAR(150)    NULL,
  `status`          VARCHAR(20)     NOT NULL DEFAULT 'active',
  `joined_at`       DATETIME        NULL,                -- app_user_roles.created_at
  `created_at`      DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`      DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_facility_admins_partner_code` (`partner_code`),
  KEY `idx_facility_admins_user_id` (`user_id`),
  KEY `idx_facility_admins_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
