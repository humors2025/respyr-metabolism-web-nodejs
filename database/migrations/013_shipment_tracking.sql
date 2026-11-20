-- ============================================================================
-- 013_shipment_tracking.sql
--
-- FedEx tracking for website purchases: one row per subscription whose device
-- has shipped. A super admin types the tracking number on Orders › Shipping;
-- the backend asks FedEx's Track API for the status and keeps the latest
-- answer here (status, estimated / actual delivery, scan history).
--
-- New table only: subscription_shipping_addresses and referral_subscriptions
-- are left unchanged. Until this runs, the Shipping tab simply shows no
-- tracking and saving a tracking number answers 503.
--
-- Run once per database (UAT and production). Requires 006.
-- ============================================================================

SET NAMES utf8mb4;

CREATE TABLE IF NOT EXISTS `shipment_tracking` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `stripe_subscription_id`  VARCHAR(64)     NOT NULL,             -- subscription_shipping_addresses.stripe_subscription_id
  `carrier`                 VARCHAR(20)     NOT NULL DEFAULT 'fedex',
  `tracking_number`         VARCHAR(40)     NOT NULL,
  `status_code`             VARCHAR(10)     NULL,                 -- FedEx latestStatusDetail.code (PU, IT, OD, DL, DE, …)
  `status_text`             VARCHAR(255)    NULL,                 -- FedEx latestStatusDetail.description
  `estimated_delivery`      DATETIME        NULL,                 -- UTC
  `delivered_at`            DATETIME        NULL,                 -- UTC
  `last_event_at`           DATETIME        NULL,                 -- UTC
  `last_event_text`         VARCHAR(255)    NULL,
  `last_event_location`     VARCHAR(150)    NULL,
  `events_json`             MEDIUMTEXT      NULL,                 -- scan history, newest first
  `last_error`              VARCHAR(255)    NULL,                 -- FedEx error from the last check, if any
  `checked_at`              DATETIME        NULL,                 -- last FedEx lookup (UTC)
  `added_by`                VARCHAR(150)    NULL,                 -- admin email who saved the number
  `created_at`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at`              DATETIME        NULL ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_st_subscription` (`stripe_subscription_id`),
  KEY `idx_st_tracking_number` (`tracking_number`),
  KEY `idx_st_status` (`status_code`, `checked_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
