-- 009 backfill: copy payout accounts that are already verified into
-- sales_crm.stripe_payout_accounts. The backend adds newly verified accounts
-- from then on; this is only for accounts verified before it was deployed.
--
-- Two steps, because production's dietician_db and sales_crm are on different
-- servers:
--   1. Run the SELECT below against dietician_db. Each result row is one
--      ready-made INSERT statement. Use `mysql -N -B` (or copy the cells) so
--      the statements come out without table borders.
--   2. Run those statements against sales_crm (after 009 has created the
--      table). Safe to run twice: an existing row is updated, not duplicated.
--
-- Set @livemode to 1 on production (live Stripe key), 0 on UAT (sandbox).

SET @livemode := 1;

SELECT CONCAT(
  'INSERT INTO `stripe_payout_accounts` (`stripe_account_id`, `user_email`, `user_name`, `role`, `partner_code`, `facility_id`, `facility_name`, `livemode`, `onboarding_status`, `details_submitted`, `payouts_enabled`, `requirements_json`, `setup_started_at`, `last_synced_at`) VALUES (',
  CONCAT_WS(', ',
    QUOTE(ppa.stripe_account_id),
    QUOTE(LOWER(ppa.user_id)),
    QUOTE(td.name),
    QUOTE(aur.role),
    QUOTE(aur.partner_code),
    QUOTE(aur.facility_id),
    QUOTE(f.name),
    @livemode,
    QUOTE(ppa.onboarding_status),
    ppa.details_submitted,
    ppa.payouts_enabled,
    QUOTE(CAST(ppa.requirements_json AS CHAR)),
    QUOTE(ppa.created_at),
    QUOTE(ppa.last_synced_at)
  ),
  ') ON DUPLICATE KEY UPDATE `onboarding_status` = VALUES(`onboarding_status`), `details_submitted` = VALUES(`details_submitted`), `payouts_enabled` = VALUES(`payouts_enabled`), `requirements_json` = VALUES(`requirements_json`), `last_synced_at` = VALUES(`last_synced_at`);'
) AS stmt
FROM partner_payout_accounts ppa
LEFT JOIN app_user_roles  aur ON LOWER(aur.user_id) = LOWER(ppa.user_id)
LEFT JOIN facilities      f   ON f.id = aur.facility_id
LEFT JOIN table_dietician td  ON LOWER(td.email) = LOWER(aur.user_id)
WHERE ppa.onboarding_status = 'verified'
  AND ppa.payouts_enabled = 1
ORDER BY ppa.created_at;
