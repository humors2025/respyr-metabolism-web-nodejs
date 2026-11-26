-- ----------------------------------------------------------------------------
-- 014: renewal_tokens
--
-- One row per tap on the app's "Renew plan" button. The app calls
-- POST /v1/renewal/link with its login JWT; the backend works out the
-- profile_id, makes a random one-time token and returns
-- https://rysflo.com/renewal/?t=<token>. Only the SHA-256 of the token is
-- stored, so a copy of this table cannot be turned back into working links.
--
-- The timestamp columns double as the renewal funnel:
--   created_at  → tapped Renew in the app
--   opened_at   → renewal page loaded
--   checkout_at → clicked "Renew my plan" (Stripe Checkout created)
--   paid_at     → Stripe confirmed payment (set by the webhook)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `renewal_tokens` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `token_hash`              CHAR(64)        NOT NULL,              -- hex SHA-256 of the token in the link
  `profile_id`              VARCHAR(64)     NOT NULL,
  `stripe_subscription_id`  VARCHAR(64)     NULL,                  -- the cancelled/expired subscription being renewed
  `expires_at`              DATETIME        NOT NULL,              -- UTC
  `used_at`                 DATETIME        NULL,                  -- UTC, set when checkout starts (one use)
  `opened_at`               DATETIME        NULL,                  -- UTC, first page load
  `open_count`              INT UNSIGNED    NOT NULL DEFAULT 0,
  `checkout_at`             DATETIME        NULL,
  `stripe_session_id`       VARCHAR(255)    NULL,
  `paid_at`                 DATETIME        NULL,
  `user_agent`              VARCHAR(255)    NULL,
  `created_at`              DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_rt_token_hash` (`token_hash`),
  KEY `idx_rt_profile` (`profile_id`),
  KEY `idx_rt_created` (`created_at`),
  KEY `idx_rt_stripe_session` (`stripe_session_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
