-- 007: Field Console CRM — the US field team's gym pipeline.
--
-- Until now the console kept its CRM in files on one laptop (crm.json, crm.log,
-- plans.json, checks.json, team.json). These tables are the same data, in the
-- database the reps already sign in to, so salesforce.rysflo.com can save.
--
-- Two kinds of table:
--   current state  fc_cards, fc_day_plans/fc_plan_stops, fc_place_checks,
--                  fc_markets, fc_reps, fc_board — updated in place.
--   history        fc_events — append-only. The API never UPDATEs or DELETEs a
--                  row here. Every card change writes its event in the same
--                  transaction, so the card and its history can't disagree, and
--                  any card can be rebuilt from its events.
--
-- Times are UTC DATETIME(3). `on_day` / *_date columns are the rep's calendar
-- day in their market's time zone (a 9pm Texas visit is that day, not UTC's).

-- ----------------------------------------------------------------------------
-- Markets and the people working them
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `fc_markets` (
  `key`         VARCHAR(32)   NOT NULL,                  -- 'rgv', 'hou', 'phoenix'
  `name`        VARCHAR(60)   NOT NULL,
  `metros`      JSON          NOT NULL,                  -- ["Rio Grande Valley"], names as in the prospect data
  `tz`          VARCHAR(64)   NOT NULL DEFAULT 'America/Chicago',
  `tz_label`    VARCHAR(30)   NOT NULL DEFAULT '',       -- what the clock is called: "Texas"
  `cc`          VARCHAR(4)    NOT NULL DEFAULT '1',      -- phone country code
  `position`    SMALLINT      NOT NULL DEFAULT 0,
  `created_at`  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)   NULL ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `fc_reps` (
  `key`         VARCHAR(32)   NOT NULL,                  -- 'derek'; what events and cards refer to
  `user_id`     VARCHAR(150)  NULL,                      -- app_user_roles.user_id (login email, lowercase)
  `name`        VARCHAR(40)   NOT NULL,
  `role`        ENUM('rep','manager') NOT NULL DEFAULT 'rep',
  `market_key`  VARCHAR(32)   NULL,
  `phone`       VARCHAR(20)   NOT NULL DEFAULT '',       -- E.164, '+19565550123'
  `base_lat`    DECIMAL(10,7)  NULL,                      -- where their day starts
  `base_lon`    DECIMAL(10,7)  NULL,
  `base_label`  VARCHAR(120)  NOT NULL DEFAULT '',
  `position`    SMALLINT      NOT NULL DEFAULT 0,
  `active`      TINYINT(1)    NOT NULL DEFAULT 1,
  `created_at`  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)   NULL ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`key`),
  UNIQUE KEY `uq_fc_reps_user` (`user_id`),
  KEY `idx_fc_reps_market` (`market_key`),
  CONSTRAINT `fk_fc_reps_market` FOREIGN KEY (`market_key`) REFERENCES `fc_markets` (`key`)
    ON UPDATE CASCADE ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- The board's stage names, rungs and per-stage fields. One row; keys never change.
CREATE TABLE IF NOT EXISTS `fc_board` (
  `id`          TINYINT       NOT NULL DEFAULT 1,
  `columns`     JSON          NOT NULL,
  `updated_at`  DATETIME(3)   NULL ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Cards: one per business in the pipeline, keyed by Google place_id
-- (or 'manual:<slug>' for a place the prospect list doesn't have)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `fc_cards` (
  `place_id`        VARCHAR(255)  NOT NULL,
  `col`             VARCHAR(40)   NOT NULL DEFAULT 'planned',  -- planned|visited|qr|stripe|sales
  `sub`             VARCHAR(40)   NOT NULL DEFAULT '',         -- the Visited rung, l1..l5
  `dead`            ENUM('','closed','moved') NOT NULL DEFAULT '',
  `rep_key`         VARCHAR(32)   NOT NULL DEFAULT '',
  -- who they dealt with
  `contact`         VARCHAR(200)  NOT NULL DEFAULT '',
  `role`            VARCHAR(200)  NOT NULL DEFAULT '',
  `phone`           VARCHAR(20)   NOT NULL DEFAULT '',
  `email`           VARCHAR(200)  NOT NULL DEFAULT '',
  -- what's next
  `next_action`     VARCHAR(500)  NOT NULL DEFAULT '',
  `next_date`       DATE          NULL,
  -- QR stage
  `qr_where`        VARCHAR(500)  NOT NULL DEFAULT '',
  `device_given`    ENUM('','yes','no') NOT NULL DEFAULT '',
  `incentive`       DECIMAL(10,2) NULL,
  `incentive_note`  VARCHAR(500)  NOT NULL DEFAULT '',
  -- a place carrying its own identity (not in the prospect list)
  `name`            VARCHAR(200)  NOT NULL DEFAULT '',
  `address`         VARCHAR(300)  NOT NULL DEFAULT '',
  `city`            VARCHAR(100)  NOT NULL DEFAULT '',
  `metro`           VARCHAR(100)  NOT NULL DEFAULT '',
  `kind`            VARCHAR(100)  NOT NULL DEFAULT '',
  `via`             VARCHAR(200)  NOT NULL DEFAULT '',
  `lat`             DECIMAL(10,7)  NULL,
  `lon`             DECIMAL(10,7)  NULL,
  `photo`           VARCHAR(500)  NOT NULL DEFAULT '',
  `rating`          VARCHAR(8)    NOT NULL DEFAULT '',
  `reviews`         VARCHAR(12)   NOT NULL DEFAULT '',
  `g_type`          VARCHAR(100)  NOT NULL DEFAULT '',
  `hours`           TEXT          NULL,
  `verified`        VARCHAR(40)   NOT NULL DEFAULT '',
  `confirm`         VARCHAR(500)  NOT NULL DEFAULT '',
  -- the day plan it is on
  `plan_id`         VARCHAR(80)   NOT NULL DEFAULT '',
  `plan_date`       DATE          NULL,
  `plan_stop`       SMALLINT      NULL,
  -- removed from the CRM ("not pursuing"), never deleted
  `removed`         TINYINT(1)    NOT NULL DEFAULT 0,
  `removed_reason`  TEXT          NULL,
  `removed_at`      DATETIME(3)   NULL,
  `removed_by`      VARCHAR(32)   NOT NULL DEFAULT '',
  -- bookkeeping the board and Analytics read
  `col_since`       DATETIME(3)   NULL,
  `first_visit`     DATE          NULL,
  `last_visit`      DATE          NULL,
  `touches`         INT UNSIGNED  NOT NULL DEFAULT 0,
  `notes_n`         INT UNSIGNED  NOT NULL DEFAULT 0,
  `last_note`       VARCHAR(280)  NOT NULL DEFAULT '',
  `last_note_at`    DATETIME(3)   NULL,
  `created_at`      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`      DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`place_id`),
  KEY `idx_fc_cards_col` (`col`),
  KEY `idx_fc_cards_rep` (`rep_key`),
  KEY `idx_fc_cards_plan_date` (`plan_date`),
  KEY `idx_fc_cards_next_date` (`next_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- History: append-only. type = added|move|edit|note|removed|restored|unplanned
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `fc_events` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `place_id`    VARCHAR(255)  NOT NULL,
  `type`        VARCHAR(20)   NOT NULL,
  `rep_key`     VARCHAR(32)   NOT NULL DEFAULT '',
  `at`          DATETIME(3)   NOT NULL,                  -- when it was saved (UTC)
  `on_day`      DATE          NOT NULL,                  -- the day it happened, as the rep says
  `col`         VARCHAR(40)   NULL,
  `sub`         VARCHAR(40)   NULL,
  `from_col`    VARCHAR(40)   NULL,
  `from_sub`    VARCHAR(40)   NULL,
  `text`        TEXT          NULL,                      -- a note
  `reason`      TEXT          NULL,                      -- why it was removed
  `changes`     JSON          NULL,                      -- {"phone": ["", "+1956…"]}
  `extra`       JSON          NULL,                      -- anything else the event carried
  PRIMARY KEY (`id`),
  KEY `idx_fc_events_place` (`place_id`, `at`),
  KEY `idx_fc_events_day` (`on_day`),
  KEY `idx_fc_events_rep_day` (`rep_key`, `on_day`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Day plans: a rep's day, its stops in order. A gym is on one day at a time
-- (per rep), which the API enforces by moving it in one transaction.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `fc_day_plans` (
  `id`          VARCHAR(80)   NOT NULL,                  -- '<rep>:<YYYY-MM-DD>'
  `rep_key`     VARCHAR(32)   NOT NULL,
  `plan_date`   DATE          NOT NULL,
  `name`        VARCHAR(120)  NOT NULL DEFAULT '',
  `created_at`  DATETIME(3)   NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at`  DATETIME(3)   NULL ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_fc_day_plans_rep_date` (`rep_key`, `plan_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `fc_plan_stops` (
  `plan_id`     VARCHAR(80)   NOT NULL,
  `position`    SMALLINT      NOT NULL,                  -- 1-based stop number
  `place_id`    VARCHAR(255)  NOT NULL,
  PRIMARY KEY (`plan_id`, `position`),
  UNIQUE KEY `uq_fc_plan_stops_place` (`plan_id`, `place_id`),
  KEY `idx_fc_plan_stops_place` (`place_id`),
  CONSTRAINT `fk_fc_plan_stops_plan` FOREIGN KEY (`plan_id`) REFERENCES `fc_day_plans` (`id`)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------
-- Is it still there? Latest Google business status per place, checked at most
-- weekly, with the day it changed.
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS `fc_place_checks` (
  `place_id`    VARCHAR(255)  NOT NULL,
  `status`      VARCHAR(40)   NOT NULL,                  -- OPERATIONAL|CLOSED_PERMANENTLY|CLOSED_TEMPORARILY|NOT_FOUND
  `name`        VARCHAR(200)  NOT NULL DEFAULT '',
  `checked_at`  DATETIME(3)   NOT NULL,
  `checked_on`  DATE          NOT NULL,
  `was`         VARCHAR(40)   NULL,                      -- the status before it changed
  `changed_on`  DATE          NULL,
  PRIMARY KEY (`place_id`),
  KEY `idx_fc_place_checks_on` (`checked_on`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
