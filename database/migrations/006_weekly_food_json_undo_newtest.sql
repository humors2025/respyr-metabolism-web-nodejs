-- 006: one step back for the dietitian diet-plan editor.
--
-- Every write to weekly_food_json_suggestions_newtest.food_json (trainer
-- update, custom meal) first snapshots the row as it was, so Undo can take
-- back the LAST thing a dietitian did — the swap they regret — without
-- throwing the whole week away the way Reset does. The stack is per plan
-- row, capped at 25 (see src/utils/weeklyFoodJsonUndo.js), and is cleared by
-- Reset: nothing to step back to is the truth after a reset.
CREATE TABLE IF NOT EXISTS `weekly_food_json_undo_newtest` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `record_id`     INT UNSIGNED    NOT NULL COMMENT 'weekly_food_json_suggestions_newtest.id',
  `dietician_id`  VARCHAR(64)     NOT NULL,
  `profile_id`    VARCHAR(64)     NOT NULL,
  `label`         VARCHAR(120)    NULL     COMMENT 'what the following write did, e.g. "swapped Turkey salad sandwich"',
  `undo_group`    VARCHAR(64)     NULL     COMMENT 'one Save from the dashboard = several writes = one step back',
  `food_json`     LONGTEXT        NOT NULL COMMENT 'the plan BEFORE the write',
  `created_at`    DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_undo_record` (`record_id`, `id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
