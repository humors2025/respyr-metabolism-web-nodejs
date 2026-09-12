-- 2026-09-12 — allergies + food_preferences on user_habits
--
-- Read by : src/controllers/dietitian/api/web/get_latest_72hr_tests.js
--           habits-manager.controller.js  (action: fetch_preferences)
-- Written : habits-manager.controller.js  (action: save_preferences)
--
-- Shape:
--   allergies        JSON list of strings            e.g. ["nuts","gluten","dairy"]
--   food_preferences JSON object {include, exclude}  e.g. {"include":["yogurt"],"exclude":["ham"]}
--
-- Both are nullable: NULL / absent reads back as [] and {include:[],exclude:[]}.
-- MySQL 8.0 (prod + UAT Docker 8.0.46). Run once per environment, UAT first.
-- Safe to re-run: the ALTERs are guarded by an information_schema check.

SET @db := DATABASE();

SET @has_allergies := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_habits' AND COLUMN_NAME = 'allergies'
);
SET @sql := IF(
  @has_allergies = 0,
  'ALTER TABLE user_habits ADD COLUMN allergies JSON NULL AFTER food_type',
  'SELECT ''user_habits.allergies already exists'' AS note'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

SET @has_prefs := (
  SELECT COUNT(*) FROM information_schema.COLUMNS
   WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_habits' AND COLUMN_NAME = 'food_preferences'
);
SET @sql := IF(
  @has_prefs = 0,
  'ALTER TABLE user_habits ADD COLUMN food_preferences JSON NULL AFTER allergies',
  'SELECT ''user_habits.food_preferences already exists'' AS note'
);
PREPARE stmt FROM @sql; EXECUTE stmt; DEALLOCATE PREPARE stmt;

-- Verify
SELECT COLUMN_NAME, COLUMN_TYPE, IS_NULLABLE
  FROM information_schema.COLUMNS
 WHERE TABLE_SCHEMA = @db AND TABLE_NAME = 'user_habits'
   AND COLUMN_NAME IN ('allergies', 'food_preferences');
