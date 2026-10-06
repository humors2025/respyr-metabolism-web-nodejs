-- 007 down: drops the Field Console tables. This deletes the field CRM and its
-- history — take a dump of the fc_* tables first.
DROP TABLE IF EXISTS `fc_plan_stops`;
DROP TABLE IF EXISTS `fc_day_plans`;
DROP TABLE IF EXISTS `fc_place_checks`;
DROP TABLE IF EXISTS `fc_events`;
DROP TABLE IF EXISTS `fc_cards`;
DROP TABLE IF EXISTS `fc_board`;
DROP TABLE IF EXISTS `fc_reps`;
DROP TABLE IF EXISTS `fc_markets`;
