const express = require('express');
const router = express.Router();

// const processController = require('../controllers/processController');
// const latestTestsController = require(
//   '../controllers/dietitian/api/web/get_score_trend1'
// );
// const latestTestByDateController = require(
//   '../controllers/dietitian/api/web/get_latest_test_by_date'
// );

const {
  get_dietician_logo,
} = require('../controllers/dietitian/api/web/get_dietician_logo');


const loginController = require(
  '../controllers/dietitian/api/web/loginController'
);

const changePasswordController = require(
  '../controllers/dietitian/api/web/changePasswordController'
);

// const createUserController = require(
//   '../controllers/dietitian/api/web/createUserController'
// );


const refreshTokenController = require(
  '../controllers/dietitian/api/web/refreshTokenController'
);

const logoutController = require(
  '../controllers/dietitian/api/web/logoutController'
);

// const {
//   get_test_analytics,
// } = require("../controllers/dietitian/api/web/get_test_analytics");

// const {
//   test_statistic_by_dietitian,
// } = require("../controllers/dietitian/api/web/test_statistic_by_dietitian");

// const {
//   get_test_stat,
// } = require('../controllers/dietitian/api/web/get_test_stat');

// const {
//   get_clients_with_diet_plan,
// } = require('../controllers/dietitian/api/web/get_clients_with_diet_plan');

// const {
//   get_client_data,
// } = require('../controllers/dietitian/api/web/get_client_data');

const getClientImageController = require('../controllers/dietitian/api/web/get_client_image');

// const weeklyAnalysis = require('../controllers/dietitian/api/web/weekly_analysis_complete1');

// const checkWeeklyAnalysis = require('../controllers/dietitian/api/web/check_weekly_analysis');

const getProfileImageController = require('../controllers/dietitian/api/web/get_profile_image');

const {
  get_calander_fill_data,
} = require('../controllers/dietitian/api/web/get_calander_fill_data');

const {
  get_clients_data_total_missed_test,
} = require('../controllers/dietitian/api/web/get_clients_data_total_missed_test');

const {
  get_profile_details_dates_taken,
} = require('../controllers/dietitian/api/web/get_profile_details_dates_taken');


const {
  get_weekly_tab_list,
} = require("../controllers/dietitian/api/web/get_weekly_tab_list");


const {
  get_data_points_score_all_ranges_coach,
} = require("../controllers/dietitian/api/web/get_data_points_score_all_ranges_coach");


const {
  get_weekly_food_json_suggestions_weeks,
} = require("../controllers/dietitian/api/web/get_weekly_food_json_suggestions_weeks");


const {
  get_graph_all_seven_trends_graph,
} = require("../controllers/dietitian/api/web/get_graph_all_seven_trends_graph");


const {
  get_macro_summary_by_date,
} = require("../controllers/dietitian/api/web/get_macro_summary_by_date");

const {
  habitsTrackingUsersChoice,
} = require("../controllers/dietitian/api/web/habits-tracking-users-choice1");

const {
  getClientSelectedHabitDetail,
} = require("../controllers/dietitian/api/web/get-client-selected-habit-detail");

const {
  listAdminTrainerUsersJwt,
} = require("../controllers/dietitian/api/web/list-admin-trainer-users-jwt");

const {
  superAdminInviteAdmin,
} = require("../controllers/dietitian/api/web/super-admin-invite-admin");

const {
  listTrainerClientInvites,
} = require("../controllers/dietitian/api/web/list-trainer-client-invites");


const {
  superAdminOverview,
} = require("../controllers/dietitian/api/web/super-admin-overview");


const {
  listAdminTrainerUsers,
} = require("../controllers/dietitian/api/web/list-admin-trainer-users");


const {
  listAllTrainersForSuperAdmin,
} = require("../controllers/dietitian/api/web/list-all-trainers-for-super-admin");


const {
  get_search_clients_details,
} = require("../controllers/dietitian/api/web/get-search-clients-details");


const {
  trainerAdminClientsListDir,
} = require("../controllers/dietitian/api/web/trainer-admin-clients-list-dir");


const {
  trainerAdminOverview,
} = require("../controllers/dietitian/api/web/trainer-admin-overview");


const {
  trainerAdminTrainersSummary,
} = require("../controllers/dietitian/api/web/trainer-admin-trainers-summary");


const {
  trainerClientsOverviewForSuperAdmin,
} = require("../controllers/dietitian/api/web/trainer-clients-overview-for-super-admin");


const {
  getClientsDataTotalMissedTestMasked,
} = require("../controllers/dietitian/api/web/get-clients-data-total-missed-test-masked");


const {
  getDataPointsScoreAllRangesCoachMasking,
} = require("../controllers/dietitian/api/web/get-data-points-score-all-ranges-coach-masking");


const {
  resendUserInvite,
} = require("../controllers/dietitian/api/web/resend-user-invite");


const {
  adminInviteTrainer,
} = require("../controllers/dietitian/api/web/admin-invite-trainer");


const {
  revokeUserInvite,
} = require("../controllers/dietitian/api/web/revoke-user-invite");


const {
  referralClientList,
} = require("../controllers/dietitian/api/web/referral-client-list");


const {
  resendClientSubscriptionInvite,
} = require("../controllers/dietitian/api/web/resend-client-subscription-invite");


/* ===============================
   Middlewares
================================ */


const authMiddleware = require('../middlewares/authMiddleware');
// const loginRateLimiter = require('../middlewares/loginRateLimiter');
const {
  loginRateLimiter,
  loginIpRateLimiter,
} = require('../middlewares/loginRateLimiter');

const upload = require('../middlewares/upload');

/* ===============================
   Routes
================================ */

// router.post('/process-data', authMiddleware, processController.processData);

// router.post(
//   '/dietitian/api/web/get_score_trend1',
//   authMiddleware,
//   latestTestsController.get_score_trend1
// );

// router.post(
//   '/dietitian/api/web/get_latest_test_by_date',
//   authMiddleware,
//   latestTestByDateController.get_latest_test_by_date
// );

// router.post('/dietitian/api/web/get_test_stat',
// authMiddleware,
// get_test_stat);

// 🔐 LOGIN (Rate Limited – Sliding Window Counter)
// router.post(
//   '/auth/login',
//   loginRateLimiter,
//   loginController.login
// );

router.post(
  '/auth/login',
  loginIpRateLimiter,
  loginRateLimiter,
  loginController.login
);

// 🔐 Protected
router.post(
  '/auth/change-password',
  authMiddleware,
  changePasswordController.changePassword
);

// 👤 CREATE USER (with logo upload)
// router.post(
//   '/auth/create-user',
//   upload.single('logo'),
//   createUserController.createUser
// );

// 🔄 Refresh Token
router.post('/auth/refresh-token', refreshTokenController.refreshToken);

// 🚪 Logout
router.post('/auth/logout', logoutController.logout);

// 📊 Analytics
// router.post('/dietitian/api/web/get_test_analytics', authMiddleware, get_test_analytics); 
// router.post('/dietitian/api/web/test_statistic_by_dietitian/', authMiddleware,test_statistic_by_dietitian);

// router.post(
//   '/dietitian/api/web/get_clients_with_diet_plan',
//   authMiddleware,
//   get_clients_with_diet_plan
// );

// router.post(
//   '/dietitian/api/web/get_client_data',
//   authMiddleware,
//   get_client_data
// );

router.get(
  '/dietitian/api/web/get_client_image',
    authMiddleware,
  getClientImageController.get_client_image
);

router.get(
  '/dietitian/api/web/get_dietician_logo',
  authMiddleware,
  get_dietician_logo
);

// router.post('/dietitian/api/web/weekly_analysis_complete1', authMiddleware,weeklyAnalysis.weekly_analysis_complete1);

// router.post(
//   '/dietitian/api/web/check_weekly_analysis',
//   authMiddleware,
//   checkWeeklyAnalysis.check_weekly_analysis
// );

router.post(
  '/dietitian/api/web/get_calander_fill_data',
  authMiddleware,
  get_calander_fill_data
);

router.get(
  '/dietitian/api/web/get_profile_image',
   authMiddleware,
  getProfileImageController.get_profile_image
);

// router.post(
//   '/dietitian/api/web/get_clients_data_total_missed_test',
//   authMiddleware,
//   get_clients_data_total_missed_test
// );


router.post(
  "/dietitian/api/web/get_clients_data_total_missed_test",
  (req, res, next) => {
    res.setHeader("X-Route-Version", "missed-test-route-v3");
    next();
  },
  authMiddleware,
  get_clients_data_total_missed_test
);


router.post(
  "/dietitian/api/web/get-search-clients-details",
  (req, res, next) => {
    res.setHeader("X-Route-Version", "search-clients-details-v1");
    next();
  },
  authMiddleware,
  get_search_clients_details
);


router.post(
  '/dietitian/api/web/get_profile_details_dates_taken',
  authMiddleware,
  get_profile_details_dates_taken
);


router.post(
  "/dietitian/api/web/get-weekly-tab-list",
  authMiddleware,
  get_weekly_tab_list
);


router.post(
  "/dietitian/api/web/get_data_points_score_all_ranges_coach",
  authMiddleware,
  get_data_points_score_all_ranges_coach
);


router.post(
  "/dietitian/api/web/get_weekly_food_json_suggestions_weeks",
  authMiddleware,
  get_weekly_food_json_suggestions_weeks
);


router.get(
  "/dietitian/api/web/get_graph_all_seven_trends_graph",
  authMiddleware,
  get_graph_all_seven_trends_graph
);


router.post(
  "/dietitian/api/web/get_macro_summary_by_date",
  authMiddleware,
  get_macro_summary_by_date
);


router.post(
  "/dietitian/api/web/habits-tracking-users-choice1",
  authMiddleware,
  habitsTrackingUsersChoice
);


router.post(
  "/dietitian/api/web/get-client-selected-habit-detail",
  authMiddleware,
  getClientSelectedHabitDetail
);


router.post(
  "/dietitian/api/web/list-admin-trainer-users-jwt",
  authMiddleware,
  listAdminTrainerUsersJwt
);


router.post(
  "/dietitian/api/web/super-admin-invite-admin",
  authMiddleware,
  superAdminInviteAdmin
);


router.post(
  "/dietitian/api/web/list-trainer-client-invites",
  authMiddleware,
  listTrainerClientInvites
);


router.post(
  "/dietitian/api/web/super-admin-overview",
  authMiddleware,
  superAdminOverview
);


router.post(
  "/dietitian/api/web/list-admin-trainer-users",
  authMiddleware,
  listAdminTrainerUsers
);


router.post(
  "/dietitian/api/web/list-all-trainers-for-super-admin",
  authMiddleware,
  listAllTrainersForSuperAdmin
);


router.post(
  "/dietitian/api/web/trainer-admin-clients-list-dir",
  authMiddleware,
  trainerAdminClientsListDir
);


router.post(
  "/dietitian/api/web/trainer-admin-overview",
  authMiddleware,
  trainerAdminOverview
);


router.post(
  "/dietitian/api/web/trainer-admin-trainers-summary",
  authMiddleware,
  trainerAdminTrainersSummary
);


router.post(
  "/dietitian/api/web/trainer-clients-overview-for-super-admin",
  authMiddleware,
  trainerClientsOverviewForSuperAdmin
);


router.post(
  "/dietitian/api/web/get-clients-data-total-missed-test-masked",
  authMiddleware,
  getClientsDataTotalMissedTestMasked
);


router.post(
  "/dietitian/api/web/get-data-points-score-all-ranges-coach-masking",
  authMiddleware,
  getDataPointsScoreAllRangesCoachMasking
);


router.post(
  "/dietitian/api/web/resend-user-invite",
  authMiddleware,
  resendUserInvite
);


router.post(
  "/dietitian/api/web/admin-invite-trainer",
  authMiddleware,
  adminInviteTrainer
);


router.post(
  "/dietitian/api/web/revoke-user-invite",
  authMiddleware,
  revokeUserInvite
);


router.post(
  "/dietitian/api/web/referral-client-list",
  authMiddleware,
  referralClientList
);


router.post(
  "/dietitian/api/web/resend-client-subscription-invite",
  authMiddleware,
  resendClientSubscriptionInvite
);

module.exports = router;

