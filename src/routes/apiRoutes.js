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
  getProfileDetailsDatesTaken,
} = require('../controllers/dietitian/api/web/get-profile-details-dates-taken');


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
  trainerUpdateWeeklyFoodJson,
} = require("../controllers/dietitian/api/web/trainer-update-weekly-food-json");


const {
  foodJsonSuggestionApprovePlan,
} = require("../controllers/dietitian/api/web/food_json_suggestion_approve_plan");


const {
  levelTypeUpdateChange,
} = require("../controllers/dietitian/api/web/level-type-update-change");


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
  get_client_profile_details,
} = require("../controllers/dietitian/api/web/get_client_profile_details");

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
  sendTrainerClientInvite,
} = require("../controllers/dietitian/api/web/send_trainer_client_invite");

const {
  resendClientSubscriptionInvite,
} = require("../controllers/dietitian/api/web/resend-client-subscription-invite");

const {
  revokeClientSubscriptionInvite,
} = require("../controllers/dietitian/api/web/revoke-client-subscription-invite");

const {
  extendClientFreeTrial14Days,
} = require("../controllers/dietitian/api/web/extend-client-free-trial-14days");


const {
  superAdminOverview,
} = require("../controllers/dietitian/api/web/super-admin-overview");


const {
  superAdminAllClientsOverview,
} = require("../controllers/dietitian/api/web/super-admin-all-clients-overview");


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
  get_clients_with_diet_plan,
} = require("../controllers/dietitian/api/web/get_clients_with_diet_plan");


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
  superAdminTrainersSummary,
} = require("../controllers/dietitian/api/web/super-admin-trainers-summary");


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
  getDataPointsScoreAllRangesCoach,
} = require("../controllers/dietitian/api/web/get-data-points-score-all-ranges-coach");


const {
  getGraphAllSevenTrendsGraph,
} = require("../controllers/dietitian/api/web/get-graph-all-seven-trends-graph");


const {
  resendUserInvite,
} = require("../controllers/dietitian/api/web/resend-user-invite");


const {
  adminInviteTrainer,
} = require("../controllers/dietitian/api/web/admin-invite-trainer");


const {
  superAdminInviteTrainer,
} = require("../controllers/dietitian/api/web/super-admin-invite-trainer");


const {
  acceptInvite,
} = require("../controllers/dietitian/api/web/accept-invite");


const {
  agreementUploadUrl,
} = require("../controllers/dietitian/api/web/agreement-upload-url");


const {
  invitePreview,
} = require("../controllers/dietitian/api/web/invite-preview");


const {
  superAdminResendTrainers,
} = require("../controllers/dietitian/api/web/super-admin-resend-trainers");


const {
  superAdminRevokeTrainers,
} = require("../controllers/dietitian/api/web/super-admin-revoke-trainers");


const {
  revokeUserInvite,
} = require("../controllers/dietitian/api/web/revoke-user-invite");


const {
  referralClientList,
} = require("../controllers/dietitian/api/web/referral-client-list");


// 🔑 Forgot-password (OTP) flow — public, rate-limited
const {
  sendDietitianOtp,
} = require("../controllers/dietitian/api/web/send_diatitian_otp");

const {
  verifyDietitianOtp,
} = require("../controllers/dietitian/api/web/verify_diatitian_otp");

const {
  updateDietitianPassword,
} = require("../controllers/dietitian/api/web/update_diatitian_password");



/* ===============================
   Middlewares
================================ */


const authMiddleware = require('../middlewares/authMiddleware');
// const loginRateLimiter = require('../middlewares/loginRateLimiter');
const {
  loginRateLimiter,
  loginIpRateLimiter,
} = require('../middlewares/loginRateLimiter');

const {
  otpSendRateLimiter,
  otpSendIpRateLimiter,
  otpVerifyRateLimiter,
  otpVerifyIpRateLimiter,
  passwordResetRateLimiter,
} = require('../middlewares/otpRateLimiter');

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

// 🔑 Forgot-password OTP flow (public — secured by rate limiting + OTP/token)
router.post(
  '/auth/send_diatitian_otp',
  otpSendIpRateLimiter,
  otpSendRateLimiter,
  sendDietitianOtp
);

router.post(
  '/auth/verify_diatitian_otp',
  otpVerifyIpRateLimiter,
  otpVerifyRateLimiter,
  verifyDietitianOtp
);

router.post(
  '/auth/update_diatitian_password',
  passwordResetRateLimiter,
  updateDietitianPassword
);

// Public token-redemption endpoint. No authMiddleware — the single-use invite
// token IS the credential. IP rate-limited to blunt DB-abuse / token guessing.
router.post(
  '/dietitian/api/web/accept-invite',
  loginIpRateLimiter,
  acceptInvite
);


router.post(
  ["/dietitian/api/web/agreement-upload-url", "/agreement-upload-url"],
  loginIpRateLimiter,
  agreementUploadUrl
);

// Public token-preview endpoint. No authMiddleware — read-only lookup keyed by
// the single-use invite token, used to pre-fill the accept screen. IP
// rate-limited to blunt enumeration / DB-abuse.
//
// Mounted at BOTH paths on purpose: the API Gateway route is the flat
// `/invite-preview` (after stage-strip Express sees `/invite-preview`), while
// the rest of the app — and any caller using the full API path — uses
// `/dietitian/api/web/invite-preview`. Accepting both means the endpoint
// resolves no matter whether the gateway forwards the short path or rewrites it
// to the full one, so it can never 404 at the Express layer over a prefix
// mismatch.
router.post(
  ['/dietitian/api/web/invite-preview', '/invite-preview'],
  loginIpRateLimiter,
  invitePreview
);

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
  getProfileImageController.get_profile_image
);

// router.post(
//   '/dietitian/api/web/get_clients_data_total_missed_test',
//   authMiddleware,
//   get_clients_data_total_missed_test
// );


router.post(
  "/dietitian/api/web/get-clients-data-total-missed-test",
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
  "/dietitian/api/web/get_clients_with_diet_plan",
  authMiddleware,
  get_clients_with_diet_plan
);


router.post(
  '/dietitian/api/web/get_profile_details_dates_taken',
  authMiddleware,
  get_profile_details_dates_taken
);

router.post(
  '/dietitian/api/web/get-profile-details-dates-taken',
  authMiddleware,
  getProfileDetailsDatesTaken
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


router.post(
  "/dietitian/api/web/trainer-update-weekly-food-json",
  authMiddleware,
  trainerUpdateWeeklyFoodJson
);


router.post(
  "/dietitian/api/web/food_json_suggestion_approve_plan",
  authMiddleware,
  foodJsonSuggestionApprovePlan
);


router.post(
  "/dietitian/api/web/level-type-update-change",
  authMiddleware,
  levelTypeUpdateChange
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
  "/dietitian/api/web/get_client_profile_details",
  authMiddleware,
  get_client_profile_details
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
  "/dietitian/api/web/send_trainer_client_invite",
  authMiddleware,
  sendTrainerClientInvite
);


router.post(
  "/dietitian/api/web/resend-client-subscription-invite",
  authMiddleware,
  resendClientSubscriptionInvite
);


router.post(
  "/dietitian/api/web/revoke-client-subscription-invite",
  authMiddleware,
  revokeClientSubscriptionInvite
);


router.post(
  "/dietitian/api/web/extend-client-free-trial-14days",
  authMiddleware,
  extendClientFreeTrial14Days
);


router.post(
  "/dietitian/api/web/super-admin-overview",
  authMiddleware,
  superAdminOverview
);


router.post(
  "/dietitian/api/web/super-admin-all-clients-overview",
  authMiddleware,
  superAdminAllClientsOverview
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
  "/dietitian/api/web/super-admin-trainers-summary",
  authMiddleware,
  superAdminTrainersSummary
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
  "/dietitian/api/web/get-data-points-score-all-ranges-coach",
  authMiddleware,
  getDataPointsScoreAllRangesCoach
);


// GET-only — matches the PHP REQUEST_METHOD gate. Identity is still token-bound
// via authMiddleware + requireProfileAccess inside the controller.
router.get(
  "/dietitian/api/web/get-graph-all-seven-trends-graph",
  authMiddleware,
  getGraphAllSevenTrendsGraph
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
  "/dietitian/api/web/super-admin-invite-trainer",
  authMiddleware,
  superAdminInviteTrainer
);


router.post(
  "/dietitian/api/web/super-admin-resend-trainers",
  authMiddleware,
  superAdminResendTrainers
);


router.post(
  "/dietitian/api/web/super-admin-revoke-trainers",
  authMiddleware,
  superAdminRevokeTrainers
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


module.exports = router;

