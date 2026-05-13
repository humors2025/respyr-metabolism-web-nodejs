const express = require('express');
const router = express.Router();

const processController = require('../controllers/processController');
const latestTestsController = require(
  '../controllers/dietitian/api/web/get_score_trend1'
);
const latestTestByDateController = require(
  '../controllers/dietitian/api/web/get_latest_test_by_date'
);

const {
  get_dietician_logo,
} = require('../controllers/dietitian/api/web/get_client_image');


const loginController = require(
  '../controllers/dietitian/api/web/loginController'
);

const changePasswordController = require(
  '../controllers/dietitian/api/web/changePasswordController'
);

const createUserController = require(
  '../controllers/dietitian/api/web/createUserController'
);


const refreshTokenController = require(
  '../controllers/dietitian/api/web/refreshTokenController'
);

const logoutController = require(
  '../controllers/dietitian/api/web/logoutController'
);

const {
  get_test_analytics,
} = require("../controllers/dietitian/api/web/get_test_analytics");

const {
  test_statistic_by_dietitian,
} = require("../controllers/dietitian/api/web/test_statistic_by_dietitian");

const {
  get_test_stat,
} = require('../controllers/dietitian/api/web/get_test_stat');

const {
  get_clients_with_diet_plan,
} = require('../controllers/dietitian/api/web/get_clients_with_diet_plan');

const {
  get_client_data,
} = require('../controllers/dietitian/api/web/get_client_data');

const getClientImageController = require('../controllers/dietitian/api/web/get_client_image');

const weeklyAnalysis = require('../controllers/dietitian/api/web/weekly_analysis_complete1');

const checkWeeklyAnalysis = require('../controllers/dietitian/api/web/check_weekly_analysis');

const getProfileImageController = require('../controllers/dietitian/api/web/get_profile_image');

const {
  get_calander_fill_data,
} = require('../controllers/dietitian/api/web/get_calander_fill_data');

const {
  get_clients_data_total_missed_test,
} = require('../controllers/dietitian/api/web/get_clients_data_total_missed_test');


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

router.post('/process-data', authMiddleware, processController.processData);

router.post(
  '/dietitian/api/web/get_score_trend1',
  authMiddleware,
  latestTestsController.get_score_trend1
);

router.post(
  '/dietitian/api/web/get_latest_test_by_date',
  authMiddleware,
  latestTestByDateController.get_latest_test_by_date
);

router.post('/dietitian/api/web/get_test_stat',
authMiddleware,
get_test_stat);

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
router.post(
  '/auth/create-user',
  upload.single('logo'),
  createUserController.createUser
);

// 🔄 Refresh Token
router.post('/auth/refresh-token', refreshTokenController.refreshToken);

// 🚪 Logout
router.post('/auth/logout', logoutController.logout);

// 📊 Analytics
router.post('/dietitian/api/web/get_test_analytics', authMiddleware, get_test_analytics); 
router.post('/dietitian/api/web/test_statistic_by_dietitian/', authMiddleware,test_statistic_by_dietitian);

router.post(
  '/dietitian/api/web/get_clients_with_diet_plan',
  authMiddleware,
  get_clients_with_diet_plan
);

router.post(
  '/dietitian/api/web/get_client_data',
  authMiddleware,
  get_client_data
);

router.get(
  '/dietitian/api/web/get_client_image',
    authMiddleware,
  getClientImageController.get_client_image
);

router.post('/dietitian/api/web/weekly_analysis_complete1', authMiddleware,weeklyAnalysis.weekly_analysis_complete1);

router.post(
  '/dietitian/api/web/check_weekly_analysis',
  authMiddleware,
  checkWeeklyAnalysis.check_weekly_analysis
);

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
    console.log("ROUTE HIT: get_clients_data_total_missed_test v3");
    res.setHeader("X-Route-Version", "missed-test-route-v3");
    next();
  },
  authMiddleware,
  get_clients_data_total_missed_test
);

module.exports = router;

