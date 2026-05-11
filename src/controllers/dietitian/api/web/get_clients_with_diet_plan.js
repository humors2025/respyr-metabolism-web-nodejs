const pool = require("../../../../config/db");
const axios = require("axios");
const dayjs = require("dayjs");
const utc = require("dayjs/plugin/utc");
const timezone = require("dayjs/plugin/timezone");
const isBetween = require("dayjs/plugin/isBetween");

const {
  requireDieticianSelfAccess,
} = require("../../../../utils/accessControl");

dayjs.extend(utc);
dayjs.extend(timezone);
dayjs.extend(isBetween);

const TZ = "Asia/Kolkata";
const isProduction = process.env.NODE_ENV === "production";

const DEFAULT_PAGE = 1;
const DEFAULT_LIMIT = 10;
const MAX_LIMIT = 50;

const PROFILE_IMAGE_BASE_URL =
  process.env.PROFILE_IMAGE_BASE_URL ||
  "https://humorstech.com/dietitian/api/web";

const METABOLISM_TARGET_URL =
  process.env.METABOLISM_TARGET_URL ||
  "https://respyr.in/metabolism_target_get";

/* ---------------------------
   Helper: Safe Integer
---------------------------- */
function toSafePositiveInt(value, fallback, maxValue = null) {
  const parsed = Number.parseInt(value, 10);

  if (!Number.isFinite(parsed) || Number.isNaN(parsed) || parsed < 1) {
    return fallback;
  }

  if (maxValue !== null) {
    return Math.min(parsed, maxValue);
  }

  return parsed;
}

/* ---------------------------
   Helper: Safe Number
---------------------------- */
function toSafePositiveNumber(value) {
  if (value === undefined || value === null || value === "") return null;

  const parsed = Number(value);

  if (!Number.isFinite(parsed) || parsed <= 0) return null;

  return parsed;
}

/* ---------------------------
   Helper: Plan Status
---------------------------- */
function computePlanStatus(start, end) {
  try {
    const today = dayjs().tz(TZ).startOf("day");

    const startDate = start ? dayjs(start).tz(TZ).startOf("day") : null;
    const endDate = end ? dayjs(end).tz(TZ).startOf("day") : null;

    if (!startDate && !endDate) return "unknown";
    if (endDate && endDate.isBefore(today)) return "completed";

    if (
      startDate &&
      endDate &&
      today.isBetween(startDate, endDate, null, "[]")
    ) {
      return "active";
    }

    if (startDate && startDate.isAfter(today)) return "not_started";
    if (!endDate && startDate && !startDate.isAfter(today)) return "active";
    if (!startDate && endDate && !endDate.isBefore(today)) return "active";

    return "unknown";
  } catch {
    return "unknown";
  }
}

/* ---------------------------
   Helper: Controlled concurrency
---------------------------- */
async function mapWithConcurrency(items, concurrency, mapper) {
  const results = new Array(items.length);
  let currentIndex = 0;

  async function worker() {
    while (currentIndex < items.length) {
      const index = currentIndex;
      currentIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, items.length) },
    () => worker()
  );

  await Promise.all(workers);

  return results;
}

/* ---------------------------
   Helper: Metabolism API
---------------------------- */
async function fetchMetabolismTarget(age, gender, height, weight) {
  const safeAge = toSafePositiveNumber(age);
  const safeHeight = toSafePositiveNumber(height);
  const safeWeight = toSafePositiveNumber(weight);

  if (!safeAge || !gender || !safeHeight || !safeWeight) return null;

  const safeGender = String(gender).trim().toLowerCase();

  if (!["male", "female"].includes(safeGender)) return null;

  try {
    const response = await axios.get(METABOLISM_TARGET_URL, {
      params: {
        age: safeAge,
        gender: safeGender,
        height_cm: safeHeight,
        current_weight_kg: safeWeight,
        diabetic: false,
      },
      timeout: 6000,
      maxRedirects: 0,
      validateStatus: (status) => status >= 200 && status < 300,
    });

    return response.data || null;
  } catch {
    /**
     * Do not expose external API failure to frontend.
     * Do not log age/gender/height/weight because these are PHI-like values.
     */
    return null;
  }
}

/* ---------------------------
   Main Controller
---------------------------- */
exports.get_clients_with_diet_plan = async (req, res) => {
  try {
    const dietician_id = req.body?.dietician_id || req.query?.dietician_id;

    /**
     * Critical VAPT check:
     * Prevents one dietician from accessing another dietician's clients.
     */
    const access = requireDieticianSelfAccess(req, dietician_id);

    if (!access.allowed) {
      return res.status(access.statusCode).json({
        success: false,
        status: false,
        error: access.message,
        message: access.message,
      });
    }

    const role = req.user?.role ? String(req.user.role).toLowerCase() : null;

    if (role !== "dietician") {
      return res.status(403).json({
        success: false,
        status: false,
        error: "Access denied",
        message: "Access denied",
      });
    }

    const normalizedDieticianId = access.dieticianId;

    /**
     * Safe pagination:
     * Prevents huge limit causing DB/API resource exhaustion.
     */
    const page = toSafePositiveInt(
      req.query.page || req.body.page,
      DEFAULT_PAGE
    );

    const limit = toSafePositiveInt(
      req.query.limit || req.body.limit,
      DEFAULT_LIMIT,
      MAX_LIMIT
    );

    const offset = (page - 1) * limit;

    /**
     * Total Count
     */
    const [[{ total }]] = await pool.execute(
      `
        SELECT COUNT(*) AS total
        FROM table_clients
        WHERE UPPER(TRIM(dietician_id)) = ?
      `,
      [normalizedDieticianId]
    );

    /**
     * Fetch clients.
     *
     * Important:
     * password removed from SELECT.
     * Never send password hash to frontend.
     */
    const [clients] = await pool.execute(
      `
        SELECT
          id,
          dietician_id,
          profile_id,
          phone_no,
          email,
          profile_name,
          age,
          gender,
          height,
          weight,
          region,
          location,
          is_notification_enabled,
          dttm
        FROM table_clients
        WHERE UPPER(TRIM(dietician_id)) = ?
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `,
      [normalizedDieticianId, limit, offset]
    );

    if (!clients.length) {
      return res.json({
        success: true,
        page,
        limit,
        total_records: total,
        total_pages: Math.ceil(total / limit),
        count: 0,
        data: [],
      });
    }

    const clientProfileIds = clients
      .map((client) => client.profile_id)
      .filter(Boolean);

    const plansByClientId = new Map();

    if (clientProfileIds.length) {
      const placeholders = clientProfileIds.map(() => "?").join(",");

      /**
       * Fetch plans in one query instead of one query per client.
       * This reduces DB load and improves VAPT/resource-consumption posture.
       */
      const [plans] = await pool.execute(
        `
          SELECT
            id,
            dietitian_id,
            client_id,
            plan_title,
            plan_start_date,
            plan_end_date,
            updated_at,
            calories_target,
            protein_target,
            fiber_target,
            water_target,
            goal,
            approach,
            status
          FROM table_diet_plan_strategy
          WHERE client_id IN (${placeholders})
            AND UPPER(TRIM(dietitian_id)) = ?
          ORDER BY updated_at DESC
        `,
        [...clientProfileIds, normalizedDieticianId]
      );

      for (const plan of plans) {
        if (!plansByClientId.has(plan.client_id)) {
          plansByClientId.set(plan.client_id, []);
        }

        plansByClientId.get(plan.client_id).push(plan);
      }
    }

    /**
     * Build response.
     * Controlled concurrency avoids too many external API calls at once.
     */
    const output = await mapWithConcurrency(clients, 5, async (client) => {
      const clientProfileId = client.profile_id;
      const dieticianId = client.dietician_id;

      const clientData = {
        ...client,
      };

      /**
       * Existing response field preserved.
       *
       * Security note:
       * This URL should ideally point to a protected or signed image endpoint.
       */
      clientData.profile_image_url = `${PROFILE_IMAGE_BASE_URL}/get_profile_image.php?profile_id=${encodeURIComponent(
        clientProfileId
      )}&dietician_id=${encodeURIComponent(dieticianId)}`;

      clientData.metabolism_target = await fetchMetabolismTarget(
        client.age,
        client.gender,
        client.height,
        client.weight
      );

      const clientPlans = plansByClientId.get(clientProfileId) || [];

      const active = [];
      const completed = [];
      const not_started = [];

      for (const plan of clientPlans) {
        const planWithStatus = {
          ...plan,
          plan_status: computePlanStatus(
            plan.plan_start_date,
            plan.plan_end_date
          ),
        };

        if (planWithStatus.plan_status === "active") {
          active.push(planWithStatus);
        } else if (planWithStatus.plan_status === "completed") {
          completed.push(planWithStatus);
        } else if (planWithStatus.plan_status === "not_started") {
          not_started.push(planWithStatus);
        }
      }

      clientData.plans_summary = {
        active,
        completed,
        not_started,
      };

      clientData.plans_count = {
        total: active.length + completed.length + not_started.length,
        active: active.length,
        completed: completed.length,
        not_started: not_started.length,
      };

      return clientData;
    });

    return res.json({
      success: true,
      page,
      limit,
      total_records: total,
      total_pages: Math.ceil(total / limit),
      count: output.length,
      data: output,
    });
  } catch (error) {
    console.error("GET_CLIENTS_WITH_DIET_PLAN_FAILED", {
      message: error.message,
      endpoint: "/dietitian/api/web/get_clients_with_diet_plan",
    });

    return res.status(500).json({
      success: false,
      status: false,
      error: "Internal server error",
      ...(isProduction ? {} : { details: error.message }),
    });
  }
};











// const pool = require('../../../../config/db');
// const axios = require('axios');
// const dayjs = require('dayjs');
// const utc = require('dayjs/plugin/utc');
// const timezone = require('dayjs/plugin/timezone');

// dayjs.extend(utc);
// dayjs.extend(timezone);

// const TZ = 'Asia/Kolkata';

// /* ---------------------------
//    Helper: Plan Status
// ---------------------------- */
// function computePlanStatus(start, end) {
//   try {
//     const today = dayjs().tz(TZ).startOf('day');

//     const startDate = start ? dayjs(start).tz(TZ) : null;
//     const endDate = end ? dayjs(end).tz(TZ) : null;

//     if (!startDate && !endDate) return 'unknown';
//     if (endDate && endDate.isBefore(today)) return 'completed';
//     if (startDate && endDate && today.isBetween(startDate, endDate, null, '[]')) return 'active';
//     if (startDate && startDate.isAfter(today)) return 'not_started';
//     if (!endDate && startDate && !startDate.isAfter(today)) return 'active';
//     if (!startDate && endDate && !endDate.isBefore(today)) return 'active';

//     return 'unknown';
//   } catch {
//     return 'unknown';
//   }
// }

// /* ---------------------------
//    Helper: Metabolism API
// ---------------------------- */
// async function fetchMetabolismTarget(age, gender, height, weight) {
//   if (!age || !gender || !height || !weight) return null;

//   gender = gender.toLowerCase();
//   if (!['male', 'female'].includes(gender)) return null;

//   try {
//     const response = await axios.get(
//       'https://respyr.in/metabolism_target_get',
//       {
//         params: {
//           age,
//           gender,
//           height_cm: height,
//           current_weight_kg: weight,
//           diabetic: false,
//         },
//         timeout: 6000,
//       }
//     );

//     return response.data || null;
//   } catch {
//     return null;
//   }
// }

// /* ---------------------------
//    Main Controller
// ---------------------------- */
// exports.get_clients_with_diet_plan = async (req, res) => {
//   try {
//     const dietician_id =
//       req.body?.dietician_id ||
//       req.query?.dietician_id;

//     if (!dietician_id) {
//       return res.status(400).json({
//         error: 'dietician_id is required',
//       });
//     }

//     /* Pagination (ADDED ONLY) */
//     const page = parseInt(req.query.page || req.body.page || 1);
//     const limit = parseInt(req.query.limit || req.body.limit || 10);
//     const offset = (page - 1) * limit;

//     /* Total Count */
//     const [[{ total }]] = await pool.query(
//       `SELECT COUNT(*) AS total
//        FROM table_clients
//        WHERE dietician_id = ?`,
//       [dietician_id]
//     );

//     /* 1️⃣ Fetch Clients */
//     const [clients] = await pool.query(
//       `SELECT
//         id,
//         dietician_id,
//         profile_id,
//         phone_no,
//         email,
//         profile_name,
//         age,
//         gender,
//         height,
//         weight,
//         region,
//         location,
//         password,
//         is_notification_enabled,
//         dttm
//        FROM table_clients
//        WHERE dietician_id = ?
//        ORDER BY id DESC
//        LIMIT ? OFFSET ?`,
//       [dietician_id, limit, offset]
//     );

//     if (!clients.length) {
//       return res.json({
//         success: true,
//         page,
//         limit,
//         total_records: total,
//         total_pages: Math.ceil(total / limit),
//         count: 0,
//         data: [],
//       });
//     }

//     const base_url = 'https://humorstech.com/dietitian/api/web';

//     /* 2️⃣ Plan Query */
//     const planQuery = `
//       SELECT
//         id,
//         dietitian_id,
//         client_id,
//         plan_title,
//         plan_start_date,
//         plan_end_date,
//         updated_at,
//         calories_target,
//         protein_target,
//         fiber_target,
//         water_target,
//         goal,
//         approach,
//         status
//       FROM table_diet_plan_strategy
//       WHERE client_id = ?
//         AND dietitian_id = ?
//       ORDER BY updated_at DESC
//     `;

//     const output = [];

//     for (const c of clients) {
//       /* ---------------------------
//          Industry-standard aliases
//       ---------------------------- */
//       const {
//         profile_id: clientProfileId,
//         dietician_id: dieticianId,
//         age: clientAgeYears,
//         gender: clientGender,
//         height: clientHeightCm,
//         weight: clientWeightKg,
//       } = c;

//       /* Profile Image */
//       c.profile_image_url = `${base_url}/get_profile_image.php?profile_id=${encodeURIComponent(
//         clientProfileId
//       )}&dietician_id=${encodeURIComponent(dieticianId)}`;

//       /* Metabolism */
//       c.metabolism_target = await fetchMetabolismTarget(
//         clientAgeYears,
//         clientGender,
//         clientHeightCm,
//         clientWeightKg
//       );

//       /* Plans */
//       const [plans] = await pool.query(planQuery, [
//         clientProfileId,
//         dietician_id,
//       ]);

//       const active = [];
//       const completed = [];
//       const not_started = [];

//       for (const plan of plans) {
//         plan.plan_status = computePlanStatus(
//           plan.plan_start_date,
//           plan.plan_end_date
//         );

//         if (plan.plan_status === 'active') active.push(plan);
//         else if (plan.plan_status === 'completed') completed.push(plan);
//         else if (plan.plan_status === 'not_started') not_started.push(plan);
//       }

//       c.plans_summary = {
//         active,
//         completed,
//         not_started,
//       };

//       c.plans_count = {
//         total: active.length + completed.length + not_started.length,
//         active: active.length,
//         completed: completed.length,
//         not_started: not_started.length,
//       };

//       output.push(c);
//     }

//     return res.json({
//       success: true,
//       page,
//       limit,
//       total_records: total,
//       total_pages: Math.ceil(total / limit),
//       count: output.length,
//       data: output,
//     });
//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({
//       error: 'Internal server error',
//     });
//   }
// };








