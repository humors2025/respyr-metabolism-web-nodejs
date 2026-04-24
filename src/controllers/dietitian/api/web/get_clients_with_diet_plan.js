const pool = require('../../../../config/db');
const axios = require('axios');
const dayjs = require('dayjs');
const utc = require('dayjs/plugin/utc');
const timezone = require('dayjs/plugin/timezone');

dayjs.extend(utc);
dayjs.extend(timezone);

const TZ = 'Asia/Kolkata';

/* ---------------------------
   Helper: Plan Status
---------------------------- */
function computePlanStatus(start, end) {
  try {
    const today = dayjs().tz(TZ).startOf('day');

    const startDate = start ? dayjs(start).tz(TZ) : null;
    const endDate = end ? dayjs(end).tz(TZ) : null;

    if (!startDate && !endDate) return 'unknown';
    if (endDate && endDate.isBefore(today)) return 'completed';
    if (startDate && endDate && today.isBetween(startDate, endDate, null, '[]')) return 'active';
    if (startDate && startDate.isAfter(today)) return 'not_started';
    if (!endDate && startDate && !startDate.isAfter(today)) return 'active';
    if (!startDate && endDate && !endDate.isBefore(today)) return 'active';

    return 'unknown';
  } catch {
    return 'unknown';
  }
}

/* ---------------------------
   Helper: Metabolism API
---------------------------- */
async function fetchMetabolismTarget(age, gender, height, weight) {
  if (!age || !gender || !height || !weight) return null;

  gender = gender.toLowerCase();
  if (!['male', 'female'].includes(gender)) return null;

  try {
    const response = await axios.get(
      'https://respyr.in/metabolism_target_get',
      {
        params: {
          age,
          gender,
          height_cm: height,
          current_weight_kg: weight,
          diabetic: false,
        },
        timeout: 6000,
      }
    );

    return response.data || null;
  } catch {
    return null;
  }
}

/* ---------------------------
   Main Controller
---------------------------- */
exports.get_clients_with_diet_plan = async (req, res) => {
  try {
    const dietician_id =
      req.body?.dietician_id ||
      req.query?.dietician_id;

    if (!dietician_id) {
      return res.status(400).json({
        error: 'dietician_id is required',
      });
    }

    /* Pagination (ADDED ONLY) */
    const page = parseInt(req.query.page || req.body.page || 1);
    const limit = parseInt(req.query.limit || req.body.limit || 10);
    const offset = (page - 1) * limit;

    /* Total Count */
    const [[{ total }]] = await pool.query(
      `SELECT COUNT(*) AS total
       FROM table_clients
       WHERE dietician_id = ?`,
      [dietician_id]
    );

    /* 1️⃣ Fetch Clients */
    const [clients] = await pool.query(
      `SELECT
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
        password,
        is_notification_enabled,
        dttm
       FROM table_clients
       WHERE dietician_id = ?
       ORDER BY id DESC
       LIMIT ? OFFSET ?`,
      [dietician_id, limit, offset]
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

    const base_url = 'https://humorstech.com/dietitian/api/web';

    /* 2️⃣ Plan Query */
    const planQuery = `
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
      WHERE client_id = ?
        AND dietitian_id = ?
      ORDER BY updated_at DESC
    `;

    const output = [];

    for (const c of clients) {
      /* ---------------------------
         Industry-standard aliases
      ---------------------------- */
      const {
        profile_id: clientProfileId,
        dietician_id: dieticianId,
        age: clientAgeYears,
        gender: clientGender,
        height: clientHeightCm,
        weight: clientWeightKg,
      } = c;

      /* Profile Image */
      c.profile_image_url = `${base_url}/get_profile_image.php?profile_id=${encodeURIComponent(
        clientProfileId
      )}&dietician_id=${encodeURIComponent(dieticianId)}`;

      /* Metabolism */
      c.metabolism_target = await fetchMetabolismTarget(
        clientAgeYears,
        clientGender,
        clientHeightCm,
        clientWeightKg
      );

      /* Plans */
      const [plans] = await pool.query(planQuery, [
        clientProfileId,
        dietician_id,
      ]);

      const active = [];
      const completed = [];
      const not_started = [];

      for (const plan of plans) {
        plan.plan_status = computePlanStatus(
          plan.plan_start_date,
          plan.plan_end_date
        );

        if (plan.plan_status === 'active') active.push(plan);
        else if (plan.plan_status === 'completed') completed.push(plan);
        else if (plan.plan_status === 'not_started') not_started.push(plan);
      }

      c.plans_summary = {
        active,
        completed,
        not_started,
      };

      c.plans_count = {
        total: active.length + completed.length + not_started.length,
        active: active.length,
        completed: completed.length,
        not_started: not_started.length,
      };

      output.push(c);
    }

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
    console.error(error);
    return res.status(500).json({
      error: 'Internal server error',
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
//        WHERE dietician_id = ?`,
//       [dietician_id]
//     );

//     if (!clients.length) {
//       return res.json({
//         success: true,
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
//       /* Profile Image */
//       c.profile_image_url = `${base_url}/get_profile_image.php?profile_id=${encodeURIComponent(
//         c.profile_id
//       )}&dietician_id=${encodeURIComponent(c.dietician_id)}`;

//       /* Metabolism */
//       c.metabolism_target = await fetchMetabolismTarget(
//         c.age,
//         c.gender,
//         c.height,
//         c.weight
//       );

//       /* Plans */
//       const [plans] = await pool.query(planQuery, [
//         c.profile_id,
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
