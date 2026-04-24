// weekly_analysis_complete1.js

const axios = require("axios");
const pool = require("../../../../config/db"); // update path as per your folder structure

// Set Timezone
process.env.TZ = "Asia/Kolkata";

function cleanAndRenumberDays(inputDays) {
  const daysMap = {};
  let counter = 1;

  for (const anyKey in inputDays) {
    const meals = inputDays[anyKey];
    if (!Array.isArray(meals)) continue;

    const cleanMeals = meals.filter(m => typeof m === "string" && m !== "");
    if (cleanMeals.length === 0) continue;

    const key = "day" + counter;
    daysMap[key] = cleanMeals;
    counter++;
  }

  return daysMap;
}

async function getLatestPpmWithin72hrs(profileId) {
  const connection = await pool.getConnection();
  try {
    // Set timezone to IST
    await connection.query("SET time_zone = '+05:30'");

    const sql = `
      SELECT acetone_ppm, h2_ppm, ethanol_ppm, date_time
      FROM table_test_data
      WHERE profile_id = ?
        AND date_time >= (NOW() - INTERVAL 72 HOUR)
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [rows] = await connection.execute(sql, [profileId]);
    if (!rows.length) return null;

    const row = rows[0];
    return {
      acetone: Math.round(Number(row.acetone_ppm)),
      hydrogen: Math.round(Number(row.h2_ppm)),
      ethanol: Math.round(Number(row.ethanol_ppm)),
      date_time: row.date_time,
    };
  } finally {
    connection.release();
  }
}

exports.weekly_analysis_complete1 = async (req, res) => {
  try {
    // CORS & Headers (same as PHP)
    res.setHeader("Content-Type", "application/json; charset=UTF-8");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-Requested-With"
    );

    if (req.method === "OPTIONS") {
      return res.status(204).send();
    }

    const input = req.body;

    if (!input || typeof input !== "object") {
      return res.status(400).json({ error: "Send JSON body" });
    }

    const required = ["dietician_id", "profile_id", "start_date", "end_date", "days"];
    for (const k of required) {
      if (!input[k] || input[k] === "") {
        return res.status(400).json({ error: `Missing required field: ${k}` });
      }
      if (k === "days" && !Array.isArray(input[k])) {
        return res.status(400).json({ error: "Field 'days' must be an object/array" });
      }
    }

    const dieticianId = String(input.dietician_id);
    const profileId = String(input.profile_id);
    const startDate = String(input.start_date);
    const endDate = String(input.end_date);
    const dietPlanId = input.diet_plan_id ? String(input.diet_plan_id) : null;

    // Check report generate time (end_date @ 9 PM IST)
    const endDateTime = new Date(endDate + " 21:00:00").getTime();
    const nowTime = Date.now();
    const formattedEndDate =
      new Date(endDate).toLocaleDateString("en-IN", {
        day: "2-digit",
        month: "long",
        year: "numeric",
      }) + " 9:00 PM";

    if (nowTime < endDateTime) {
      return res.status(200).json({
        message: "Weekly analysis will be available after " + formattedEndDate,
        end_date: formattedEndDate,
      });
    }

    // Clean + renumber days
    const daysMap = cleanAndRenumberDays(input.days);

    // Fetch latest ppm
    const ppm = await getLatestPpmWithin72hrs(profileId);
    if (!ppm) {
      return res.status(200).json({
        message:
          "Latest test data is older than 72 hours (or not found). Please take a new test to generate weekly analysis.",
        profile_id: profileId,
      });
    }

    const secondUrl = "https://humorstech.com/dietitian/api/web/weekly_analysis.php";

    const secondPayload = {
      dietician_id: dieticianId,
      profile_id: profileId,
      start_date: startDate,
      end_date: endDate,
      acetone: ppm.acetone,
      ethanol: ppm.ethanol,
      hydrogen: ppm.hydrogen,
      diabetic: false,
      goal: "fat_loss",
      days: daysMap,
      debug: 1,
    };

    if (dietPlanId) secondPayload.diet_plan_id = dietPlanId;

    // POST to weekly_analysis.php
    const response = await axios.post(secondUrl, secondPayload, {
      headers: { "Content-Type": "application/json" },
      timeout: 25000,
    });

    return res.status(response.status).send(response.data);

  } catch (err) {
    return res.status(500).json({
      error: "Network error (weekly_analysis API)",
      details: err.message,
    });
  }
};
