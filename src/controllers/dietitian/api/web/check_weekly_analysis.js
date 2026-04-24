// check_weekly_analysis.js

const pool = require("../../../../config/db"); // update path if needed

exports.check_weekly_analysis = async (req, res) => {
  try {
    // Set response header like PHP
    res.setHeader("Content-Type", "application/json");

    const input = req.body;

    if (!input || typeof input !== "object") {
      return res.json({
        status: false,
        message: "Invalid JSON body",
      });
    }

    const dietician_id = input.dietician_id || null;
    const profile_id = input.profile_id || null;
    const target_date = input.start_date || null; // same as PHP

    if (!dietician_id || !profile_id || !target_date) {
      return res.json({
        status: false,
        message: "Missing required parameters (dietician_id, profile_id, start_date)",
      });
    }

    const connection = await pool.getConnection();
    try {
      const sql = `
        SELECT id, diet_plan_id, data_json, start_date, end_date
        FROM weekly_analysis
        WHERE LOWER(dietician_id) = LOWER(?)
          AND profile_id = ?
          AND ? BETWEEN DATE(start_date) AND DATE(end_date)
        ORDER BY id DESC
        LIMIT 1
      `;

      const [rows] = await connection.execute(sql, [
        dietician_id,
        profile_id,
        target_date,
      ]);

      if (!rows.length) {
        return res.json({
          status: false,
          message: "No record found for given date range",
        });
      }

      const row = rows[0];
      let decoded;

      try {
        decoded = JSON.parse(row.data_json);
      } catch (err) {
        decoded = row.data_json;
      }

      return res.json({
        status: true,
        diet_plan_id: row.diet_plan_id,
        start_date: row.start_date,
        end_date: row.end_date,
        data_json: decoded ?? row.data_json,
      });

    } finally {
      connection.release();
    }

  } catch (err) {
    return res.json({
      status: false,
      message: "Database error",
      error: err.message,
    });
  }
};
