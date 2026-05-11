const pool = require('../../../../config/db'); // adjust path to your db.js

const get_calander_fill_data = async (req, res) => {
  try {
    const { dietician_id } = req.body;

    // ✅ Validate required field
    if (!dietician_id) {
      return res.status(400).json({
        status: false,
        message: "dietician_id is required"
      });
    }

    // ✅ Normalize: uppercase + trim (matches PHP logic)
    const normalizedDieticianId = dietician_id.toString().trim().toUpperCase();

    // ✅ FINAL QUERY (MATCHES SUMMARY LOGIC)
    const query = `
      SELECT
        DATE(tt.date_time) AS test_date,
        COUNT(DISTINCT tc.profile_id) AS total_tests
      FROM table_clients tc

      LEFT JOIN table_test_data tt
        ON tt.profile_id = tc.profile_id
        AND UPPER(TRIM(tt.dietitian_id)) = ?
        AND tt.date_time >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)

      WHERE UPPER(TRIM(tc.dietician_id)) = ?

      GROUP BY DATE(tt.date_time)
      HAVING test_date IS NOT NULL

      ORDER BY test_date ASC
    `;

    const [results] = await pool.execute(query, [
      normalizedDieticianId,
      normalizedDieticianId
    ]);

    return res.status(200).json({
      status: true,
      message: "Success",
      dietician_id: normalizedDieticianId,
      data: results
    });

  } catch (error) {
    console.error("❌ get_calander_fill_data error:", error);
    return res.status(500).json({
      status: false,
      message: "Server error",
      error: error.message
    });
  }
};

module.exports = { get_calander_fill_data };