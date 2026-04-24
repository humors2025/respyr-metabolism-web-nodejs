/**
 * test_statistic_by_dietitian.js
 * POST raw JSON: { "dietician_id": "RespyrD01" }
 * Returns:
 *  - total tests purchased  (from table_dietitian_test_counts.test_count)
 *  - total tests "used"     (from table_diet_plan_strategy.test_no_assigned)
 *  - remaining tests        = purchased - used
 *  - raw records for debugging
 */

const pool = require("../../../../config/db"); // Adjust path if needed

exports.test_statistic_by_dietitian = async (req, res) => {
  try {
    // ---------- helpers ----------
    const inData = req.body;

    if (!inData || typeof inData !== "object") {
      return res.status(400).json({
        success: false,
        error: "invalid_json",
      });
    }

    const dietician_id = inData.dietician_id;
    if (!dietician_id || dietician_id.trim() === "") {
      return res.status(400).json({
        success: false,
        error: "missing_param",
        param: "dietician_id",
      });
    }

    // Set timezone and encoding (same as PHP)
    await pool.query("SET NAMES utf8mb4");
    await pool.query("SET time_zone = '+05:30'");

    /* =============== TABLE 1: TOTAL TESTS PURCHASED =============== */
    const [rowsPurchased] = await pool.query(
      `
      SELECT id, dietician_id, test_count, dttm 
      FROM table_dietitian_test_counts 
      WHERE dietician_id = ? 
      ORDER BY id DESC
      `,
      [dietician_id]
    );

    let totalPurchased = 0;
    rowsPurchased.forEach((r) => {
      totalPurchased += parseInt(r.test_count);
    });

    /* =============== TABLE 2: TOTAL TESTS ASSIGNED (USED) =============== */
    const [rowsAssigned] = await pool.query(
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
        carbs_target,
        fat_target,
        water_target,
        goal,
        approach,
        status,
        test_no_assigned,
        diabetic,
        diet_type
      FROM table_diet_plan_strategy
      WHERE dietitian_id = ?
      ORDER BY id DESC
      `,
      [dietician_id]
    );

    let totalUsed = 0;
    rowsAssigned.forEach((r) => {
      totalUsed += parseInt(r.test_no_assigned);
    });

    /* =============== RAW TEST LOG (for debug only) =============== */
    const [rowsTestLog] = await pool.query(
      `
      SELECT id, test_id, diet_plan_id, dietitian_id, client_id, test_taken, updated_at
      FROM table_test_log
      WHERE dietitian_id = ?
      ORDER BY id DESC
      `,
      [dietician_id]
    );

    /* =============== COMPUTE REMAINING =============== */
    let remaining = totalPurchased - totalUsed;
    if (remaining < 0) remaining = 0;

    /* =============== RESPONSE =============== */
    return res.json({
      success: true,
      dietician_id: dietician_id,
      summary: {
        total_tests_purchased: totalPurchased,
        total_tests_used: totalUsed,
        remaining_tests: remaining,
      },
      purchased_records: rowsPurchased,
      assigned_records: rowsAssigned,
      test_log_records: rowsTestLog,
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "server_exception",
      message: err.message,
    });
  }
};
