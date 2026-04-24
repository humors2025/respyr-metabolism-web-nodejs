const pool = require('../../../../config/db'); 

exports.get_test_stat = async (req, res) => {
  try {
    // 1️⃣ Accept RAW JSON / POST / GET (priority order)
    const dietitian_id =
      (req.body?.dietitian_id ?? null) ??
      (req.body?.dietitian_id ?? null) ??
      (req.query?.dietitian_id ?? null);

    if (!dietitian_id) {
      return res.json({
        success: false,
        message: "dietitian_id is required",
      });
    }

    // 2️⃣ TOTAL TESTS ADDED (table_dietitian_test_counts)
    // column = dietician_id (with c)
    const sqlAdded = `
      SELECT SUM(test_count) AS total_added
      FROM table_dietitian_test_counts
      WHERE dietician_id = ?
    `;

    const [addedRows] = await pool.query(sqlAdded, [dietitian_id]);
    const total_added = addedRows[0]?.total_added ?? 0;

    // 3️⃣ TOTAL TESTS ASSIGNED (table_diet_plan_strategy)
    const sqlAssigned = `
      SELECT SUM(test_no_assigned) AS total_assigned
      FROM table_diet_plan_strategy
      WHERE dietitian_id = ?
    `;

    const [assignedRows] = await pool.query(sqlAssigned, [dietitian_id]);
    const total_assigned = assignedRows[0]?.total_assigned ?? 0;

    // 4️⃣ REMAINING = ADDED − ASSIGNED
    let remaining = parseInt(total_added) - parseInt(total_assigned);
    if (remaining < 0) remaining = 0;

    // 5️⃣ FINAL RESPONSE
    return res.json({
      success: true,
      dietitian_id: dietitian_id,
      total_added: parseInt(total_added),
      total_assigned: parseInt(total_assigned),
      remaining: remaining,
    });

  } catch (error) {
    return res.json({
      success: false,
      message: "Error: " + error.message,
    });
  }
};
