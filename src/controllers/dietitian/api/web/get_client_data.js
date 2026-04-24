const pool = require('../../../../config/db'); // adjust path if needed

// --- Helper: compute plan status ---
function computePlanStatus(start, end, tz = 'Asia/Kolkata') {
  try {
    const today = new Date(
      new Date().toLocaleDateString('en-US', { timeZone: tz })
    );

    const startDate = start ? new Date(start) : null;
    const endDate = end ? new Date(end) : null;

    if (!startDate && !endDate) return 'unknown';
    if (endDate && endDate < today) return 'completed';
    if (startDate && endDate && startDate <= today && today <= endDate)
      return 'active';
    if (startDate && startDate > today) return 'not_started';
    if (!endDate && startDate && startDate <= today) return 'active';
    if (!startDate && endDate && today <= endDate) return 'active';

    return 'unknown';
  } catch (err) {
    return 'unknown';
  }
}

// ================================
// GET CLIENT DATA API
// ================================
exports.get_client_data = async (req, res) => {
  try {
    const data = req.body || {};

    const dietician_id =
      data.dietician_id || req.query.dietician_id || null;

    const profile_id =
      data.profile_id || req.query.profile_id || null;

    // --- Validate ---
    if (!dietician_id || !profile_id) {
      return res.json({
        error: 'Both dietician_id and profile_id are required',
      });
    }

    // --- Fetch single client ---
    const clientSql = `
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
        password,
        is_notification_enabled,
        dttm
      FROM table_clients
      WHERE dietician_id = ?
        AND profile_id = ?
    `;

    const [clients] = await pool.execute(clientSql, [
      dietician_id,
      profile_id,
    ]);

    if (!clients.length) {
      return res.json({
        success: false,
        message: 'No data found for given IDs',
      });
    }

    const client = clients[0];

    const base_url = 'https://humorstech.com/dietitian/api/web';
    client.profile_image_url =
      `${base_url}/get_profile_image.php?profile_id=${encodeURIComponent(
        profile_id
      )}&dietician_id=${encodeURIComponent(dietician_id)}`;

    // --- Fetch diet plans ---
    const planSql = `
      SELECT 
        id,
        dietitian_id,
        client_id,
        plan_title,
        plan_start_date,
        plan_end_date,
        updated_at,
        diet_type,
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

    const [plans] = await pool.execute(planSql, [
      profile_id,
      dietician_id,
    ]);

    const activePlans = [];
    const completedPlans = [];
    const notStartedPlans = [];

    if (plans.length) {
      plans.forEach((p) => {
        p.plan_status = computePlanStatus(
          p.plan_start_date,
          p.plan_end_date,
          'Asia/Kolkata'
        );

        if (p.plan_status === 'completed') completedPlans.push(p);
        else if (p.plan_status === 'active') activePlans.push(p);
        else if (p.plan_status === 'not_started') notStartedPlans.push(p);
      });
    }

    client.plans_summary = {
      active: activePlans,
      completed: completedPlans,
      not_started: notStartedPlans,
    };

    client.plans_count = {
      total:
        activePlans.length +
        completedPlans.length +
        notStartedPlans.length,
      active: activePlans.length,
      completed: completedPlans.length,
      not_started: notStartedPlans.length,
    };

    return res.json({
      success: true,
      data: client, 
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({
      error: 'Database error: ' + err.message,
    });
  }
};
