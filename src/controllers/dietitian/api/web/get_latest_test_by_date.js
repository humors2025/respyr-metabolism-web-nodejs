const pool = require('../../../../config/db');

// helpers
const isYmd = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s);

const pctOrZero = (consumed, target) => {
  consumed = Number(consumed || 0);
  target = Number(target || 0);
  if (target <= 0) return 0;
  return Math.round((consumed / target) * 100 * 100) / 100;
};

const weightedTotalPercent = (p) => {
  const weights = {
    calories: 0.35,
    protein: 0.25,
    carbs: 0.2,
    fat: 0.15,
    fiber: 0.05,
  };

  let total =
    (p.calories || 0) * weights.calories +
    (p.protein || 0) * weights.protein +
    (p.carbs || 0) * weights.carbs +
    (p.fat || 0) * weights.fat +
    (p.fiber || 0) * weights.fiber;

  return Math.max(0, Math.min(100, Math.round(total * 100) / 100));
};

exports.get_latest_test_by_date = async (req, res) => {
  try {
    const { dietician_id, profile_id, date } = req.body || {};

    if (!dietician_id || !profile_id || !date) {
      return res.status(400).json({
        error: 'Missing required parameter(s): dietician_id, profile_id, date',
      });
    }

    if (!isYmd(date)) {
      return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
    }

    // ---- latest test for date ----
    const [tests] = await pool.execute(
      `
      SELECT *
      FROM table_test_data
      WHERE dietitian_id = ?
        AND profile_id   = ?
        AND date_time BETWEEN ? AND ?
      ORDER BY test_id DESC
      LIMIT 1
      `,
      [
        dietician_id,
        profile_id,
        `${date} 00:00:00`,
        `${date} 23:59:59`,
      ]
    );

    if (!tests.length) {
      return res.status(404).json({
        error: 'No test_data found for given inputs',
      });
    }

    const row = tests[0];

    // ---- decode test_json ----
    let decodedTestJson = null;
    if (row.test_json) {
      try {
        decodedTestJson = JSON.parse(row.test_json);
      } catch {
        decodedTestJson = { raw: row.test_json };
      }
    }

    // ---- diet plan targets (3-step fallback) ----
    let planRow = null;
    let dietPlanId = row.diet_plan_id || null;

    if (dietPlanId) {
      const [p1] = await pool.execute(
        `SELECT * FROM table_diet_plan_strategy WHERE id = ? LIMIT 1`,
        [dietPlanId]
      );
      planRow = p1[0];
    }

    if (!planRow) {
      const [p2] = await pool.execute(
        `
        SELECT *
        FROM table_diet_plan_strategy
        WHERE dietitian_id = ?
          AND client_id    = ?
          AND status = 'active'
          AND plan_start_date <= ?
          AND plan_end_date   >= ?
        ORDER BY id DESC
        LIMIT 1
        `,
        [dietician_id, profile_id, date, date]
      );
      planRow = p2[0];
    }

    if (!planRow && dietPlanId) {
      const [p3] = await pool.execute(
        `
        SELECT *
        FROM table_diet_plan_strategy
        WHERE dietitian_id = ?
          AND client_id    = ?
          AND status = 'active'
          AND id = ?
        LIMIT 1
        `,
        [dietician_id, profile_id, dietPlanId]
      );
      planRow = p3[0];
    }

    const planTargets = planRow
      ? {
          diet_plan_id: planRow.id,
          calories: Number(planRow.calories_target || 0),
          protein: Number(planRow.protein_target || 0),
          fiber: Number(planRow.fiber_target || 0),
          carbs: Number(planRow.carbs_target || 0),
          fat: Number(planRow.fat_target || 0),
          water: Number(planRow.water_target || 0),
        }
      : null;

    if (planRow) dietPlanId = planRow.id;

    // ---- food logs ----
    const foodTotals = {
      calories: 0,
      protein: 0,
      fat: 0,
      carbs: 0,
      fiber: 0,
      water: 0,
      entries: 0,
    };

    let foodSql = `
      SELECT meal_values
      FROM table_food_log
      WHERE dietician_id = ?
        AND profile_id   = ?
        AND meal_date    = ?
    `;
    const foodParams = [dietician_id, profile_id, date];

    if (dietPlanId) {
      foodSql += ' AND diet_plan_id = ?';
      foodParams.push(dietPlanId);
    }

    const [foods] = await pool.execute(foodSql, foodParams);

    for (const f of foods) {
      if (!f.meal_values) continue;
      let m;
      try {
        m = JSON.parse(f.meal_values);
        if (typeof m === 'string') m = JSON.parse(m);
      } catch {
        continue;
      }

      foodTotals.calories += Number(m.foodCalories || 0);
      foodTotals.protein += Number(m.foodProtein || 0);
      foodTotals.fat += Number(m.foodFat || 0);
      foodTotals.carbs += Number(m.foodCarbs || 0);
      foodTotals.fiber += Number(m.foodFiber || 0);
      foodTotals.water += Number(m.foodWater || 0);
      foodTotals.entries++;
    }

    // ---- percentages ----
    const foodPercent = planTargets
      ? {
          calories: pctOrZero(foodTotals.calories, planTargets.calories),
          protein: pctOrZero(foodTotals.protein, planTargets.protein),
          fat: pctOrZero(foodTotals.fat, planTargets.fat),
          carbs: pctOrZero(foodTotals.carbs, planTargets.carbs),
          fiber: pctOrZero(foodTotals.fiber, planTargets.fiber),
          water: pctOrZero(foodTotals.water, planTargets.water),
        }
      : {
          calories: 0,
          protein: 0,
          fat: 0,
          carbs: 0,
          fiber: 0,
          water: 0,
        };

    const nutritionTotalPercent = weightedTotalPercent(foodPercent);

    // ---- response ----
    res.json({
      dietician_id,
      profile_id,
      date,
      plan_targets: planTargets,
      food_log_totals: foodTotals,
      food_log_percentage: foodPercent,
      nutrition_total_percent: nutritionTotalPercent,
      latest_test: {
        test_id: row.test_id,
        diet_plan_id: row.diet_plan_id,
        date_time: row.date_time,
        scores: {
          absorptive: Number(row.absorptive_metabolism_score),
          fermentative: Number(row.fermentative_metabolism_score),
          fat: Number(row.fat_metabolism_score),
          glucose: Number(row.glucose_metabolism_score),
          hepatic_stress: Number(row.hepatic_stress_metabolism_score),
          detoxification: Number(row.detoxification_metabolism_score),
        },
        ppm: {
          acetone: Number(row.acetone_ppm),
          h2: Number(row.h2_ppm),
          ethanol: Number(row.ethanol_ppm),
        },
        test_json: decodedTestJson,
      },
    });
  } catch (err) {
    console.error('❌ get_latest_test_by_date:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
};
