const pool = require('../../../../config/db');

/**
 * POST /get-latest-tests
 * Body: { dietitian_id, profile_id }
 */
exports.get_score_trend1 = async (req, res) => {
    try {
        // -------- read input ----------
        const { dietitian_id, profile_id } = req.body || {};

        if (!dietitian_id || !profile_id) {
            return res.status(400).json({
                error: 'Missing required parameter(s): dietitian_id, profile_id'
            });
        }

        // -------- SQL (same logic as PHP) ----------
        const sql = `
            SELECT 
                td.test_id,
                td.dietitian_id,
                td.profile_id,
                td.diet_plan_id,
                td.absorptive_metabolism_score,
                td.fermentative_metabolism_score,
                td.fat_metabolism_score,
                td.glucose_metabolism_score,
                td.hepatic_stress_metabolism_score,
                td.detoxification_metabolism_score,
                td.fat_loss_metabolism_score,
                td.acetone_ppm,
                td.h2_ppm,
                td.ethanol_ppm,
                td.test_json,
                td.date_time
            FROM table_test_data td
            INNER JOIN (
                SELECT 
                    DATE(date_time) AS d,
                    MAX(date_time) AS maxdt
                FROM table_test_data
                WHERE dietitian_id = ?
                  AND profile_id   = ?
                GROUP BY DATE(date_time)
            ) x
              ON DATE(td.date_time) = x.d
             AND td.date_time = x.maxdt
            WHERE td.dietitian_id = ?
              AND td.profile_id   = ?
            ORDER BY td.date_time DESC
        `;

        // -------- DB query ----------
        const [rows] = await pool.execute(sql, [
            dietitian_id,
            profile_id,
            dietitian_id,
            profile_id
        ]);

        // -------- build response ----------
        const testsByDate = {};
        const testsList = [];

        for (const r of rows) {
            const dt = new Date(r.date_time);

            const date = dt.toISOString().slice(0, 10); // YYYY-MM-DD
            const time = dt.toTimeString().slice(0, 8); // HH:mm:ss

            const entry = {
                test_id: Number(r.test_id),
                dietitian_id: r.dietitian_id,
                profile_id: r.profile_id,
                diet_plan_id: r.diet_plan_id,
                date,
                time,
                date_time: r.date_time,
                scores: {
                    absorptive: Number(r.absorptive_metabolism_score),
                    fermentative: Number(r.fermentative_metabolism_score),
                    fat: Number(r.fat_metabolism_score),
                    glucose: Number(r.glucose_metabolism_score),
                    hepatic_stress: Number(r.hepatic_stress_metabolism_score),
                    detoxification: Number(r.detoxification_metabolism_score),
                    fat_loss: Number(r.fat_loss_metabolism_score)
                },
                ppm: {
                    acetone: Number(r.acetone_ppm),
                    h2: Number(r.h2_ppm),
                    ethanol: Number(r.ethanol_ppm)
                },
                test_json: r.test_json
            };

            testsByDate[date] = entry;
            testsList.push(entry);
        }

        // -------- final response ----------
        return res.json({
            dietitian_id,
            profile_id,
            total_days: Object.keys(testsByDate).length,
            tests_by_date: testsByDate,
            tests_list: testsList
        });

    } catch (error) {
        console.error('❌ Error in get_score_trend1:', error);
        return res.status(500).json({
            error: 'Internal server error',
            message: error.message
        });
    }
};
