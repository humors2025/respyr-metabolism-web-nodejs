

const pool = require("../../../../config/db"); // adjust path if needed

exports.get_test_analytics = async (req, res) => {
  try {
    const { dietitian_id } = req.body;

    if (!dietitian_id || dietitian_id.trim() === "") {
      return res.status(400).json({
        success: false,
        error: "Missing parameter",
        param: "dietitian_id",
      });
    }

    // Same as PHP
    await pool.query("SET time_zone = '+05:30'");
    await pool.query("SET NAMES utf8mb4");

    // 1️⃣ Fetch all clients
    const [clients] = await pool.query(
      `
      SELECT profile_id, DATE(dttm) AS reg_date
      FROM table_clients
      WHERE dietician_id = ?
      ORDER BY dttm ASC
      `,
      [dietitian_id]
    );

    if (!clients || clients.length === 0) {
      return res.json({
        success: true,
        dietitian_id,
        days: [],
        message: "No clients found for this dietitian",
      });
    }

    // 2️⃣ Fetch all tests
    const [tests] = await pool.query(
      `
      SELECT profile_id, DATE(date_time) AS test_date
      FROM table_test_data
      WHERE dietitian_id = ?
      ORDER BY date_time ASC
      `,
      [dietitian_id]
    );

    // Collect all relevant dates
    let allDates = tests.map(t => t.test_date);
    clients.forEach(c => allDates.push(c.reg_date));

    const uniqueDates = [...new Set(allDates)].sort();

    // 3️⃣ Registration map
    const regMap = {};
    clients.forEach(c => {
      if (!regMap[c.reg_date]) regMap[c.reg_date] = 0;
      regMap[c.reg_date]++;
    });

    // 4️⃣ Test map
    const testMap = {};
    tests.forEach(t => {
      if (!testMap[t.test_date]) testMap[t.test_date] = [];
      testMap[t.test_date].push(t.profile_id);
    });

    // 5️⃣ Calculate cumulative analytics
    let cumulativeClients = 0;
    const result = [];

    uniqueDates.forEach(day => {
      const newRegs = regMap[day] || 0;
      cumulativeClients += newRegs;

      const testedProfiles = testMap[day]
        ? [...new Set(testMap[day])]
        : [];

      const testedCount = testedProfiles.length;
      let notTestedCount = cumulativeClients - testedCount;
      if (notTestedCount < 0) notTestedCount = 0;

      result.push({
        date: day,
        new_registrations: newRegs,
        total_clients: cumulativeClients,
        tested_clients: testedCount,
        not_tested_clients: notTestedCount,
      });
    });

    return res.json({
      success: true,
      dietitian_id,
      days: result,
    });

  } catch (err) {
    return res.status(500).json({
      success: false,
      error: "Server Exception",
      message: err.message,
    });
  }
};
