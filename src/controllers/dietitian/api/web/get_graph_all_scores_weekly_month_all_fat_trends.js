const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

const sendResponse = (res, httpCode, status, message, data = []) => {
  return res.status(httpCode).json({
    status,
    message,
    data,
  });
};

const formatDateOnly = (value) => {
  if (!value) return null;

  if (value instanceof Date) {
    const year = value.getFullYear();
    const month = String(value.getMonth() + 1).padStart(2, "0");
    const day = String(value.getDate()).padStart(2, "0");

    return `${year}-${month}-${day}`;
  }

  return String(value).slice(0, 10);
};

const formatLabelDate = (value) => {
  const dateOnly = formatDateOnly(value);

  if (!dateOnly || !/^\d{4}-\d{2}-\d{2}$/.test(dateOnly)) {
    return "";
  }

  const [, month, day] = dateOnly.split("-").map(Number);

  const shortMonths = [
    "",
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];

  return `${String(day).padStart(2, "0")} ${shortMonths[month] || ""}`;
};

const cleanFloat = (value, defaultValue = 0) => {
  if (value === null || value === undefined || value === "") {
    return defaultValue;
  }

  const number = Number(value);

  return Number.isFinite(number) ? number : defaultValue;
};

const getRangeConfig = (range) => {
  switch (range) {
    case "weekly":
      return {
        range: "weekly",
        rangeLabel: "Last 7 Days",
        dateConditionSql: "AND date_time >= DATE_SUB(NOW(), INTERVAL 7 DAY)",
      };

    case "monthly":
      return {
        range: "monthly",
        rangeLabel: "Last 30 Days",
        dateConditionSql: "AND date_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)",
      };

    case "all_time":
      return {
        range: "all_time",
        rangeLabel: "Last 3 Months",
        dateConditionSql: "AND date_time >= DATE_SUB(NOW(), INTERVAL 3 MONTH)",
      };

    default:
      return null;
  }
};

const getInputValue = (req, key, defaultValue = "") => {
  const queryValue = req.query?.[key];
  const bodyValue = req.body?.[key];

  const value =
    queryValue !== undefined && queryValue !== null ? queryValue : bodyValue;

  if (value === undefined || value === null || value === "") {
    return defaultValue;
  }

  return String(value).trim();
};

const get_graph_all_scores_weekly_month_all_fat_trends = async (req, res) => {
  try {
    const profileId = normalizeId(getInputValue(req, "profile_id"));
    const dietitianId = normalizeDieticianId(getInputValue(req, "dietitian_id"));
    const range = getInputValue(req, "range", "weekly");

    if (!profileId) {
      return sendResponse(res, 400, false, "profile_id is required");
    }

    if (!dietitianId) {
      return sendResponse(res, 400, false, "dietitian_id is required");
    }

    const rangeConfig = getRangeConfig(range);

    if (!rangeConfig) {
      return sendResponse(
        res,
        400,
        false,
        "Invalid range. Use weekly, monthly, or all_time"
      );
    }

    /**
     * VAPT / IDOR protection:
     * 1. Token dietitian must match requested dietitian_id.
     * 2. profile_id must belong to that dietitian.
     */
    const access = await requireProfileAccess(req, dietitianId, profileId);

    if (!access.allowed) {
      return sendResponse(res, access.statusCode, false, access.message);
    }

    const graphQuery = `
      SELECT 
        DATE(t1.date_time) AS test_date,
        t1.fat_loss_metabolism_score
      FROM table_test_data t1
      INNER JOIN (
        SELECT 
          DATE(date_time) AS only_date,
          MAX(date_time) AS max_date_time
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(TRIM(dietitian_id)) = ?
          ${rangeConfig.dateConditionSql}
        GROUP BY DATE(date_time)
      ) t2 
        ON DATE(t1.date_time) = t2.only_date
       AND t1.date_time = t2.max_date_time
      WHERE t1.profile_id = ?
        AND UPPER(TRIM(t1.dietitian_id)) = ?
      ORDER BY t1.date_time ASC
    `;

    const [graphRows] = await pool.execute(graphQuery, [
      access.profileId,
      access.dieticianId,
      access.profileId,
      access.dieticianId,
    ]);

    const graphPoints = graphRows.map((row) => {
      const testDate = formatDateOnly(row.test_date);

      return {
        date: testDate,
        label: formatLabelDate(testDate),
        value:
          row.fat_loss_metabolism_score !== null &&
          row.fat_loss_metabolism_score !== undefined
            ? cleanFloat(row.fat_loss_metabolism_score, 0)
            : 0,
      };
    });

    const rangeQuery = `
      SELECT min_range, max_range
      FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        ${rangeConfig.dateConditionSql}
      ORDER BY date_time DESC
      LIMIT 1
    `;

    const [rangeRows] = await pool.execute(rangeQuery, [
      access.profileId,
      access.dieticianId,
    ]);

    let minRange = null;
    let maxRange = null;
    let rangeText = "";

    if (rangeRows.length) {
      const rangeData = rangeRows[0];

      minRange =
        rangeData.min_range !== null && rangeData.min_range !== undefined
          ? cleanFloat(rangeData.min_range, null)
          : null;

      maxRange =
        rangeData.max_range !== null && rangeData.max_range !== undefined
          ? cleanFloat(rangeData.max_range, null)
          : null;

      if (minRange !== null && maxRange !== null) {
        rangeText = `${minRange}%-${maxRange}%`;
      }
    }

    return sendResponse(
      res,
      200,
      true,
      "Fat trend graph data fetched successfully",
      {
        profile_id: access.profileId,
        dietitian_id: access.dieticianId,
        range: rangeConfig.range,
        range_label: rangeConfig.rangeLabel,
        title: "In Range",
        recommended_trend_range: {
          min: minRange,
          max: maxRange,
          label: rangeText,
        },
        total_points: graphPoints.length,
        graph_points: graphPoints,
      }
    );
  } catch (error) {
    console.error("get_graph_all_scores_weekly_month_all_fat_trends error:", {
      message: error.message,
      stack: isProduction ? undefined : error.stack,
    });

    return sendResponse(
      res,
      500,
      false,
      isProduction ? "Internal server error" : "Something went wrong"
    );
  }
};

module.exports = {
  get_graph_all_scores_weekly_month_all_fat_trends,
};