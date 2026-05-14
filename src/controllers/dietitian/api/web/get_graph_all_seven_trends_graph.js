const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

const sendResponse = (res, httpCode, status, message, data = {}) => {
  return res.status(httpCode).json({
    status,
    message,
    data,
  });
};

const GRAPH_MAPPINGS = [
  {
    key: "nutrient_utilization_trend",
    column: "absorptive_metabolism_score",
    title: "Nutrient Utilization Trend",
  },
  {
    key: "digestive_activity_trend",
    column: "fermentative_metabolism_score",
    title: "Digestive Activity Trend",
  },
  {
    key: "fuel_utilization_trend",
    column: "fat_metabolism_score",
    title: "Fuel Utilization Trend",
  },
  {
    key: "energy_source_trend",
    column: "glucose_metabolism_score",
    title: "Energy Source Trend",
  },
  {
    key: "metabolic_load_trend",
    column: "hepatic_stress_metabolism_score",
    title: "Metabolic Load Trend",
  },
  {
    key: "recovery_activity_trend",
    column: "detoxification_metabolism_score",
    title: "Recovery Activity Trend",
  },
  {
    key: "overall_fat_loss_score",
    column: "fat_loss_metabolism_score",
    title: "Overall Fat Loss Score",
  },
];

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

const getLatestRangeData = async (profileId, dieticianId, dateConditionSql) => {
  const query = `
    SELECT min_range, max_range
    FROM table_test_data
    WHERE profile_id = ?
      AND UPPER(TRIM(dietitian_id)) = ?
      ${dateConditionSql}
    ORDER BY date_time DESC
    LIMIT 1
  `;

  const [rows] = await pool.execute(query, [profileId, dieticianId]);

  let minRange = null;
  let maxRange = null;
  let rangeText = "";

  if (rows.length) {
    const row = rows[0];

    minRange =
      row.min_range !== null && row.min_range !== undefined
        ? cleanFloat(row.min_range, null)
        : null;

    maxRange =
      row.max_range !== null && row.max_range !== undefined
        ? cleanFloat(row.max_range, null)
        : null;

    if (minRange !== null && maxRange !== null) {
      rangeText = `${minRange}%-${maxRange}%`;
    }
  }

  return {
    minRange,
    maxRange,
    rangeText,
  };
};

const getGraphPointsForColumn = async ({
  profileId,
  dieticianId,
  selectedColumn,
  dateConditionSql,
}) => {
  /**
   * VAPT note:
   * selectedColumn is never accepted from request.
   * It only comes from fixed GRAPH_MAPPINGS whitelist above.
   */
  const query = `
    SELECT 
      DATE(t1.date_time) AS test_date,
      t1.${selectedColumn} AS graph_score
    FROM table_test_data t1
    INNER JOIN (
      SELECT 
        DATE(date_time) AS only_date,
        MAX(date_time) AS max_date_time
      FROM table_test_data
      WHERE profile_id = ?
        AND UPPER(TRIM(dietitian_id)) = ?
        ${dateConditionSql}
      GROUP BY DATE(date_time)
    ) t2 
      ON DATE(t1.date_time) = t2.only_date
     AND t1.date_time = t2.max_date_time
    WHERE t1.profile_id = ?
      AND UPPER(TRIM(t1.dietitian_id)) = ?
    ORDER BY t1.date_time ASC
  `;

  const [rows] = await pool.execute(query, [
    profileId,
    dieticianId,
    profileId,
    dieticianId,
  ]);

  return rows.map((row) => {
    const testDate = formatDateOnly(row.test_date);

    return {
      date: testDate,
      label: formatLabelDate(testDate),
      value:
        row.graph_score !== null && row.graph_score !== undefined
          ? cleanFloat(row.graph_score, 0)
          : 0,
    };
  });
};

const get_graph_all_seven_trends_graph = async (req, res) => {
  try {
    const rawDietitianId = getInputValue(req, "dietitian_id");
    const rawProfileId = getInputValue(req, "profile_id");
    const rawRange = getInputValue(req, "range");

    const missingFields = [];

    if (!rawDietitianId) {
      missingFields.push("dietitian_id");
    }

    if (!rawProfileId) {
      missingFields.push("profile_id");
    }

    if (!rawRange) {
      missingFields.push("range");
    }

    if (missingFields.length) {
      return sendResponse(
        res,
        400,
        false,
        `${missingFields.join(", ")} are required`
      );
    }

    const dietitianId = normalizeDieticianId(rawDietitianId);
    const profileId = normalizeId(rawProfileId);

    if (!dietitianId) {
      return sendResponse(res, 400, false, "Invalid dietitian_id");
    }

    if (!profileId) {
      return sendResponse(res, 400, false, "Invalid profile_id");
    }

    const rangeConfig = getRangeConfig(rawRange);

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
     * 1. JWT dietitian must match requested dietitian_id.
     * 2. profile_id must belong to that dietitian.
     */
    const access = await requireProfileAccess(req, dietitianId, profileId);

    if (!access.allowed) {
      return sendResponse(res, access.statusCode, false, access.message);
    }

    const { minRange, maxRange, rangeText } = await getLatestRangeData(
      access.profileId,
      access.dieticianId,
      rangeConfig.dateConditionSql
    );

    const allGraphs = {};
    let hasAnyData = false;

    for (const graph of GRAPH_MAPPINGS) {
      const graphPoints = await getGraphPointsForColumn({
        profileId: access.profileId,
        dieticianId: access.dieticianId,
        selectedColumn: graph.column,
        dateConditionSql: rangeConfig.dateConditionSql,
      });

      if (graphPoints.length > 0) {
        hasAnyData = true;
      }

      allGraphs[graph.key] = {
        title: graph.title,
        column_name: graph.column,
        recommended_trend_range: {
          min: minRange,
          max: maxRange,
          label: rangeText,
        },
        total_points: graphPoints.length,
        graph_points: graphPoints,
      };
    }

    if (!hasAnyData) {
      return sendResponse(
        res,
        404,
        false,
        "No graph data found for the given dietitian_id, profile_id, and range"
      );
    }

    return sendResponse(res, 200, true, "All graph data fetched successfully", {
      /**
       * Keeping original casing here to match old PHP response.
       * Security check still uses normalized uppercase internally.
       */
      dietitian_id: rawDietitianId,
      profile_id: access.profileId,
      range: rangeConfig.range,
      range_label: rangeConfig.rangeLabel,
      graphs: allGraphs,
    });
  } catch (error) {
    console.error("get_graph_all_seven_trends_graph error:", {
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
  get_graph_all_seven_trends_graph,
};