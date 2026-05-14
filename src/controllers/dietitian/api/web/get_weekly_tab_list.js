const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

const sendResponse = (res, statusCode, response) => {
  return res.status(statusCode).json(response);
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

const formatDateTime = (value) => {
  if (!value) return null;

  if (value instanceof Date) {
    const year = value.getFullYear();
    const month = String(value.getMonth() + 1).padStart(2, "0");
    const day = String(value.getDate()).padStart(2, "0");

    const hours = String(value.getHours()).padStart(2, "0");
    const minutes = String(value.getMinutes()).padStart(2, "0");
    const seconds = String(value.getSeconds()).padStart(2, "0");

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  }

  return String(value);
};

const getDateParts = (yyyyMmDd) => {
  const safeDate = formatDateOnly(yyyyMmDd);

  if (!safeDate || !/^\d{4}-\d{2}-\d{2}$/.test(safeDate)) {
    return null;
  }

  const [year, month, day] = safeDate.split("-").map(Number);

  return {
    year,
    month,
    day,
  };
};

const getMonthName = (monthNumber) => {
  const months = [
    "",
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
  ];

  return months[monthNumber] || "";
};

const getShortMonthName = (monthNumber) => {
  const months = [
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

  return months[monthNumber] || "";
};

const formatDisplayDate = (yyyyMmDd) => {
  const parts = getDateParts(yyyyMmDd);

  if (!parts) return null;

  const day = String(parts.day).padStart(2, "0");
  const month = getShortMonthName(parts.month);

  return `${day} ${month}, ${parts.year}`;
};

const get_weekly_tab_list = async (req, res) => {
  try {
    const body = req.body;

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return sendResponse(res, 400, {
        status: false,
        message: "Invalid JSON payload",
      });
    }

    const profileId = normalizeId(body.profile_id);
    const dietitianId = normalizeDieticianId(body.dietitian_id);

    if (!profileId) {
      return sendResponse(res, 400, {
        status: false,
        message: "profile_id is required",
      });
    }

    if (!dietitianId) {
      return sendResponse(res, 400, {
        status: false,
        message: "dietitian_id is required",
      });
    }

    const access = await requireProfileAccess(req, dietitianId, profileId);

    if (!access.allowed) {
      return sendResponse(res, access.statusCode, {
        status: false,
        message: access.message,
      });
    }

    const sql = `
      SELECT 
        id,
        dietician_id,
        profile_id,
        week_start_date,
        week_end_date,
        month_no,
        year_no,
        created_at,
        updated_at
      FROM weekly_food_json_suggestions
      WHERE profile_id = ?
        AND UPPER(TRIM(dietician_id)) = ?
        AND week_start_date >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
      ORDER BY week_start_date DESC
    `;

    const [rows] = await pool.execute(sql, [access.profileId, access.dieticianId]);

    if (!rows.length) {
      return sendResponse(res, 404, {
        status: false,
        message: "No weekly data found for last 3 months",
        profile_id: access.profileId,
        dietitian_id: access.dieticianId,
      });
    }

    const formatted = rows.map((row) => {
      const weekStartDate = formatDateOnly(row.week_start_date);
      const weekEndDate = formatDateOnly(row.week_end_date);

      const startParts = getDateParts(weekStartDate);

      const dayOfMonth = startParts?.day || 1;
      const weekNoInMonth = Math.ceil(dayOfMonth / 7);

      const monthLabel =
        startParts && getMonthName(startParts.month)
          ? `${getMonthName(startParts.month)} ${startParts.year}`
          : "";

      const formattedStart = formatDisplayDate(weekStartDate);
      const formattedEnd = formatDisplayDate(weekEndDate);

      return {
        id: Number(row.id),
        week_no_in_month: weekNoInMonth,
        week_label: `Week ${weekNoInMonth}`,
        month_label: monthLabel,
        dietitian_id: row.dietician_id,
        profile_id: row.profile_id,
        week_start_date: weekStartDate,
        week_end_date: weekEndDate,
        week_range:
          formattedStart && formattedEnd
            ? `${formattedStart} - ${formattedEnd}`
            : "",
        month_no: Number(row.month_no),
        year_no: Number(row.year_no),
        created_at: formatDateTime(row.created_at),
        updated_at: formatDateTime(row.updated_at),
      };
    });

    return sendResponse(res, 200, {
      status: true,
      message: "Weekly tabs fetched successfully",
      profile_id: access.profileId,
      dietitian_id: access.dieticianId,
      total_weeks: formatted.length,
      data: formatted,
    });
  } catch (error) {
    console.error("get_weekly_tab_list error:", {
      message: error.message,
      stack: isProduction ? undefined : error.stack,
    });

    return sendResponse(res, 500, {
      status: false,
      message: isProduction ? "Internal server error" : "Server error",
      ...(!isProduction && {
        error: error.message,
      }),
    });
  }
};

module.exports = {
  get_weekly_tab_list,
};