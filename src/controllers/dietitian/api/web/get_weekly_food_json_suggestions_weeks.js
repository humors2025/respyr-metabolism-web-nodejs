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

const isPlainObject = (value) => {
  return value !== null && typeof value === "object" && !Array.isArray(value);
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

const isValidDateOnly = (value) => {
  if (typeof value !== "string") return false;

  const trimmed = value.trim();

  if (!/^\d{4}-\d{2}-\d{2}$/.test(trimmed)) {
    return false;
  }

  const date = new Date(`${trimmed}T00:00:00.000Z`);

  if (Number.isNaN(date.getTime())) {
    return false;
  }

  const [year, month, day] = trimmed.split("-").map(Number);

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() + 1 === month &&
    date.getUTCDate() === day
  );
};

const isStartDateBeforeOrSameEndDate = (startDate, endDate) => {
  if (!isValidDateOnly(startDate) || !isValidDateOnly(endDate)) {
    return false;
  }

  const start = new Date(`${startDate}T00:00:00.000Z`).getTime();
  const end = new Date(`${endDate}T00:00:00.000Z`).getTime();

  return start <= end;
};

const formatDisplayDate = (dateString) => {
  const dateOnly = formatDateOnly(dateString);

  if (!dateOnly || !isValidDateOnly(dateOnly)) {
    return null;
  }

  const [year, month, day] = dateOnly.split("-").map(Number);

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

  return `${String(day).padStart(2, "0")} ${shortMonths[month]}, ${year}`;
};

const sanitizeJsonText = (value) => {
  return String(value)
    .replace(/^\uFEFF/, "") // remove UTF-8 BOM
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F]/g, "") // remove hidden/control characters
    .trim();
};

const parseJsonColumn = (columnValue) => {
  if (columnValue === null || columnValue === undefined) {
    return {
      ok: false,
      empty: true,
      data: null,
      error: null,
    };
  }

  if (Buffer.isBuffer(columnValue)) {
    const candidates = [
      columnValue.toString("utf8"),
      columnValue.toString("latin1"),
    ];

    for (const candidate of candidates) {
      const parsed = parseJsonTextCandidate(candidate);

      if (parsed.ok) return parsed;
    }

    return {
      ok: false,
      empty: false,
      data: null,
      error: "Invalid JSON stored in database",
    };
  }

  if (
    isPlainObject(columnValue) &&
    columnValue.type === "Buffer" &&
    Array.isArray(columnValue.data)
  ) {
    const bufferValue = Buffer.from(columnValue.data);
    const candidates = [
      bufferValue.toString("utf8"),
      bufferValue.toString("latin1"),
    ];

    for (const candidate of candidates) {
      const parsed = parseJsonTextCandidate(candidate);

      if (parsed.ok) return parsed;
    }

    return {
      ok: false,
      empty: false,
      data: null,
      error: "Invalid JSON stored in database",
    };
  }

  if (typeof columnValue === "string") {
    return parseJsonTextCandidate(columnValue);
  }

  if (isPlainObject(columnValue) || Array.isArray(columnValue)) {
    return {
      ok: true,
      empty: false,
      data: columnValue,
      error: null,
    };
  }

  return {
    ok: false,
    empty: false,
    data: null,
    error: "Invalid JSON stored in database",
  };
};

const parseJsonTextCandidate = (text) => {
  const jsonText = sanitizeJsonText(text);

  if (!jsonText) {
    return {
      ok: false,
      empty: true,
      data: null,
      error: null,
    };
  }

  try {
    const decoded = JSON.parse(jsonText);

    if (!isPlainObject(decoded) && !Array.isArray(decoded)) {
      return {
        ok: false,
        empty: false,
        data: null,
        error: "Decoded JSON root must be object or array",
      };
    }

    return {
      ok: true,
      empty: false,
      data: decoded,
      error: null,
    };
  } catch (error) {
    return {
      ok: false,
      empty: false,
      data: null,
      error: error.message,
    };
  }
};

const get_weekly_food_json_suggestions_weeks = async (req, res) => {
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

    const weekStartDate =
      body.week_start_date === undefined || body.week_start_date === null
        ? ""
        : String(body.week_start_date).trim();

    const weekEndDate =
      body.week_end_date === undefined || body.week_end_date === null
        ? ""
        : String(body.week_end_date).trim();

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

    if (!weekStartDate) {
      return sendResponse(res, 400, {
        status: false,
        message: "week_start_date is required",
      });
    }

    if (!weekEndDate) {
      return sendResponse(res, 400, {
        status: false,
        message: "week_end_date is required",
      });
    }

    if (!isValidDateOnly(weekStartDate)) {
      return sendResponse(res, 400, {
        status: false,
        message: "week_start_date must be in Y-m-d format",
      });
    }

    if (!isValidDateOnly(weekEndDate)) {
      return sendResponse(res, 400, {
        status: false,
        message: "week_end_date must be in Y-m-d format",
      });
    }

    if (!isStartDateBeforeOrSameEndDate(weekStartDate, weekEndDate)) {
      return sendResponse(res, 400, {
        status: false,
        message: "week_end_date must be greater than or equal to week_start_date",
      });
    }

    /**
     * VAPT / IDOR protection:
     * 1. Token dietitian must match requested dietitian_id.
     * 2. profile_id must belong to that dietitian.
     */
    const access = await requireProfileAccess(req, dietitianId, profileId);

    if (!access.allowed) {
      return sendResponse(res, access.statusCode, {
        status: false,
        message: access.message,
      });
    }

    const [rows] = await pool.execute(
      `
        SELECT
          id,
          dietician_id,
          profile_id,
          week_start_date,
          week_end_date,
          month_no,
          year_no,
          source_api_date,
          status,
          food_json,
          created_at,
          updated_at
        FROM weekly_food_json_suggestions
        WHERE profile_id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND week_start_date = ?
          AND week_end_date = ?
        LIMIT 1
      `,
      [access.profileId, access.dieticianId, weekStartDate, weekEndDate]
    );

    if (!rows.length) {
      return sendResponse(res, 404, {
        status: false,
        message: "No food json found for selected week",
        profile_id: access.profileId,
        dietitian_id: access.dieticianId,
        week_start_date: weekStartDate,
        week_end_date: weekEndDate,
      });
    }

    const row = rows[0];

    const parsedFoodJson = parseJsonColumn(row.food_json);

    if (parsedFoodJson.empty) {
      return sendResponse(res, 500, {
        status: false,
        message: "food_json is empty in database",
      });
    }

    if (!parsedFoodJson.ok) {
      console.error("Invalid weekly food_json:", {
        profile_id: access.profileId,
        dietitian_id: access.dieticianId,
        week_start_date: weekStartDate,
        week_end_date: weekEndDate,
        error: parsedFoodJson.error,
      });

      return sendResponse(res, 500, {
        status: false,
        message: "Invalid food_json stored in database",
        ...(!isProduction && {
          error: parsedFoodJson.error,
        }),
      });
    }

    const rowWeekStartDate = formatDateOnly(row.week_start_date);
    const rowWeekEndDate = formatDateOnly(row.week_end_date);

    return sendResponse(res, 200, {
      status: true,
      message: "Weekly food json suggestions fetched successfully",
      data: {
        id: Number(row.id),
        dietitian_id: row.dietician_id,
        profile_id: row.profile_id,
        week_start_date: rowWeekStartDate,
        week_end_date: rowWeekEndDate,
        week_range: `${formatDisplayDate(rowWeekStartDate)} - ${formatDisplayDate(
          rowWeekEndDate
        )}`,
        month_no: Number(row.month_no),
        year_no: Number(row.year_no),
        source_api_date: formatDateOnly(row.source_api_date),
        status_value: Number(row.status),
        food_json: parsedFoodJson.data,
        created_at: formatDateTime(row.created_at),
        updated_at: formatDateTime(row.updated_at),
      },
    });
  } catch (error) {
    console.error("get_weekly_food_json_suggestions_weeks error:", {
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
  get_weekly_food_json_suggestions_weeks,
};