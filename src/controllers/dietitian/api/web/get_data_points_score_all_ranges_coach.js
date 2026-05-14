const pool = require("../../../../config/db");

const {
  normalizeId,
  normalizeDieticianId,
  requireProfileAccess,
} = require("../../../../utils/accessControl");

const isProduction =
  process.env.NODE_ENV === "production" ||
  Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

const sendResponse = (res, httpCode, status, message, data = null) => {
  const response = {
    status,
    message,
  };

  if (status === true && data !== null) {
    response.data = data;
  }

  return res.status(httpCode).json(response);
};

const getValue = (object, keys, defaultValue = null) => {
  let temp = object;

  for (const key of keys) {
    if (
      temp === null ||
      temp === undefined ||
      typeof temp !== "object" ||
      Array.isArray(temp) ||
      !Object.prototype.hasOwnProperty.call(temp, key)
    ) {
      return defaultValue;
    }

    temp = temp[key];
  }

  return temp;
};

const cleanFloat = (value, defaultValue = 0) => {
  if (value === null || value === undefined || value === "") {
    return defaultValue;
  }

  const number = Number(value);

  return Number.isFinite(number) ? number : defaultValue;
};

const cleanString = (value, defaultValue = "NA") => {
  if (value === null || value === undefined || value === "") {
    return defaultValue;
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

const formatDateTime = (value) => {
  if (!value) return "NA";

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

const formatDisplayDate = (dateString) => {
  if (!isValidDateOnly(dateString)) {
    return "NA";
  }

  const [year, month, day] = dateString.split("-").map(Number);

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

const resolveProfileImage = (profileImage, profileId) => {
  if (!profileImage) return null;

  const image = String(profileImage).trim();

  if (!image) return null;

  try {
    const url = new URL(image);

    if (url.protocol === "https:" || url.protocol === "http:") {
      return image;
    }
  } catch (_) {
    // Not a full URL, fallback below.
  }

  return `https://humorstech.com/dietitian/api/web/get_profile_image.php?profile_id=${encodeURIComponent(
    profileId
  )}`;
};

const parseFoodType = (foodTypeRaw) => {
  if (!foodTypeRaw) {
    return {
      raw: "NA",
      diet_type: "NA",
      primary_cuisine: "NA",
      secondary_cuisine: "NA",
    };
  }

  const raw = String(foodTypeRaw).trim();

  const result = {
    raw,
    diet_type: "NA",
    primary_cuisine: "NA",
    secondary_cuisine: "NA",
  };

  try {
    const decoded = JSON.parse(raw);

    if (decoded && typeof decoded === "object" && !Array.isArray(decoded)) {
      result.diet_type =
        decoded.diet_type !== undefined && decoded.diet_type !== ""
          ? String(decoded.diet_type)
          : "NA";

      result.primary_cuisine =
        decoded.primary_cuisine !== undefined && decoded.primary_cuisine !== ""
          ? String(decoded.primary_cuisine)
          : "NA";

      result.secondary_cuisine =
        decoded.secondary_cuisine !== undefined &&
        decoded.secondary_cuisine !== ""
          ? String(decoded.secondary_cuisine)
          : "NA";

      return result;
    }
  } catch (_) {
    // Continue with legacy fallback parsing.
  }

  const trimmed = raw.replace(/^\{/, "").replace(/\}$/, "").trim();
  const pairs = trimmed.split(",");

  for (const pair of pairs) {
    const parts = pair.split(":");

    if (parts.length < 2) continue;

    const key = parts[0].trim();
    const value = parts.slice(1).join(":").trim();

    if (key === "diet_type") {
      result.diet_type = value !== "" ? value : "NA";
    } else if (key === "primary_cuisine") {
      result.primary_cuisine = value !== "" ? value : "NA";
    } else if (key === "secondary_cuisine") {
      result.secondary_cuisine = value !== "" ? value : "NA";
    }
  }

  return result;
};

const buildTrendItem = (decodedJson, key, title) => {
  return {
    title,
    score: cleanFloat(
      getValue(decodedJson, ["Metabolism_Score_Analysis", key, "score"], 0)
    ),
    zone: cleanString(
      getValue(decodedJson, ["Metabolism_Score_Analysis", key, "zone"], "NA")
    ),
    short_text: cleanString(
      getValue(
        decodedJson,
        ["Metabolism_Score_Analysis", key, "client_state"],
        "NA"
      )
    ),
    interpretation: cleanString(
      getValue(
        decodedJson,
        ["Metabolism_Score_Analysis", key, "interpretation"],
        "NA"
      )
    ),
    intervention: cleanString(
      getValue(
        decodedJson,
        ["Metabolism_Score_Analysis", key, "intervention"],
        "NA"
      )
    ),
    what_is_this_score: cleanString(
      getValue(
        decodedJson,
        ["Metabolism_Score_Analysis", key, "what_is_this_score"],
        "NA"
      )
    ),
  };
};

const get_data_points_score_all_ranges_coach = async (req, res) => {
  try {
    const body = req.body;

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return sendResponse(res, 400, false, "Invalid raw JSON body");
    }

    const profileId = normalizeId(body.profile_id);
    const dietitianId = normalizeDieticianId(body.dietitian_id);
    const selectedDate =
      body.date === undefined || body.date === null
        ? ""
        : String(body.date).trim();

    if (!profileId) {
      return sendResponse(res, 400, false, "profile_id is required");
    }

    if (!dietitianId) {
      return sendResponse(res, 400, false, "dietitian_id is required");
    }

    if (!selectedDate) {
      return sendResponse(res, 400, false, "date is required");
    }

    if (!isValidDateOnly(selectedDate)) {
      return sendResponse(res, 400, false, "Invalid date format. Use YYYY-MM-DD");
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

    // =========================
    // TOTAL TEST TAKEN
    // =========================
    const [countRows] = await pool.execute(
      `
        SELECT COUNT(*) AS total_test_taken
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(TRIM(dietitian_id)) = ?
      `,
      [access.profileId, access.dieticianId]
    );

    const totalTestTaken = Number(countRows?.[0]?.total_test_taken || 0);

    // =========================
    // PROFILE DETAILS
    // =========================
    const [profileRows] = await pool.execute(
      `
        SELECT
          profile_id,
          dietician_id,
          profile_name,
          phone_no,
          email,
          profile_image,
          dob,
          age,
          gender,
          height,
          weight,
          region,
          location,
          level_type,
          dttm
        FROM table_clients
        WHERE profile_id = ?
          AND UPPER(TRIM(dietician_id)) = ?
        LIMIT 1
      `,
      [access.profileId, access.dieticianId]
    );

    if (!profileRows.length) {
      return sendResponse(res, 404, false, "Profile details not found");
    }

    const profileRow = profileRows[0];

    const profileDetails = {
      profile_id: cleanString(profileRow.profile_id, "NA"),
      dietitian_id: cleanString(profileRow.dietician_id, "NA"),
      profile_name: cleanString(profileRow.profile_name, "NA"),
      phone_no: cleanString(profileRow.phone_no, "NA"),
      email: cleanString(profileRow.email, "NA"),
      profile_image: resolveProfileImage(
        profileRow.profile_image,
        profileRow.profile_id
      ),
      dob: cleanString(profileRow.dob, "NA"),
      age: cleanString(profileRow.age, "NA"),
      gender: cleanString(profileRow.gender, "NA"),
      height: cleanString(profileRow.height, "NA"),
      weight: cleanString(profileRow.weight, "NA"),
      region: cleanString(profileRow.region, "NA"),
      location: cleanString(profileRow.location, "NA"),
      joined_dttm: cleanString(formatDateTime(profileRow.dttm), "NA"),
      level_type: cleanString(profileRow.level_type, "NA"),
    };

    // =========================
    // USER HABITS
    // =========================
    const [habitRows] = await pool.execute(
      `
        SELECT
          profile_id,
          goal,
          activity,
          food_type,
          dttm,
          tsstamp
        FROM user_habits
        WHERE profile_id = ?
        ORDER BY id DESC
        LIMIT 1
      `,
      [access.profileId]
    );

    let userHabits;

    if (habitRows.length) {
      const habitsRow = habitRows[0];
      const parsedFoodType = parseFoodType(habitsRow.food_type);

      userHabits = {
        profile_id: cleanString(habitsRow.profile_id, "NA"),
        goal: cleanString(habitsRow.goal, "NA"),
        activity: cleanString(habitsRow.activity, "NA"),
        food_type: parsedFoodType,
        dttm: cleanString(formatDateTime(habitsRow.dttm), "NA"),
        tsstamp: cleanString(formatDateTime(habitsRow.tsstamp), "NA"),
      };
    } else {
      userHabits = {
        profile_id: access.profileId,
        goal: "NA",
        activity: "NA",
        food_type: {
          raw: "NA",
          diet_type: "NA",
          primary_cuisine: "NA",
          secondary_cuisine: "NA",
        },
        dttm: "NA",
        tsstamp: "NA",
      };
    }

    // =========================
    // TEST DATA FOR EXACT DATE
    // =========================
    const [testRows] = await pool.execute(
      `
        SELECT
          test_id,
          profile_id,
          test_json,
          date_time
        FROM table_test_data
        WHERE profile_id = ?
          AND UPPER(TRIM(dietitian_id)) = ?
          AND DATE(date_time) = ?
        ORDER BY date_time DESC
        LIMIT 1
      `,
      [access.profileId, access.dieticianId, selectedDate]
    );

    if (!testRows.length) {
      return sendResponse(res, 404, false, "No data available for selected date");
    }

    const selectedRow = testRows[0];
    const jsonString = selectedRow.test_json;

    if (!jsonString) {
      return sendResponse(res, 404, false, "test_json is empty");
    }

    let decodedJson;

    try {
      decodedJson =
        typeof jsonString === "object" ? jsonString : JSON.parse(jsonString);
    } catch (error) {
      console.error("Invalid test_json:", {
        profile_id: access.profileId,
        dietitian_id: access.dieticianId,
        selected_date: selectedDate,
      });

      return sendResponse(res, 500, false, "Invalid JSON in test_json column");
    }

    if (
      decodedJson === null ||
      typeof decodedJson !== "object" ||
      Array.isArray(decodedJson)
    ) {
      return sendResponse(res, 500, false, "Invalid JSON in test_json column");
    }

    const fatScore = cleanFloat(
      getValue(decodedJson, ["Fat_Use_Pattern_trend", "score"], 0)
    );

    const fatZone = cleanString(
      getValue(decodedJson, ["Fat_Use_Pattern_trend", "zone"], "NA")
    );

    const fatTitle = cleanString(
      getValue(
        decodedJson,
        ["Fat_Use_Pattern_trend", "client_interpretation", "title"],
        "NA"
      )
    );

    const fatText = cleanString(
      getValue(
        decodedJson,
        ["Fat_Use_Pattern_trend", "client_interpretation", "text"],
        "NA"
      )
    );

    const fatScientificTitle = cleanString(
      getValue(
        decodedJson,
        ["Fat_Use_Pattern_trend", "scientific_interpretation", "title"],
        "NA"
      )
    );

    const fatScientificText = cleanString(
      getValue(
        decodedJson,
        ["Fat_Use_Pattern_trend", "scientific_interpretation", "text"],
        "NA"
      )
    );

    const digestiveActivity = buildTrendItem(
      decodedJson,
      "Digestive_Activity_Trend",
      "Digestive Activity Trend"
    );

    const nutrientUtilization = buildTrendItem(
      decodedJson,
      "Nutrient_Utilization_Trend",
      "Nutrient Utilization Trend"
    );

    const fuelUtilization = buildTrendItem(
      decodedJson,
      "Fuel_Utilization_Trend",
      "Fuel Utilization Trend"
    );

    const energySource = buildTrendItem(
      decodedJson,
      "Energy_Source_Trend",
      "Energy Source Trend"
    );

    const recoveryActivity = buildTrendItem(
      decodedJson,
      "Recovery_Activity_Trend",
      "Recovery Activity Trend"
    );

    const metabolicLoad = buildTrendItem(
      decodedJson,
      "Metabolic_Load_Trend",
      "Metabolic Load Trend"
    );

    const whatToDo = getValue(decodedJson, ["day_focus", "what_to_do"], []);
    const avoidToday = getValue(decodedJson, ["day_focus", "avoid_today"], []);
    const signals = getValue(decodedJson, ["day_focus", "signals"], []);

    const dayFocus = {
      title: cleanString(getValue(decodedJson, ["day_focus", "title"], "NA")),
      note: cleanString(getValue(decodedJson, ["day_focus", "note"], "NA")),
      why_today: cleanString(
        getValue(decodedJson, ["day_focus", "why_today"], "NA")
      ),
      what_to_do: Array.isArray(whatToDo) ? whatToDo : [],
      avoid_today: Array.isArray(avoidToday) ? avoidToday : [],
      signals: Array.isArray(signals) ? signals : [],
    };

    const energy = {
      mode: cleanString(getValue(decodedJson, ["energy", "mode"], "NA")),
      activity: cleanString(getValue(decodedJson, ["energy", "activity"], "NA")),
      bmr_kcal: cleanFloat(getValue(decodedJson, ["energy", "bmr_kcal"], 0)),
      tdee_kcal: cleanFloat(getValue(decodedJson, ["energy", "tdee_kcal"], 0)),
      target_kcal: cleanFloat(
        getValue(decodedJson, ["energy", "target_kcal"], 0)
      ),
    };

    const breathMarkers = {
      acetone: {
        ppm: cleanFloat(
          getValue(decodedJson, ["breath_marker_analysis", "acetone", "ppm"], 0)
        ),
        marker: cleanString(
          getValue(
            decodedJson,
            ["breath_marker_analysis", "acetone", "marker"],
            "acetone"
          )
        ),
      },
      ethanol: {
        ppm: cleanFloat(
          getValue(decodedJson, ["breath_marker_analysis", "ethanol", "ppm"], 0)
        ),
        marker: cleanString(
          getValue(
            decodedJson,
            ["breath_marker_analysis", "ethanol", "marker"],
            "ethanol"
          )
        ),
      },
      hydrogen: {
        ppm: cleanFloat(
          getValue(decodedJson, ["breath_marker_analysis", "hydrogen", "ppm"], 0)
        ),
        marker: cleanString(
          getValue(
            decodedJson,
            ["breath_marker_analysis", "hydrogen", "marker"],
            "hydrogen"
          )
        ),
      },
    };

    const metabolismScoreSummary = getValue(
      decodedJson,
      ["Metabolism_Score_Analysis", "metabolism_score_summary"],
      []
    );

    const aiStatus = getValue(decodedJson, ["ai_status"], []);

    const responseData = {
      total_test_taken: totalTestTaken,
      profile_details: profileDetails,
      user_habits: userHabits,
      selected_test: {
        test_id: Number(selectedRow.test_id),
        profile_id: selectedRow.profile_id,
        dietitian_id: access.dieticianId,
        date: selectedDate,
        display_date: formatDisplayDate(selectedDate),
        date_time: formatDateTime(selectedRow.date_time),
        bmi: cleanFloat(getValue(decodedJson, ["bmi"], 0)),
        mode: cleanString(getValue(decodedJson, ["mode"], "NA")),
        wellness_note: cleanString(
          getValue(decodedJson, ["wellness_note"], "NA")
        ),
      },
      fat_use_pattern_trend: {
        title: "Fat-use pattern Trend",
        score: Number(fatScore.toFixed(2)),
        score_text: `${Math.round(fatScore)}%`,
        zone: fatZone,
        client_title: fatTitle,
        client_text: fatText,
        scientific_title: fatScientificTitle,
        scientific_text: fatScientificText,
      },
      trend_breakdown: {
        digestive_balance_trend: {
          tab_title: "Digestive Balance Trend",
          items: [nutrientUtilization, digestiveActivity],
        },
        fuel_and_energy_trend: {
          tab_title: "Fuel & Energy Trend",
          items: [fuelUtilization, energySource],
        },
        metabolic_recovery_trend: {
          tab_title: "Metabolic Recovery Trend",
          items: [recoveryActivity, metabolicLoad],
        },
      },
      trainer_note_section: {
        section_label: "TRAINER NOTE",
        sub_label: "What to focus on today",
        title: dayFocus.title,
        note: dayFocus.note,
        why_today: dayFocus.why_today,
        what_to_do: dayFocus.what_to_do,
        avoid_today: dayFocus.avoid_today,
        signals: dayFocus.signals,
      },
      energy,
      breath_markers: breathMarkers,
      metabolism_score_summary: Array.isArray(metabolismScoreSummary)
        ? metabolismScoreSummary
        : [],
      ai_status: Array.isArray(aiStatus) ? aiStatus : [],
      raw_json: decodedJson,
    };

    return sendResponse(res, 200, true, "Data fetched successfully", responseData);
  } catch (error) {
    console.error("get_data_points_score_all_ranges_coach error:", {
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
  get_data_points_score_all_ranges_coach,
};