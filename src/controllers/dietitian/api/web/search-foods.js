"use strict";

const axios = require("axios");

/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
|
| Do NOT hardcode the FitChef domain here.
|
| Lambda / server environment:
|
| FITCHEF_API_BASE_URL=https://respyr.in/fitchef-dashboard
|
| Later, when the FitChef URL changes, only change the environment variable.
| No frontend or source-code change will be required.
|
*/

const FITCHEF_API_BASE_URL = String(
  process.env.FITCHEF_API_BASE_URL || ""
)
  .trim()
  .replace(/\/+$/, "");

const FITCHEF_API_TIMEOUT_MS =
  Number(process.env.FITCHEF_API_TIMEOUT_MS) || 10000;

/*
|--------------------------------------------------------------------------
| Optional service-to-service authentication
|--------------------------------------------------------------------------
|
| You can leave this empty for now.
|
| Later, if you protect the Python/FitChef API itself:
|
| FITCHEF_SERVICE_KEY=<secret>
|
| Node will automatically send:
|
| X-Service-Key: <secret>
|
*/

const FITCHEF_SERVICE_KEY = String(
  process.env.FITCHEF_SERVICE_KEY || ""
).trim();

/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

function cleanString(value, maxLength = 100) {
  if (value === undefined || value === null) {
    return "";
  }

  return String(value)
    .trim()
    .slice(0, maxLength);
}

function validSearchText(value) {
  /*
   * Allow normal food-search characters.
   *
   * Examples:
   * chicken
   * chicken breast
   * chicken & rice
   * greek-yogurt
   * 96% beef
   */
  return /^[a-zA-Z0-9\s&(),'%.+\-_/]*$/.test(value);
}

function normalizeSlot(value) {
  const slot = cleanString(value, 40)
    .toLowerCase()
    .replace(/\s+/g, "_");

  const aliases = {
    breakfast: "breakfast",
    lunch: "lunch",
    dinner: "dinner",

    snack: "snack",
    snacks: "snack",

    snack_evening: "snack",
    evening_snack: "snack",
    evening_snacks: "snack",
  };

  return aliases[slot] || slot;
}

/*
|--------------------------------------------------------------------------
| Controller
|--------------------------------------------------------------------------
|
| Endpoint:
|
| GET /dietitian/api/web/search-foods
|
| Example:
|
| /dietitian/api/web/search-foods
|   ?slot=breakfast
|   &diet=non_veg
|   &q=chicken
|
| Authentication:
| authMiddleware MUST run before this controller.
|
*/

const searchFoods = async (req, res) => {
  /*
  |--------------------------------------------------------------------------
  | HIPAA / sensitive-data caching protection
  |--------------------------------------------------------------------------
  */

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  try {
    /*
    |--------------------------------------------------------------------------
    | 1. Configuration check
    |--------------------------------------------------------------------------
    */

    if (!FITCHEF_API_BASE_URL) {
      console.error("FITCHEF_API_BASE_URL_MISSING");

      return res.status(500).json({
        status: false,
        ok: false,
        message: "Food search service is not configured",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | 2. Authentication safety check
    |--------------------------------------------------------------------------
    |
    | authMiddleware should already have populated req.user.
    | This additional check makes the controller fail closed if somebody
    | accidentally registers the route without authMiddleware.
    |--------------------------------------------------------------------------
    */

    if (!req.user) {
      return res.status(401).json({
        status: false,
        ok: false,
        message: "Authentication required",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | 3. Read and validate query parameters
    |--------------------------------------------------------------------------
    */

    const slot = normalizeSlot(req.query?.slot);

    const diet = cleanString(
      req.query?.diet,
      50
    ).toLowerCase();

    const q = cleanString(
      req.query?.q,
      100
    );

    /*
    |--------------------------------------------------------------------------
    | slot
    |--------------------------------------------------------------------------
    */

    if (!slot) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "slot is required",
      });
    }

    const allowedSlots = new Set([
      "breakfast",
      "lunch",
      "dinner",
      "snack",
    ]);

    if (!allowedSlots.has(slot)) {
      return res.status(400).json({
        status: false,
        ok: false,
        message:
          "Invalid slot. Allowed: breakfast, lunch, dinner, snack",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | diet
    |--------------------------------------------------------------------------
    |
    | Do not unnecessarily restrict diet values because FitChef may add
    | additional diet types later.
    |
    | Only restrict format/length.
    |--------------------------------------------------------------------------
    */

    if (diet && !/^[a-z0-9_-]{1,50}$/.test(diet)) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "Invalid diet value",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | q
    |--------------------------------------------------------------------------
    */

    if (!q) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "q is required",
      });
    }

    if (q.length < 2) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "Search query must contain at least 2 characters",
      });
    }

    if (!validSearchText(q)) {
      return res.status(400).json({
        status: false,
        ok: false,
        message: "Search query contains invalid characters",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Optional pagination
    |--------------------------------------------------------------------------
    */

    let page = null;
    let pageSize = null;

    if (
      req.query?.page !== undefined &&
      req.query?.page !== ""
    ) {
      page = Number.parseInt(
        req.query.page,
        10
      );

      if (
        !Number.isInteger(page) ||
        page < 0 ||
        page > 1000
      ) {
        return res.status(400).json({
          status: false,
          ok: false,
          message: "Invalid page",
        });
      }
    }

    if (
      req.query?.page_size !== undefined &&
      req.query?.page_size !== ""
    ) {
      pageSize = Number.parseInt(
        req.query.page_size,
        10
      );

      if (
        !Number.isInteger(pageSize) ||
        pageSize < 1 ||
        pageSize > 100
      ) {
        return res.status(400).json({
          status: false,
          ok: false,
          message:
            "page_size must be between 1 and 100",
        });
      }
    }

    /*
    |--------------------------------------------------------------------------
    | 4. Build FitChef query
    |--------------------------------------------------------------------------
    */

    const params = {
      slot,
      q,
    };

    if (diet) {
      params.diet = diet;
    }

    if (page !== null) {
      params.page = page;
    }

    if (pageSize !== null) {
      params.page_size = pageSize;
    }

    /*
    |--------------------------------------------------------------------------
    | 5. Optional internal authentication
    |--------------------------------------------------------------------------
    */

    const upstreamHeaders = {
      Accept: "application/json",
    };

    if (FITCHEF_SERVICE_KEY) {
      upstreamHeaders["X-Service-Key"] =
        FITCHEF_SERVICE_KEY;
    }

    /*
    |--------------------------------------------------------------------------
    | 6. Call FitChef
    |--------------------------------------------------------------------------
    |
    | Internally this becomes:
    |
    | https://respyr.in/fitchef-dashboard/api/foods
    | ?slot=breakfast
    | &diet=non_veg
    | &q=chicken
    |
    | But the browser never needs to know that URL.
    |--------------------------------------------------------------------------
    */

    const response = await axios.get(
      `${FITCHEF_API_BASE_URL}/api/foods`,
      {
        params,

        headers: upstreamHeaders,

        timeout:
          FITCHEF_API_TIMEOUT_MS,

        /*
         * Don't silently follow unexpected redirects.
         */
        maxRedirects: 0,

        /*
         * Protect the Node/Lambda process from an unexpectedly
         * massive upstream response.
         */
        maxContentLength:
          5 * 1024 * 1024,

        validateStatus: (status) =>
          status >= 200 && status < 300,
      }
    );

    /*
    |--------------------------------------------------------------------------
    | 7. Validate upstream response
    |--------------------------------------------------------------------------
    */

    const data = response.data;

    if (
      !data ||
      typeof data !== "object"
    ) {
      console.error(
        "FITCHEF_SEARCH_INVALID_RESPONSE"
      );

      return res.status(502).json({
        status: false,
        ok: false,
        message:
          "Invalid response from food search service",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | 8. Return FitChef response
    |--------------------------------------------------------------------------
    |
    | Returning the upstream response directly means your frontend can keep
    | using:
    |
    | response.results
    | response.count
    | response.page
    | response.pages
    | etc.
    |
    |--------------------------------------------------------------------------
    */

    return res
      .status(200)
      .json(data);

  } catch (error) {
    /*
    |--------------------------------------------------------------------------
    | Axios timeout
    |--------------------------------------------------------------------------
    */

    if (
      error?.code === "ECONNABORTED" ||
      error?.code === "ETIMEDOUT"
    ) {
      console.error(
        "FITCHEF_SEARCH_TIMEOUT"
      );

      return res.status(504).json({
        status: false,
        ok: false,
        message:
          "Food search service timed out",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | FitChef HTTP error
    |--------------------------------------------------------------------------
    */

    if (error?.response) {
      console.error(
        "FITCHEF_SEARCH_UPSTREAM_ERROR:",
        {
          status:
            error.response.status,
        }
      );

      return res.status(502).json({
        status: false,
        ok: false,
        message:
          "Food search service is temporarily unavailable",
      });
    }

    /*
    |--------------------------------------------------------------------------
    | Network / other error
    |--------------------------------------------------------------------------
    */

    console.error(
      "SEARCH_FOODS_ERROR:",
      {
        code:
          error?.code || null,

        message:
          error?.message || null,
      }
    );

    return res.status(500).json({
      status: false,
      ok: false,
      message:
        "Something went wrong while searching foods",
    });
  }
};

module.exports = {
  searchFoods,
};