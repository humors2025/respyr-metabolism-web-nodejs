"use strict";

/**
 * search-ingredients.js
 *
 * Ingredient-level search against the FitChef service — the two steps of
 * the trainer dashboard's "search by ingredient" flow, proxied the same way
 * search-foods.js proxies the dish bank so the browser never learns the
 * FitChef URL:
 *
 *   GET /dietitian/api/web/search-ingredients?q=salmon
 *       → FitChef /api/fc_ingredients   every ingredient harvested from real
 *                                       FitChef recipes, with the
 *                                       excludable-set (`set`) it maps to
 *
 *   GET /dietitian/api/web/recipes-by-ingredient?set=salmon_fillet&user=<plan>&day=0&meal=2
 *       → FitChef /api/fc_recipes       recipes containing that ingredient,
 *                                       filtered to the meal's slot and
 *                                       scored by the day deviation they
 *                                       leave (needs the plan FitChef
 *                                       generated — `user` is the stem of
 *                                       food_json._saved_to)
 *
 * Auth: authMiddleware MUST run before both handlers. Read-only.
 */

const axios = require("axios");

const FITCHEF_API_BASE_URL = String(process.env.FITCHEF_API_BASE_URL || process.env.FITCHEF_DASHBOARD_URL || "")
  .trim()
  .replace(/\/+$/, "");

const FITCHEF_API_TIMEOUT_MS = Number(process.env.FITCHEF_API_TIMEOUT_MS) || 10000;

// fc_recipes may have to ask FitChef itself for recipe detail; give it longer
const FITCHEF_RECIPES_TIMEOUT_MS = Number(process.env.FITCHEF_RECIPES_TIMEOUT_MS) || 30000;

const FITCHEF_SERVICE_KEY = String(process.env.FITCHEF_SERVICE_KEY || "").trim();

function cleanString(value, maxLength = 100) {
  if (value === undefined || value === null) return "";
  return String(value).trim().slice(0, maxLength);
}

function resolveImage(url) {
  const value = cleanString(url, 2000);
  if (!value) return null;
  if (/^https?:\/\//i.test(value)) return value;
  return `${FITCHEF_API_BASE_URL}${value.startsWith("/") ? "" : "/"}${value}`;
}

function upstreamHeaders() {
  const headers = { Accept: "application/json" };
  if (FITCHEF_SERVICE_KEY) headers["X-Service-Key"] = FITCHEF_SERVICE_KEY;
  return headers;
}

function notConfigured(res) {
  console.error("FITCHEF_API_BASE_URL_MISSING");
  return res.status(500).json({ status: false, ok: false, message: "Food search service is not configured" });
}

function upstreamError(res, error, tag) {
  if (error?.code === "ECONNABORTED" || error?.code === "ETIMEDOUT") {
    console.error(`${tag}_TIMEOUT`);
    return res.status(504).json({ status: false, ok: false, message: "Food search service timed out" });
  }
  if (error?.response) {
    console.error(`${tag}_UPSTREAM_ERROR:`, { status: error.response.status });
    // 404 = no such plan / meal on the FitChef side; the caller can act on that
    if (error.response.status === 404) {
      return res.status(404).json({ status: false, ok: false, message: error.response.data?.error || "Not found" });
    }
    return res.status(502).json({ status: false, ok: false, message: "Food search service is temporarily unavailable" });
  }
  console.error(`${tag}_ERROR:`, { code: error?.code || null, message: error?.message || null });
  return res.status(500).json({ status: false, ok: false, message: "Something went wrong while searching" });
}

/*
|--------------------------------------------------------------------------
| GET /dietitian/api/web/search-ingredients?q=
|--------------------------------------------------------------------------
*/
const searchIngredients = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  try {
    if (!FITCHEF_API_BASE_URL) return notConfigured(res);
    if (!req.user) return res.status(401).json({ status: false, ok: false, message: "Authentication required" });

    const q = cleanString(req.query?.q, 100);
    if (!/^[a-zA-Z0-9\s&(),'%.+\-_/]*$/.test(q)) {
      return res.status(400).json({ status: false, ok: false, message: "Search query contains invalid characters" });
    }

    const response = await axios.get(`${FITCHEF_API_BASE_URL}/api/fc_ingredients`, {
      params: { q },
      headers: upstreamHeaders(),
      timeout: FITCHEF_API_TIMEOUT_MS,
      maxRedirects: 0,
      maxContentLength: 5 * 1024 * 1024,
      validateStatus: (s) => s >= 200 && s < 300,
    });

    const data = response.data;
    if (!data || typeof data !== "object") {
      console.error("FITCHEF_INGREDIENTS_INVALID_RESPONSE");
      return res.status(502).json({ status: false, ok: false, message: "Invalid response from food search service" });
    }

    // only what the picker needs; the harvest carries recipe ids we never show
    const results = Array.isArray(data.results)
      ? data.results.map((r) => ({
          key: cleanString(r?.key, 80),
          name: cleanString(r?.name, 120),
          unit: cleanString(r?.unit, 40),
          set: cleanString(r?.set, 80),
          recipes: Number(r?.recipes) || 0,
        }))
      : [];

    return res.status(200).json({
      status: true,
      ok: true,
      query: q,
      corrected: data.corrected && typeof data.corrected === "object" ? data.corrected : {},
      count: Number(data.count) || results.length,
      searchable: Number(data.searchable) || 0,
      results,
    });
  } catch (error) {
    return upstreamError(res, error, "FITCHEF_INGREDIENTS");
  }
};

/*
|--------------------------------------------------------------------------
| GET /dietitian/api/web/recipes-by-ingredient?set=&user=&day=&meal=
|--------------------------------------------------------------------------
*/
const recipesByIngredient = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  try {
    if (!FITCHEF_API_BASE_URL) return notConfigured(res);
    if (!req.user) return res.status(401).json({ status: false, ok: false, message: "Authentication required" });

    const set = cleanString(req.query?.set, 80);
    if (!set || !/^[a-z0-9_\-]+$/i.test(set)) {
      return res.status(400).json({ status: false, ok: false, message: "set is required (an ingredient set slug)" });
    }
    const user = cleanString(req.query?.user, 120);
    if (!user || !/^[A-Za-z0-9_\-]+$/.test(user)) {
      return res.status(400).json({ status: false, ok: false, message: "user is required (the FitChef plan key)" });
    }
    const day = Number.parseInt(req.query?.day, 10);
    const meal = Number.parseInt(req.query?.meal, 10);
    if (!Number.isInteger(day) || day < 0 || day > 30 || !Number.isInteger(meal) || meal < 0 || meal > 20) {
      return res.status(400).json({ status: false, ok: false, message: "day and meal must be non-negative integers" });
    }

    const response = await axios.get(`${FITCHEF_API_BASE_URL}/api/fc_recipes`, {
      params: { set, user, day, meal },
      headers: upstreamHeaders(),
      timeout: FITCHEF_RECIPES_TIMEOUT_MS,
      maxRedirects: 0,
      maxContentLength: 5 * 1024 * 1024,
      validateStatus: (s) => s >= 200 && s < 300,
    });

    const data = response.data;
    if (!data || typeof data !== "object") {
      console.error("FITCHEF_RECIPES_INVALID_RESPONSE");
      return res.status(502).json({ status: false, ok: false, message: "Invalid response from food search service" });
    }

    const results = Array.isArray(data.results)
      ? data.results.map((r) => ({
          recipe_id: cleanString(r?.recipe_id, 40),
          name: cleanString(r?.name, 160),
          image: resolveImage(r?.image),
          method: typeof r?.method === "string" ? r.method : "",
          ingredients: Array.isArray(r?.ingredients) ? r.ingredients.map((x) => cleanString(x, 160)).filter(Boolean) : [],
          slot: cleanString(r?.slot, 40),
          p: Number(r?.p) || 0,
          c: Number(r?.c) || 0,
          f: Number(r?.f) || 0,
          kcal: Number(r?.kcal) || 0,
          prep_minutes: Number.parseInt(r?.prep_minutes, 10) || null,
          equipment: cleanString(r?.equipment, 160),
          day_deviation: Number.isFinite(Number(r?.day_deviation)) ? Number(r.day_deviation) : null,
          source: "fitchef",
        }))
      : [];

    return res.status(200).json({
      status: true,
      ok: true,
      set,
      slot: cleanString(data.slot, 40),
      source: cleanString(data.source, 60),
      count: Number(data.count) || results.length,
      results,
    });
  } catch (error) {
    return upstreamError(res, error, "FITCHEF_RECIPES");
  }
};

module.exports = { searchIngredients, recipesByIngredient };
