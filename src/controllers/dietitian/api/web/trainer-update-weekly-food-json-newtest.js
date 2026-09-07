"use strict";

/**
 * trainer-update-weekly-food-json-newtest.js
 *
 * Cloned from: trainer-update-weekly-food-json.js — identical logic, but the
 * business table is weekly_food_json_suggestions_newtest instead of
 * weekly_food_json_suggestions. Keep the two files in sync.
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint : POST /dietitian/api/web/trainer-update-weekly-food-json-newtest
 * Auth     : Bearer JWT (authMiddleware must run before this handler)
 *
 * Purpose  : Single API to add / update / delete one food item inside
 *            weekly_food_json_suggestions_newtest.food_json. It accepts either
 *            the dashboard food shape or the authenticated /search-foods result
 *            shape, then recomputes the weekly
 *            macro averages and persist them (food_json, cal, cabs, fats,
 *            `Protein`, `Fibre`).
 *
 * Behaviour parity with the PHP:
 *  - Payload key spelling is dietitian_id; DB column remains dietician_id.
 *  - status is NEVER read as an edit gate and is NEVER written here. status=0
 *    (draft) and status=1 (mobile-visible) both stay editable from the dashboard.
 *  - add  : append a fully-validated food object to the meal.
 *    update: patch an existing food object at food_index (omitted fields kept).
 *    delete: splice out the food object at food_index.
 *  - Weekly macros = sum of every food across all days / day-count (min 7),
 *    rounded to 2 dp, with the same default note string.
 *  - Response keys/shape match the PHP (ok, message, action, id, dietitian_id,
 *    profile_id, week_start_date, week_end_date, status_value, day_code,
 *    meal_type, food_index, changed_food, deleted_food, meal_summary,
 *    day_summary, weekly_json_data, food_json).
 *
 * VAPT hardening:
 *  - Token-bound identity.
 *  - SELECT ... FOR UPDATE transaction locking.
 *  - Parameterized SQL.
 *  - Production-safe error responses.
 *
 * Shopping behaviour:
 *  - NO axios.
 *  - NO FitChef shopping URL.
 *  - NO external shopping regeneration.
 *  - Shopping is rebuilt locally from the exact updated food_json.
 *  - Existing aisle + price metadata is reused whenever possible.
 *  - New ingredients without existing pricing are marked unpriced.
 *
 * Search API compatibility:
 *  - Accepts the raw food object returned by /search-foods.
 *
 *     name      -> food_name
 *     kcal      -> calories
 *     c         -> carbs_g
 *     p         -> protein_g
 *     f         -> fat_g
 *     fiber     -> fiber_g
 *     portion   -> portion_with_metric
 *     contains  -> ingredients
 *     key       -> fitchefKey
 *     method    -> recipe.method
 *     thumb     -> recipe.image
 */

const crypto = require("crypto");
const pool = require("../../../../config/db");

const {
  requireDieticianSelfAccess,
  normalizeId,
} = require("../../../../utils/accessControl");

// =============================================================================
// CONSTANTS
// =============================================================================

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const APP_DEBUG = process.env.NODE_ENV !== "production";

const ALLOWED_ACTIONS = new Set([
  "add",
  "update",
  "delete",
]);

const ALLOWED_MEALS = [
  "breakfast",
  "lunch",
  "snacks",
  "dinner",
];

const REQUIRED_TEXT_FIELDS = [
  "food_name",
  "portion_with_metric",
  "category",
];

const REQUIRED_MACRO_FIELDS = [
  "calories",
  "carbs_g",
  "protein_g",
  "fat_g",
  "fiber_g",
];

const RECIPE_PASSTHROUGH_FIELDS = [
  "recipe",
  "ingredients",
  "recipeId",
  "variantId",
  "hash",
  "eatingMomentId",
  "fitchefKey",
];

const DEFAULT_WEEKLY_NOTE =
  "These values represent the average daily nutrient intake across the full 7-day week.";

// =============================================================================
// API ERROR
// =============================================================================

class ApiError extends Error {
  constructor(statusCode, message, extra = {}) {
    super(message);

    this.statusCode = statusCode;

    this.payload = {
      ok: false,
      message,
      ...extra,
    };
  }
}

function fail(statusCode, message, extra = {}) {
  throw new ApiError(
    statusCode,
    message,
    extra
  );
}

// =============================================================================
// GENERIC HELPERS
// =============================================================================

function isPlainObject(value) {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
  );
}

function copyRecipePassthrough(
  source,
  target
) {
  if (!isPlainObject(source)) {
    return target;
  }

  for (
    const key of
    RECIPE_PASSTHROUGH_FIELDS
  ) {
    if (source[key] !== undefined) {
      target[key] = source[key];
    }
  }

  return target;
}

function isNumericValue(value) {
  if (typeof value === "number") {
    return Number.isFinite(value);
  }

  if (typeof value === "string") {
    const trimmed = value.trim();

    return (
      trimmed !== "" &&
      Number.isFinite(
        Number(trimmed)
      )
    );
  }

  return false;
}

function roundMacro(value) {
  const n = Number(value) || 0;

  return (
    Math.sign(n) *
    Math.round(
      Math.abs(n) * 100 +
        Number.EPSILON
    ) /
    100
  );
}

function requiredString(
  payload,
  key
) {
  if (
    payload[key] === undefined ||
    payload[key] === null ||
    String(payload[key]).trim() === ""
  ) {
    fail(
      400,
      `${key} is required`
    );
  }

  return String(
    payload[key]
  ).trim();
}

function isValidDateString(date) {
  if (
    typeof date !== "string" ||
    date === ""
  ) {
    return false;
  }

  if (
    !/^\d{4}-\d{2}-\d{2}$/.test(
      date
    )
  ) {
    return false;
  }

  const parsed = new Date(
    `${date}T00:00:00.000Z`
  );

  if (
    Number.isNaN(
      parsed.getTime()
    )
  ) {
    return false;
  }

  const [y, m, d] =
    date
      .split("-")
      .map(Number);

  return (
    parsed.getUTCFullYear() === y &&
    parsed.getUTCMonth() + 1 === m &&
    parsed.getUTCDate() === d
  );
}

function formatDateOnly(value) {
  if (!value) {
    return null;
  }

  if (value instanceof Date) {
    if (
      Number.isNaN(
        value.getTime()
      )
    ) {
      return null;
    }

    const pad = (n) =>
      String(n).padStart(
        2,
        "0"
      );

    return (
      `${value.getFullYear()}-` +
      `${pad(
        value.getMonth() + 1
      )}-` +
      `${pad(
        value.getDate()
      )}`
    );
  }

  return String(
    value
  ).slice(0, 10);
}

// =============================================================================
// DAY RESOLUTION
// =============================================================================

const DAY_ID_KEYS = [
  "day_code",
  "day",
  "day_key",
  "day_id",
  "code",
  "day_name",
  "name",
];

const WEEKDAY_NAMES = [
  "sun",
  "mon",
  "tue",
  "wed",
  "thu",
  "fri",
  "sat",
];

function canonicalDayCode(value) {
  const norm =
    String(value ?? "")
      .toLowerCase()
      .replace(
        /[^a-z0-9]/g,
        ""
      );

  if (!norm) {
    return "";
  }

  const positional =
    norm.match(
      /^(?:d|day)0*(\d{1,2})$/
    );

  if (positional) {
    return `d${Number(
      positional[1]
    )}`;
  }

  const weekday =
    WEEKDAY_NAMES.find(
      (w) =>
        norm === w ||
        norm.startsWith(w)
    );

  return weekday || norm;
}

function storedDayCodes(day) {
  if (!isPlainObject(day)) {
    return [];
  }

  const codes = [];

  for (
    const key of
    DAY_ID_KEYS
  ) {
    if (
      day[key] !== undefined &&
      day[key] !== null &&
      day[key] !== ""
    ) {
      const canon =
        canonicalDayCode(
          day[key]
        );

      if (canon) {
        codes.push(canon);
      }
    }
  }

  return codes;
}

function resolveDayIndex(
  days,
  requestedCode
) {
  const target =
    canonicalDayCode(
      requestedCode
    );

  if (
    !target ||
    !Array.isArray(days)
  ) {
    return -1;
  }

  for (
    let i = 0;
    i < days.length;
    i++
  ) {
    if (
      storedDayCodes(
        days[i]
      ).includes(target)
    ) {
      return i;
    }
  }

  const positional =
    target.match(
      /^d(\d{1,2})$/
    );

  if (positional) {
    const idx =
      Number(
        positional[1]
      ) - 1;

    if (
      idx >= 0 &&
      idx < days.length &&
      isPlainObject(
        days[idx]
      )
    ) {
      return idx;
    }
  }

  return -1;
}

// =============================================================================
// MEAL RESOLUTION
// =============================================================================

const MEAL_CONTAINER_KEYS = [
  "meals",
  "meal",
  "meal_plan",
  "mealplan",
  "menu",
  "diet",
  "plan",
];

const MEAL_ID_KEYS = [
  "meal_type",
  "mealtype",
  "meal_name",
  "mealname",
  "meal",
  "slot",
  "title",
  "eating_moment",
  "eatingmoment",
  "code",
  "key",
  "type",
  "name",
];

const FOODS_KEYS = [
  "foods",
  "items",
  "food_items",
  "food_list",
  "food",
  "dishes",
  "list",
  "entries",
];

const EXTRA_FOODS_KEY =
  "extra_foods";

const NUTRITION_TO_MACRO = {
  calories: [
    "kcals",
    "kcal",
    "calories",
    "energy",
  ],

  carbs_g: [
    "carbohydrate",
    "carbohydrates",
    "carbs",
    "carbs_g",
  ],

  protein_g: [
    "protein",
    "proteins",
    "protein_g",
  ],

  fat_g: [
    "fat",
    "fats",
    "fat_g",
  ],

  fiber_g: [
    "fiber",
    "fibre",
    "fiber_g",
    "fibre_g",
  ],
};

function canonicalToken(value) {
  return String(
    value ?? ""
  )
    .toLowerCase()
    .replace(
      /[^a-z0-9]/g,
      ""
    );
}

function canonicalMealType(value) {
  const norm =
    canonicalToken(value);

  if (!norm) {
    return "";
  }

  if (
    norm.includes(
      "breakfast"
    )
  ) {
    return "breakfast";
  }

  if (
    norm.includes(
      "lunch"
    )
  ) {
    return "lunch";
  }

  if (
    norm.includes(
      "dinner"
    )
  ) {
    return "dinner";
  }

  if (
    norm.includes(
      "snack"
    )
  ) {
    return "snacks";
  }

  return norm;
}

function findKeyCI(
  obj,
  wanted
) {
  if (!isPlainObject(obj)) {
    return null;
  }

  const targets =
    (
      Array.isArray(wanted)
        ? wanted
        : [wanted]
    ).map(
      canonicalToken
    );

  for (
    const key of
    Object.keys(obj)
  ) {
    if (
      targets.includes(
        canonicalToken(key)
      )
    ) {
      return key;
    }
  }

  return null;
}

function entryMatchesMeal(
  entry,
  want
) {
  if (
    !isPlainObject(
      entry
    )
  ) {
    return false;
  }

  const idTokens =
    MEAL_ID_KEYS.map(
      canonicalToken
    );

  for (
    const key of
    Object.keys(entry)
  ) {
    if (
      !idTokens.includes(
        canonicalToken(key)
      )
    ) {
      continue;
    }

    const value =
      entry[key];

    if (
      typeof value !== "string" &&
      typeof value !== "number"
    ) {
      continue;
    }

    if (
      canonicalMealType(
        value
      ) === want
    ) {
      return true;
    }
  }

  const rmt =
    entry.recipe
      ?.recipe_meal_type;

  if (
    Array.isArray(rmt) &&
    rmt.length === 1 &&
    canonicalMealType(
      rmt[0]
    ) === want
  ) {
    return true;
  }

  return false;
}

function entryMealLabel(entry) {
  if (
    !isPlainObject(
      entry
    )
  ) {
    return null;
  }

  const preferred = [
    "mealName",
    "meal_name",
    "meal_type",
    "mealType",
    "meal",
    "slot",
    "title",
  ];

  for (
    const key of
    preferred
  ) {
    if (
      typeof entry[key] ===
        "string" &&
      entry[key] !== ""
    ) {
      return entry[key];
    }
  }

  const idTokens =
    MEAL_ID_KEYS.map(
      canonicalToken
    );

  for (
    const key of
    Object.keys(entry)
  ) {
    if (
      idTokens.includes(
        canonicalToken(key)
      ) &&
      (
        typeof entry[key] ===
          "string" ||
        typeof entry[key] ===
          "number"
      )
    ) {
      return String(
        entry[key]
      );
    }
  }

  return null;
}

function foodsArrayOf(
  meal,
  create
) {
  if (
    Array.isArray(meal)
  ) {
    return meal;
  }

  if (
    !isPlainObject(meal)
  ) {
    return null;
  }

  for (
    const key of
    FOODS_KEYS
  ) {
    if (
      Array.isArray(
        meal[key]
      )
    ) {
      return meal[key];
    }
  }

  const ciKey =
    findKeyCI(
      meal,
      FOODS_KEYS
    );

  if (
    ciKey &&
    Array.isArray(
      meal[ciKey]
    )
  ) {
    return meal[ciKey];
  }

  if (create) {
    meal.foods = [];

    return meal.foods;
  }

  return null;
}

function isRecipeMeal(entry) {
  if (
    !isPlainObject(
      entry
    )
  ) {
    return false;
  }

  if (
    foodsArrayOf(
      entry,
      false
    )
  ) {
    return false;
  }

  return (
    isPlainObject(
      entry.nutrition
    ) ||
    entry.recipeId !==
      undefined ||
    entry.recipe_id !==
      undefined ||
    isPlainObject(
      entry.recipe
    ) ||
    typeof entry.name ===
      "string"
  );
}

function readNutritionValue(
  nutrition,
  macroKey
) {
  if (
    !isPlainObject(
      nutrition
    )
  ) {
    return 0;
  }

  for (
    const key of
    NUTRITION_TO_MACRO[
      macroKey
    ]
  ) {
    if (
      nutrition[key] !==
        undefined &&
      nutrition[key] !==
        null &&
      isNumericValue(
        nutrition[key]
      )
    ) {
      return Number(
        nutrition[key]
      );
    }
  }

  const ciKey =
    findKeyCI(
      nutrition,
      NUTRITION_TO_MACRO[
        macroKey
      ]
    );

  return (
    ciKey &&
    isNumericValue(
      nutrition[ciKey]
    )
      ? Number(
          nutrition[
            ciKey
          ]
        )
      : 0
  );
}

function writeNutritionValue(
  nutrition,
  macroKey,
  value
) {
  const ciKey =
    findKeyCI(
      nutrition,
      NUTRITION_TO_MACRO[
        macroKey
      ]
    );

  nutrition[
    ciKey ||
      NUTRITION_TO_MACRO[
        macroKey
      ][0]
  ] =
    roundMacro(value);
}

function servingsText(entry) {
  if (
    typeof entry
      .portion_with_metric ===
      "string" &&
    entry.portion_with_metric
      .trim() !== ""
  ) {
    return entry
      .portion_with_metric;
  }

  const people =
    entry.recipe
      ?.recipe_amount_of_people;

  if (
    Array.isArray(
      people
    ) &&
    people.length &&
    isNumericValue(
      people[0]
    )
  ) {
    return (
      `serves ${Number(
        people[0]
      )}`
    );
  }

  return "serves 1";
}

function capitalize(s) {
  const t = String(
    s ?? ""
  );

  return t
    ? (
        t[0].toUpperCase() +
        t.slice(1)
      )
    : t;
}

function alternativeSummary(
  alt
) {
  if (
    !isPlainObject(alt)
  ) {
    return null;
  }

  return {
    food_name:
      String(
        alt.name ?? ""
      ),

    calories:
      roundMacro(
        readNutritionValue(
          alt.nutrition,
          "calories"
        )
      ),

    carbs_g:
      roundMacro(
        readNutritionValue(
          alt.nutrition,
          "carbs_g"
        )
      ),

    protein_g:
      roundMacro(
        readNutritionValue(
          alt.nutrition,
          "protein_g"
        )
      ),

    fat_g:
      roundMacro(
        readNutritionValue(
          alt.nutrition,
          "fat_g"
        )
      ),

    fiber_g:
      roundMacro(
        readNutritionValue(
          alt.nutrition,
          "fiber_g"
        )
      ),

    recipe_id:
      alt.recipeId ??
      alt.recipe_id ??
      null,

    variant_id:
      alt.variantId ??
      alt.variant_id ??
      null,

    image:
      alt.recipe
        ?.image ??
      null,
  };
}

function recipeMealToFood(
  entry,
  mealType
) {
  return {
    food_name:
      String(
        entry.name ?? ""
      ),

    calories:
      roundMacro(
        readNutritionValue(
          entry.nutrition,
          "calories"
        )
      ),

    carbs_g:
      roundMacro(
        readNutritionValue(
          entry.nutrition,
          "carbs_g"
        )
      ),

    protein_g:
      roundMacro(
        readNutritionValue(
          entry.nutrition,
          "protein_g"
        )
      ),

    fat_g:
      roundMacro(
        readNutritionValue(
          entry.nutrition,
          "fat_g"
        )
      ),

    fiber_g:
      roundMacro(
        readNutritionValue(
          entry.nutrition,
          "fiber_g"
        )
      ),

    portion_with_metric:
      servingsText(entry),

    category:
      (
        typeof entry.category ===
          "string" &&
        entry.category !== ""
      )
        ? entry.category
        : capitalize(
            mealType
          ),

    recipe_id:
      entry.recipeId ??
      entry.recipe_id ??
      null,

    variant_id:
      entry.variantId ??
      entry.variant_id ??
      null,

    image:
      entry.recipe
        ?.image ??
      null,

    ingredients:
      Array.isArray(
        entry.ingredients
      )
        ? entry.ingredients
        : [],

    alternatives:
      Array.isArray(
        entry.alternatives
      )
        ? entry.alternatives
            .map(
              alternativeSummary
            )
            .filter(
              Boolean
            )
        : [],
  };
}

function applyFoodToRecipeMeal(
  parent,
  key,
  food
) {
  let entry =
    parent[key];

  const wantName =
    canonicalToken(
      food.food_name
    );

  const alts =
    Array.isArray(
      entry.alternatives
    )
      ? entry.alternatives
      : [];

  const altIdx =
    alts.findIndex(
      (alt) =>
        isPlainObject(
          alt
        ) &&
        canonicalToken(
          alt.name
        ) === wantName
    );

  let swappedOut =
    null;

  if (
    altIdx >= 0 &&
    canonicalToken(
      entry.name
    ) !== wantName
  ) {
    const chosen =
      alts[altIdx];

    const {
      alternatives:
        _ignored,

      [EXTRA_FOODS_KEY]:
        extras,

      ...previousRecipe
    } = entry;

    swappedOut =
      previousRecipe;

    const swapped = {
      ...chosen,
    };

    swapped.alternatives =
      alts.slice();

    swapped.alternatives[
      altIdx
    ] = previousRecipe;

    if (
      swapped.mealName ===
        undefined &&
      entry.mealName !==
        undefined
    ) {
      swapped.mealName =
        entry.mealName;
    }

    if (
      swapped
        .eatingMomentId ===
        undefined &&
      entry
        .eatingMomentId !==
        undefined
    ) {
      swapped.eatingMomentId =
        entry.eatingMomentId;
    }

    if (
      extras !== undefined
    ) {
      swapped[
        EXTRA_FOODS_KEY
      ] = extras;
    }

    parent[key] =
      swapped;

    entry =
      swapped;
  }

  entry.name =
    String(
      food.food_name
    );

  if (
    !isPlainObject(
      entry.nutrition
    )
  ) {
    entry.nutrition =
      {};
  }

  for (
    const macroKey of
    REQUIRED_MACRO_FIELDS
  ) {
    if (
      food[macroKey] !==
        undefined &&
      isNumericValue(
        food[macroKey]
      )
    ) {
      writeNutritionValue(
        entry.nutrition,
        macroKey,
        food[macroKey]
      );
    }
  }

  if (
    typeof food
      .portion_with_metric ===
      "string" &&
    food
      .portion_with_metric
      .trim() !== ""
  ) {
    entry.portion_with_metric =
      food
        .portion_with_metric
        .trim();
  }

  if (
    typeof food.category ===
      "string" &&
    food.category
      .trim() !== ""
  ) {
    entry.category =
      food.category.trim();
  }

  for (
    const key of
    RECIPE_PASSTHROUGH_FIELDS
  ) {
    if (
      food[key] ===
      undefined
    ) {
      continue;
    }

    if (
      swappedOut &&
      food[key] ===
        swappedOut[key]
    ) {
      continue;
    }

    entry[key] =
      food[key];
  }

  return entry;
}

function newRecipeMealFromFood(
  mealType,
  food
) {
  const nutrition = {};

  for (
    const macroKey of
    REQUIRED_MACRO_FIELDS
  ) {
    writeNutritionValue(
      nutrition,
      macroKey,
      food[macroKey]
    );
  }

  return {
    mealName:
      mealType,

    name:
      String(
        food.food_name
      ),

    nutrition,

    portion_with_metric:
      food.portion_with_metric,

    category:
      food.category,

    ingredients: [],

    alternatives: [],

    custom: true,

    ...copyRecipePassthrough(
      food,
      {}
    ),
  };
}

function makeFoodsAccessor(
  arr
) {
  return {
    kind:
      "foods",

    list:
      () => arr,

    count:
      () =>
        arr.length,

    get:
      (i) =>
        arr[i],

    set:
      (i, food) => {
        arr[i] =
          food;
      },

    push:
      (food) => {
        arr.push(
          food
        );

        return (
          arr.length -
          1
        );
      },

    remove:
      (i) =>
        arr.splice(
          i,
          1
        )[0],
  };
}

function makeRecipeAccessor(
  parent,
  key,
  mealType
) {
  const entry =
    () => parent[key];

  const hasPrimary =
    () => {
      const e =
        entry();

      return (
        isPlainObject(e) &&
        e.name !== null &&
        e.name !==
          undefined &&
        String(
          e.name
        ) !== ""
      );
    };

  const extras =
    (create) => {
      const e =
        entry();

      if (
        !Array.isArray(
          e[
            EXTRA_FOODS_KEY
          ]
        )
      ) {
        if (!create) {
          return [];
        }

        e[
          EXTRA_FOODS_KEY
        ] = [];
      }

      return e[
        EXTRA_FOODS_KEY
      ];
    };

  return {
    kind:
      "recipe",

    list:
      () =>
        (
          hasPrimary()
            ? [
                recipeMealToFood(
                  entry(),
                  mealType
                ),
              ]
            : []
        ).concat(
          extras(false)
        ),

    count:
      () =>
        (
          hasPrimary()
            ? 1
            : 0
        ) +
        extras(false)
          .length,

    get:
      (i) =>
        (
          i === 0 &&
          hasPrimary()
        )
          ? recipeMealToFood(
              entry(),
              mealType
            )
          : extras(
              false
            )[
              i -
                (
                  hasPrimary()
                    ? 1
                    : 0
                )
            ],

    set:
      (i, food) => {
        if (
          i === 0 &&
          hasPrimary()
        ) {
          applyFoodToRecipeMeal(
            parent,
            key,
            food
          );
        } else {
          extras(true)[
            i -
              (
                hasPrimary()
                  ? 1
                  : 0
              )
          ] = food;
        }
      },

    push:
      (food) => {
        if (
          !hasPrimary()
        ) {
          applyFoodToRecipeMeal(
            parent,
            key,
            food
          );

          return 0;
        }

        const e =
          extras(true);

        e.push(food);

        return e.length;
      },

    remove:
      (i) => {
        if (
          i === 0 &&
          hasPrimary()
        ) {
          if (
            extras(false)
              .length > 0
          ) {
            fail(
              400,
              "Remove the added foods of this meal before deleting its recipe"
            );
          }

          const removed =
            recipeMealToFood(
              entry(),
              mealType
            );

          if (
            Array.isArray(
              parent
            )
          ) {
            parent.splice(
              key,
              1
            );
          } else {
            delete parent[
              key
            ];
          }

          return removed;
        }

        return extras(
          true
        ).splice(
          i -
            (
              hasPrimary()
                ? 1
                : 0
            ),
          1
        )[0];
      },
  };
}

function locateMeal(
  day,
  mealType
) {
  if (
    !isPlainObject(day)
  ) {
    return null;
  }

  const want =
    canonicalMealType(
      mealType
    );

  if (
    day[mealType] !==
      null &&
    typeof day[
      mealType
    ] === "object"
  ) {
    return {
      parent: day,
      key: mealType,
    };
  }

  for (
    const key of
    Object.keys(day)
  ) {
    if (
      canonicalMealType(
        key
      ) === want &&
      day[key] !== null &&
      typeof day[key] ===
        "object"
    ) {
      return {
        parent: day,
        key,
      };
    }
  }

  const containerKey =
    findKeyCI(
      day,
      MEAL_CONTAINER_KEYS
    );

  const container =
    containerKey
      ? day[
          containerKey
        ]
      : null;

  if (
    Array.isArray(
      container
    )
  ) {
    for (
      let i = 0;
      i <
      container.length;
      i++
    ) {
      if (
        entryMatchesMeal(
          container[i],
          want
        )
      ) {
        return {
          parent:
            container,

          key:
            i,
        };
      }
    }

    return null;
  }

  if (
    isPlainObject(
      container
    )
  ) {
    for (
      const key of
      Object.keys(
        container
      )
    ) {
      if (
        canonicalMealType(
          key
        ) === want &&
        container[
          key
        ] !== null &&
        typeof container[
          key
        ] === "object"
      ) {
        return {
          parent:
            container,

          key,
        };
      }
    }
  }

  return null;
}

function resolveMealAccessor(
  day,
  mealType,
  create = false
) {
  if (
    !isPlainObject(day)
  ) {
    return null;
  }

  const located =
    locateMeal(
      day,
      mealType
    );

  if (located) {
    const node =
      located.parent[
        located.key
      ];

    const foods =
      foodsArrayOf(
        node,
        false
      );

    if (foods) {
      return makeFoodsAccessor(
        foods
      );
    }

    if (
      isRecipeMeal(
        node
      )
    ) {
      return makeRecipeAccessor(
        located.parent,
        located.key,
        mealType
      );
    }

    if (
      create &&
      isPlainObject(
        node
      )
    ) {
      return makeFoodsAccessor(
        foodsArrayOf(
          node,
          true
        )
      );
    }

    return null;
  }

  if (!create) {
    return null;
  }

  const containerKey =
    findKeyCI(
      day,
      MEAL_CONTAINER_KEYS
    );

  const container =
    containerKey
      ? day[
          containerKey
        ]
      : null;

  if (
    Array.isArray(
      container
    )
  ) {
    if (
      container.some(
        isRecipeMeal
      )
    ) {
      container.push({
        mealName:
          mealType,

        name:
          "",

        nutrition:
          {},

        ingredients:
          [],

        alternatives:
          [],

        custom:
          true,
      });

      return makeRecipeAccessor(
        container,
        container.length -
          1,
        mealType
      );
    }

    const entry = {
      meal_type:
        mealType,

      foods:
        [],
    };

    container.push(
      entry
    );

    return makeFoodsAccessor(
      entry.foods
    );
  }

  if (
    isPlainObject(
      container
    )
  ) {
    container[
      mealType
    ] = {
      foods: [],
    };

    return makeFoodsAccessor(
      container[
        mealType
      ].foods
    );
  }

  day[
    mealType
  ] = {
    foods: [],
  };

  return makeFoodsAccessor(
    day[
      mealType
    ].foods
  );
}

function listDayFoods(day) {
  if (
    !isPlainObject(day)
  ) {
    return [];
  }

  const seen =
    new Set();

  let all = [];

  for (
    const mealType of
    ALLOWED_MEALS
  ) {
    const located =
      locateMeal(
        day,
        mealType
      );

    if (!located) {
      continue;
    }

    const node =
      located.parent[
        located.key
      ];

    if (
      seen.has(node)
    ) {
      continue;
    }

    seen.add(node);

    const accessor =
      resolveMealAccessor(
        day,
        mealType,
        false
      );

    if (accessor) {
      all =
        all.concat(
          accessor.list()
        );
    }
  }

  const containerKey =
    findKeyCI(
      day,
      MEAL_CONTAINER_KEYS
    );

  const container =
    containerKey
      ? day[
          containerKey
        ]
      : null;

  if (
    Array.isArray(
      container
    )
  ) {
    container.forEach(
      (
        entry,
        i
      ) => {
        if (
          seen.has(
            entry
          ) ||
          !isRecipeMeal(
            entry
          )
        ) {
          return;
        }

        seen.add(
          entry
        );

        all =
          all.concat(
            makeRecipeAccessor(
              container,
              i,
              entryMealLabel(
                entry
              ) ||
                "meal"
            ).list()
          );
      }
    );
  }

  return all;
}

function syncDayNutrition(
  day,
  totals
) {
  if (
    !isPlainObject(
      day
    ) ||
    !isPlainObject(
      day.nutrition
    )
  ) {
    return;
  }

  for (
    const macroKey of
    REQUIRED_MACRO_FIELDS
  ) {
    const ciKey =
      findKeyCI(
        day.nutrition,
        NUTRITION_TO_MACRO[
          macroKey
        ]
      );

    if (ciKey) {
      day.nutrition[
        ciKey
      ] =
        roundMacro(
          totals[
            macroKey
          ]
        );
    }
  }
}

function describeDayShape(
  day
) {
  if (
    !isPlainObject(day)
  ) {
    return {
      day_type:
        Array.isArray(
          day
        )
          ? "array"
          : typeof day,
    };
  }

  const containerKey =
    findKeyCI(
      day,
      MEAL_CONTAINER_KEYS
    );

  const container =
    containerKey
      ? day[
          containerKey
        ]
      : null;

  let mealIds =
    null;

  if (
    Array.isArray(
      container
    )
  ) {
    mealIds =
      container.map(
        entryMealLabel
      );
  } else if (
    isPlainObject(
      container
    )
  ) {
    mealIds =
      Object.keys(
        container
      );
  }

  return {
    day_keys:
      Object.keys(
        day
      ),

    meals_container:
      containerKey,

    meal_ids:
      mealIds,

    meals_found:
      ALLOWED_MEALS.filter(
        (m) =>
          resolveMealAccessor(
            day,
            m,
            false
          ) !== null
      ),
  };
}

// =============================================================================
// FOOD JSON DESERIALIZATION
// =============================================================================

function sanitizeJsonText(value) {
  return String(value)
    .replace(
      /^﻿/,
      ""
    )
    .replace(
      /[\x00-\x08\x0B\x0C\x0E-\x1F]/g,
      ""
    )
    .trim();
}

function decodeStoredFoodJson(
  columnValue
) {
  if (
    columnValue === null ||
    columnValue ===
      undefined
  ) {
    fail(
      400,
      "Stored food_json is invalid JSON",
      {
        json_error:
          "empty column",
      }
    );
  }

  if (
    isPlainObject(
      columnValue
    ) ||
    Array.isArray(
      columnValue
    )
  ) {
    return columnValue;
  }

  let text;

  if (
    Buffer.isBuffer(
      columnValue
    )
  ) {
    text =
      columnValue.toString(
        "utf8"
      );
  } else if (
    isPlainObject(
      columnValue
    ) &&
    columnValue.type ===
      "Buffer" &&
    Array.isArray(
      columnValue.data
    )
  ) {
    text =
      Buffer.from(
        columnValue.data
      ).toString(
        "utf8"
      );
  } else {
    text =
      String(
        columnValue
      );
  }

  const jsonText =
    sanitizeJsonText(
      text
    );

  if (!jsonText) {
    fail(
      400,
      "Stored food_json is invalid JSON",
      {
        json_error:
          "empty value",
      }
    );
  }

  try {
    const decoded =
      JSON.parse(
        jsonText
      );

    if (
      !isPlainObject(
        decoded
      )
    ) {
      fail(
        400,
        "Stored food_json does not contain days array"
      );
    }

    return decoded;
  } catch (err) {
    if (
      err instanceof
      ApiError
    ) {
      throw err;
    }

    fail(
      400,
      "Stored food_json is invalid JSON",
      {
        json_error:
          err.message,
      }
    );
  }
}

// =============================================================================
// SEARCH API / FOOD NORMALIZATION
// =============================================================================

function normalizeIncomingFoodShape(
  food
) {
  if (
    !isPlainObject(food)
  ) {
    return food;
  }

  const normalized = {
    ...food,
  };

  if (
    normalized.food_name ===
      undefined &&
    normalized.name !==
      undefined
  ) {
    normalized.food_name =
      normalized.name;
  }

  if (
    normalized.calories ===
      undefined &&
    normalized.kcal !==
      undefined
  ) {
    normalized.calories =
      normalized.kcal;
  }

  if (
    normalized.carbs_g ===
      undefined &&
    normalized.c !==
      undefined
  ) {
    normalized.carbs_g =
      normalized.c;
  }

  if (
    normalized.protein_g ===
      undefined &&
    normalized.p !==
      undefined
  ) {
    normalized.protein_g =
      normalized.p;
  }

  if (
    normalized.fat_g ===
      undefined &&
    normalized.f !==
      undefined
  ) {
    normalized.fat_g =
      normalized.f;
  }

  if (
    normalized.fiber_g ===
      undefined &&
    normalized.fiber !==
      undefined
  ) {
    normalized.fiber_g =
      normalized.fiber;
  }

  if (
    normalized
      .portion_with_metric ===
      undefined &&
    normalized.portion !==
      undefined
  ) {
    normalized.portion_with_metric =
      normalized.portion;
  }

  if (
    normalized.category ===
      undefined &&
    normalized.slot !==
      undefined
  ) {
    normalized.category =
      capitalize(
        canonicalMealType(
          normalized.slot
        ) ||
          normalized.slot
      );
  }

  /*
   * CRITICAL:
   *
   * /search-foods returns recipe ingredients under:
   *
   * contains: [...]
   *
   * Shopping rebuild uses:
   *
   * ingredients: [...]
   */

  if (
    normalized.ingredients ===
      undefined &&
    Array.isArray(
      normalized.contains
    )
  ) {
    normalized.ingredients =
      normalized.contains.map(
        (ingredient) =>
          isPlainObject(
            ingredient
          )
            ? {
                ...ingredient,
              }
            : ingredient
      );
  }

  if (
    normalized.fitchefKey ===
      undefined &&
    normalized.key !==
      undefined
  ) {
    normalized.fitchefKey =
      normalized.key;
  }

  /*
   * Search response has:
   *
   * method
   * thumb
   *
   * Store those inside recipe.
   */

  if (
    normalized.method !==
      undefined ||
    normalized.thumb !==
      undefined
  ) {
    const recipe =
      isPlainObject(
        normalized.recipe
      )
        ? {
            ...normalized.recipe,
          }
        : {};

    if (
      recipe.method ===
        undefined &&
      normalized.method !==
        undefined
    ) {
      recipe.method =
        normalized.method;
    }

    if (
      recipe.image ===
        undefined &&
      normalized.thumb !==
        undefined
    ) {
      recipe.image =
        normalized.thumb;
    }

    normalized.recipe =
      recipe;
  }

  return normalized;
}

function normalizeFoodForAdd(
  food
) {
  food =
    normalizeIncomingFoodShape(
      food
    );

  if (
    !isPlainObject(food)
  ) {
    fail(
      400,
      "food must be an object"
    );
  }

  for (
    const field of
    REQUIRED_TEXT_FIELDS
  ) {
    if (
      food[field] ===
        undefined ||
      food[field] ===
        null ||
      String(
        food[field]
      ).trim() === ""
    ) {
      fail(
        400,
        `food.${field} is required`
      );
    }
  }

  for (
    const field of
    REQUIRED_MACRO_FIELDS
  ) {
    if (
      !(field in food) ||
      food[field] === "" ||
      !isNumericValue(
        food[field]
      )
    ) {
      fail(
        400,
        `food.${field} must be numeric`
      );
    }

    if (
      Number(
        food[field]
      ) < 0
    ) {
      fail(
        400,
        `food.${field} cannot be negative`
      );
    }
  }

  return {
    food_name:
      String(
        food.food_name
      ).trim(),

    calories:
      roundMacro(
        food.calories
      ),

    carbs_g:
      roundMacro(
        food.carbs_g
      ),

    protein_g:
      roundMacro(
        food.protein_g
      ),

    fat_g:
      roundMacro(
        food.fat_g
      ),

    fiber_g:
      roundMacro(
        food.fiber_g
      ),

    portion_with_metric:
      String(
        food.portion_with_metric
      ).trim(),

    category:
      String(
        food.category
      ).trim(),

    ...copyRecipePassthrough(
      food,
      {}
    ),
  };
}

function patchExistingFood(
  existingFood,
  incomingFood
) {
  const updatedFood =
    isPlainObject(
      existingFood
    )
      ? {
          ...existingFood,
        }
      : {};

  incomingFood =
    normalizeIncomingFoodShape(
      incomingFood
    );

  if (
    !isPlainObject(
      incomingFood
    )
  ) {
    fail(
      400,
      "food must be an object"
    );
  }

  for (
    const field of
    REQUIRED_TEXT_FIELDS
  ) {
    if (
      field in
      incomingFood
    ) {
      const value =
        String(
          incomingFood[
            field
          ]
        ).trim();

      if (
        value === ""
      ) {
        fail(
          400,
          `food.${field} cannot be empty`
        );
      }

      updatedFood[
        field
      ] = value;
    }
  }

  for (
    const field of
    REQUIRED_MACRO_FIELDS
  ) {
    if (
      field in
      incomingFood
    ) {
      if (
        incomingFood[
          field
        ] === "" ||
        !isNumericValue(
          incomingFood[
            field
          ]
        )
      ) {
        fail(
          400,
          `food.${field} must be numeric`
        );
      }

      if (
        Number(
          incomingFood[
            field
          ]
        ) < 0
      ) {
        fail(
          400,
          `food.${field} cannot be negative`
        );
      }

      updatedFood[
        field
      ] =
        roundMacro(
          incomingFood[
            field
          ]
        );
    }
  }

  copyRecipePassthrough(
    incomingFood,
    updatedFood
  );

  return updatedFood;
}

// =============================================================================
// MACRO AGGREGATION
// =============================================================================

function sumFoods(foods) {
  const total = {
    calories: 0,
    carbs_g: 0,
    protein_g: 0,
    fat_g: 0,
    fiber_g: 0,
  };

  for (
    const food of
    Array.isArray(
      foods
    )
      ? foods
      : []
  ) {
    total.calories +=
      Number(
        food?.calories ??
          0
      ) || 0;

    total.carbs_g +=
      Number(
        food?.carbs_g ??
          0
      ) || 0;

    total.protein_g +=
      Number(
        food?.protein_g ??
          0
      ) || 0;

    total.fat_g +=
      Number(
        food?.fat_g ??
          0
      ) || 0;

    total.fiber_g +=
      Number(
        food?.fiber_g ??
          0
      ) || 0;
  }

  return {
    calories:
      roundMacro(
        total.calories
      ),

    carbs_g:
      roundMacro(
        total.carbs_g
      ),

    protein_g:
      roundMacro(
        total.protein_g
      ),

    fat_g:
      roundMacro(
        total.fat_g
      ),

    fiber_g:
      roundMacro(
        total.fiber_g
      ),
  };
}

function sumDay(day) {
  return sumFoods(
    listDayFoods(
      day
    )
  );
}

function recalculateWeeklyMacros(
  foodJson
) {
  if (
    !Array.isArray(
      foodJson.days
    )
  ) {
    fail(
      400,
      "Invalid food_json structure. days array missing."
    );
  }

  const weeklyTotal = {
    calories: 0,
    carbs_g: 0,
    protein_g: 0,
    fat_g: 0,
    fiber_g: 0,
  };

  for (
    const day of
    foodJson.days
  ) {
    for (
      const food of
      listDayFoods(day)
    ) {
      weeklyTotal.calories +=
        Number(
          food?.calories ??
            0
        ) || 0;

      weeklyTotal.carbs_g +=
        Number(
          food?.carbs_g ??
            0
        ) || 0;

      weeklyTotal.protein_g +=
        Number(
          food?.protein_g ??
            0
        ) || 0;

      weeklyTotal.fat_g +=
        Number(
          food?.fat_g ??
            0
        ) || 0;

      weeklyTotal.fiber_g +=
        Number(
          food?.fiber_g ??
            0
        ) || 0;
    }
  }

  let dayCount =
    foodJson.days.length;

  if (
    dayCount <= 0
  ) {
    dayCount = 7;
  }

  const note =
    foodJson
      .weekly_json_data &&
    typeof foodJson
      .weekly_json_data
      .note === "string"
      ? foodJson
          .weekly_json_data
          .note
      : DEFAULT_WEEKLY_NOTE;

  const weeklyMacros = {
    calories:
      roundMacro(
        weeklyTotal
          .calories /
          dayCount
      ),

    carbs_g:
      roundMacro(
        weeklyTotal
          .carbs_g /
          dayCount
      ),

    protein_g:
      roundMacro(
        weeklyTotal
          .protein_g /
          dayCount
      ),

    fat_g:
      roundMacro(
        weeklyTotal
          .fat_g /
          dayCount
      ),

    fiber_g:
      roundMacro(
        weeklyTotal
          .fiber_g /
          dayCount
      ),

    note,
  };

  foodJson.weekly_json_data =
    weeklyMacros;

  return weeklyMacros;
}

// =============================================================================
// SHOPPING LIST
// =============================================================================

const SHOPPING_NAME_KEYS = [
  "name",
  "ingredient",
  "ingredient_name",
  "ingredientName",
  "title",
  "label",
  "food_name",
  "item",
  "product",
];

const SHOPPING_PRICE_KEYS = [
  "price",
  "cost",
  "total_price",
  "totalPrice",
];

function cleanSpaces(value) {
  return String(
    value ?? ""
  )
    .replace(
      /\s+/g,
      " "
    )
    .trim();
}

function shoppingNameKey(value) {
  return cleanSpaces(
    value
  )
    .toLowerCase()
    .replace(
      /&/g,
      " and "
    )
    .replace(
      /[^a-z0-9%]+/g,
      " "
    )
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .sort()
    .join("|");
}

function titleCaseIngredient(
  value
) {
  const text =
    cleanSpaces(
      value
    );

  if (!text) {
    return "";
  }

  return (
    text[0].toUpperCase() +
    text.slice(1)
  );
}

function numericOrNull(value) {
  if (
    typeof value ===
    "number"
  ) {
    return Number.isFinite(
      value
    )
      ? value
      : null;
  }

  if (
    typeof value !==
    "string"
  ) {
    return null;
  }

  const m =
    value
      .trim()
      .match(
        /^-?\d+(?:[.,]\d+)?/
      );

  return m
    ? Number(
        m[0].replace(
          ",",
          "."
        )
      )
    : null;
}

function roundShopping(
  value,
  decimals = 2
) {
  const n =
    Number(value);

  if (
    !Number.isFinite(n)
  ) {
    return 0;
  }

  const factor =
    10 ** decimals;

  return (
    Math.round(
      (
        n +
        Number.EPSILON
      ) *
        factor
    ) / factor
  );
}

function prettyNumber(value) {
  const n =
    roundShopping(
      value,
      2
    );

  return Number.isInteger(
    n
  )
    ? String(n)
    : String(n)
        .replace(
          /0+$/,
          ""
        )
        .replace(
          /\.$/,
          ""
        );
}

function normalizeShoppingUnit(
  value
) {
  const u =
    cleanSpaces(value)
      .toLowerCase()
      .replace(
        /\./g,
        ""
      );

  if (!u) {
    return "";
  }

  const aliases =
    new Map([
      ["g", "g"],
      ["gram", "g"],
      ["grams", "g"],

      ["kg", "kg"],
      [
        "kilogram",
        "kg",
      ],
      [
        "kilograms",
        "kg",
      ],

      ["oz", "oz"],
      [
        "ounce",
        "oz",
      ],
      [
        "ounces",
        "oz",
      ],

      ["lb", "lb"],
      ["lbs", "lb"],
      [
        "pound",
        "lb",
      ],
      [
        "pounds",
        "lb",
      ],

      ["ml", "ml"],
      [
        "milliliter",
        "ml",
      ],
      [
        "milliliters",
        "ml",
      ],
      [
        "millilitre",
        "ml",
      ],
      [
        "millilitres",
        "ml",
      ],

      ["l", "l"],
      [
        "liter",
        "l",
      ],
      [
        "liters",
        "l",
      ],
      [
        "litre",
        "l",
      ],
      [
        "litres",
        "l",
      ],

      ["cup", "cup"],
      ["cups", "cup"],

      [
        "fl oz",
        "floz",
      ],
      [
        "fluid ounce",
        "floz",
      ],
      [
        "fluid ounces",
        "floz",
      ],

      [
        "tablespoon",
        "tbsp",
      ],
      [
        "tablespoons",
        "tbsp",
      ],
      ["tbsp", "tbsp"],

      [
        "teaspoon",
        "tsp",
      ],
      [
        "teaspoons",
        "tsp",
      ],
      ["tsp", "tsp"],

      [
        "squeeze",
        "squeeze",
      ],
      [
        "squeezes",
        "squeeze",
      ],

      [
        "piece",
        "piece",
      ],
      [
        "pieces",
        "piece",
      ],
      ["item", "piece"],
      [
        "items",
        "piece",
      ],

      [
        "slice",
        "slice",
      ],
      [
        "slices",
        "slice",
      ],

      [
        "clove",
        "clove",
      ],
      [
        "cloves",
        "clove",
      ],

      [
        "handful",
        "handful",
      ],
      [
        "handfuls",
        "handful",
      ],

      [
        "pinch",
        "pinch",
      ],
      [
        "pinches",
        "pinch",
      ],

      [
        "stalk",
        "stalk",
      ],
      [
        "stalks",
        "stalk",
      ],

      [
        "cube",
        "cube",
      ],
      [
        "cubes",
        "cube",
      ],
    ]);

  return (
    aliases.get(u) ||
    u
  );
}

function unitLabel(
  unit,
  quantity
) {
  const singular =
    Number(
      quantity
    ) === 1;

  switch (unit) {
    case "piece":
      return singular
        ? "piece"
        : "pieces";

    case "slice":
      return singular
        ? "slice"
        : "slices";

    case "clove":
      return singular
        ? "clove"
        : "cloves";

    case "handful":
      return singular
        ? "handful"
        : "handfuls";

    case "pinch":
      return singular
        ? "pinch"
        : "pinches";

    case "stalk":
      return singular
        ? "stalk"
        : "stalks";

    case "cube":
      return singular
        ? "cube"
        : "cubes";

    case "cup":
      return singular
        ? "cup"
        : "cups";

    case "floz":
      return singular
        ? "fluid ounce"
        : "fluid ounces";

    case "tbsp":
      return singular
        ? "tablespoon"
        : "tablespoons";

    case "tsp":
      return singular
        ? "teaspoon"
        : "teaspoons";

    case "squeeze":
      return singular
        ? "squeeze"
        : "squeezes";

    case "oz":
      return singular
        ? "ounce"
        : "ounces";

    case "lb":
      return singular
        ? "pound"
        : "pounds";

    default:
      return (
        unit ||
        "units"
      );
  }
}

function ingredientQuantity(
  ingredient
) {
  if (
    !isPlainObject(
      ingredient
    )
  ) {
    return null;
  }

  const candidates = [
    ingredient.units,
    ingredient.quantity,
    ingredient.qty,
    ingredient.amount,
    ingredient.count,
  ];

  for (
    const value of
    candidates
  ) {
    const n =
      numericOrNull(
        value
      );

    if (
      n !== null
    ) {
      return n;
    }
  }

  return null;
}

function ingredientUnit(
  ingredient
) {
  if (
    !isPlainObject(
      ingredient
    )
  ) {
    return "";
  }

  const quantity =
    ingredientQuantity(
      ingredient
    );

  const candidates =
    quantity === 1
      ? [
          ingredient
            .unitSingular,

          ingredient
            .unitMultiple,

          ingredient.unit,

          ingredient.uom,

          ingredient.measure,
        ]
      : [
          ingredient
            .unitMultiple,

          ingredient
            .unitSingular,

          ingredient.unit,

          ingredient.uom,

          ingredient.measure,
        ];

  for (
    const value of
    candidates
  ) {
    if (
      typeof value ===
        "string" &&
      value.trim() !== ""
    ) {
      return normalizeShoppingUnit(
        value
      );
    }
  }

  return "";
}

function parseShoppingText(
  text
) {
  if (
    typeof text !==
    "string"
  ) {
    return null;
  }

  const value =
    cleanSpaces(
      text
    ).toLowerCase();

  if (!value) {
    return null;
  }

  let m =
    value.match(
      /^(-?\d+(?:[.,]\d+)?)\s+([a-z ]+?)\s*\((-?\d+(?:[.,]\d+)?)\s*(g|ml)\)$/i
    );

  if (m) {
    return {
      primaryQty:
        Number(
          m[1].replace(
            ",",
            "."
          )
        ),

      primaryUnit:
        normalizeShoppingUnit(
          m[2]
        ),

      metricQty:
        Number(
          m[3].replace(
            ",",
            "."
          )
        ),

      metricUnit:
        normalizeShoppingUnit(
          m[4]
        ),
    };
  }

  m =
    value.match(
      /^(-?\d+(?:[.,]\d+)?)\s+(.+)$/i
    );

  if (m) {
    return {
      primaryQty:
        Number(
          m[1].replace(
            ",",
            "."
          )
        ),

      primaryUnit:
        normalizeShoppingUnit(
          m[2]
        ),

      metricQty:
        null,

      metricUnit:
        null,
    };
  }

  return null;
}

function toBaseMeasure(
  quantity,
  unit
) {
  const q =
    Number(quantity);

  if (
    !Number.isFinite(q)
  ) {
    return null;
  }

  switch (unit) {
    case "g":
      return {
        kind: "mass",
        value: q,
        unit: "g",
      };

    case "kg":
      return {
        kind: "mass",
        value:
          q * 1000,
        unit: "g",
      };

    case "oz":
      return {
        kind: "mass",
        value:
          q * 28,
        unit: "g",
      };

    case "lb":
      return {
        kind: "mass",
        value:
          q * 454,
        unit: "g",
      };

    case "ml":
      return {
        kind: "volume",
        value: q,
        unit: "ml",
      };

    case "l":
      return {
        kind: "volume",
        value:
          q * 1000,
        unit: "ml",
      };

    case "cup":
      return {
        kind: "volume",
        value:
          q * 237,
        unit: "ml",
      };

    case "floz":
      return {
        kind: "volume",
        value:
          q * 30,
        unit: "ml",
      };

    case "tbsp":
      return {
        kind: "volume",
        value:
          q * 15,
        unit: "ml",
      };

    case "tsp":
      return {
        kind: "volume",
        value:
          q * 5,
        unit: "ml",
      };

    case "squeeze":
      return {
        kind: "volume",
        value:
          q * 5,
        unit: "ml",
      };

    case "clove":
      return {
        kind:
          "count_mass",

        value:
          q,

        unit:
          "clove",

        metricValue:
          q * 5,

        metricUnit:
          "g",
      };

    case "handful":
      return {
        kind:
          "count_mass",

        value:
          q,

        unit:
          "handful",

        metricValue:
          q * 25,

        metricUnit:
          "g",
      };

    case "pinch":
      return {
        kind:
          "count_mass",

        value:
          q,

        unit:
          "pinch",

        metricValue:
          q * 0.5,

        metricUnit:
          "g",
      };

    case "piece":
    case "slice":
    case "stalk":
    case "cube":
      return {
        kind:
          "count",

        value:
          q,

        unit,
      };

    default:
      return {
        kind:
          "other",

        value:
          q,

        unit:
          unit ||
          "units",
      };
  }
}

function extractOldShoppingMetadata(
  shopping
) {
  const metadata =
    new Map();

  if (
    !isPlainObject(
      shopping
    ) ||
    !isPlainObject(
      shopping.week
    ) ||
    !Array.isArray(
      shopping.week
        .aisles
    )
  ) {
    return metadata;
  }

  for (
    const aisleGroup of
    shopping.week
      .aisles
  ) {
    if (
      !isPlainObject(
        aisleGroup
      ) ||
      !Array.isArray(
        aisleGroup.items
      )
    ) {
      continue;
    }

    const aisle =
      cleanSpaces(
        aisleGroup.aisle
      ) || "Other";

    for (
      const item of
      aisleGroup.items
    ) {
      if (
        !isPlainObject(
          item
        )
      ) {
        continue;
      }

      const name =
        cleanSpaces(
          item.name
        );

      const key =
        shoppingNameKey(
          name
        );

      if (!key) {
        continue;
      }

      metadata.set(
        key,
        {
          name,

          aisle,

          oldText:
            typeof item.text ===
              "string"
              ? item.text
              : null,

          oldParsed:
            parseShoppingText(
              item.text
            ),

          price:
            numericOrNull(
              item.price
            ),

          price_source:
            item.price_source ??
            null,

          approx:
            item.approx ??
            null,

          price_note:
            item.price_note ??
            null,
        }
      );
    }
  }

  return metadata;
}

function htmlToPlainText(html) {
  if (
    typeof html !==
      "string" ||
    html.trim() === ""
  ) {
    return "";
  }

  return html
    .replace(
      /<br\s*\/?>/gi,
      "\n"
    )
    .replace(
      /<\/li>/gi,
      "\n"
    )
    .replace(
      /<[^>]+>/g,
      ""
    )
    .replace(
      /&nbsp;/gi,
      " "
    )
    .replace(
      /&amp;/gi,
      "&"
    )
    .replace(
      /&quot;/gi,
      '"'
    )
    .replace(
      /&#39;/gi,
      "'"
    )
    .replace(
      /\r/g,
      ""
    )
    .replace(
      /[ \t]+\n/g,
      "\n"
    )
    .replace(
      /\n{2,}/g,
      "\n"
    )
    .trim();
}

function recipeSteps(recipe) {
  if (
    !isPlainObject(
      recipe
    )
  ) {
    return [];
  }

  if (
    typeof recipe
      .post_content ===
      "string" &&
    recipe
      .post_content
      .trim() !== ""
  ) {
    const html =
      recipe.post_content;

    const liMatches = [
      ...html.matchAll(
        /<li[^>]*>([\s\S]*?)<\/li>/gi
      ),
    ];

    if (
      liMatches.length
    ) {
      return liMatches
        .map(
          (m) =>
            htmlToPlainText(
              m[1]
            )
        )
        .map(
          cleanSpaces
        )
        .filter(
          Boolean
        );
    }

    const plain =
      htmlToPlainText(
        html
      );

    return plain
      ? [plain]
      : [];
  }

  if (
    typeof recipe.method ===
      "string" &&
    recipe.method
      .trim() !== ""
  ) {
    return recipe.method
      .replace(
        /\r/g,
        ""
      )
      .split(
        /\n+/
      )
      .map(
        cleanSpaces
      )
      .filter(
        Boolean
      );
  }

  return [];
}

function recipeTip(recipe) {
  if (
    !isPlainObject(
      recipe
    )
  ) {
    return "";
  }

  return htmlToPlainText(
    recipe.recipe_tip ||
      ""
  );
}

function recipeMinutes(recipe) {
  if (
    !isPlainObject(
      recipe
    )
  ) {
    return null;
  }

  const value =
    recipe
      .recipe_taxonomy_preparation_time;

  if (
    Array.isArray(value) &&
    value.length
  ) {
    return String(
      value[0]
    );
  }

  if (
    value !== undefined &&
    value !== null &&
    value !== ""
  ) {
    return String(
      value
    );
  }

  return null;
}

function listShoppingMeals(day) {
  if (
    !isPlainObject(day)
  ) {
    return [];
  }

  const result = [];

  const seenNodes =
    new Set();

  function addRecipeNode(
    node,
    fallbackSlot
  ) {
    if (
      !isPlainObject(
        node
      )
    ) {
      return;
    }

    const slot =
      cleanSpaces(
        node.mealName ||
          node.meal_name ||
          fallbackSlot ||
          "meal"
      );

    if (
      typeof node.name ===
        "string" &&
      node.name.trim() !==
        ""
    ) {
      result.push({
        title:
          cleanSpaces(
            node.name
          ),

        slot,

        ingredients:
          Array.isArray(
            node.ingredients
          )
            ? node.ingredients
            : [],

        recipe:
          isPlainObject(
            node.recipe
          )
            ? node.recipe
            : null,
      });
    }

    if (
      Array.isArray(
        node[
          EXTRA_FOODS_KEY
        ]
      )
    ) {
      for (
        const extra of
        node[
          EXTRA_FOODS_KEY
        ]
      ) {
        if (
          !isPlainObject(
            extra
          )
        ) {
          continue;
        }

        result.push({
          title:
            cleanSpaces(
              extra.food_name ||
                extra.name ||
                node.name ||
                "Added food"
            ),

          slot,

          ingredients:
            Array.isArray(
              extra.ingredients
            )
              ? extra.ingredients
              : [],

          recipe:
            isPlainObject(
              extra.recipe
            )
              ? extra.recipe
              : null,
        });
      }
    }
  }

  function addFoodsArray(
    arr,
    slot
  ) {
    if (
      !Array.isArray(
        arr
      )
    ) {
      return;
    }

    for (
      const food of
      arr
    ) {
      if (
        !isPlainObject(
          food
        )
      ) {
        continue;
      }

      result.push({
        title:
          cleanSpaces(
            food.food_name ||
              food.name ||
              "Food"
          ),

        slot:
          cleanSpaces(
            slot ||
              food.mealName ||
              food.meal_type ||
              "meal"
          ),

        ingredients:
          Array.isArray(
            food.ingredients
          )
            ? food.ingredients
            : [],

        recipe:
          isPlainObject(
            food.recipe
          )
            ? food.recipe
            : null,
      });
    }
  }

  for (
    const mealType of
    ALLOWED_MEALS
  ) {
    const located =
      locateMeal(
        day,
        mealType
      );

    if (!located) {
      continue;
    }

    const node =
      located.parent[
        located.key
      ];

    if (
      seenNodes.has(
        node
      )
    ) {
      continue;
    }

    seenNodes.add(
      node
    );

    const foods =
      foodsArrayOf(
        node,
        false
      );

    if (foods) {
      addFoodsArray(
        foods,
        mealType
      );
    } else if (
      isRecipeMeal(
        node
      )
    ) {
      addRecipeNode(
        node,
        mealType
      );
    }
  }

  const containerKey =
    findKeyCI(
      day,
      MEAL_CONTAINER_KEYS
    );

  const container =
    containerKey
      ? day[
          containerKey
        ]
      : null;

  if (
    Array.isArray(
      container
    )
  ) {
    for (
      const entry of
      container
    ) {
      if (
        seenNodes.has(
          entry
        )
      ) {
        continue;
      }

      if (
        !isRecipeMeal(
          entry
        )
      ) {
        continue;
      }

      seenNodes.add(
        entry
      );

      addRecipeNode(
        entry,
        entryMealLabel(
          entry
        ) ||
          "meal"
      );
    }
  }

  return result;
}

function buildIngredientOccurrence(
  raw,
  dayNumber,
  meal
) {
  const ingredient =
    (
      typeof raw ===
        "string" &&
      raw.trim() !== ""
    )
      ? {
          name:
            raw.trim(),
        }
      : raw;

  if (
    !isPlainObject(
      ingredient
    )
  ) {
    return null;
  }

  const name =
    cleanSpaces(
      ingredient.name ||
        ingredient.ingredient ||
        ingredient.food_name
    );

  if (!name) {
    return null;
  }

  const quantity =
    ingredientQuantity(
      ingredient
    );

  if (
    quantity === null ||
    quantity <= 0
  ) {
    return null;
  }

  const unit =
    ingredientUnit(
      ingredient
    );

  /*
   * /search-foods contains:
   *
   * {
   *   grams: 42,
   *   name: "chicken",
   *   unit: "ounces",
   *   units: 1.5
   * }
   *
   * Exact grams are better than approximate local conversion.
   */

  const exactGrams =
    numericOrNull(
      ingredient.grams
    );

  const measure =
    (
      exactGrams !== null &&
      exactGrams > 0
    )
      ? {
          kind:
            "mass",

          value:
            exactGrams,

          unit:
            "g",
        }
      : toBaseMeasure(
          quantity,
          unit
        );

  return {
    name,

    key:
      shoppingNameKey(
        name
      ),

    productId:
      ingredient.productId ??
      ingredient.product_id ??
      null,

    unitId:
      ingredient.unitId ??
      ingredient.unit_id ??
      null,

    quantity,

    unit,

    measure,

    day:
      dayNumber,

    mealTitle:
      meal.title,

    mealSlot:
      meal.slot,

    recipe:
      meal.recipe,
  };
}

function displayOccurrenceText(
  occurrence,
  oldMeta = null
) {
  const m =
    occurrence.measure;

  if (!m) {
    return (
      `${prettyNumber(
        occurrence.quantity
      )} ` +
      `${unitLabel(
        occurrence.unit,
        occurrence.quantity
      )}`
    );
  }

  if (
    m.kind === "mass"
  ) {
    return (
      `${prettyNumber(
        m.value
      )} g`
    );
  }

  if (
    m.kind ===
      "volume"
  ) {
    return (
      `${prettyNumber(
        m.value
      )} ml`
    );
  }

  if (
    m.kind ===
      "count_mass"
  ) {
    return (
      `${prettyNumber(
        m.value
      )} ` +
      `${unitLabel(
        m.unit,
        m.value
      )} ` +
      `(${prettyNumber(
        m.metricValue
      )} ${m.metricUnit})`
    );
  }

  if (
    m.kind ===
      "count"
  ) {
    const parsed =
      oldMeta
        ?.oldParsed;

    if (
      parsed &&
      parsed.metricQty !==
        null &&
      parsed.metricUnit &&
      parsed.primaryQty >
        0 &&
      normalizeShoppingUnit(
        parsed.primaryUnit
      ) === m.unit
    ) {
      const metricPerUnit =
        parsed.metricQty /
        parsed.primaryQty;

      const metric =
        metricPerUnit *
        m.value;

      return (
        `${prettyNumber(
          m.value
        )} ` +
        `${unitLabel(
          m.unit,
          m.value
        )} ` +
        `(${prettyNumber(
          metric
        )} ${parsed.metricUnit})`
      );
    }

    return (
      `${prettyNumber(
        m.value
      )} ` +
      `${unitLabel(
        m.unit,
        m.value
      )}`
    );
  }

  return (
    `${prettyNumber(
      m.value
    )} ` +
    `${unitLabel(
      m.unit,
      m.value
    )}`
  );
}

function aggregateCurrentIngredients(
  foodJson
) {
  const groups =
    new Map();

  const dayMeals =
    [];

  if (
    !Array.isArray(
      foodJson.days
    )
  ) {
    return {
      groups,
      dayMeals,
    };
  }

  foodJson.days.forEach(
    (
      day,
      dayIndex
    ) => {
      const dayNumber =
        dayIndex + 1;

      const mealViews =
        listShoppingMeals(
          day
        );

      const builtMeals =
        [];

      for (
        const meal of
        mealViews
      ) {
        const occurrences =
          [];

        for (
          const raw of
          meal.ingredients
        ) {
          const occ =
            buildIngredientOccurrence(
              raw,
              dayNumber,
              meal
            );

          if (
            !occ ||
            !occ.key
          ) {
            continue;
          }

          occurrences.push(
            occ
          );

          let group =
            groups.get(
              occ.key
            );

          if (!group) {
            group = {
              key:
                occ.key,

              name:
                occ.name,

              productId:
                occ.productId,

              unitId:
                occ.unitId,

              days:
                new Set(),

              mealKeys:
                new Set(),

              occurrences:
                [],
            };

            groups.set(
              occ.key,
              group
            );
          }

          group.days.add(
            dayNumber
          );

          group.mealKeys.add(
            `${dayNumber}:${meal.slot}:${meal.title}`
          );

          group.occurrences.push(
            occ
          );
        }

        builtMeals.push({
          ...meal,

          occurrences,
        });
      }

      dayMeals.push({
        day:
          dayNumber,

        meals:
          builtMeals,
      });
    }
  );

  return {
    groups,
    dayMeals,
  };
}

function aggregateGroupMeasure(
  group
) {
  const occs =
    group.occurrences;

  if (
    !occs.length
  ) {
    return null;
  }

  const kinds =
    new Set(
      occs.map(
        (o) =>
          o.measure
            ?.kind ||
          "none"
      )
    );

  if (
    [...kinds].every(
      (k) =>
        k === "mass"
    )
  ) {
    return {
      kind:
        "mass",

      value:
        occs.reduce(
          (
            s,
            o
          ) =>
            s +
            o.measure.value,
          0
        ),

      unit:
        "g",
    };
  }

  if (
    [...kinds].every(
      (k) =>
        k === "volume"
    )
  ) {
    return {
      kind:
        "volume",

      value:
        occs.reduce(
          (
            s,
            o
          ) =>
            s +
            o.measure.value,
          0
        ),

      unit:
        "ml",
    };
  }

  const countLike =
    occs.every(
      (o) =>
        o.measure &&
        (
          o.measure
            .kind ===
            "count" ||
          o.measure
            .kind ===
            "count_mass"
        )
    );

  if (
    countLike
  ) {
    const units =
      new Set(
        occs.map(
          (o) =>
            o.measure
              .unit
        )
      );

    if (
      units.size === 1
    ) {
      const unit =
        occs[0]
          .measure
          .unit;

      const value =
        occs.reduce(
          (
            s,
            o
          ) =>
            s +
            o.measure.value,
          0
        );

      const metricValues =
        occs
          .map(
            (o) =>
              o.measure
                .metricValue
          )
          .filter(
            (v) =>
              Number.isFinite(
                v
              )
          );

      return {
        kind:
          metricValues
            .length ===
          occs.length
            ? "count_mass"
            : "count",

        value,

        unit,

        metricValue:
          metricValues
            .length ===
          occs.length
            ? metricValues.reduce(
                (
                  a,
                  b
                ) =>
                  a + b,
                0
              )
            : null,

        metricUnit:
          metricValues
            .length ===
          occs.length
            ? occs[0]
                .measure
                .metricUnit
            : null,
      };
    }
  }

  const units =
    new Set(
      occs.map(
        (o) =>
          o.unit
      )
    );

  if (
    units.size === 1
  ) {
    const unit =
      occs[0].unit;

    return {
      kind:
        "other",

      value:
        occs.reduce(
          (
            s,
            o
          ) =>
            s +
            o.quantity,
          0
        ),

      unit,
    };
  }

  const buckets =
    new Map();

  for (
    const occ of
    occs
  ) {
    const unit =
      occ.unit ||
      "units";

    buckets.set(
      unit,
      (
        buckets.get(
          unit
        ) || 0
      ) +
        occ.quantity
    );
  }

  return {
    kind:
      "composite",

    buckets,
  };
}

function displayAggregateText(
  measure,
  oldMeta = null
) {
  if (!measure) {
    return "";
  }

  if (
    measure.kind ===
      "mass"
  ) {
    return (
      `${prettyNumber(
        measure.value
      )} g`
    );
  }

  if (
    measure.kind ===
      "volume"
  ) {
    return (
      `${prettyNumber(
        measure.value
      )} ml`
    );
  }

  if (
    measure.kind ===
      "count_mass"
  ) {
    return (
      `${prettyNumber(
        measure.value
      )} ` +
      `${unitLabel(
        measure.unit,
        measure.value
      )} ` +
      `(${prettyNumber(
        measure.metricValue
      )} ${measure.metricUnit})`
    );
  }

  if (
    measure.kind ===
      "count"
  ) {
    const parsed =
      oldMeta
        ?.oldParsed;

    if (
      parsed &&
      parsed.metricQty !==
        null &&
      parsed.primaryQty >
        0 &&
      normalizeShoppingUnit(
        parsed.primaryUnit
      ) ===
        measure.unit
    ) {
      const metric =
        (
          parsed.metricQty /
          parsed.primaryQty
        ) *
        measure.value;

      return (
        `${prettyNumber(
          measure.value
        )} ` +
        `${unitLabel(
          measure.unit,
          measure.value
        )} ` +
        `(${prettyNumber(
          metric
        )} ${parsed.metricUnit})`
      );
    }

    return (
      `${prettyNumber(
        measure.value
      )} ` +
      `${unitLabel(
        measure.unit,
        measure.value
      )}`
    );
  }

  if (
    measure.kind ===
      "composite"
  ) {
    return [
      ...measure
        .buckets
        .entries(),
    ]
      .map(
        (
          [
            unit,
            qty,
          ]
        ) =>
          `${prettyNumber(
            qty
          )} ${unitLabel(
            unit,
            qty
          )}`
      )
      .join(
        " + "
      );
  }

  return (
    `${prettyNumber(
      measure.value
    )} ` +
    `${unitLabel(
      measure.unit,
      measure.value
    )}`
  );
}

function comparableQuantityFromAggregate(
  measure,
  oldMeta
) {
  if (
    !measure ||
    !oldMeta
      ?.oldParsed
  ) {
    return null;
  }

  const old =
    oldMeta.oldParsed;

  if (
    measure.kind ===
      "mass" &&
    old.primaryUnit ===
      "g"
  ) {
    return {
      current:
        measure.value,

      old:
        old.primaryQty,
    };
  }

  if (
    measure.kind ===
      "volume" &&
    old.primaryUnit ===
      "ml"
  ) {
    return {
      current:
        measure.value,

      old:
        old.primaryQty,
    };
  }

  if (
    (
      measure.kind ===
        "count" ||
      measure.kind ===
        "count_mass"
    ) &&
    normalizeShoppingUnit(
      old.primaryUnit
    ) ===
      measure.unit
  ) {
    return {
      current:
        measure.value,

      old:
        old.primaryQty,
    };
  }

  if (
    old.metricQty !==
      null
  ) {
    if (
      measure.kind ===
        "mass" &&
      old.metricUnit ===
        "g"
    ) {
      return {
        current:
          measure.value,

        old:
          old.metricQty,
      };
    }

    if (
      measure.kind ===
        "volume" &&
      old.metricUnit ===
        "ml"
    ) {
      return {
        current:
          measure.value,

        old:
          old.metricQty,
      };
    }
  }

  return null;
}

function scaledPrice(
  oldMeta,
  aggregateMeasure
) {
  if (
    !oldMeta ||
    oldMeta.price ===
      null ||
    oldMeta.price ===
      undefined
  ) {
    return null;
  }

  const comparison =
    comparableQuantityFromAggregate(
      aggregateMeasure,
      oldMeta
    );

  if (
    !comparison ||
    !Number.isFinite(
      comparison.old
    ) ||
    comparison.old <= 0
  ) {
    const currentText =
      displayAggregateText(
        aggregateMeasure,
        oldMeta
      );

    return (
      currentText ===
      oldMeta.oldText
    )
      ? roundShopping(
          oldMeta.price
        )
      : null;
  }

  return roundShopping(
    oldMeta.price *
      (
        comparison.current /
        comparison.old
      )
  );
}

function scaledOccurrencePrice(
  oldMeta,
  aggregateMeasure,
  occurrence,
  aggregatePrice
) {
  if (
    aggregatePrice ===
      null ||
    aggregatePrice ===
      undefined
  ) {
    return null;
  }

  if (
    aggregateMeasure.kind ===
      "mass" &&
    occurrence.measure
      ?.kind ===
      "mass" &&
    aggregateMeasure.value >
      0
  ) {
    return roundShopping(
      aggregatePrice *
        (
          occurrence
            .measure
            .value /
          aggregateMeasure
            .value
        )
    );
  }

  if (
    aggregateMeasure.kind ===
      "volume" &&
    occurrence.measure
      ?.kind ===
      "volume" &&
    aggregateMeasure.value >
      0
  ) {
    return roundShopping(
      aggregatePrice *
        (
          occurrence
            .measure
            .value /
          aggregateMeasure
            .value
        )
    );
  }

  if (
    (
      aggregateMeasure
        .kind ===
        "count" ||
      aggregateMeasure
        .kind ===
        "count_mass"
    ) &&
    occurrence.measure &&
    (
      occurrence
        .measure
        .kind ===
        "count" ||
      occurrence
        .measure
        .kind ===
        "count_mass"
    ) &&
    aggregateMeasure
      .unit ===
      occurrence
        .measure
        .unit &&
    aggregateMeasure
      .value > 0
  ) {
    return roundShopping(
      aggregatePrice *
        (
          occurrence
            .measure
            .value /
          aggregateMeasure
            .value
        )
    );
  }

  return null;
}

function buildUpdatedShopping(
  foodJson
) {
  const oldShopping =
    isPlainObject(
      foodJson.shopping
    )
      ? foodJson.shopping
      : {};

  const oldMetadata =
    extractOldShoppingMetadata(
      oldShopping
    );

  const {
    groups,
    dayMeals,
  } =
    aggregateCurrentIngredients(
      foodJson
    );

  const aisleMap =
    new Map();

  const groupRuntime =
    new Map();

  let priced = 0;

  let unpriced = 0;

  let total = 0;

  const priceSources =
    new Set();

  for (
    const group of
    groups.values()
  ) {
    const oldMeta =
      oldMetadata.get(
        group.key
      ) ||
      null;

    const aggregateMeasure =
      aggregateGroupMeasure(
        group
      );

    const text =
      displayAggregateText(
        aggregateMeasure,
        oldMeta
      );

    const price =
      scaledPrice(
        oldMeta,
        aggregateMeasure
      );

    const aisle =
      cleanSpaces(
        oldMeta?.aisle
      ) ||
      "Other";

    const item = {
      name:
        oldMeta?.name ||
        titleCaseIngredient(
          group.name
        ),

      text,

      days:
        [
          ...group.days,
        ].sort(
          (
            a,
            b
          ) =>
            a - b
        ),

      meals:
        group
          .mealKeys
          .size,
    };

    if (
      price !== null
    ) {
      item.price =
        price;

      priced += 1;

      total += price;

      if (
        oldMeta
          ?.price_source
      ) {
        item.price_source =
          oldMeta
            .price_source;

        priceSources.add(
          String(
            oldMeta
              .price_source
          )
        );
      }

      if (
        oldMeta
          ?.approx !==
          null &&
        oldMeta
          ?.approx !==
          undefined
      ) {
        item.approx =
          oldMeta.approx;
      }

      if (
        oldMeta
          ?.price_note
      ) {
        item.price_note =
          oldMeta
            .price_note;
      }
    } else {
      unpriced += 1;
    }

    if (
      !aisleMap.has(
        aisle
      )
    ) {
      aisleMap.set(
        aisle,
        []
      );
    }

    aisleMap
      .get(aisle)
      .push(item);

    groupRuntime.set(
      group.key,
      {
        oldMeta,

        aggregateMeasure,

        aggregatePrice:
          price,
      }
    );
  }

  const existingAisleOrder =
    Array.isArray(
      oldShopping
        ?.week
        ?.aisles
    )
      ? oldShopping
          .week
          .aisles
          .map(
            (a) =>
              cleanSpaces(
                a?.aisle
              )
          )
          .filter(
            Boolean
          )
      : [];

  const orderedAisles =
    [];

  const usedAisles =
    new Set();

  for (
    const aisle of
    existingAisleOrder
  ) {
    if (
      !aisleMap.has(
        aisle
      )
    ) {
      continue;
    }

    orderedAisles.push({
      aisle,

      items:
        aisleMap
          .get(aisle)
          .sort(
            (
              a,
              b
            ) =>
              a.name.localeCompare(
                b.name
              )
          ),
    });

    usedAisles.add(
      aisle
    );
  }

  for (
    const [
      aisle,
      items,
    ] of
    [
      ...aisleMap.entries(),
    ].sort(
      (
        [a],
        [b]
      ) =>
        a.localeCompare(
          b
        )
    )
  ) {
    if (
      usedAisles.has(
        aisle
      )
    ) {
      continue;
    }

    orderedAisles.push({
      aisle,

      items:
        items.sort(
          (
            a,
            b
          ) =>
            a.name.localeCompare(
              b.name
            )
        ),
    });
  }

  const byDayDays =
    [];

  for (
    const dayEntry of
    dayMeals
  ) {
    const meals =
      [];

    let dayItems = 0;

    let dayPrice = 0;

    for (
      const meal of
      dayEntry.meals
    ) {
      const items =
        [];

      let mealPrice = 0;

      for (
        const occ of
        meal.occurrences
      ) {
        const runtime =
          groupRuntime.get(
            occ.key
          );

        const item = {
          name:
            runtime
              ?.oldMeta
              ?.name ||
            titleCaseIngredient(
              occ.name
            ),

          text:
            displayOccurrenceText(
              occ,
              runtime
                ?.oldMeta ||
                null
            ),
        };

        const p =
          runtime
            ? scaledOccurrencePrice(
                runtime.oldMeta,
                runtime.aggregateMeasure,
                occ,
                runtime.aggregatePrice
              )
            : null;

        if (
          p !== null
        ) {
          item.price =
            p;

          mealPrice +=
            p;

          if (
            runtime
              ?.oldMeta
              ?.price_source
          ) {
            item.price_source =
              runtime
                .oldMeta
                .price_source;
          }
        }

        items.push(
          item
        );
      }

      const builtMeal = {
        title:
          meal.title,

        slot:
          meal.slot,

        items,

        count:
          items.length,

        price:
          roundShopping(
            mealPrice
          ),
      };

      const steps =
        recipeSteps(
          meal.recipe
        );

      const tip =
        recipeTip(
          meal.recipe
        );

      const minutes =
        recipeMinutes(
          meal.recipe
        );

      if (
        steps.length
      ) {
        builtMeal.steps =
          steps;
      }

      if (tip) {
        builtMeal.tip =
          tip;
      }

      if (
        minutes !== null
      ) {
        builtMeal.minutes =
          minutes;
      }

      meals.push(
        builtMeal
      );

      dayItems +=
        items.length;

      dayPrice +=
        mealPrice;
    }

    byDayDays.push({
      day:
        dayEntry.day,

      meals,

      items:
        dayItems,

      price:
        roundShopping(
          dayPrice
        ),
    });
  }

  const oldWeek =
    isPlainObject(
      oldShopping.week
    )
      ? oldShopping.week
      : {};

  const week = {
    aisles:
      orderedAisles,

    items:
      groups.size,

    days:
      Array.isArray(
        foodJson.days
      )
        ? foodJson.days
            .length
        : 0,

    total:
      roundShopping(
        total
      ),

    priced,

    ...(
      oldWeek.region !==
      undefined
        ? {
            region:
              oldWeek.region,
          }
        : {}
    ),

    ...(
      oldWeek.zip !==
      undefined
        ? {
            zip:
              oldWeek.zip,
          }
        : {}
    ),

    approx:
      priced,

    unpriced,

    price_sources:
      [
        ...priceSources,
      ],

    disclaimer:
      "Shopping quantities are rebuilt from the edited meal plan. Existing stored price metadata is reused/scaled where safely possible; newly introduced or non-comparable ingredients may be unpriced. Prices are not refreshed from a retailer by this API.",
  };

  foodJson.shopping = {
    generated_at:
      Math.floor(
        Date.now() /
          1000
      ),

    note:
      "derived from the current days[].meals[].ingredients by trainer-update-weekly-food-json-newtest; no external shopping service is called",

    week,

    by_day: {
      days:
        byDayDays,
    },
  };

  return "updated";
}

function syncShoppingList(
  foodJson
) {
  try {
    if (
      !isPlainObject(
        foodJson
      )
    ) {
      return "failed";
    }

    if (
      !Array.isArray(
        foodJson.days
      )
    ) {
      return "failed";
    }

    return buildUpdatedShopping(
      foodJson
    );
  } catch (err) {
    console.error(
      "SHOPPING_SYNC_FAILED:",
      err?.message
    );

    return "failed";
  }
}

// =============================================================================
// AUDIT LOG
// =============================================================================

function getClientIp(req) {
  const ip =
    (
      typeof req.ip ===
        "string" &&
      req.ip
    ) ||
    req.socket
      ?.remoteAddress ||
    req.connection
      ?.remoteAddress ||
    "0.0.0.0";

  return String(
    ip
  ).slice(
    0,
    64
  );
}

function getUserAgent(req) {
  const ua =
    (
      typeof req.get ===
        "function" &&
      req.get(
        "user-agent"
      )
    ) ||
    req.headers
      ?.[
        "user-agent"
      ] ||
    "";

  return String(
    ua
  ).slice(
    0,
    500
  );
}

function authLogHash(value) {
  if (
    value === null ||
    value ===
      undefined
  ) {
    return null;
  }

  return crypto
    .createHmac(
      "sha256",
      SECURITY_PEPPER
    )
    .update(
      String(
        value
      )
        .trim()
        .toLowerCase()
    )
    .digest(
      "hex"
    );
}

async function writeAuthLogSafe(
  req,
  {
    eventType,
    userId,
    partnerCode,
    identifier,
    success,
    failureReason,
  }
) {
  try {
    const ipHash =
      authLogHash(
        getClientIp(req)
      );

    const userAgentHash =
      authLogHash(
        getUserAgent(req)
      );

    const identifierHash =
      identifier !== null &&
      identifier !==
        undefined
        ? authLogHash(
            identifier
          )
        : null;

    await pool.execute(
      `
      INSERT INTO app_auth_logs (
        event_type,
        user_id,
        role,
        partner_code,
        identifier_hash,
        ip_hash,
        user_agent_hash,
        session_id_hash,
        success,
        failure_reason
      )
      VALUES (
        ?,
        ?,
        NULL,
        ?,
        ?,
        ?,
        ?,
        NULL,
        ?,
        ?
      )
      `,
      [
        String(
          eventType ||
            ""
        ).slice(
          0,
          60
        ),

        userId !== null &&
        userId !==
          undefined
          ? String(
              userId
            ).slice(
              0,
              191
            )
          : null,

        partnerCode ??
          null,

        identifierHash,

        ipHash,

        userAgentHash,

        success
          ? 1
          : 0,

        failureReason !==
          null &&
        failureReason !==
          undefined
          ? String(
              failureReason
            ).slice(
              0,
              255
            )
          : null,
      ]
    );
  } catch (err) {
    console.error(
      "AUTH_LOG_WRITE_FAILED:",
      err?.code ||
        err?.message
    );
  }
}

// =============================================================================
// CONTROLLER
// =============================================================================

const trainerUpdateWeeklyFoodJsonNewtest =
  async (
    req,
    res
  ) => {
    res.setHeader(
      "Cache-Control",
      "no-store"
    );

    res.setHeader(
      "Pragma",
      "no-cache"
    );

    if (
      req.method !==
      "POST"
    ) {
      return res
        .status(405)
        .json({
          ok: false,

          message:
            "Only POST method is allowed",
        });
    }

    let connection =
      null;

    let auditDietitianId =
      null;

    let auditProfileId =
      null;

    let auditAction =
      null;

    try {
      const payload =
        req.body;

      if (
        !isPlainObject(
          payload
        )
      ) {
        fail(
          400,
          "Invalid JSON payload"
        );
      }

      // =====================================================================
      // 1. ACTION
      // =====================================================================

      const action =
        String(
          payload.action ??
            ""
        )
          .trim()
          .toLowerCase();

      if (
        !ALLOWED_ACTIONS.has(
          action
        )
      ) {
        fail(
          400,
          "Invalid action. Allowed: add, update, delete"
        );
      }

      auditAction =
        action;

      const id =
        Number.parseInt(
          payload.id,
          10
        );

      if (
        !Number.isInteger(
          id
        ) ||
        id <= 0
      ) {
        fail(
          400,
          "id is required"
        );
      }

      // =====================================================================
      // 2. IDENTITY / TARGET
      // =====================================================================

      const dietitianId =
        String(
          payload
            .dietitian_id ??
            ""
        ).trim();

      if (
        dietitianId === ""
      ) {
        fail(
          400,
          "dietitian_id is required"
        );
      }

      const profileId =
        requiredString(
          payload,
          "profile_id"
        );

      const dayCode =
        requiredString(
          payload,
          "day_code"
        ).toLowerCase();

      let mealType =
        requiredString(
          payload,
          "meal_type"
        ).toLowerCase();

      /*
       * Accept snack aliases from frontend.
       */

      mealType =
        canonicalMealType(
          mealType
        );

      if (
        !ALLOWED_MEALS.includes(
          mealType
        )
      ) {
        fail(
          400,
          "Invalid meal_type. Allowed: breakfast, lunch, snacks, dinner"
        );
      }

      const weekStartDate =
        String(
          payload
            .week_start_date ??
            ""
        ).trim();

      const weekEndDate =
        String(
          payload
            .week_end_date ??
            ""
        ).trim();

      if (
        weekStartDate !==
          "" &&
        !isValidDateString(
          weekStartDate
        )
      ) {
        fail(
          400,
          "week_start_date must be YYYY-MM-DD"
        );
      }

      if (
        weekEndDate !==
          "" &&
        !isValidDateString(
          weekEndDate
        )
      ) {
        fail(
          400,
          "week_end_date must be YYYY-MM-DD"
        );
      }

      // =====================================================================
      // 3. FOOD INDEX / FOOD
      // =====================================================================

      let foodIndex =
        null;

      if (
        action ===
          "update" ||
        action ===
          "delete"
      ) {
        if (
          payload
            .food_index ===
            undefined ||
          !isNumericValue(
            payload
              .food_index
          )
        ) {
          fail(
            400,
            "food_index is required for update/delete"
          );
        }

        foodIndex =
          Number.parseInt(
            payload
              .food_index,
            10
          );

        if (
          !Number.isInteger(
            foodIndex
          ) ||
          foodIndex < 0
        ) {
          fail(
            400,
            "food_index cannot be negative"
          );
        }
      }

      if (
        (
          action ===
            "add" ||
          action ===
            "update"
        ) &&
        !isPlainObject(
          payload.food
        )
      ) {
        fail(
          400,
          "food object is required for add/update"
        );
      }

      // =====================================================================
      // 4. JWT / DIETITIAN AUTHORIZATION
      // =====================================================================

      const self =
        requireDieticianSelfAccess(
          req,
          dietitianId
        );

      if (
        !self.allowed
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              "weekly_food_json_denied",

            userId:
              String(
                req.user
                  ?.sub ||
                  req.user
                    ?.dietician
                    ?.dietician_id ||
                  ""
              ),

            partnerCode:
              null,

            identifier:
              profileId,

            success:
              false,

            failureReason:
              self.message,
          }
        );

        return res
          .status(
            self.statusCode
          )
          .json({
            ok:
              false,

            message:
              self.message,
          });
      }

      const normalizedProfileId =
        normalizeId(
          profileId
        );

      if (
        !normalizedProfileId
      ) {
        fail(
          400,
          "Invalid profile_id"
        );
      }

      const access = {
        dieticianId:
          self.dieticianId,

        profileId:
          normalizedProfileId,
      };

      auditDietitianId =
        access.dieticianId;

      auditProfileId =
        access.profileId;

      // =====================================================================
      // 5. START TRANSACTION + LOCK WEEK
      // =====================================================================

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const selectParams = [
        access.dieticianId,
        access.profileId,
      ];

      let selectSql = `
        SELECT
          id,
          dietician_id,
          profile_id,
          week_start_date,
          week_end_date,
          status,
          food_json
        FROM weekly_food_json_suggestions_newtest
        WHERE id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
      `;

      /*
       * id must be first because first SQL placeholder is id.
       */

      selectParams.unshift(
        id
      );

      if (
        weekStartDate !==
        ""
      ) {
        selectSql +=
          " AND week_start_date = ? ";

        selectParams.push(
          weekStartDate
        );
      }

      if (
        weekEndDate !==
        ""
      ) {
        selectSql +=
          " AND week_end_date = ? ";

        selectParams.push(
          weekEndDate
        );
      }

      selectSql +=
        " LIMIT 1 FOR UPDATE ";

      const [
        rows,
      ] =
        await connection.execute(
          selectSql,
          selectParams
        );

      const row =
        rows[0];

      if (!row) {
        fail(
          404,
          "Diet plan row not found. No row matched id + dietitian_id + profile_id."
        );
      }

      const foodJson =
        decodeStoredFoodJson(
          row.food_json
        );

      if (
        !Array.isArray(
          foodJson.days
        )
      ) {
        fail(
          400,
          "Stored food_json does not contain days array"
        );
      }

      // =====================================================================
      // 6. LOCATE DAY
      // =====================================================================

      const dayIndex =
        resolveDayIndex(
          foodJson.days,
          dayCode
        );

      if (
        dayIndex < 0
      ) {
        fail(
          404,
          "day_code not found in food_json",
          {
            requested_day_code:
              dayCode,

            available_day_codes:
              foodJson.days.map(
                (
                  d,
                  i
                ) => {
                  if (
                    !isPlainObject(
                      d
                    )
                  ) {
                    return null;
                  }

                  const key =
                    DAY_ID_KEYS.find(
                      (k) =>
                        d[k] !==
                          undefined &&
                        d[k] !==
                          null &&
                        d[k] !==
                          ""
                    );

                  return key
                    ? String(
                        d[key]
                      )
                    : `d${i + 1}`;
                }
              ),
          }
        );
      }

      const resolvedDay =
        foodJson.days[
          dayIndex
        ];

      const resolvedDayCode =
        isPlainObject(
          resolvedDay
        ) &&
        resolvedDay
          .day_code !==
          undefined &&
        resolvedDay
          .day_code !==
          null
          ? String(
              resolvedDay
                .day_code
            )
          : dayCode;

      // =====================================================================
      // 7. APPLY ADD / UPDATE / DELETE
      // =====================================================================

      let changedFood =
        null;

      let deletedFood =
        null;

      let finalFoodIndex =
        null;

      const day =
        foodJson.days[
          dayIndex
        ];

      if (
        !isPlainObject(
          day
        )
      ) {
        fail(
          400,
          "Stored day entry is not an object",
          {
            day_code:
              resolvedDayCode,
          }
        );
      }

      const meal =
        resolveMealAccessor(
          day,
          mealType,
          action === "add"
        );

      if (!meal) {
        fail(
          404,
          "Meal foods not found in food_json",
          {
            day_code:
              resolvedDayCode,

            meal_type:
              mealType,

            ...describeDayShape(
              day
            ),
          }
        );
      }

      // ---------------------------------------------------------------------
      // ADD
      // ---------------------------------------------------------------------

      if (
        action === "add"
      ) {
        const newFood =
          normalizeFoodForAdd(
            payload.food
          );

        finalFoodIndex =
          meal.push(
            newFood
          );

        changedFood =
          meal.get(
            finalFoodIndex
          );
      }

      // ---------------------------------------------------------------------
      // INDEX VALIDATION
      // ---------------------------------------------------------------------

      if (
        action ===
          "update" ||
        action ===
          "delete"
      ) {
        if (
          foodIndex >=
            meal.count() ||
          meal.get(
            foodIndex
          ) === undefined
        ) {
          fail(
            404,
            "Food index not found",
            {
              day_code:
                resolvedDayCode,

              meal_type:
                mealType,

              food_index:
                foodIndex,

              food_count:
                meal.count(),
            }
          );
        }
      }

      // ---------------------------------------------------------------------
      // UPDATE / SWAP
      // ---------------------------------------------------------------------

      if (
        action ===
        "update"
      ) {
        /*
         * payload.food can now be the RAW /search-foods result.
         *
         * Example:
         *
         * {
         *   name: "Chicken Omelette",
         *   kcal: 268,
         *   c: 6.4,
         *   p: 17.7,
         *   f: 19.1,
         *   fiber: 0,
         *   portion: "1 omelette (150 g)",
         *   contains: [...],
         *   key: "usa_breakfast:750",
         *   method: "...",
         *   thumb: "..."
         * }
         */

        const updatedFood =
          patchExistingFood(
            meal.get(
              foodIndex
            ),
            payload.food
          );

        meal.set(
          foodIndex,
          updatedFood
        );

        finalFoodIndex =
          foodIndex;

        changedFood =
          meal.get(
            foodIndex
          );
      }

      // ---------------------------------------------------------------------
      // DELETE
      // ---------------------------------------------------------------------

      if (
        action ===
        "delete"
      ) {
        deletedFood =
          meal.remove(
            foodIndex
          );

        finalFoodIndex =
          foodIndex;
      }

      // =====================================================================
      // 8. RECALCULATE DAY
      // =====================================================================

      syncDayNutrition(
        day,
        sumDay(day)
      );

      // =====================================================================
      // 9. REBUILD SHOPPING LOCALLY
      // =====================================================================

      /*
       * Important:
       *
       * Shopping is rebuilt from THIS exact updated foodJson.
       *
       * No:
       *
       * axios
       * FitChef shopping endpoint
       * respyr.in shopping URL
       * background regeneration
       */

      const shoppingSync =
        syncShoppingList(
          foodJson
        );

      /*
       * Do not silently persist stale shopping.
       *
       * If local shopping rebuilding fails,
       * rollback the complete edit.
       */

      if (
        shoppingSync !==
        "updated"
      ) {
        fail(
          500,
          "Shopping list could not be rebuilt. Diet plan update was cancelled."
        );
      }

      // =====================================================================
      // 10. RECALCULATE WEEKLY MACROS
      // =====================================================================

      const weeklyMacros =
        recalculateWeeklyMacros(
          foodJson
        );

      // =====================================================================
      // 11. SERIALIZE
      // =====================================================================

      let updatedFoodJson;

      try {
        updatedFoodJson =
          JSON.stringify(
            foodJson
          );
      } catch (err) {
        fail(
          500,
          "Failed to encode updated food_json"
        );
      }

      // =====================================================================
      // 12. SAVE COMPLETE JSON + WEEKLY MACROS
      // =====================================================================

      const updateParams = [
        updatedFoodJson,

        String(
          weeklyMacros.calories
        ),

        String(
          weeklyMacros.carbs_g
        ),

        String(
          weeklyMacros.fat_g
        ),

        String(
          weeklyMacros.protein_g
        ),

        String(
          weeklyMacros.fiber_g
        ),

        id,

        access.dieticianId,

        access.profileId,
      ];

      let updateSql = `
        UPDATE weekly_food_json_suggestions_newtest
        SET
          food_json = ?,
          cal = ?,
          cabs = ?,
          fats = ?,
          \`Protein\` = ?,
          \`Fibre\` = ?,
          updated_at = NOW()
        WHERE id = ?
          AND UPPER(TRIM(dietician_id)) = ?
          AND profile_id = ?
      `;

      if (
        weekStartDate !==
        ""
      ) {
        updateSql +=
          " AND week_start_date = ? ";

        updateParams.push(
          weekStartDate
        );
      }

      if (
        weekEndDate !==
        ""
      ) {
        updateSql +=
          " AND week_end_date = ? ";

        updateParams.push(
          weekEndDate
        );
      }

      updateSql +=
        " LIMIT 1 ";

      const [
        updateResult,
      ] =
        await connection.execute(
          updateSql,
          updateParams
        );

      if (
        !updateResult ||
        updateResult
          .affectedRows !== 1
      ) {
        fail(
          409,
          "Diet plan row could not be updated"
        );
      }

      // =====================================================================
      // 13. COMMIT
      // =====================================================================

      await connection.commit();

      // =====================================================================
      // 14. RESPONSE SUMMARIES
      // =====================================================================

      const selectedDay =
        foodJson.days[
          dayIndex
        ];

      const selectedMeal =
        resolveMealAccessor(
          selectedDay,
          mealType,
          false
        );

      const selectedMealFoods =
        selectedMeal
          ? selectedMeal.list()
          : [];

      // =====================================================================
      // 15. AUDIT SUCCESS
      // =====================================================================

      writeAuthLogSafe(
        req,
        {
          eventType:
            `weekly_food_json_${action}`,

          userId:
            access.dieticianId,

          partnerCode:
            access.dieticianId,

          identifier:
            access.profileId,

          success:
            true,

          failureReason:
            `Diet plan food ${action} successful`,
        }
      );

      // =====================================================================
      // 16. RESPONSE
      // =====================================================================

      return res
        .status(200)
        .json({
          ok:
            true,

          message:
            `Diet plan food ${action} successful`,

          action,

          id,

          dietitian_id:
            access.dieticianId,

          profile_id:
            access.profileId,

          week_start_date:
            formatDateOnly(
              row.week_start_date
            ),

          week_end_date:
            formatDateOnly(
              row.week_end_date
            ),

          status_value:
            row.status ===
              null ||
            row.status ===
              undefined
              ? null
              : Number(
                  row.status
                ),

          day_code:
            dayCode,

          resolved_day_code:
            resolvedDayCode,

          day_index:
            dayIndex,

          meal_type:
            mealType,

          food_index:
            finalFoodIndex,

          changed_food:
            changedFood,

          deleted_food:
            deletedFood,

          meal_summary:
            sumFoods(
              selectedMealFoods
            ),

          day_summary:
            sumDay(
              selectedDay
            ),

          weekly_json_data:
            weeklyMacros,

          shopping_sync:
            shoppingSync,

          food_json:
            foodJson,
        });
    } catch (err) {
      // =====================================================================
      // ROLLBACK
      // =====================================================================

      if (connection) {
        try {
          await connection.rollback();
        } catch (
          rollbackErr
        ) {
          console.error(
            "WEEKLY_FOOD_JSON_NEWTEST_ROLLBACK_FAILED:",
            rollbackErr
              ?.code ||
              rollbackErr
                ?.message
          );
        }
      }

      // =====================================================================
      // EXPECTED API ERRORS
      // =====================================================================

      if (
        err instanceof
        ApiError
      ) {
        await writeAuthLogSafe(
          req,
          {
            eventType:
              `weekly_food_json_${auditAction || "error"}_failed`,

            userId:
              auditDietitianId ||
              String(
                req.user
                  ?.sub ||
                  ""
              ),

            partnerCode:
              auditDietitianId,

            identifier:
              auditProfileId,

            success:
              false,

            failureReason:
              err.message,
          }
        );

        return res
          .status(
            err.statusCode
          )
          .json(
            err.payload
          );
      }

      // =====================================================================
      // UNKNOWN ERROR
      // =====================================================================

      console.error(
        "WEEKLY_FOOD_JSON_NEWTEST_ERROR:",
        {
          code:
            err?.code,

          errno:
            err?.errno,

          sqlState:
            err?.sqlState,

          message:
            err?.message,
        }
      );

      await writeAuthLogSafe(
        req,
        {
          eventType:
            "weekly_food_json_error",

          userId:
            auditDietitianId ||
            String(
              req.user
                ?.sub ||
                ""
            ),

          partnerCode:
            auditDietitianId,

          identifier:
            auditProfileId,

          success:
            false,

          failureReason:
            err?.code ||
            "internal_error",
        }
      );

      return res
        .status(500)
        .json({
          ok:
            false,

          message:
            "Something went wrong while managing diet plan food",

          ...(
            APP_DEBUG
              ? {
                  debug_error:
                    err?.message,
                }
              : {}
          ),
        });
    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// =============================================================================
// EXPORT
// =============================================================================

module.exports = {
  trainerUpdateWeeklyFoodJsonNewtest,
};