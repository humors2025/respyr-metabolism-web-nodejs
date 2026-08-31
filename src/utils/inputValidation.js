/**
 * src/utils/inputValidation.js
 *
 * Shared frontend input-validation helpers.
 *
 * IMPORTANT:
 * Frontend validation is only defense-in-depth and improves UX.
 * The backend validation remains the actual security control.
 */

/*
|--------------------------------------------------------------------------
| Human Name Validation
|--------------------------------------------------------------------------
|
| Allowed:
| - Unicode letters
| - Unicode combining marks
| - Spaces
| - Apostrophe '
| - Curly apostrophe ’
| - Hyphen -
| - Period .
|
| Valid examples:
|
| John
| John Smith
| Md. Amanul Haque
| Anne-Marie
| O'Connor
| José García
|
| Invalid examples:
|
| <h1>HTML INJECTION</h1>
| <script>alert(1)</script>
| {{7*7}}
| ${7*7}
| <img src=x>
|--------------------------------------------------------------------------
*/

export const HUMAN_NAME_RE =
  /^[\p{L}\p{M} .'’\-]{1,100}$/u;

/*
|--------------------------------------------------------------------------
| Normalize Human Name
|--------------------------------------------------------------------------
*/

export function normalizeHumanName(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return "";
  }

  return String(value)
    .normalize("NFC")
    .trim()
    .replace(/\s+/g, " ");
}

/*
|--------------------------------------------------------------------------
| Validate Human Name
|--------------------------------------------------------------------------
*/

export function validateHumanName(
  value,
  fieldName = "Name",
  {
    required = true,
    minLength = 1,
    maxLength = 100,
  } = {}
) {
  const name =
    normalizeHumanName(value);

  /*
  |--------------------------------------------------------------------------
  | Empty value
  |--------------------------------------------------------------------------
  */

  if (!name) {
    if (!required) {
      return {
        ok: true,
        value: "",
        message: null,
      };
    }

    return {
      ok: false,
      value: "",
      message:
        `${fieldName} is required.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Minimum Length
  |--------------------------------------------------------------------------
  */

  if (
    name.length <
    minLength
  ) {
    return {
      ok: false,
      value: "",
      message:
        `${fieldName} must be at least ${minLength} character${
          minLength === 1
            ? ""
            : "s"
        }.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Maximum Length
  |--------------------------------------------------------------------------
  */

  if (
    name.length >
    maxLength
  ) {
    return {
      ok: false,
      value: "",
      message:
        `${fieldName} must not exceed ${maxLength} characters.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Character Allowlist
  |--------------------------------------------------------------------------
  */

  if (
    !HUMAN_NAME_RE.test(
      name
    )
  ) {
    return {
      ok: false,
      value: "",
      message:
        `${fieldName} contains invalid characters.`,
    };
  }

  return {
    ok: true,
    value: name,
    message: null,
  };
}

/*
|--------------------------------------------------------------------------
| Email Validation
|--------------------------------------------------------------------------
|
| This intentionally mirrors the backend rules closely.
|
| Invalid:
|
| <script>@example.com
| {{7*7}}@example.com
| test<>@example.com
| test user@example.com
|
| Valid:
|
| john@example.com
| john.smith@example.com
| john+respyr@example.com
|--------------------------------------------------------------------------
*/

export function validateEmailAddress(
  value,
  fieldName = "Email"
) {
  if (
    typeof value !==
    "string"
  ) {
    return {
      ok: false,
      value: "",
      message:
        `${fieldName} is required.`,
    };
  }

  const email =
    value
      .trim()
      .toLowerCase();

  /*
  |--------------------------------------------------------------------------
  | Required
  |--------------------------------------------------------------------------
  */

  if (!email) {
    return {
      ok: false,
      value: "",
      message:
        `${fieldName} is required.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Length + Dangerous Characters
  |--------------------------------------------------------------------------
  */

  if (
    email.length > 254 ||
    /[\x00-\x20\x7f<>"{}]/.test(
      email
    )
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()}.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Exactly One @
  |--------------------------------------------------------------------------
  */

  const at =
    email.lastIndexOf(
      "@"
    );

  if (
    at <= 0 ||
    at !==
      email.indexOf("@")
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()}.`,
    };
  }

  const local =
    email.slice(
      0,
      at
    );

  const domain =
    email.slice(
      at + 1
    );

  /*
  |--------------------------------------------------------------------------
  | Local Part
  |--------------------------------------------------------------------------
  */

  if (
    local.length > 64 ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    !/^[a-z0-9.!#$%&'*+/=?^_`|~-]+$/i.test(
      local
    )
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()}.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Domain
  |--------------------------------------------------------------------------
  */

  const labels =
    domain.split(".");

  if (
    labels.length < 2 ||
    domain.length > 253 ||
    labels.some(
      (label) =>
        !label ||
        label.length > 63 ||
        !/^[a-z0-9-]+$/i.test(
          label
        ) ||
        label.startsWith(
          "-"
        ) ||
        label.endsWith(
          "-"
        )
    )
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()}.`,
    };
  }

  return {
    ok: true,
    value: email,
    message: null,
  };
}

/*
|--------------------------------------------------------------------------
| Simple Email Boolean Helper
|--------------------------------------------------------------------------
*/

export function isValidEmail(
  value
) {
  return validateEmailAddress(
    value
  ).ok;
}

/*
|--------------------------------------------------------------------------
| Phone Validation
|--------------------------------------------------------------------------
|
| Allowed characters:
|
| digits
| spaces
| +
| -
| (
| )
| .
|
| Valid:
|
| +91 98765 43210
| +1 (555) 123-4567
| 9876543210
|
| Invalid:
|
| +91<script>9876543210
| +91{{7*7}}9876543210
|
| IMPORTANT:
| Do not remove arbitrary characters BEFORE validation.
|--------------------------------------------------------------------------
*/

export function validatePhoneNumber(
  value,
  fieldName = "Phone",
  {
    required = true,
    minDigits = 7,
    maxDigits = 15,
  } = {}
) {
  /*
  |--------------------------------------------------------------------------
  | Empty
  |--------------------------------------------------------------------------
  */

  if (
    value === null ||
    value === undefined ||
    String(value).trim() ===
      ""
  ) {
    if (!required) {
      return {
        ok: true,
        value: "",
        message: null,
      };
    }

    return {
      ok: false,
      value: "",
      message:
        `${fieldName} is required.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Type
  |--------------------------------------------------------------------------
  */

  if (
    typeof value !==
      "string" &&
    typeof value !==
      "number"
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()} number.`,
    };
  }

  const raw =
    String(value).trim();

  /*
  |--------------------------------------------------------------------------
  | Character Validation
  |--------------------------------------------------------------------------
  */

  if (
    raw.length > 30 ||
    !/^\+?[0-9\s().-]+$/.test(
      raw
    ) ||
    /[\x00-\x1f\x7f]/.test(
      raw
    )
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()} number.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Extract Digits only AFTER validation
  |--------------------------------------------------------------------------
  */

  const digits =
    raw.replace(
      /\D/g,
      ""
    );

  /*
  |--------------------------------------------------------------------------
  | Digit Length
  |--------------------------------------------------------------------------
  */

  if (
    digits.length <
      minDigits ||
    digits.length >
      maxDigits
  ) {
    return {
      ok: false,
      value: "",
      message:
        `Please enter a valid ${fieldName.toLowerCase()} number.`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Normalized Value
  |--------------------------------------------------------------------------
  */

  const normalized =
    raw.startsWith("+")
      ? `+${digits}`
      : digits;

  return {
    ok: true,
    value: normalized,
    message: null,
  };
}

/*
|--------------------------------------------------------------------------
| Simple Phone Boolean Helper
|--------------------------------------------------------------------------
*/

export function isValidPhone(
  value,
  options = {}
) {
  return validatePhoneNumber(
    value,
    "Phone",
    options
  ).ok;
}

/*
|--------------------------------------------------------------------------
| Dangerous Input Helper
|--------------------------------------------------------------------------
|
| This is NOT a replacement for field-specific validation.
|
| It can be useful for detecting obvious attack payloads in generic text.
|--------------------------------------------------------------------------
*/

export function containsDangerousMarkup(
  value
) {
  if (
    value === null ||
    value === undefined
  ) {
    return false;
  }

  const text =
    String(value);

  return (
    /<[^>]*>/i.test(
      text
    ) ||
    /<script\b/i.test(
      text
    ) ||
    /javascript\s*:/i.test(
      text
    ) ||
    /\{\{[\s\S]*\}\}/.test(
      text
    ) ||
    /\$\{[\s\S]*\}/.test(
      text
    )
  );
}