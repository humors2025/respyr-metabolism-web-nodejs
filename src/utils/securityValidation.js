'use strict';

/*
|--------------------------------------------------------------------------
| Human-name validation
|--------------------------------------------------------------------------
|
| Human names are treated as plain text, NEVER HTML.
|
| Allowed:
| - Unicode letters
| - Unicode combining marks
| - Spaces
| - Apostrophes
| - Curly apostrophes
| - Hyphens
| - Periods
|
| Examples allowed:
|
| John
| John Smith
| Md. Amanul Haque
| O'Connor
| Anne-Marie
| José García
|
| Examples rejected:
|
| <h1>John</h1>
| <script>alert(1)</script>
| {{7*7}}
| ${7*7}
| <img src=x>
|--------------------------------------------------------------------------
*/

const HUMAN_NAME_RE =
  /^[\p{L}\p{M} .'’\-]{1,100}$/u;


/*
|--------------------------------------------------------------------------
| Normalize human name
|--------------------------------------------------------------------------
*/

function normalizeHumanName(value) {
  if (
    value === null ||
    value === undefined
  ) {
    return '';
  }

  return String(value)
    .normalize('NFC')
    .trim()
    .replace(/\s+/g, ' ');
}


/*
|--------------------------------------------------------------------------
| Validate human name
|--------------------------------------------------------------------------
*/

function validateHumanName(
  value,
  fieldName = 'name'
) {
  const name =
    normalizeHumanName(value);

  if (!name) {
    return {
      ok: false,
      value: '',
      message: `${fieldName} is required`,
    };
  }

  if (name.length > 100) {
    return {
      ok: false,
      value: '',
      message:
        `${fieldName} must be maximum 100 characters`,
    };
  }

  if (!HUMAN_NAME_RE.test(name)) {
    return {
      ok: false,
      value: '',
      message:
        `${fieldName} contains invalid characters`,
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
| Email validation
|--------------------------------------------------------------------------
|
| Email addresses are treated as plain data.
|
| This validator rejects:
|
| <script>@example.com
| {{7*7}}@example.com
| test<>@example.com
| test user@example.com
| malformed domains
| multiple @ symbols
|
| Instead of trying to sanitize malicious email values, they are rejected.
|--------------------------------------------------------------------------
*/

function validateEmailAddress(
  value,
  fieldName = 'email'
) {
  if (typeof value !== 'string') {
    return {
      ok: false,
      value: '',
      message: `${fieldName} is required`,
    };
  }

  const email =
    value
      .trim()
      .toLowerCase();

  if (!email) {
    return {
      ok: false,
      value: '',
      message: `${fieldName} is required`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Reject dangerous/control characters
  |--------------------------------------------------------------------------
  */

  if (
    email.length > 254 ||
    /[\x00-\x20\x7f<>"{}]/.test(email)
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Validate @
  |--------------------------------------------------------------------------
  */

  const at =
    email.lastIndexOf('@');

  if (
    at <= 0 ||
    at !== email.indexOf('@')
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
    };
  }

  const local =
    email.slice(0, at);

  const domain =
    email.slice(at + 1);

  /*
  |--------------------------------------------------------------------------
  | Validate local portion
  |--------------------------------------------------------------------------
  */

  if (
    local.length > 64 ||
    local.startsWith('.') ||
    local.endsWith('.') ||
    local.includes('..') ||
    !/^[a-z0-9.!#$%&'*+/=?^_`|~-]+$/i.test(local)
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Validate domain
  |--------------------------------------------------------------------------
  */

  const labels =
    domain.split('.');

  if (
    labels.length < 2 ||
    domain.length > 253 ||
    labels.some(
      (label) =>
        !label ||
        label.length > 63 ||
        !/^[a-z0-9-]+$/i.test(label) ||
        label.startsWith('-') ||
        label.endsWith('-')
    )
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
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
| Phone validation
|--------------------------------------------------------------------------
|
| Important:
|
| We DO NOT remove malicious characters first.
|
| Bad:
|
| +1<script>alert(1)</script>5551234567
|
| must be rejected.
|
| It should NOT become:
|
| +15551234567
|
| Valid examples:
|
| +91 98765 43210
| +1 (555) 123-4567
| 9876543210
|--------------------------------------------------------------------------
*/

function validatePhoneNumber(
  value,
  fieldName = 'phone',
  { required = false } = {}
) {
  /*
  |--------------------------------------------------------------------------
  | Empty value handling
  |--------------------------------------------------------------------------
  */

  if (
    value === null ||
    value === undefined ||
    value === ''
  ) {
    if (required) {
      return {
        ok: false,
        value: '',
        message: `${fieldName} is required`,
      };
    }

    return {
      ok: true,
      value: '',
      message: null,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Type validation
  |--------------------------------------------------------------------------
  */

  if (
    typeof value !== 'string' &&
    typeof value !== 'number'
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
    };
  }

  const raw =
    String(value).trim();

  if (!raw) {
    if (required) {
      return {
        ok: false,
        value: '',
        message: `${fieldName} is required`,
      };
    }

    return {
      ok: true,
      value: '',
      message: null,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Reject unexpected characters
  |--------------------------------------------------------------------------
  |
  | Allowed:
  |
  | digits
  | spaces
  | +
  | (
  | )
  | .
  | -
  |--------------------------------------------------------------------------
  */

  if (
    raw.length > 30 ||
    !/^\+?[0-9\s().-]+$/.test(raw) ||
    /[\x00-\x1f\x7f]/.test(raw)
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
    };
  }

  /*
  |--------------------------------------------------------------------------
  | Normalize after validation
  |--------------------------------------------------------------------------
  */

  const digits =
    raw.replace(/\D/g, '');

  /*
  |--------------------------------------------------------------------------
  | E.164 maximum = 15 digits
  |--------------------------------------------------------------------------
  */

  if (
    digits.length < 7 ||
    digits.length > 15
  ) {
    return {
      ok: false,
      value: '',
      message: `Invalid ${fieldName} format`,
    };
  }

  return {
    ok: true,

    value:
      raw.startsWith('+')
        ? `+${digits}`
        : digits,

    message: null,
  };
}


/*
|--------------------------------------------------------------------------
| HTML escaping
|--------------------------------------------------------------------------
|
| Use this whenever plain-text data is inserted into an HTML email/template.
|
| Example:
|
| <h1>TEST</h1>
|
| becomes:
|
| &lt;h1&gt;TEST&lt;/h1&gt;
|--------------------------------------------------------------------------
*/

function escapeHtml(value) {
  return String(
    value === null ||
    value === undefined
      ? ''
      : value
  )
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}


/*
|--------------------------------------------------------------------------
| Exports
|--------------------------------------------------------------------------
*/

module.exports = {
  HUMAN_NAME_RE,
  normalizeHumanName,
  validateHumanName,
  validateEmailAddress,
  validatePhoneNumber,
  escapeHtml,
};










// 'use strict';

// /*
// |--------------------------------------------------------------------------
// | Human-name validation
// |--------------------------------------------------------------------------
// |
// | Human names are treated as plain text, NEVER HTML.
// |
// | Allowed:
// | - Unicode letters
// | - Unicode combining marks
// | - Spaces
// | - Apostrophes
// | - Curly apostrophes
// | - Hyphens
// | - Periods
// |
// | Examples allowed:
// |
// | John
// | John Smith
// | Md. Amanul Haque
// | O'Connor
// | Anne-Marie
// | José García
// |
// | Examples rejected:
// |
// | <h1>John</h1>
// | <script>alert(1)</script>
// | {{7*7}}
// | ${7*7}
// | <img src=x>
// |--------------------------------------------------------------------------
// */

// const HUMAN_NAME_RE =
//   /^[\p{L}\p{M} .'’\-]{1,100}$/u;


// /*
// |--------------------------------------------------------------------------
// | Normalize human name
// |--------------------------------------------------------------------------
// */

// function normalizeHumanName(value) {
//   if (
//     value === null ||
//     value === undefined
//   ) {
//     return '';
//   }

//   return String(value)
//     .normalize('NFC')
//     .trim()
//     .replace(/\s+/g, ' ');
// }


// /*
// |--------------------------------------------------------------------------
// | Validate human name
// |--------------------------------------------------------------------------
// */

// function validateHumanName(
//   value,
//   fieldName = 'name'
// ) {
//   const name =
//     normalizeHumanName(value);

//   if (!name) {
//     return {
//       ok: false,
//       value: '',
//       message: `${fieldName} is required`,
//     };
//   }

//   if (name.length > 100) {
//     return {
//       ok: false,
//       value: '',
//       message:
//         `${fieldName} must be maximum 100 characters`,
//     };
//   }

//   if (!HUMAN_NAME_RE.test(name)) {
//     return {
//       ok: false,
//       value: '',
//       message:
//         `${fieldName} contains invalid characters`,
//     };
//   }

//   return {
//     ok: true,
//     value: name,
//     message: null,
//   };
// }


// /*
// |--------------------------------------------------------------------------
// | HTML escaping
// |--------------------------------------------------------------------------
// |
// | This should be used whenever plain-text data is inserted into an HTML
// | template.
// |
// | Example:
// |
// | <h1>TEST</h1>
// |
// | becomes:
// |
// | &lt;h1&gt;TEST&lt;/h1&gt;
// |
// | so the browser/email client displays it as text instead of HTML.
// |--------------------------------------------------------------------------
// */

// function escapeHtml(value) {
//   return String(
//     value === null ||
//     value === undefined
//       ? ''
//       : value
//   )
//     .replace(/&/g, '&amp;')
//     .replace(/</g, '&lt;')
//     .replace(/>/g, '&gt;')
//     .replace(/"/g, '&quot;')
//     .replace(/'/g, '&#39;');
// }


// /*
// |--------------------------------------------------------------------------
// | Exports
// |--------------------------------------------------------------------------
// */

// module.exports = {
//   HUMAN_NAME_RE,
//   normalizeHumanName,
//   validateHumanName,
//   escapeHtml,
// };