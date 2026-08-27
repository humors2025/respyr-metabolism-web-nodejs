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
| HTML escaping
|--------------------------------------------------------------------------
|
| This should be used whenever plain-text data is inserted into an HTML
| template.
|
| Example:
|
| <h1>TEST</h1>
|
| becomes:
|
| &lt;h1&gt;TEST&lt;/h1&gt;
|
| so the browser/email client displays it as text instead of HTML.
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
  escapeHtml,
};