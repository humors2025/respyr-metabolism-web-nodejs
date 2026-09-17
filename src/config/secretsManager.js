"use strict";

const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

const secretsManagerClient = new SecretsManagerClient({
  region: process.env.AWS_REGION || "us-west-2",
});

// ---------------------------------------------------------------------------
// Secret layout.
//
// Two secret shapes are accepted, so prod and UAT can each keep their own:
//
//   prod (respyr/prod/backend) - canonical env-var names:
//     { DB_HOST, DB_PORT, DB_NAME, DB_USER, DB_PASSWORD,
//       JWT_SECRET, JWT_REFRESH_SECRET, RESEND_API_KEY }
//
//   UAT - DB-only, short names:
//     { host, port, database, username, password }
//
// Each canonical DB key is resolved from the first non-blank alias below.
// The three non-DB keys are taken from the secret when present (prod) and
// otherwise MUST already exist as plain Lambda environment variables (UAT).
// Either way every key is present in process.env before ./src/index is
// required, which is what the module-load-time constants in the controllers
// depend on.
// ---------------------------------------------------------------------------

const DB_KEY_ALIASES = {
  DB_HOST: ["DB_HOST", "host"],
  DB_PORT: ["DB_PORT", "port"],
  DB_NAME: ["DB_NAME", "database", "dbname"],
  DB_USER: ["DB_USER", "username", "user"],
  DB_PASSWORD: ["DB_PASSWORD", "password"],
};

const SECRET_OR_ENV_KEYS = [
  "JWT_SECRET",
  "JWT_REFRESH_SECRET",
  "RESEND_API_KEY",
];

// Cache the initialization promise for warm Lambda invocations.
let hydrateSecretsPromise = null;

function isBlank(value) {
  return value === undefined || value === null || String(value).trim() === "";
}

async function fetchSecret() {
  const secretId = process.env.APP_SECRET_ID;

  if (!secretId) {
    throw new Error(
      "APP_SECRET_ID is missing from Lambda environment variables."
    );
  }

  const response = await secretsManagerClient.send(
    new GetSecretValueCommand({
      SecretId: secretId,
    })
  );

  if (!response.SecretString) {
    throw new Error(
      "SecretString was not returned by AWS Secrets Manager."
    );
  }

  try {
    return JSON.parse(response.SecretString);
  } catch (error) {
    throw new Error(
      "AWS Secrets Manager value is not valid JSON."
    );
  }
}

/**
 * Map the raw secret JSON onto canonical env-var names and verify that every
 * required value is available from either the secret or the environment.
 *
 * Returns only the values that came from the secret; env-provided values are
 * already in process.env and are left untouched.
 */
function resolveSecrets(secrets, env = process.env) {
  const resolved = {};
  const missing = [];

  for (const [canonical, aliases] of Object.entries(DB_KEY_ALIASES)) {
    const alias = aliases.find((name) => !isBlank(secrets[name]));

    if (!alias) {
      missing.push(`${canonical} (secret key: ${aliases.join(" or ")})`);
      continue;
    }

    resolved[canonical] = String(secrets[alias]);
  }

  for (const key of SECRET_OR_ENV_KEYS) {
    if (!isBlank(secrets[key])) {
      resolved[key] = String(secrets[key]);
    } else if (isBlank(env[key])) {
      missing.push(`${key} (secret key or Lambda env var)`);
    }
  }

  if (missing.length > 0) {
    throw new Error(
      `Missing required configuration: ${missing.join(", ")}`
    );
  }

  return resolved;
}

function applySecretsToEnvironment(resolved) {
  for (const [key, value] of Object.entries(resolved)) {
    process.env[key] = value;
  }
}

async function performHydration() {
  const secrets = await fetchSecret();

  const resolved = resolveSecrets(secrets);

  applySecretsToEnvironment(resolved);

  // Never log secret values or the complete process.env object.
  console.log(
    "✅ AWS Secrets Manager configuration loaded successfully"
  );
}

async function hydrateSecrets() {
  if (!hydrateSecretsPromise) {
    hydrateSecretsPromise = performHydration().catch((error) => {
      // Let the next invocation retry if initialization fails.
      hydrateSecretsPromise = null;
      throw error;
    });
  }

  return hydrateSecretsPromise;
}

module.exports = {
  hydrateSecrets,
  resolveSecrets,
};
