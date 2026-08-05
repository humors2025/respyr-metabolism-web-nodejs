"use strict";

const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

const secretsManagerClient = new SecretsManagerClient({
  region: process.env.AWS_REGION || "us-west-2",
});

// Cache the initialization promise for warm Lambda invocations.
let hydrateSecretsPromise = null;

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

function validateSecrets(secrets) {
  const requiredKeys = [
    "DB_HOST",
    "DB_PORT",
    "DB_NAME",
    "DB_USER",
    "DB_PASSWORD",
    "JWT_SECRET",
    "JWT_REFRESH_SECRET",
    "RESEND_API_KEY",
  ];

  const missingKeys = requiredKeys.filter((key) => {
    const value = secrets[key];

    return (
      value === undefined ||
      value === null ||
      String(value).trim() === ""
    );
  });

  if (missingKeys.length > 0) {
    throw new Error(
      `Missing required Secrets Manager keys: ${missingKeys.join(", ")}`
    );
  }

  return requiredKeys;
}

function applySecretsToEnvironment(secrets, requiredKeys) {
  for (const key of requiredKeys) {
    process.env[key] = String(secrets[key]);
  }
}

async function performHydration() {
  const secrets = await fetchSecret();

  const requiredKeys = validateSecrets(secrets);

  applySecretsToEnvironment(secrets, requiredKeys);

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
};