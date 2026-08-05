/**
 * src/config/secrets.js
 *
 * Loads application secrets from AWS Secrets Manager and hydrates
 * process.env BEFORE the Express app is required.
 *
 * WHY hydration instead of an async getSecrets() everywhere:
 * 50+ controllers and both auth middlewares capture secrets into
 * module-load-time constants, e.g.:
 *     const JWT_SECRET = process.env.JWT_SECRET;
 * Rewriting all of them is high-risk. Instead, lambda.js awaits
 * hydrateSecrets() ONCE per container cold start, before require("./src/index"),
 * so every existing process.env read works unchanged.
 *
 * Secret: respyr/prod/backend (us-west-2), JSON with keys:
 *   DB_HOST, DB_USER, DB_PASSWORD, JWT_SECRET, JWT_REFRESH_SECRET,
 *   RESEND_API_KEY, SERVICE_API_KEYS (nested object)
 *
 * NOTE on SERVICE_API_KEYS: stored as a nested JSON object in the secret,
 * but serviceAuthMiddleware does JSON.parse(process.env.SERVICE_API_KEYS),
 * so we re-stringify it during hydration.
 *
 * Rotation note: because values are captured at cold start, rotating the
 * secret requires cycling Lambda containers (any redeploy, or bumping any
 * env var / publishing a new version forces new containers).
 *
 * Local development: if the secret can't be fetched (no AWS creds / no VPC
 * endpoint) and we are NOT in Lambda, we fall back to whatever .env provided
 * and log a warning instead of crashing.
 */

const {
  SecretsManagerClient,
  GetSecretValueCommand,
} = require("@aws-sdk/client-secrets-manager");

const SECRET_ID = process.env.BACKEND_SECRET_ID || "respyr/prod/backend";
const REGION = process.env.AWS_REGION || "us-west-2";

const isLambda = Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);

// Keys copied 1:1 from the secret into process.env (strings expected).
const STRING_KEYS = [
  "DB_HOST",
  "DB_USER",
  "DB_PASSWORD",
  "JWT_SECRET",
  "JWT_REFRESH_SECRET",
  "RESEND_API_KEY",
];

let hydrated = false;
let inFlight = null;

async function fetchAndApply() {
  const client = new SecretsManagerClient({ region: REGION });

  const response = await client.send(
    new GetSecretValueCommand({ SecretId: SECRET_ID })
  );

  const secrets = JSON.parse(response.SecretString);

  for (const key of STRING_KEYS) {
    if (secrets[key] !== undefined && secrets[key] !== null) {
      process.env[key] = String(secrets[key]);
    }
  }

  // SERVICE_API_KEYS lives as a nested object in the secret; existing
  // middleware expects a JSON *string* in process.env.
  if (secrets.SERVICE_API_KEYS !== undefined && secrets.SERVICE_API_KEYS !== null) {
    process.env.SERVICE_API_KEYS =
      typeof secrets.SERVICE_API_KEYS === "string"
        ? secrets.SERVICE_API_KEYS
        : JSON.stringify(secrets.SERVICE_API_KEYS);
  }

  hydrated = true;
  // Safe log: names only, never values.
  console.log("Secrets hydrated from Secrets Manager:", {
    secretId: SECRET_ID,
    keys: Object.keys(secrets),
  });
}

/**
 * Await this ONCE before requiring the Express app.
 * Concurrent callers share the same in-flight promise.
 */
async function hydrateSecrets() {
  if (hydrated) return;

  if (!inFlight) {
    inFlight = fetchAndApply()
      .catch((err) => {
        inFlight = null; // allow retry on next invocation

        if (!isLambda) {
          // Local dev: fall back to .env values, don't crash.
          console.warn(
            "Secrets Manager unavailable locally (" +
              err.name +
              "); falling back to .env values."
          );
          hydrated = true;
          return;
        }

        // In Lambda this is fatal: without secrets the app cannot serve
        // authenticated traffic. Log the class of failure (never values)
        // and rethrow so the invocation errors visibly in CloudWatch.
        console.error("SECRETS_HYDRATION_FAILED:", {
          secretId: SECRET_ID,
          errorName: err.name,
          // AccessDeniedException  -> IAM policy (GetSecretValue or kms:Decrypt)
          // TimeoutError/ENETUNREACH -> VPC endpoint missing/misconfigured
          // ResourceNotFoundException -> wrong SECRET_ID or region
          message: err.message,
        });
        throw err;
      })
      .finally(() => {
        inFlight = null;
      });
  }

  return inFlight;
}

module.exports = { hydrateSecrets };