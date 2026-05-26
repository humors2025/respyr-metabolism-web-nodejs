// config/validateEnv.js
//
// Boot-time check for security-critical env vars. Called once from src/index.js.
// In production: hard-fails the process if a required secret is missing or weak.
// In development: logs warnings but allows the app to start so onboarding is easy.

'use strict';

const MIN_SECRET_BYTES = 32; // 256-bit minimum for HMAC secrets

function isWeakSecret(value) {
  if (typeof value !== 'string') return true;
  const v = value.trim();
  if (v.length < MIN_SECRET_BYTES) return true;
  // Reject obvious placeholder values
  const weak = ['changeme', 'secret', 'password', 'default', 'jwt_secret'];
  if (weak.includes(v.toLowerCase())) return true;
  return false;
}

function validateEnv() {
  const isLambda = Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);
  const isProduction = process.env.NODE_ENV === 'production' || isLambda;

  const required = [
    { name: 'JWT_SECRET', checkStrength: true },
    { name: 'JWT_REFRESH_SECRET', checkStrength: true },
    { name: 'SECURITY_PEPPER', checkStrength: true },
    { name: 'DB_HOST', checkStrength: false },
    { name: 'DB_USER', checkStrength: false },
    { name: 'DB_NAME', checkStrength: false },
    { name: 'DB_PASSWORD', checkStrength: false },
  ];

  const problems = [];

  for (const { name, checkStrength } of required) {
    const val = process.env[name];

    if (!val || (typeof val === 'string' && val.trim() === '')) {
      problems.push(`${name} is not set`);
      continue;
    }

    if (checkStrength && isWeakSecret(val)) {
      problems.push(
        `${name} is too weak (need at least ${MIN_SECRET_BYTES} chars, non-default)`
      );
    }
  }

  if (problems.length === 0) {
    console.log('Env validation passed');
    return;
  }

  const header = `Environment validation found ${problems.length} issue(s):`;
  const body = problems.map((p) => `  - ${p}`).join('\n');

  if (isProduction) {
    console.error(`FATAL: ${header}\n${body}`);
    console.error('Refusing to start in production with insecure configuration.');
    process.exit(1);
  } else {
    console.warn(`WARNING: ${header}\n${body}`);
    console.warn('In production this would refuse to start.');
  }
}

module.exports = validateEnv;
