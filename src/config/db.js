


// const mysql = require("mysql2/promise");
// require("dotenv").config();

// const pool = mysql.createPool({
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   port: process.env.DB_PORT,
//   waitForConnections: true,
//   connectionLimit: 10,
//   queueLimit: 0,
// });

// module.exports = pool;



const fs = require("fs");
const path = require("path");
const mysql = require("mysql2/promise");

// Check if running in AWS Lambda
const isLambda = !!process.env.AWS_LAMBDA_FUNCTION_NAME;

const poolConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

/*
 * TLS / SSL — HIPAA Transmission Security (§164.312(e)).
 *
 * The CA certificate is resolved from, in order:
 *   1. DB_SSL_CA       — full CA cert PEM provided inline (e.g. Secrets Manager)
 *   2. DB_SSL_CA_PATH  — path to a CA bundle file
 *   3. ./rds-global-bundle.pem — bundled alongside this file (Amazon RDS CA)
 *
 * For Amazon RDS, download the bundle and ship it next to this file:
 *   https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
 *
 * rejectUnauthorized is ALWAYS true: an encrypted-but-unauthenticated channel
 * offers no protection against an in-path (MITM) attacker.
 */
function resolveDbCa() {
  if (process.env.DB_SSL_CA) {
    return process.env.DB_SSL_CA;
  }

  const caPath =
    process.env.DB_SSL_CA_PATH || path.join(__dirname, "rds-global-bundle.pem");

  if (fs.existsSync(caPath)) {
    return fs.readFileSync(caPath, "utf8");
  }

  return undefined;
}

if (isLambda) {
  const ca = resolveDbCa();

  if (!ca) {
    console.warn(
      "DB_TLS_CA_MISSING: no CA bundle found. Provide DB_SSL_CA / DB_SSL_CA_PATH " +
        "or bundle rds-global-bundle.pem. Verifying against system trust store only."
    );
  }

  poolConfig.ssl = {
    // Authenticate the server certificate — do NOT accept arbitrary certs.
    rejectUnauthorized: true,
    minVersion: "TLSv1.2",
    ...(ca ? { ca } : {}),
  };

  // Add connection timeout for Lambda
  poolConfig.connectTimeout = 10000;
  poolConfig.acquireTimeout = 10000;
}

console.log('Database config:', {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  isLambda: isLambda
});

const pool = mysql.createPool(poolConfig);

// Test connection on startup
pool.getConnection()
  .then(connection => {
    console.log('Database connected successfully');
    connection.release();
  })
  .catch(err => {
    console.error('Database connection failed:', err.message);
  });

module.exports = pool;