const mysql = require("mysql2/promise");
const fs = require("fs");
const path = require("path");

// Check if running in AWS Lambda
const isLambda = !!process.env.AWS_LAMBDA_FUNCTION_NAME;

// NOTE: DB_HOST / DB_USER / DB_PASSWORD are hydrated into process.env from
// AWS Secrets Manager (respyr/prod/backend) by lambda.js BEFORE this module
// is required. DB_NAME / DB_PORT remain plain Lambda env vars (config, not
// secrets). Locally, all values come from .env as before.

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

if (isLambda) {
  // ---------------------------------------------------------------------------
  // Transport security to MySQL, selected per environment with DB_SSL_MODE:
  //
  //   pinned    (default) TLS with full certificate CHAIN validation against a
  //             CA file shipped in src/config. This is PRODUCTION. Only
  //             certificates signed by the pinned CA are accepted, so a MITM
  //             presenting any other certificate is rejected. Hostname matching
  //             is skipped (checkServerIdentity) because MySQL auto-generated
  //             certs carry a generic CN, not our IP; chain validation is
  //             unaffected. The CA file is chosen with DB_CA_PATH (a file name
  //             inside src/config, default mysql-ca.pem). If the DB server
  //             certificates are ever regenerated, replace that file and
  //             redeploy or connections fail closed with HANDSHAKE_SSL_ERROR.
  //
  //   encrypted TLS on the wire but the server certificate is NOT verified.
  //             Needs no CA file. Acceptable ONLY for non-production databases
  //             that share a private subnet with the Lambda (e.g. UAT), where
  //             a network-level MITM is not a realistic threat. Never for prod.
  //
  //   disabled  Plain TCP, no TLS. Same restriction as "encrypted"; the MySQL
  //             user must not carry REQUIRE SSL.
  //
  // Any other value fails closed at startup rather than silently downgrading.
  // ---------------------------------------------------------------------------
  const sslMode = String(process.env.DB_SSL_MODE || "pinned")
    .trim()
    .toLowerCase();

  if (sslMode === "pinned") {
    const caFileName = process.env.DB_CA_PATH || "mysql-ca.pem";
    const caPath = path.resolve(__dirname, caFileName);

    if (!caPath.startsWith(path.resolve(__dirname) + path.sep)) {
      throw new Error("DB_CA_PATH must be a file inside src/config");
    }

    if (!fs.existsSync(caPath)) {
      throw new Error(
        `DB CA file not found: ${caFileName} (set DB_CA_PATH to a file inside src/config)`
      );
    }

    poolConfig.ssl = {
      rejectUnauthorized: true,
      ca: fs.readFileSync(caPath, "utf8"),
      checkServerIdentity: () => undefined,
    };
  } else if (sslMode === "encrypted") {
    poolConfig.ssl = {
      rejectUnauthorized: false,
    };
  } else if (sslMode === "disabled") {
    // No poolConfig.ssl: mysql2 connects without TLS.
  } else {
    throw new Error(
      `Invalid DB_SSL_MODE "${process.env.DB_SSL_MODE}". Expected pinned, encrypted or disabled.`
    );
  }

  // Safe to log: the mode is configuration, not a secret.
  console.log("Database TLS mode:", sslMode);

  // Add connection timeout for Lambda
  poolConfig.connectTimeout = 10000;
}

// Safe log: never log the password.
console.log("Database config:", {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  database: process.env.DB_NAME,
  isLambda: isLambda,
});

const pool = mysql.createPool(poolConfig);

// Test connection on startup
pool.getConnection()
  .then((connection) => {
    console.log("Database connected successfully");
    connection.release();
  })
  .catch((err) => {
    console.error("Database connection failed:", err.message);
  });

module.exports = pool;





// const mysql = require("mysql2/promise");

// // Check if running in AWS Lambda
// const isLambda = !!process.env.AWS_LAMBDA_FUNCTION_NAME;

// const poolConfig = {
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   password: process.env.DB_PASSWORD,
//   database: process.env.DB_NAME,
//   port: process.env.DB_PORT || 3306,
//   waitForConnections: true,
//   connectionLimit: 10,
//   queueLimit: 0,
// };

// // Add SSL configuration for AWS if needed
// if (isLambda) {
//   poolConfig.ssl = {
//     rejectUnauthorized: false
//   };
  
//   // Add connection timeout for Lambda
//   poolConfig.connectTimeout = 10000;
//   poolConfig.acquireTimeout = 10000;
// }

// console.log('Database config:', {
//   host: process.env.DB_HOST,
//   user: process.env.DB_USER,
//   database: process.env.DB_NAME,
//   isLambda: isLambda
// });

// const pool = mysql.createPool(poolConfig);

// // Test connection on startup
// pool.getConnection()
//   .then(connection => {
//     console.log('Database connected successfully');
//     connection.release();
//   })
//   .catch(err => {
//     console.error('Database connection failed:', err.message);
//   });

// module.exports = pool;