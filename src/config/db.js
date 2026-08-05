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
  // TLS via certificate pinning (self-hosted MySQL on EC2).
  //
  // The DB is MySQL on an EC2 instance using MySQL's auto-generated
  // self-signed certificates, so the public RDS CA bundle cannot validate it.
  // Instead we PIN the server's own CA (src/config/mysql-ca.pem, copied from
  // /var/lib/mysql/ca.pem on the DB host):
  //
  //   - rejectUnauthorized: true  -> full certificate CHAIN validation is ON.
  //     Only certificates signed by our pinned CA are accepted. A MITM with
  //     any other certificate (including any other self-signed cert) is
  //     rejected. This replaces the previous rejectUnauthorized:false, which
  //     accepted ANY certificate.
  //
  //   - checkServerIdentity: () => undefined -> skips ONLY the hostname
  //     check. MySQL auto-generated certs carry a generic CN (not our IP),
  //     so hostname matching can never succeed. Chain validation above is
  //     unaffected. Returning undefined = identity accepted.
  //
  // If the DB server's certificates are ever regenerated (e.g. MySQL
  // reinstall), copy the new ca.pem into src/config/mysql-ca.pem and
  // redeploy, or connections will fail closed with HANDSHAKE_SSL_ERROR.
  // ---------------------------------------------------------------------------
  poolConfig.ssl = {
    rejectUnauthorized: true,
    ca: fs.readFileSync(path.join(__dirname, "mysql-ca.pem"), "utf8"),
    checkServerIdentity: () => undefined,
  };

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