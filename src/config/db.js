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
  // Strict TLS: verify the RDS server certificate against Amazon's RDS CA
  // bundle and validate the hostname. Requires DB_HOST to be the RDS DNS
  // endpoint (xxx.rds.amazonaws.com), NOT a raw IP — certificate hostname
  // validation fails against IPs.
  //
  // rds-global-bundle.pem is the public AWS RDS trust store, downloaded from
  // https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem
  // It is a public certificate bundle, safe to commit.
  poolConfig.ssl = {
    rejectUnauthorized: true,
    ca: fs.readFileSync(
      path.join(__dirname, "rds-global-bundle.pem"),
      "utf8"
    ),
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