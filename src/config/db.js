


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

// Add SSL configuration for AWS if needed
if (isLambda) {
  poolConfig.ssl = {
    rejectUnauthorized: false
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