const express = require("express");
require("dotenv").config();

const apiRoutes = require("./routes/apiRoutes");

const app = express();

console.log("🔥 Lambda function HIT hua");

// =====================================================
// ✅ CONDITIONAL CORS MIDDLEWARE (Works for both local and AWS)
// =====================================================
app.use((req, res, next) => {
  // Check if running locally (not in AWS Lambda)
  const isLocal = !process.env.AWS_LAMBDA_FUNCTION_NAME;
  
  if (isLocal) {
    // Local development - handle CORS manually
    
    // Allow specific origins for local development
    const allowedOrigins = [
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173', // Vite dev server
      'http://127.0.0.1:3000',
      'http://127.0.0.1:3001'
    ];
    
    const origin = req.headers.origin;
    
    // Set Access-Control-Allow-Origin if origin is in allowed list
    if (allowedOrigins.includes(origin)) {
      res.header("Access-Control-Allow-Origin", origin);
      res.header("Access-Control-Allow-Credentials", "true");
    }
    
    // Set other CORS headers
    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-api-key"
    );
    res.header(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    );
    res.header("Access-Control-Max-Age", "86400"); // 24 hours
    
    // Expose headers if needed
    res.header("Access-Control-Expose-Headers", "Content-Length, X-JSON");
  }
  
  // Handle preflight OPTIONS request (only needed locally)
  // In AWS, API Gateway handles OPTIONS requests
  if (req.method === "OPTIONS" && isLocal) {
    return res.status(200).end();
  }
  
  next();
});

// =====================================================
// Body parsers
// =====================================================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =====================================================
// Debug middleware (only locally for cleaner logs in AWS)
// =====================================================
if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  app.use((req, res, next) => {
    console.log("=== REQUEST DEBUG ===");
    console.log("Method:", req.method);
    console.log("Original URL:", req.originalUrl);
    console.log("Path:", req.path);
    console.log("Headers:", JSON.stringify(req.headers, null, 2));
    console.log("=====================");
    next();
  });
}

// =====================================================
// API Gateway stage path fix
// Only needed in AWS Lambda when using API Gateway stages
// =====================================================
app.use((req, res, next) => {
  // Check if we're in AWS Lambda environment
  if (process.env.AWS_LAMBDA_FUNCTION_NAME && req.url.startsWith("/v1")) {
    req.url = req.url.replace("/v1", "");
    console.log("🔄 Stage path removed:", req.url);
  }
  next();
});

// =====================================================
// Health check routes
// =====================================================
app.get("/", (req, res) => {
  res.status(200).json({
    message: "Metabolic Node.js API is live!",
    environment: process.env.AWS_LAMBDA_FUNCTION_NAME
      ? "AWS Lambda"
      : "Local Development",
    stage: process.env.AWS_LAMBDA_FUNCTION_NAME ? "v1" : "local",
    cors: process.env.AWS_LAMBDA_FUNCTION_NAME 
      ? "Handled by API Gateway" 
      : "Handled by Express middleware",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "OK",
    service: "dietitian-api",
    environment: process.env.AWS_LAMBDA_FUNCTION_NAME ? "AWS" : "Local",
    timestamp: new Date().toISOString(),
  });
});

// CORS test endpoint (useful for debugging)
app.options("/cors-test", (req, res) => {
  res.status(200).end();
});

app.get("/cors-test", (req, res) => {
  res.status(200).json({
    message: "CORS test successful",
    corsConfigured: !process.env.AWS_LAMBDA_FUNCTION_NAME,
    origin: req.headers.origin,
    timestamp: new Date().toISOString(),
  });
});

// =====================================================
// API Routes
// =====================================================
app.use("/", apiRoutes);

// =====================================================
// 404 handler
// =====================================================
app.use((req, res) => {
  console.log(`❌ Route not found: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    error: "Route not found",
    path: req.originalUrl,
    method: req.method,
    environment: process.env.AWS_LAMBDA_FUNCTION_NAME ? "AWS" : "Local",
  });
});

// =====================================================
// Global error handler
// =====================================================
app.use((err, req, res, next) => {
  console.error("❌ Server Error:", err);
  res.status(500).json({
    error: "Internal Server Error",
    message: err.message,
    environment: process.env.AWS_LAMBDA_FUNCTION_NAME ? "AWS" : "Local",
    timestamp: new Date().toISOString(),
  });
});

// =====================================================
// Local server (ONLY for local testing)
// =====================================================
if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`✅ Server running locally on port ${PORT}`);
    console.log(`✅ CORS enabled for local development`);
    console.log(`✅ Health check: http://localhost:${PORT}/health`);
    console.log(`✅ CORS test: http://localhost:${PORT}/cors-test`);
  });
}

module.exports = app;






// const express = require('express');
// const cors = require('cors');
// require('dotenv').config();

// // Import your routes
// const apiRoutes = require('./routes/apiRoutes');

// const app = express();

// // --- Middleware ---
// app.use(cors());
// // Standard body parsers for JSON and URL-encoded data
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));

// app.get('/', (req, res) => {
//   res.status(200).json({
//     message: "Metabolic Node.js API is live!",
//     timestamp: new Date().toISOString()
//   });
// });

// app.get('/health', (req, res) => {
//   res.status(200).json({ status: 'OK' });
// });

// app.use('/', apiRoutes);

// app.use((req, res) => {
//   res.status(404).json({
//     error: "Route not found",
//     path: req.originalUrl
//   });
// });

// /* ✅ START SERVER ONLY FOR LOCAL */
// if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
//   const PORT = process.env.PORT || 3000;
//   app.listen(PORT, () => {
//     console.log(`✅ Server running on port ${PORT}`);
//   });
// }


// module.exports = app;






// const express = require('express');
// const cors = require('cors');
// require('dotenv').config(); // 👈 MUST be at the top

// // Import the database pool
// const db = require('./config/db'); 
// const apiRoutes = require('./routes/apiRoutes');

// const app = express();

// // Middleware
// app.use(cors());
// app.use(express.urlencoded({ extended: true }));
// app.use(express.json());

// app.use('/', apiRoutes);

// // Health check
// app.get('/health', (req, res) => {
//   res.json({ status: 'OK' });
// });

// // Start server
// const PORT = process.env.PORT || 3000;

// app.listen(PORT, async () => {
//   console.log(`Server is running on port ${PORT}`);

//   try {
//     const connection = await db.getConnection();
//     console.log('✅ Database connected successfully!');
//     connection.release();
//   } catch (err) {
//     console.error('❌ Database connection failed:', err.message);
//   }
// });
