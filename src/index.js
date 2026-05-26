const express = require("express");
require("dotenv").config();

// Fail fast in production if security-critical env vars are missing/weak.
require("./config/validateEnv")();

const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const apiRoutes = require("./routes/apiRoutes");

const app = express();

const isLambda = Boolean(process.env.AWS_LAMBDA_FUNCTION_NAME);
const isProduction = process.env.NODE_ENV === "production" || isLambda;

console.log("✅ Respyr Dietitian API initialized");

// =====================================================
// Security basics
// =====================================================

// Hide Express fingerprint
app.disable("x-powered-by");

// Required when behind API Gateway / proxy
app.set("trust proxy", 1);

// Security headers
app.use(
  helmet({
    crossOriginResourcePolicy: false,
    contentSecurityPolicy: false, // API-only backend, safer to avoid frontend/API breakage
  })
);

// Prevent caching health/client/test data
app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  next();
});

// =====================================================
// Local CORS only
// In AWS, prefer API Gateway CORS configuration
// =====================================================
app.use((req, res, next) => {
  const isLocal = !isLambda;

  if (isLocal) {
    const allowedOrigins = [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:5173",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:3001",
    ];

    const origin = req.headers.origin;

    if (allowedOrigins.includes(origin)) {
      res.header("Access-Control-Allow-Origin", origin);
      res.header("Access-Control-Allow-Credentials", "true");
    }

    res.header(
      "Access-Control-Allow-Headers",
      "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-api-key"
    );

    res.header(
      "Access-Control-Allow-Methods",
      "GET, POST, PUT, DELETE, OPTIONS, PATCH"
    );

    res.header("Access-Control-Max-Age", "86400");
    res.header("Access-Control-Expose-Headers", "Content-Length");
  }

  if (req.method === "OPTIONS" && isLocal) {
    return res.status(204).end();
  }

  return next();
});

// =====================================================
// Body parsers with strict size limits
// =====================================================
app.use(
  express.json({
    limit: "1mb",
    strict: true,
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb",
    parameterLimit: 100,
  })
);

// =====================================================
// General API rate limiter
// Login-specific limiter can still remain inside apiRoutes.js
// =====================================================
const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: false,
    message: "Too many requests. Please try again later.",
  },
  skip: (req) => {
    return req.path === "/health" || req.path === "/";
  },
});

app.use(apiRateLimiter);

// =====================================================
// Safe request logging
// Never log Authorization token, request body, health data, or PHI
// =====================================================
app.use((req, res, next) => {
  if (!isProduction) {
    console.log("=== REQUEST DEBUG ===");
    console.log("Method:", req.method);
    console.log("Original URL:", req.originalUrl);
    console.log("Path:", req.path);
    console.log("Origin:", req.headers.origin || "N/A");
    console.log("User-Agent:", req.headers["user-agent"] || "N/A");
    console.log("=====================");
  }

  next();
});

// =====================================================
// API Gateway stage path fix
// Example:
// /v1/dietitian/api/web/... -> /dietitian/api/web/...
// =====================================================
app.use((req, res, next) => {
  if (isLambda && (req.url === "/v1" || req.url.startsWith("/v1/"))) {
    req.url = req.url.replace(/^\/v1/, "") || "/";
  }

  next();
});

// =====================================================
// Health check routes
// =====================================================
app.get("/", (req, res) => {
  return res.status(200).json({
    status: true,
    message: "Metabolic Node.js API is live",
    service: "dietitian-api",
    environment: isLambda ? "AWS Lambda" : "Local Development",
    timestamp: new Date().toISOString(),
  });
});

app.get("/health", (req, res) => {
  return res.status(200).json({
    status: true,
    message: "OK",
    service: "dietitian-api",
    environment: isLambda ? "AWS" : "Local",
    timestamp: new Date().toISOString(),
  });
});

// =====================================================
// API Routes
// =====================================================
app.use("/", apiRoutes);

// =====================================================
// 404 handler
// Do not expose unnecessary internal info
// =====================================================
app.use((req, res) => {
  console.warn("Route not found:", {
    method: req.method,
    path: req.originalUrl,
  });

  return res.status(404).json({
    status: false,
    message: "Route not found",
  });
});

// =====================================================
// Global error handler
// Do not expose err.message in production/Lambda
// =====================================================
app.use((err, req, res, next) => {
  console.error("Server Error:", {
    method: req.method,
    path: req.originalUrl,
    message: err.message,
    stack: isProduction ? undefined : err.stack,
  });

  return res.status(err.statusCode || 500).json({
    status: false,
    message: isProduction ? "Internal server error" : err.message,
  });
});

// =====================================================
// Local server only
// =====================================================
if (!isLambda) {
  const PORT = process.env.PORT || 3000;

  app.listen(PORT, () => {
    console.log(`✅ Server running locally on port ${PORT}`);
    console.log(`✅ Health check: http://localhost:${PORT}/health`);
  });
}

module.exports = app;









// const express = require("express");
// require("dotenv").config();

// const apiRoutes = require("./routes/apiRoutes");

// const app = express();

// console.log("🔥 Lambda function gets HIT done ");

// // =====================================================
// // ✅ CONDITIONAL CORS MIDDLEWARE (Works for both local and AWS)
// // =====================================================
// app.use((req, res, next) => {
//   // Check if running locally (not in AWS Lambda)
//   const isLocal = !process.env.AWS_LAMBDA_FUNCTION_NAME;
  
//   if (isLocal) {
//     // Local development - handle CORS manually
    
//     // Allow specific origins for local development
//     const allowedOrigins = [
//       'http://localhost:3000',
//       'http://localhost:3001',
//       'http://localhost:5173', // Vite dev server
//       'http://127.0.0.1:3000',
//       'http://127.0.0.1:3001'
//     ];
    
//     const origin = req.headers.origin;
    
//     // Set Access-Control-Allow-Origin if origin is in allowed list
//     if (allowedOrigins.includes(origin)) {
//       res.header("Access-Control-Allow-Origin", origin);
//       res.header("Access-Control-Allow-Credentials", "true");
//     }
    
//     // Set other CORS headers
//     res.header(
//       "Access-Control-Allow-Headers",
//       "Origin, X-Requested-With, Content-Type, Accept, Authorization, x-api-key"
//     );
//     res.header(
//       "Access-Control-Allow-Methods",
//       "GET, POST, PUT, DELETE, OPTIONS, PATCH"
//     );
//     res.header("Access-Control-Max-Age", "86400"); // 24 hours
    
//     // Expose headers if needed
//     res.header("Access-Control-Expose-Headers", "Content-Length, X-JSON");
//   }
  
//   // Handle preflight OPTIONS request (only needed locally)
//   // In AWS, API Gateway handles OPTIONS requests
//   if (req.method === "OPTIONS" && isLocal) {
//     return res.status(200).end();
//   }
  
//   next();
// });

// // =====================================================
// // Body parsers
// // =====================================================
// app.use(express.json());
// app.use(express.urlencoded({ extended: true }));

// // =====================================================
// // Debug middleware (only locally for cleaner logs in AWS)
// // =====================================================
// if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
//   app.use((req, res, next) => {
//     console.log("=== REQUEST DEBUG ===");
//     console.log("Method:", req.method);
//     console.log("Original URL:", req.originalUrl);
//     console.log("Path:", req.path);
//     console.log("Headers:", JSON.stringify(req.headers, null, 2));
//     console.log("=====================");
//     next();
//   });
// }

// // =====================================================
// // API Gateway stage path fix
// // Only needed in AWS Lambda when using API Gateway stages
// // =====================================================
// app.use((req, res, next) => {
//   // Check if we're in AWS Lambda environment
//   if (process.env.AWS_LAMBDA_FUNCTION_NAME && req.url.startsWith("/v1")) {
//     req.url = req.url.replace("/v1", "");
//     console.log("🔄 Stage path removed:", req.url);
//   }
//   next();
// });

// // =====================================================
// // Health check routes
// // =====================================================
// app.get("/", (req, res) => {
//   res.status(200).json({
//     message: "Metabolic Node.js API is live!",
//     environment: process.env.AWS_LAMBDA_FUNCTION_NAME
//       ? "AWS Lambda"
//       : "Local Development",
//     stage: process.env.AWS_LAMBDA_FUNCTION_NAME ? "v1" : "local",
//     cors: process.env.AWS_LAMBDA_FUNCTION_NAME 
//       ? "Handled by API Gateway" 
//       : "Handled by Express middleware",
//     timestamp: new Date().toISOString(),
//   });
// });

// app.get("/health", (req, res) => {
//   res.status(200).json({
//     status: "OK",
//     service: "dietitian-api",
//     environment: process.env.AWS_LAMBDA_FUNCTION_NAME ? "AWS" : "Local",
//     timestamp: new Date().toISOString(),
//   });
// });

// // CORS test endpoint (useful for debugging)
// app.options("/cors-test", (req, res) => {
//   res.status(200).end();
// });

// app.get("/cors-test", (req, res) => {
//   res.status(200).json({
//     message: "CORS test successful",
//     corsConfigured: !process.env.AWS_LAMBDA_FUNCTION_NAME,
//     origin: req.headers.origin,
//     timestamp: new Date().toISOString(),
//   });
// });

// // =====================================================
// // API Routes
// // =====================================================
// app.use("/", apiRoutes);

// // =====================================================
// // 404 handler
// // =====================================================
// app.use((req, res) => {
//   console.log(`❌ Route not found: ${req.method} ${req.originalUrl}`);
//   res.status(404).json({
//     error: "Route not found",
//     path: req.originalUrl,
//     method: req.method,
//     environment: process.env.AWS_LAMBDA_FUNCTION_NAME ? "AWS" : "Local",
//   });
// });

// // =====================================================
// // Global error handler
// // =====================================================
// app.use((err, req, res, next) => {
//   console.error("❌ Server Error:", err);
//   res.status(500).json({
//     error: "Internal Server Error",
//     message: err.message,
//     environment: process.env.AWS_LAMBDA_FUNCTION_NAME ? "AWS" : "Local",
//     timestamp: new Date().toISOString(),
//   });
// });

// // =====================================================
// // Local server (ONLY for local testing)
// // =====================================================
// if (!process.env.AWS_LAMBDA_FUNCTION_NAME) {
//   const PORT = process.env.PORT || 3000;
//   app.listen(PORT, () => {
//     console.log(`✅ Server running locally on port ${PORT}`);
//     console.log(`✅ CORS enabled for local development`);
//     console.log(`✅ Health check: http://localhost:${PORT}/health`);
//     console.log(`✅ CORS test: http://localhost:${PORT}/cors-test`);
//   });
// }

// module.exports = app;
