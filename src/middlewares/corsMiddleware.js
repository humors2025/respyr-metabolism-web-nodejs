module.exports = function(req, res, next) {
    // Determine if we're running locally
    const isLocal = !process.env.AWS_LAMBDA_FUNCTION_NAME;
    
    if (isLocal) {
      // Local development - handle CORS
      const allowedOrigins = [
        'http://localhost:3000',
        'http://localhost:3001', 
        'http://localhost:5173' // Vite/React
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
      
      if (req.method === "OPTIONS") {
        return res.status(200).end();
      }
    }
    
    next();
  };