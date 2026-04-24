const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  // Skip auth for OPTIONS requests
  // Locally: Handled by Express CORS middleware
  // In AWS: Handled by API Gateway
  if (req.method === "OPTIONS") {
    return next();
  }

  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({
      ok: false,
      message: "Authorization token required",
    });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
      ok: false,
      message: "Invalid or expired token",
    });
  }
};