const jwt = require("jsonwebtoken");

const JWT_ALGORITHM = process.env.JWT_ALGORITHM || "HS256";

// Must match the values the token signers use (loginController / refreshTokenController).
const JWT_ISS = process.env.JWT_ISS || process.env.JWT_ISSUER || "api.respyr.ai";
const JWT_AUD =
  process.env.JWT_AUD || process.env.JWT_AUDIENCE || "respyr-dietitian-app";

module.exports = (req, res, next) => {
  if (req.method === "OPTIONS") {
    return next();
  }

  try {
    const jwtSecret = process.env.JWT_SECRET;

    if (!jwtSecret) {
      console.error("JWT_SECRET_MISSING");

      return res.status(500).json({
        status: false,
        ok: false,
        message: "Server configuration error",
      });
    }

    const authHeader = req.headers.authorization;

    if (!authHeader || typeof authHeader !== "string") {
      return res.status(401).json({
        status: false,
        ok: false,
        message: "Authorization token required",
      });
    }

    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);

    if (!bearerMatch || !bearerMatch[1]) {
      return res.status(401).json({
        status: false,
        ok: false,
        message: "Invalid authorization format",
      });
    }

    const token = bearerMatch[1].trim();

    if (!token || token.length > 4096) {
      return res.status(401).json({
        status: false,
        ok: false,
        message: "Invalid authorization token",
      });
    }

    const decoded = jwt.verify(token, jwtSecret, {
      algorithms: [JWT_ALGORITHM],
      clockTolerance: 5,
      issuer: JWT_ISS,
      audience: JWT_AUD,
    });

    req.user = decoded;

    return next();
  } catch (error) {
    return res.status(401).json({
      status: false,
      ok: false,
      message: "Invalid or expired token",
    });
  }
};











// const jwt = require("jsonwebtoken");

// module.exports = (req, res, next) => {
//   // Skip auth for OPTIONS requests
//   // Locally: Handled by Express CORS middleware
//   // In AWS: Handled by API Gateway
//   if (req.method === "OPTIONS") {
//     return next();
//   }

//   const authHeader = req.headers.authorization;

//   if (!authHeader) {
//     return res.status(401).json({
//       ok: false,
//       message: "Authorization token required",
//     });
//   }

//   const token = authHeader.split(" ")[1];

//   try {
//     const decoded = jwt.verify(token, process.env.JWT_SECRET);
//     req.user = decoded;
//     next();
//   } catch (error) {
//     return res.status(401).json({
//       ok: false,
//       message: "Invalid or expired token",
//     });
//   }
// };