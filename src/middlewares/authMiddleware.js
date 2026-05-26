const jwt = require("jsonwebtoken");

const JWT_ALGORITHM = process.env.JWT_ALGORITHM || "HS256";
const JWT_ISS = process.env.JWT_ISS || "api.respyr.ai";
const JWT_AUD = process.env.JWT_AUD || "respyr-dietitian-app";

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
      issuer: JWT_ISS,
      audience: JWT_AUD,
      clockTolerance: 5,
    });

    // Scope gate: tokens issued with scope="password_reset" can ONLY be used
    // on routes that opt in by setting `req.allowResetScope = true` upstream.
    // Tokens with scope="full" or no scope claim pass through.
    const scope = decoded && decoded.scope;
    if (scope === "password_reset" && !req.allowResetScope) {
      return res.status(403).json({
        status: false,
        ok: false,
        message: "Password reset required",
        must_reset_password: true,
      });
    }

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