const jwt = require("jsonwebtoken");

const JWT_ALGORITHM = process.env.JWT_ALGORITHM || "HS256";

const getCookieValue = (req, cookieName) => {
  const cookieHeader = req.headers?.cookie;
  if (!cookieHeader || typeof cookieHeader !== "string") return null;

  const cookies = cookieHeader.split(";").map((item) => item.trim());

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");
    if (index === -1) continue;

    const name = cookie.substring(0, index);
    const value = cookie.substring(index + 1);

    if (name === cookieName) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
};

const extractToken = (req) => {
  const authHeader = req.headers.authorization;

  // Normal API calls: Authorization: Bearer <access_token>
  if (authHeader && typeof authHeader === "string") {
    const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch?.[1]) {
      return bearerMatch[1].trim();
    }
  }

  // Image request like <img src=""> cannot send Authorization header.
  // So token is taken from cookie.
  return getCookieValue(req, "access_token");
};

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

    const token = extractToken(req);

    if (!token || typeof token !== "string" || token.length > 4096) {
      return res.status(401).json({
        status: false,
        ok: false,
        message: "Authorization token required",
      });
    }

    const decoded = jwt.verify(token, jwtSecret, {
      algorithms: [JWT_ALGORITHM],
      clockTolerance: 5,
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

// const JWT_ALGORITHM = process.env.JWT_ALGORITHM || "HS256";

// // Must match the values the token signers use (loginController / refreshTokenController).
// const JWT_ISS = process.env.JWT_ISS || process.env.JWT_ISSUER || "api.respyr.ai";
// const JWT_AUD =
//   process.env.JWT_AUD || process.env.JWT_AUDIENCE || "respyr-dietitian-app";

// module.exports = (req, res, next) => {
//   if (req.method === "OPTIONS") {
//     return next();
//   }

//   try {
//     const jwtSecret = process.env.JWT_SECRET;

//     if (!jwtSecret) {
//       console.error("JWT_SECRET_MISSING");

//       return res.status(500).json({
//         status: false,
//         ok: false,
//         message: "Server configuration error",
//       });
//     }

//     const authHeader = req.headers.authorization;

//     if (!authHeader || typeof authHeader !== "string") {
//       return res.status(401).json({
//         status: false,
//         ok: false,
//         message: "Authorization token required",
//       });
//     }

//     const bearerMatch = authHeader.match(/^Bearer\s+(.+)$/i);

//     if (!bearerMatch || !bearerMatch[1]) {
//       return res.status(401).json({
//         status: false,
//         ok: false,
//         message: "Invalid authorization format",
//       });
//     }

//     const token = bearerMatch[1].trim();

//     if (!token || token.length > 4096) {
//       return res.status(401).json({
//         status: false,
//         ok: false,
//         message: "Invalid authorization token",
//       });
//     }

//     const decoded = jwt.verify(token, jwtSecret, {
//       algorithms: [JWT_ALGORITHM],
//       clockTolerance: 5,
//       issuer: JWT_ISS,
//       audience: JWT_AUD,
//     });

//     req.user = decoded;

//     return next();
//   } catch (error) {
//     return res.status(401).json({
//       status: false,
//       ok: false,
//       message: "Invalid or expired token",
//     });
//   }
// };





