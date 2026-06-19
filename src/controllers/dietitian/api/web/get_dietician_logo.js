const pool = require("../../../../config/db");
const { requireDieticianSelfAccess } = require("../../../../utils/accessControl");

const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5 MB

// 1x1 transparent PNG fallback (avoids leaking "logo not configured")
const DEFAULT_LOGO = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64"
);

// Detect content-type from magic bytes only — never trust client/db-stored mime.
const detectImageType = (buf) => {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "image/png";
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
  if (buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46) return "image/webp";
  return null;
};

const setSecureImageHeaders = (res, contentType, length) => {
  res.setHeader("Content-Type", contentType);
  res.setHeader("Content-Length", length);
  res.setHeader("X-Content-Type-Options", "nosniff");
  // Lock everything down BUT allow the image itself to render. A bare
  // "default-src 'none'" also blocks the <img> in the synthetic document the
  // browser builds when the URL is opened directly, producing a broken-image
  // icon even though the bytes are a valid image. img-src 'self' fixes that
  // while still blocking scripts/objects/frames. nosniff keeps the declared
  // type authoritative, so this stays safe for user-uploaded content.
  res.setHeader("Content-Security-Policy", "default-src 'none'; img-src 'self'");
  // cross-origin so the dashboard (admin.respyr.ai, a different origin than
  // api.respyr.ai) can embed the logo in an <img> tag. With "same-origin" the
  // browser blocks the cross-origin embed and the logo shows broken.
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "private, max-age=3600, no-transform");
};

exports.get_dietician_logo = async (req, res) => {
  try {
    const access = requireDieticianSelfAccess(req, req.query.dietician_id);
    if (!access.allowed) {
      return res.status(access.statusCode).json({
        status: false,
        ok: false,
        message: access.message,
      });
    }

    const [rows] = await pool.execute(
      "SELECT logo FROM table_dietician WHERE UPPER(TRIM(dietician_id)) = ? LIMIT 1",
      [access.dieticianId]
    );

    if (!rows.length || !rows[0].logo) {
      setSecureImageHeaders(res, "image/png", DEFAULT_LOGO.length);
      return res.end(DEFAULT_LOGO);
    }

    const imageData = rows[0].logo;

    if (imageData.length > MAX_IMAGE_BYTES) {
      return res.status(500).json({
        status: false,
        ok: false,
        message: "Image too large",
      });
    }

    const contentType = detectImageType(imageData);
    if (!contentType) {
      return res.status(500).json({
        status: false,
        ok: false,
        message: "Invalid image data",
      });
    }

    setSecureImageHeaders(res, contentType, imageData.length);
    return res.end(imageData);
  } catch (error) {
    console.error("get_dietician_logo error:", {
      message: error.message,
      dietician_id: req.query?.dietician_id,
    });
    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
    });
  }
};










// const pool = require("../../../../config/db");
// const { requireDieticianSelfAccess } = require("../../../../utils/accessControl");

// const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5 MB

// // 1x1 transparent PNG fallback (avoids leaking "logo not configured")
// const DEFAULT_LOGO = Buffer.from(
//   "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
//   "base64"
// );

// // Detect content-type from magic bytes only — never trust client/db-stored mime.
// const detectImageType = (buf) => {
//   if (!buf || buf.length < 4) return null;
//   if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "image/png";
//   if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
//   if (buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46) return "image/webp";
//   return null;
// };

// const setSecureImageHeaders = (res, contentType, length) => {
//   res.setHeader("Content-Type", contentType);
//   res.setHeader("Content-Length", length);
//   res.setHeader("X-Content-Type-Options", "nosniff");
//   res.setHeader("Content-Security-Policy", "default-src 'none'");
//   res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
//   res.setHeader("Referrer-Policy", "no-referrer");
//   res.setHeader("Cache-Control", "private, max-age=3600, no-transform");
// };

// exports.get_dietician_logo = async (req, res) => {
//   try {
//     const access = requireDieticianSelfAccess(req, req.query.dietician_id);
//     if (!access.allowed) {
//       return res.status(access.statusCode).json({
//         status: false,
//         ok: false,
//         message: access.message,
//       });
//     }

//     const [rows] = await pool.execute(
//       "SELECT logo FROM table_dietician WHERE UPPER(TRIM(dietician_id)) = ? LIMIT 1",
//       [access.dieticianId]
//     );

//     if (!rows.length || !rows[0].logo) {
//       setSecureImageHeaders(res, "image/png", DEFAULT_LOGO.length);
//       return res.end(DEFAULT_LOGO);
//     }

//     const imageData = rows[0].logo;

//     if (imageData.length > MAX_IMAGE_BYTES) {
//       return res.status(500).json({
//         status: false,
//         ok: false,
//         message: "Image too large",
//       });
//     }

//     const contentType = detectImageType(imageData);
//     if (!contentType) {
//       return res.status(500).json({
//         status: false,
//         ok: false,
//         message: "Invalid image data",
//       });
//     }

//     setSecureImageHeaders(res, contentType, imageData.length);
//     return res.end(imageData);
//   } catch (error) {
//     console.error("get_dietician_logo error:", {
//       message: error.message,
//       dietician_id: req.query?.dietician_id,
//     });
//     return res.status(500).json({
//       status: false,
//       ok: false,
//       message: "Internal server error",
//     });
//   }
// };
