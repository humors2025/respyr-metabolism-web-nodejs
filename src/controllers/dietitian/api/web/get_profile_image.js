const pool = require("../../../../config/db");
const { requireProfileAccess } = require("../../../../utils/accessControl");
const {
  verifyProfileImageSignature,
} = require("../../../../utils/imageUrlSigner");

const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5 MB

// 1x1 transparent PNG used as fallback
const DEFAULT_IMAGE = Buffer.from(
  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
  "base64"
);

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
  // cross-origin so the dashboard (a different origin than api.respyr.ai) can
  // embed the image in an <img> tag. The signed sig/exp still gate access.
  res.setHeader("Cross-Origin-Resource-Policy", "cross-origin");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "private, max-age=3600, no-transform");
};

exports.get_profile_image = async (req, res) => {
  try {
    // Two ways to authorize this request, in order:
    //   1. Signed URL (sig + exp): minted by an already-authenticated dashboard
    //      endpoint so the link can load in an <img> tag with no auth header.
    //   2. Fallback: JWT/cookie access check (requireProfileAccess) for callers
    //      that still issue unsigned URLs.
    let profileId;
    let dieticianId;

    if (req.query.sig) {
      const signed = verifyProfileImageSignature(req.query);
      if (!signed.valid) {
        return res.status(403).json({
          status: false,
          ok: false,
          message: "Invalid or expired image link",
        });
      }
      profileId = signed.profileId;
      dieticianId = signed.dieticianId;
    } else {
      const access = await requireProfileAccess(
        req,
        req.query.dietician_id,
        req.query.profile_id
      );

      if (!access.allowed) {
        return res.status(access.statusCode).json({
          status: false,
          ok: false,
          message: access.message,
        });
      }
      profileId = access.profileId;
      dieticianId = access.dieticianId;
    }

    const [rows] = await pool.execute(
      `SELECT profile_image
         FROM table_clients
        WHERE profile_id = ?
          AND UPPER(TRIM(dietician_id)) = ?
        LIMIT 1`,
      [profileId, dieticianId]
    );

    if (!rows.length || !rows[0].profile_image) {
      // Serve default placeholder for missing image
      setSecureImageHeaders(res, "image/png", DEFAULT_IMAGE.length);
      return res.end(DEFAULT_IMAGE);
    }

    const imageData = rows[0].profile_image;

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
    console.error("get_profile_image error:", {
      message: error.message,
      dietician_id: req.query?.dietician_id,
      profile_id: req.query?.profile_id,
    });

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
    });
  }
};










// // controllers/dietitian/api/web/get_profile_image.js

// const pool = require('../../../../config/db');

// exports.get_profile_image = async (req, res) => {
//   try {
//     const { profile_id } = req.query;

//     if (!profile_id) {
//       return res.status(400).json({ error: "Profile ID is required" });
//     }

//     const [rows] = await pool.query(
//       "SELECT profile_image FROM table_clients WHERE profile_id = ?",
//       [profile_id]
//     );

//     if (rows.length && rows[0].profile_image) {
//       const imageBuffer = rows[0].profile_image;

//       // IMPORTANT: Send raw buffer
//       res.writeHead(200, {
//         "Content-Type": "image/png", // or image/jpeg
//         "Content-Length": imageBuffer.length,
//         "Cache-Control": "public, max-age=86400"
//       });

//       return res.end(imageBuffer);
//     }

//     // Default image (1x1 PNG)
//     const defaultImage = Buffer.from(
//       "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
//       "base64"
//     );

//     res.writeHead(200, {
//       "Content-Type": "image/png",
//       "Content-Length": defaultImage.length
//     });

//     return res.end(defaultImage);

//   } catch (err) {
//     console.error("Image API error:", err);

//     const fallback = Buffer.from(
//       "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
//       "base64"
//     );

//     res.writeHead(200, {
//       "Content-Type": "image/png",
//       "Content-Length": fallback.length
//     });

//     return res.end(fallback);
//   }
// };
