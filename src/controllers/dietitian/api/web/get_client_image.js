const pool = require("../../../../config/db");
const { requireDieticianSelfAccess } = require("../../../../utils/accessControl");

const MAX_IMAGE_BYTES = 5 * 1024 * 1024; // 5 MB

const detectImageType = (buf) => {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) return "image/png";
  if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "image/jpeg";
  if (buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46) return "image/webp";
  return null;
};

exports.get_client_image = async (req, res) => {
  try {
    const access = requireDieticianSelfAccess(req, req.query.dietician_id);
    if (!access.allowed) {
      return res.status(access.statusCode).json({
        status: false, ok: false, message: access.message,
      });
    }

    const [rows] = await pool.execute(
      "SELECT logo FROM table_dietician WHERE UPPER(TRIM(dietician_id)) = ? LIMIT 1",
      [access.dieticianId]
    );

    if (!rows.length || !rows[0].logo) {
      return res.status(404).json({ status: false, ok: false, message: "Logo not found" });
    }

    const imageData = rows[0].logo;

    if (imageData.length > MAX_IMAGE_BYTES) {
      return res.status(500).json({ status: false, ok: false, message: "Image too large" });
    }

    const contentType = detectImageType(imageData);
    if (!contentType) {
      return res.status(500).json({ status: false, ok: false, message: "Invalid image data" });
    }

    res.setHeader("Content-Type", contentType);
    res.setHeader("Content-Length", imageData.length);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Content-Security-Policy", "default-src 'none'");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cache-Control", "private, max-age=3600, no-transform");

    return res.send(imageData);
  } catch (error) {
    console.error("get_client_image error:", { message: error.message, dietician_id: req.query?.dietician_id });
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};




// const pool = require("../../../../config/db");

// exports.get_client_image = async (req, res) => {
//   try {
//     const dietician_id = req.query.dietician_id;
//     const profile_id = req.query.profile_id;

//     // Validate both parameters
//     if (!dietician_id || !profile_id) {
//       return res.status(400).send("❌ Missing dietician_id or profile_id");
//     }

//     // Fetch image from DB using both dietician_id and profile_id
//     const [rows] = await pool.execute(
//       "SELECT logo FROM table_dietician WHERE dietician_id = ? AND profile_id = ?",
//       [dietician_id, profile_id]
//     );

//     if (rows.length === 0) {
//       return res.status(404).send("❌ Dietician not found.");
//     }

//     const imageData = rows[0].logo;

//     if (!imageData) {
//       return res.status(500).send("❌ Image data is empty or corrupt.");
//     }

//     // Send image response
//     res.setHeader("Content-Type", "image/png");
//     res.setHeader("Content-Length", imageData.length);

//     return res.send(imageData);

//   } catch (error) {
//     console.error(error);
//     return res.status(500).send("❌ Internal Server Error");
//   }
// };
