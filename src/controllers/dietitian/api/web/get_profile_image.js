// controllers/dietitian/api/web/get_profile_image.js

const pool = require('../../../../config/db');

exports.get_profile_image = async (req, res) => {
  try {
    const { profile_id } = req.query;

    if (!profile_id) {
      return res.status(400).json({ error: "Profile ID is required" });
    }

    const [rows] = await pool.query(
      "SELECT profile_image FROM table_clients WHERE profile_id = ?",
      [profile_id]
    );

    if (rows.length && rows[0].profile_image) {
      const imageBuffer = rows[0].profile_image;

      // IMPORTANT: Send raw buffer
      res.writeHead(200, {
        "Content-Type": "image/png", // or image/jpeg
        "Content-Length": imageBuffer.length,
        "Cache-Control": "public, max-age=86400"
      });

      return res.end(imageBuffer);
    }

    // Default image (1x1 PNG)
    const defaultImage = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
      "base64"
    );

    res.writeHead(200, {
      "Content-Type": "image/png",
      "Content-Length": defaultImage.length
    });

    return res.end(defaultImage);

  } catch (err) {
    console.error("Image API error:", err);

    const fallback = Buffer.from(
      "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==",
      "base64"
    );

    res.writeHead(200, {
      "Content-Type": "image/png",
      "Content-Length": fallback.length
    });

    return res.end(fallback);
  }
};
