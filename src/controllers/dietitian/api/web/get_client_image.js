// const pool = require("../../../../config/db");

// exports.get_client_image = async (req, res) => {
//   try {
//     const dietician_id = req.query.dietician_id;

//     if (!dietician_id) {
//       return res.status(400).send("❌ Missing dietician_id");
//     }

//     const [rows] = await pool.execute(
//       "SELECT logo FROM table_dietician WHERE dietician_id = ?",
//       [dietician_id]
//     );

//     if (rows.length === 0) {
//       return res.status(404).send("❌ Dietician not found.");
//     }

//     const imageData = rows[0].logo;

//     if (!imageData) {
//       return res.status(500).send("❌ Image data is empty or corrupt.");
//     }

//     res.setHeader("Content-Type", "image/png");
//     res.setHeader("Content-Length", imageData.length);

//     return res.send(imageData);

//   } catch (error) {
//     console.error(error);
//     return res.status(500).send("❌ Internal Server Error");
//   }
// };




const pool = require("../../../../config/db");

exports.get_client_image = async (req, res) => {
  try {
    const dietician_id = req.query.dietician_id;
    const profile_id = req.query.profile_id;

    // Validate both parameters
    if (!dietician_id || !profile_id) {
      return res.status(400).send("❌ Missing dietician_id or profile_id");
    }

    // Fetch image from DB using both dietician_id and profile_id
    const [rows] = await pool.execute(
      "SELECT logo FROM table_dietician WHERE dietician_id = ? AND profile_id = ?",
      [dietician_id, profile_id]
    );

    if (rows.length === 0) {
      return res.status(404).send("❌ Dietician not found.");
    }

    const imageData = rows[0].logo;

    if (!imageData) {
      return res.status(500).send("❌ Image data is empty or corrupt.");
    }

    // Send image response
    res.setHeader("Content-Type", "image/png");
    res.setHeader("Content-Length", imageData.length);

    return res.send(imageData);

  } catch (error) {
    console.error(error);
    return res.status(500).send("❌ Internal Server Error");
  }
};
