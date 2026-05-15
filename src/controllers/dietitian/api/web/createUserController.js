// createUserController.js
const pool = require('../../../../config/db');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

exports.createUser = async (req, res) => {
  try {
    const { dietician_id, email, name, phone_no, location } = req.body;

    if (!dietician_id || !email || !req.file) {
      return res.status(400).json({
        ok: false,
        message: 'dietician_id, email and logo are required',
      });
    }

    const tempPassword = 'Temp@123';
    const hashedPassword = await bcrypt.hash(tempPassword, 10);

    // Generate refresh token
    const refreshToken = crypto.randomBytes(40).toString('hex');
    const hashedRefreshToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const logoBuffer = req.file.buffer;

    await pool.query(
      `INSERT INTO table_dietician
       (dietician_id, name, phone_no, email, location, logo, password, refresh_token_hash, is_reset_password)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      [
        dietician_id,
        name,
        phone_no,
        email,
        location,
        logoBuffer,
        hashedPassword,
        hashedRefreshToken,
      ]
    );

    return res.status(201).json({
      ok: true,
      message: 'User created successfully',
      refresh_token: refreshToken,
    });

  } catch (error) {
    console.error('Create User Error:', error);
    return res.status(500).json({
      ok: false,
      message: 'Server error',
    });
  }
};






// const pool = require('../../../../config/db');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');

// exports.createUser = async (req, res) => {
//   try {
//     const { dietician_id, email, name, phone_no, location } = req.body;

//     if (!dietician_id || !email || !req.file) {
//       return res.status(400).json({
//         ok: false,
//         message: 'dietician_id, email and logo are required',
//       });
//     }

//     // -----------------------------
//     // Temporary Password
//     // -----------------------------
//     const tempPassword = 'Temp@123';
//     const hashedPassword = await bcrypt.hash(tempPassword, 10);

//     // -----------------------------
//     // Generate Refresh Token
//     // -----------------------------
//     const refreshToken = crypto.randomBytes(40).toString('hex');

//     // Hash refresh token before storing
//     const hashedRefreshToken = await bcrypt.hash(refreshToken, 10);

//     // -----------------------------
//     // Logo as BLOB
//     // -----------------------------
//     const logoBuffer = req.file.buffer;

//     // -----------------------------
//     // Insert into DB
//     // -----------------------------
//     await pool.query(
//       `
//       INSERT INTO table_dietician
//       (
//         dietician_id,
//         name,
//         phone_no,
//         email,
//         location,
//         logo,
//         password,
//         refresh_token,
//         is_reset_password
//       )
//       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
//       `,
//       [
//         dietician_id,
//         name,
//         phone_no,
//         email,
//         location,
//         logoBuffer,
//         hashedPassword,
//         hashedRefreshToken,
//       ]
//     );

//     return res.status(201).json({
//       ok: true,
//       message: 'User created successfully',
//       refresh_token: refreshToken, // send only once
//     });

//   } catch (error) {
//     console.error('Create User Error:', error);
//     return res.status(500).json({
//       ok: false,
//       message: 'Server error',
//     });
//   }
// };
