const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

exports.refreshToken = async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        ok: false,
        message: 'refresh_token is required',
      });
    }

    // 🔍 Verify refresh token
    jwt.verify(refresh_token, process.env.JWT_REFRESH_SECRET);

    // 🔒 Hash refresh token
    const hashedToken = crypto
      .createHash('sha256')
      .update(refresh_token)
      .digest('hex');

    // 🔍 Check token in DB
    const [rows] = await pool.query(
      `SELECT dietician_id, name, email, phone_no, location
       FROM table_dietician
       WHERE refresh_token_hash = ?
       AND refresh_token_expires_at > NOW()`,
      [hashedToken]
    );

    if (rows.length === 0) {
      return res.status(401).json({
        ok: false,
        message: 'Invalid or expired refresh token',
      });
    }

    const dietician = rows[0];

    // 🔑 New access token
    const accessToken = jwt.sign(
      {
        sub: dietician.dietician_id,
        role: 'dietician',
        dietician: {
          dietician_id: dietician.dietician_id,
          name: dietician.name,
          email: dietician.email,
          phone_no: dietician.phone_no,
          location: dietician.location,
        },
      },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    return res.json({
      ok: true,
      token_type: 'Bearer',
      access_token: accessToken,
      expires_in: 900,
    });

  } catch (error) {
    console.error('Refresh Token Error:', error);
    return res.status(401).json({
      ok: false,
      message: 'Invalid or expired refresh token',
    });
  }
};






// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const crypto = require('crypto');

// exports.refreshToken = async (req, res) => {
//   try {
//     const { refresh_token } = req.body;

//     if (!refresh_token) {
//       return res.status(400).json({
//         ok: false,
//         message: 'refresh_token is required',
//       });
//     }

//     // Verify JWT signature & expiry
//     const decoded = jwt.verify(
//       refresh_token,
//       process.env.JWT_REFRESH_SECRET
//     );

//     // 🔐 Hash incoming refresh token
//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refresh_token)
//       .digest('hex');

//     // Check token exists & not revoked
//     const [rows] = await pool.query(
//       `SELECT * FROM refresh_tokens
//        WHERE token = ? AND revoked = 0`,
//       [hashedToken]
//     );

//     if (rows.length === 0) {
//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid refresh token',
//       });
//     }

//     // 🔹 Issue new access token
//     const accessToken = jwt.sign(
//       {
//         sub: decoded.sub,
//         role: decoded.role,
//         email: decoded.email,
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: process.env.JWT_EXPIRES_IN }
//     );

//     return res.json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       expires_in: 3600,
//     });

//   } catch (error) {
//     console.error('Refresh Token Error:', error);
//     return res.status(401).json({
//       ok: false,
//       message: 'Invalid or expired refresh token',
//     });
//   }
// };



