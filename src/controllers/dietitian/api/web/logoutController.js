const pool = require('../../../../config/db');
const crypto = require('crypto');

exports.logout = async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({
        ok: false,
        message: 'refresh_token is required',
      });
    }

    // 🔒 Hash refresh token
    const hashedToken = crypto
      .createHash('sha256')
      .update(refresh_token)
      .digest('hex');

    // ❌ Remove refresh token from DB
    await pool.query(
      `UPDATE table_dietician
       SET refresh_token_hash = NULL,
           refresh_token_expires_at = NULL
       WHERE refresh_token_hash = ?`,
      [hashedToken]
    );

    return res.json({
      ok: true,
      message: 'Logged out successfully',
    });

  } catch (error) {
    console.error('Logout Error:', error);
    return res.status(500).json({
      ok: false,
      message: 'Internal server error',
    });
  }
};









// const pool = require('../../../../config/db');

// exports.logout = async (req, res) => {
//   try {
//     const { refresh_token } = req.body;

//     if (!refresh_token) {
//       return res.status(400).json({
//         ok: false,
//         message: 'refresh_token is required',
//       });
//     }

//     await pool.query(
//       `UPDATE refresh_tokens
//        SET revoked = 1
//        WHERE token = ?`,
//       [refresh_token]
//     );

//     return res.json({
//       ok: true,
//       message: 'Logged out successfully',
//     });
//   } catch (error) {
//     console.error(error);
//     return res.status(500).json({
//       ok: false,
//       message: 'Internal server error',
//     });
//   }
// };
