// changePasswordController.js
const pool = require('../../../../config/db');
const bcrypt = require('bcryptjs');

const isStrongPassword = (password) => {
  return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(password);
};

exports.changePassword = async (req, res) => {
  try {
    const { new_password } = req.body;
    const dieticianId = req.user.sub;

    if (!new_password) {
      return res.status(400).json({
        ok: false,
        message: 'new_password is required',
      });
    }

    if (!isStrongPassword(new_password)) {
      return res.status(400).json({
        ok: false,
        message:
          'Password must contain uppercase, lowercase, number and special character',
      });
    }

    const hashedPassword = await bcrypt.hash(new_password, 10);

    await pool.query(
      `UPDATE table_dietician
       SET password = ?, is_reset_password = 0
       WHERE dietician_id = ?`,
      [hashedPassword, dieticianId]
    );

    return res.json({
      ok: true,
      message: 'Password changed successfully. Please login again.',
    });

  } catch (error) {
    console.error('Change Password Error:', error);
    return res.status(500).json({
      ok: false,
      message: 'Internal server error',
    });
  }
};









// const pool = require('../../../../config/db');
// const bcrypt = require('bcryptjs');

// const isStrongPassword = (password) => {
//   return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(password);
// };

// exports.changePassword = async (req, res) => {
//   try {
//     const { new_password } = req.body;
//     const dieticianId = req.user.sub;

//     if (!new_password) {
//       return res.status(400).json({
//         ok: false,
//         message: 'new_password is required',
//       });
//     }

//     if (!isStrongPassword(new_password)) {
//       return res.status(400).json({
//         ok: false,
//         message:
//           'Password must contain uppercase, lowercase, number and special character',
//       });
//     }

//     const hashedPassword = await bcrypt.hash(new_password, 10);

//     // 🔐 Update password
//     const [result] = await pool.query(
//       `UPDATE login_dieticians
//        SET password = ?, is_first_login = 0
//        WHERE dietician_id = ?`,
//       [hashedPassword, dieticianId]
//     );

//     if (result.affectedRows === 0) {
//       return res.status(404).json({
//         ok: false,
//         message: 'User not found',
//       });
//     }

//     // 🔥 IMPORTANT: Revoke ALL refresh tokens
//     await pool.query(
//       `UPDATE refresh_tokens
//        SET revoked = 1
//        WHERE dietician_id = ?`,
//       [dieticianId]
//     );

//     return res.json({
//       ok: true,
//       message: 'Password changed successfully. Please login again.',
//     });

//   } catch (error) {
//     console.error('Change Password Error:', error);
//     return res.status(500).json({
//       ok: false,
//       message: 'Internal server error',
//     });
//   }
// };





