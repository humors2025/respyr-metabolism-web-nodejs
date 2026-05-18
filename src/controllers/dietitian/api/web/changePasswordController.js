// // changePasswordController.js
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

//     await pool.query(
//       `UPDATE table_dietician
//        SET password = ?, is_reset_password = 0
//        WHERE dietician_id = ?`,
//       [hashedPassword, dieticianId]
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









// changePasswordController.js
const pool = require('../../../../config/db');
const bcrypt = require('bcryptjs');

const BCRYPT_ROUNDS = Number(process.env.BCRYPT_ROUNDS || 12);

const validatePassword = (password) => {
  if (typeof password !== 'string') {
    return 'Password must be a string';
  }

  if (password.length < 12) {
    return 'Password must be at least 12 characters long';
  }

  if (Buffer.byteLength(password, 'utf8') > 72) {
    return 'Password must not exceed 72 bytes';
  }

  if (!/[a-z]/.test(password)) {
    return 'Password must contain at least one lowercase letter';
  }

  if (!/[A-Z]/.test(password)) {
    return 'Password must contain at least one uppercase letter';
  }

  if (!/\d/.test(password)) {
    return 'Password must contain at least one number';
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    return 'Password must contain at least one special character';
  }

  return null;
};

exports.changePassword = async (req, res) => {
  try {
    const dieticianId = req.user?.sub;

    if (!dieticianId) {
      return res.status(401).json({
        ok: false,
        message: 'Unauthorized',
      });
    }

    const {
      current_password,
      new_password,
      confirm_password,
    } = req.body || {};

    if (!current_password || !new_password || !confirm_password) {
      return res.status(400).json({
        ok: false,
        message: 'current_password, new_password and confirm_password are required',
      });
    }

    if (new_password !== confirm_password) {
      return res.status(400).json({
        ok: false,
        message: 'New password and confirm password do not match',
      });
    }

    const passwordError = validatePassword(new_password);

    if (passwordError) {
      return res.status(400).json({
        ok: false,
        message: passwordError,
      });
    }

    const [rows] = await pool.query(
      `SELECT dietician_id, password
       FROM table_dietician
       WHERE dietician_id = ?
       LIMIT 1`,
      [dieticianId]
    );

    if (!rows.length) {
      return res.status(404).json({
        ok: false,
        message: 'Dietician account not found',
      });
    }

    const dietician = rows[0];

    const isCurrentPasswordValid = await bcrypt.compare(
      current_password,
      dietician.password
    );

    if (!isCurrentPasswordValid) {
      return res.status(401).json({
        ok: false,
        message: 'Current password is incorrect',
      });
    }

    const isSamePassword = await bcrypt.compare(
      new_password,
      dietician.password
    );

    if (isSamePassword) {
      return res.status(400).json({
        ok: false,
        message: 'New password must be different from current password',
      });
    }

    const hashedPassword = await bcrypt.hash(new_password, BCRYPT_ROUNDS);

    const [updateResult] = await pool.query(
      `UPDATE table_dietician
       SET password = ?, is_reset_password = 0
       WHERE dietician_id = ?`,
      [hashedPassword, dieticianId]
    );

    if (updateResult.affectedRows !== 1) {
      return res.status(500).json({
        ok: false,
        message: 'Password could not be updated',
      });
    }

    return res.status(200).json({
      ok: true,
      message: 'Password changed successfully. Please login again.',
    });
  } catch (error) {
    console.error('Change Password Error:', {
      message: error.message,
      stack: process.env.NODE_ENV === 'production' ? undefined : error.stack,
    });

    return res.status(500).json({
      ok: false,
      message: 'Internal server error',
    });
  }
};