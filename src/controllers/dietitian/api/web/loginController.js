const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

exports.login = async (req, res) => {
  try {
    // ✅ FIX 1: Handle Lambda body (string → JSON)
    if (typeof req.body === 'string') {
      req.body = JSON.parse(req.body);
    }

    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        message: 'Email and password are required',
      });
    }

    // 🔍 Find dietician
    const [rows] = await pool.query(
      `SELECT 
         td.dietician_id,
         td.name,
         td.email,
         td.phone_no,
         td.location,
         td.password,
         tc.profile_id
       FROM table_dietician td
       LEFT JOIN table_clients tc 
         ON td.dietician_id = tc.dietician_id
       WHERE tc.email = ?
       LIMIT 1`,
      [identifier]
    );

    if (!rows.length) {
      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    const dietician = rows[0];

    // 🔐 Verify password
    const isPasswordValid = await bcrypt.compare(password, dietician.password);
    if (!isPasswordValid) {
      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    // ✅ FIX 2: BASE URL safe for Lambda + Local
    const baseUrl =
      process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

    const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;
    const profileUrl = `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`;

    // 🔑 ACCESS TOKEN
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
          logo_url: logoUrl,
          profile_url: profileUrl,
        },
      },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    // 🔁 REFRESH TOKEN
    const refreshToken = jwt.sign(
      {
        sub: dietician.dietician_id,
        role: 'dietician',
      },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    // 🔒 Hash refresh token
    const hashedToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await pool.query(
      `UPDATE table_dietician
       SET refresh_token_hash = ?, refresh_token_exp = ?
       WHERE dietician_id = ?`,
      [hashedToken, expiresAt, dietician.dietician_id]
    );

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 900,
    });

  } catch (error) {
    // ✅ FIX 3: Real error visibility in Lambda
    console.error('LOGIN ERROR 🔥:', error);

    return res.status(500).json({
      ok: false,
      error: error.message,
    });
  }
};









// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');

// exports.login = async (req, res) => {
//   try {
//     const { identifier, password } = req.body;

//     if (!identifier || !password) {
//       return res.status(400).json({
//         ok: false,
//         message: 'Email and password are required',
//       });
//     }

//     // 🔍 Find user
//     const [rows] = await pool.query(
//       `SELECT td.dietician_id, td.name, td.email, td.phone_no, td.location, td.password, tc.profile_id
//        FROM table_dietician td left join table_clients tc on 
//        td.dietician_id = tc.dietician_id
//        WHERE tc.email = ? LIMIT 1`,
//       [identifier]
//     );

//     if (rows.length === 0) {
//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     const dietician = rows[0];

//     // 🔐 Verify password
//     const isPasswordValid = await bcrypt.compare(password, dietician.password);
//     if (!isPasswordValid) {
//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     // 🖼 Logo URL
//     const logoUrl = `${process.env.BASE_URL}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;

//     // 🖼 Profile URL
//     const profileUrl = `${process.env.BASE_URL}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`;

//     // 🔑 ACCESS TOKEN (SHORT-LIVED)
//     const accessToken = jwt.sign(
//       {
//         sub: dietician.dietician_id,
//         role: 'dietician',
//         dietician: {
//           dietician_id: dietician.dietician_id,
//           name: dietician.name,
//           email: dietician.email,
//           phone_no: dietician.phone_no,
//           location: dietician.location,
//           logo_url: logoUrl,
//           profile_url: profileUrl
//         },
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: '15m' } // ⬅️ IMPORTANT
//     );

//     // 🔁 REFRESH TOKEN
//     const refreshToken = jwt.sign(
//       {
//         sub: dietician.dietician_id,
//         role: 'dietician',
//       },
//       process.env.JWT_REFRESH_SECRET,
//       { expiresIn: '7d' }
//     );

//     // 🔒 Hash refresh token before storing
//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refreshToken)
//       .digest('hex');

//     const expiresAt = new Date();
//     expiresAt.setDate(expiresAt.getDate() + 7);

//     await pool.query(
//       `UPDATE table_dietician
//        SET refresh_token_hash = ?, refresh_token_expires_at = ?
//        WHERE dietician_id = ?`,
//       [hashedToken, expiresAt, dietician.dietician_id]
//     );

//     return res.status(200).json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       refresh_token: refreshToken,
//       expires_in: 900, // 15 minutes
//     });

//   } catch (error) {
//     console.error('Login Error:', error);
//     return res.status(500).json({
//       ok: false,
//       message: 'Internal server error',
//     });
//   }
// };



