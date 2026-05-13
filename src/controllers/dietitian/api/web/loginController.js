// const pool = require('../../../../config/db');
// const jwt = require('jsonwebtoken');
// const bcrypt = require('bcryptjs');
// const crypto = require('crypto');

// exports.login = async (req, res) => {
//   try {
//     // Handle Lambda body string
//     if (typeof req.body === 'string') {
//       try {
//         req.body = JSON.parse(req.body);
//       } catch (parseError) {
//         return res.status(400).json({
//           ok: false,
//           message: 'Invalid JSON body',
//         });
//       }
//     }

//     const identifier = String(req.body?.identifier || '').trim().toLowerCase();
//     const password = String(req.body?.password || '');

//     if (!identifier || !password) {
//       return res.status(400).json({
//         ok: false,
//         message: 'Email and password are required',
//       });
//     }

//     /**
//      * ROOT FIX:
//      * Login should check table_dietician email/phone,
//      * not table_clients email.
//      */
//     const [rows] = await pool.query(
//       `SELECT 
//          td.dietician_id,
//          td.name,
//          td.email,
//          td.phone_no,
//          td.location,
//          td.password,
//          tc.profile_id
//        FROM table_dietician td
//        LEFT JOIN table_clients tc 
//          ON td.dietician_id = tc.dietician_id
//        WHERE LOWER(td.email) = ?
//           OR td.phone_no = ?
//        LIMIT 1`,
//       [identifier, identifier]
//     );

//     if (!rows.length) {
//       console.log('LOGIN FAILED: dietician not found', {
//         identifier,
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     const dietician = rows[0];

//     if (!dietician.password) {
//       console.log('LOGIN FAILED: password missing in DB', {
//         dietician_id: dietician.dietician_id,
//         email: dietician.email,
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     /**
//      * bcrypt.compare works only if DB password is bcrypt hashed.
//      * Example hash starts with:
//      * $2a$, $2b$, or $2y$
//      */
//     const isPasswordValid = await bcrypt.compare(password, dietician.password);

//     if (!isPasswordValid) {
//       console.log('LOGIN FAILED: invalid password', {
//         dietician_id: dietician.dietician_id,
//         email: dietician.email,
//         password_hash_prefix: String(dietician.password).substring(0, 4),
//       });

//       return res.status(401).json({
//         ok: false,
//         message: 'Invalid email or password',
//       });
//     }

//     const baseUrl =
//       process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

//     const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;

//     const profileUrl = dietician.profile_id
//       ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`
//       : null;

//     if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
//       console.error('JWT secrets missing');

//       return res.status(500).json({
//         ok: false,
//         message: 'Server configuration error',
//       });
//     }

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
//           profile_url: profileUrl,
//         },
//       },
//       process.env.JWT_SECRET,
//       { expiresIn: '15m' }
//     );

//     const refreshToken = jwt.sign(
//       {
//         sub: dietician.dietician_id,
//         role: 'dietician',
//       },
//       process.env.JWT_REFRESH_SECRET,
//       { expiresIn: '7d' }
//     );

//     const hashedToken = crypto
//       .createHash('sha256')
//       .update(refreshToken)
//       .digest('hex');

//     const expiresAt = new Date();
//     expiresAt.setDate(expiresAt.getDate() + 7);

//     await pool.query(
//       `UPDATE table_dietician
//        SET refresh_token_hash = ?, refresh_token_exp = ?
//        WHERE dietician_id = ?`,
//       [hashedToken, expiresAt, dietician.dietician_id]
//     );

//     return res.status(200).json({
//       ok: true,
//       token_type: 'Bearer',
//       access_token: accessToken,
//       refresh_token: refreshToken,
//       expires_in: 900,
//     });
//   } catch (error) {
//     console.error('LOGIN ERROR 🔥:', {
//       message: error.message,
//       code: error.code,
//       errno: error.errno,
//       sqlState: error.sqlState,
//       stack: error.stack,
//     });

//     return res.status(500).json({
//       ok: false,
//       error: error.message,
//     });
//   }
// };






const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

function getClientIp(req) {
  const forwardedFor = req.headers?.['x-forwarded-for'];

  if (forwardedFor) {
    return String(forwardedFor).split(',')[0].trim().substring(0, 45);
  }

  return (
    req.ip ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    null
  );
}

function getUserAgent(req) {
  const userAgent =
    typeof req.get === 'function'
      ? req.get('user-agent')
      : req.headers?.['user-agent'];

  return userAgent ? String(userAgent).substring(0, 255) : null;
}

exports.login = async (req, res) => {
  try {
    /**
     * Handle Lambda/API Gateway body string
     */
    if (typeof req.body === 'string') {
      try {
        req.body = JSON.parse(req.body);
      } catch (parseError) {
        return res.status(400).json({
          ok: false,
          message: 'Invalid JSON body',
        });
      }
    }

    const identifier = String(req.body?.identifier || '')
      .trim()
      .toLowerCase();

    const password = String(req.body?.password || '');

    if (!identifier || !password) {
      return res.status(400).json({
        ok: false,
        message: 'Email and password are required',
      });
    }

    /**
     * Check dietician table using email or phone.
     */
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
       WHERE LOWER(td.email) = ?
          OR td.phone_no = ?
       LIMIT 1`,
      [identifier, identifier]
    );

    if (!rows.length) {
      console.log('LOGIN FAILED: dietician not found', {
        identifier,
      });

      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    const dietician = rows[0];

    if (!dietician.password) {
      console.log('LOGIN FAILED: password missing in DB', {
        dietician_id: dietician.dietician_id,
        email: dietician.email,
      });

      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    /**
     * bcrypt.compare works only if DB password is bcrypt hashed.
     * Valid bcrypt hashes usually start with $2a$, $2b$, or $2y$.
     */
    const isPasswordValid = await bcrypt.compare(
      password,
      dietician.password
    );

    if (!isPasswordValid) {
      console.log('LOGIN FAILED: invalid password', {
        dietician_id: dietician.dietician_id,
        email: dietician.email,
        password_hash_prefix: String(dietician.password).substring(0, 4),
      });

      return res.status(401).json({
        ok: false,
        message: 'Invalid email or password',
      });
    }

    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
      console.error('JWT secrets missing');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    const baseUrl =
      process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;

    const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${dietician.dietician_id}`;

    const profileUrl = dietician.profile_id
      ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${dietician.profile_id}&dietician_id=${dietician.dietician_id}`
      : null;

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
      {
        expiresIn: '15m',
      }
    );

    const refreshToken = jwt.sign(
      {
        sub: dietician.dietician_id,
        role: 'dietician',
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: '7d',
      }
    );

    const hashedToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    const ipAddress = getClientIp(req);
    const userAgent = getUserAgent(req);

    /**
     * Store refresh token in separate table.
     * Do NOT update table_dietician with refresh_token_hash.
     */
    await pool.query(
      `INSERT INTO dietician_refresh_tokens
       (
         dietician_id,
         token_hash,
         expires_at,
         ip_address,
         user_agent
       )
       VALUES (?, ?, ?, ?, ?)`,
      [
        dietician.dietician_id,
        hashedToken,
        expiresAt,
        ipAddress,
        userAgent,
      ]
    );

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: 900,
    });
  } catch (error) {
    console.error('LOGIN ERROR 🔥 FULL:', error);

    console.error('LOGIN ERROR DETAILS:', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlMessage: error?.sqlMessage || null,
      sqlState: error?.sqlState || null,
      stack: error?.stack || null,
    });

    return res.status(500).json({
      ok: false,
      message: 'Login failed due to server error',
      error:
        error?.message ||
        error?.sqlMessage ||
        'Unknown server error',
    });
  }
};