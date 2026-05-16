const pool = require('../../../../config/db');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Dummy bcrypt hash used to equalize timing when user is not found.
// Real $2b$ hash of a random string — never matches any real password.
const DUMMY_BCRYPT_HASH =
  '$2b$10$CwTycUXWue0Thq9StjUM0uJ8.LJ3pP0NRmI8r1mB6q1RZ5lOq8eqW';

const MAX_IDENTIFIER_LENGTH = 254;
const MAX_PASSWORD_LENGTH = 128;
const MIN_PASSWORD_LENGTH = 6;

const ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
const REFRESH_TOKEN_TTL_DAYS = 7;

function getClientIp(req) {
  const ip =
    req.ip ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    null;

  return ip ? String(ip).substring(0, 45) : null;
}

function getUserAgent(req) {
  const ua =
    typeof req.get === 'function'
      ? req.get('user-agent')
      : req.headers?.['user-agent'];

  return ua ? String(ua).substring(0, 255) : null;
}

function isValidIdentifier(identifier) {
  if (!identifier || identifier.length > MAX_IDENTIFIER_LENGTH) return false;

  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const phoneRe = /^\+?\d{7,15}$/;

  return emailRe.test(identifier) || phoneRe.test(identifier);
}

function sendInvalidCredentials(res) {
  return res.status(401).json({
    ok: false,
    message: 'Invalid email or password',
  });
}

function normalizePhone(value) {
  return String(value || '').replace(/\D/g, '');
}

function maskIdentifier(identifier) {
  return crypto
    .createHash('sha256')
    .update(String(identifier || ''))
    .digest('hex')
    .slice(0, 12);
}

function normalizeBcryptHash(hash) {
  if (!hash) return null;

  let cleanedHash = String(hash).trim();

  // PHP password_hash() often creates $2y$ bcrypt hashes.
  // bcryptjs works safely when converted to $2b$.
  if (cleanedHash.startsWith('$2y$')) {
    cleanedHash = '$2b$' + cleanedHash.slice(4);
  }

  return cleanedHash;
}

function isBcryptHash(value) {
  const hash = String(value || '').trim();
  return (
    hash.startsWith('$2a$') ||
    hash.startsWith('$2b$') ||
    hash.startsWith('$2y$')
  );
}

function safeComparePlainText(inputPassword, storedPassword) {
  const input = Buffer.from(String(inputPassword || ''), 'utf8');
  const stored = Buffer.from(String(storedPassword || ''), 'utf8');

  if (input.length !== stored.length) {
    return false;
  }

  return crypto.timingSafeEqual(input, stored);
}

async function verifyPasswordAndMigrateIfNeeded({
  password,
  dietician,
}) {
  if (!dietician || !dietician.password) {
    await bcrypt.compare(password || 'x', DUMMY_BCRYPT_HASH);
    return false;
  }

  const storedPassword = String(dietician.password).trim();

  // Case 1: Proper bcrypt password
  if (isBcryptHash(storedPassword)) {
    const normalizedHash = normalizeBcryptHash(storedPassword);

    try {
      return await bcrypt.compare(password, normalizedHash);
    } catch (error) {
      console.error('[AUTH] bcrypt compare failed:', {
        dietician_id: dietician.dietician_id,
        error: error?.message || null,
      });
      return false;
    }
  }

  // Case 2: Legacy plain-text password support.
  // Keep this OFF by default for VAPT safety.
  // Use only temporarily if your old DB has plain-text passwords.
  if (process.env.ALLOW_LEGACY_PLAINTEXT_PASSWORD_LOGIN === 'true') {
    const isPlainTextMatch = safeComparePlainText(password, storedPassword);

    if (!isPlainTextMatch) {
      return false;
    }

    // Auto-migrate plain-text password to bcrypt after successful login.
    const newHash = await bcrypt.hash(password, 10);

    await pool.query(
      `UPDATE table_dietician
       SET password = ?
       WHERE dietician_id = ?
       LIMIT 1`,
      [newHash, dietician.dietician_id]
    );

    console.warn('[AUTH] Legacy plain-text password migrated to bcrypt', {
      dietician_id: dietician.dietician_id,
    });

    return true;
  }

  return false;
}

exports.login = async (req, res) => {
  try {
    // Lambda/API Gateway raw body handling
    if (typeof req.body === 'string') {
      try {
        req.body = JSON.parse(req.body);
      } catch {
        return res.status(400).json({
          ok: false,
          message: 'Invalid JSON body',
        });
      }
    }

    const rawIdentifier = req.body?.identifier;
    const rawPassword = req.body?.password;

    if (typeof rawIdentifier !== 'string' || typeof rawPassword !== 'string') {
      return res.status(400).json({
        ok: false,
        message: 'Email and password are required',
      });
    }

    const identifier = rawIdentifier.trim().toLowerCase();
    const password = rawPassword;
    const phoneDigits = normalizePhone(rawIdentifier);

    if (
      !identifier ||
      !password ||
      password.length < MIN_PASSWORD_LENGTH ||
      password.length > MAX_PASSWORD_LENGTH ||
      !isValidIdentifier(identifier)
    ) {
      await bcrypt.compare(password || 'x', DUMMY_BCRYPT_HASH);

      console.warn('[AUTH] Login failed', {
        identifier_hash: maskIdentifier(identifier),
        ip: getClientIp(req),
        reason: 'invalid_input_format',
      });

      return sendInvalidCredentials(res);
    }

    if (!process.env.JWT_SECRET || !process.env.JWT_REFRESH_SECRET) {
      console.error('[AUTH] JWT secrets missing in environment');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    // IMPORTANT:
    // This login checks dietician credentials from table_dietician.
    // Use dietician email or dietician phone number in Postman.
    const [rows] = await pool.query(
      `SELECT
         td.dietician_id,
         td.name,
         td.email,
         td.phone_no,
         td.location,
         td.password,
         (
           SELECT tc.profile_id
           FROM table_clients tc
           WHERE tc.dietician_id = td.dietician_id
           ORDER BY tc.profile_id ASC
           LIMIT 1
         ) AS profile_id
       FROM table_dietician td
       WHERE LOWER(TRIM(td.email)) = ?
          OR REPLACE(
               REPLACE(
                 REPLACE(
                   REPLACE(
                     REPLACE(TRIM(td.phone_no), ' ', ''),
                   '-', ''),
                 '(', ''),
               ')', ''),
             '+', '') = ?
       LIMIT 1`,
      [identifier, phoneDigits]
    );

    const dietician = rows[0];

    console.log('[AUTH DEBUG]', {
      identifier_hash: maskIdentifier(identifier),
      rows_found: rows.length,
      dietician_id: dietician?.dietician_id || null,
      db_email: dietician?.email || null,
      db_phone: dietician?.phone_no || null,
      has_password: !!dietician?.password,
      password_prefix: dietician?.password
        ? String(dietician.password).trim().slice(0, 4)
        : null,
      password_length: dietician?.password
        ? String(dietician.password).trim().length
        : 0,
    });

    const isPasswordValid = await verifyPasswordAndMigrateIfNeeded({
      password,
      dietician,
    });

    if (!dietician || !dietician.password || !isPasswordValid) {
      console.warn('[AUTH] Login failed', {
        identifier_hash: maskIdentifier(identifier),
        ip: getClientIp(req),
        reason: !dietician
          ? 'user_not_found'
          : !dietician.password
          ? 'no_password_set'
          : 'bad_password',
      });

      return sendInvalidCredentials(res);
    }

    const baseUrl = process.env.BASE_URL;

    if (!baseUrl) {
      console.error('[AUTH] BASE_URL not configured');

      return res.status(500).json({
        ok: false,
        message: 'Server configuration error',
      });
    }

    const logoUrl = `${baseUrl}/dietitian/api/web/get_client_image?dietician_id=${encodeURIComponent(
      dietician.dietician_id
    )}`;

    const profileUrl = dietician.profile_id
      ? `${baseUrl}/dietitian/api/web/get_profile_image?profile_id=${encodeURIComponent(
          dietician.profile_id
        )}&dietician_id=${encodeURIComponent(dietician.dietician_id)}`
      : null;

    const accessTokenJti = crypto.randomBytes(16).toString('hex');

    const accessToken = jwt.sign(
      {
        sub: String(dietician.dietician_id),
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
        expiresIn: ACCESS_TOKEN_TTL_SECONDS,
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER || 'dietician-api',
        audience: process.env.JWT_AUDIENCE || 'dietician-app',
        jwtid: accessTokenJti,
      }
    );

    const refreshToken = jwt.sign(
      {
        sub: String(dietician.dietician_id),
        role: 'dietician',
      },
      process.env.JWT_REFRESH_SECRET,
      {
        expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d`,
        algorithm: 'HS256',
        issuer: process.env.JWT_ISSUER || 'dietician-api',
        audience: process.env.JWT_AUDIENCE || 'dietician-app',
        jwtid: crypto.randomBytes(16).toString('hex'),
      }
    );

    const hashedRefreshToken = crypto
      .createHash('sha256')
      .update(refreshToken)
      .digest('hex');

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_TTL_DAYS);

    const ipAddress = getClientIp(req);
    const userAgent = getUserAgent(req);

    await pool.query(
      `DELETE FROM dietician_refresh_tokens
       WHERE dietician_id = ? AND expires_at < NOW()`,
      [dietician.dietician_id]
    );

    await pool.query(
      `INSERT INTO dietician_refresh_tokens
         (dietician_id, token_hash, expires_at, ip_address, user_agent)
       VALUES (?, ?, ?, ?, ?)`,
      [
        dietician.dietician_id,
        hashedRefreshToken,
        expiresAt,
        ipAddress,
        userAgent,
      ]
    );

    if (process.env.USE_REFRESH_COOKIE === 'true') {
      res.cookie('refresh_token', refreshToken, {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000,
        path: '/v1/auth',
      });
    }

    return res.status(200).json({
      ok: true,
      token_type: 'Bearer',
      access_token: accessToken,
      refresh_token: refreshToken,
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
    });
  } catch (error) {
    console.error('[AUTH] Login error:', {
      message: error?.message || null,
      name: error?.name || null,
      code: error?.code || null,
      errno: error?.errno || null,
      sqlState: error?.sqlState || null,
      sqlMessage:
        process.env.NODE_ENV !== 'production' ? error?.sqlMessage : undefined,
      stack: process.env.NODE_ENV !== 'production' ? error?.stack : undefined,
    });

    return res.status(500).json({
      ok: false,
      message: 'Login failed. Please try again later.',
    });
  }
};