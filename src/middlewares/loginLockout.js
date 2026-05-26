// middlewares/loginLockout.js
//
// HIPAA §164.308(a)(5)(ii)(C) — automated lockout after repeated failed logins.
//
// Reads the existing `app_auth_logs` table (no schema changes). Counts
// `login_failed` rows for this identifier_hash inside the lockout window;
// if the count is at/above threshold, the request is rejected with 423 Locked.
//
// Pairs with the in-memory loginRateLimiter (which is per-process and can be
// bypassed across Lambda cold starts). This one is durable because it reads
// the DB, so it survives restarts and works across all instances.
//
// Timestamp column is auto-detected on first use (created_at / logged_at /
// event_time / ts). If none exists, the middleware fails open with a warning.

'use strict';

const crypto = require('crypto');
const pool = require('../config/db');

const LOCKOUT_THRESHOLD =
  parseInt(process.env.LOGIN_LOCKOUT_THRESHOLD, 10) || 5;
const LOCKOUT_WINDOW_MIN =
  parseInt(process.env.LOGIN_LOCKOUT_WINDOW_MIN, 10) || 15;

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || '';

function authLogHash(value) {
  return crypto
    .createHmac('sha256', SECURITY_PEPPER)
    .update(String(value == null ? '' : value).trim().toLowerCase())
    .digest('hex');
}

// Auto-detected timestamp column on app_auth_logs. null = not yet probed,
// false = no usable column found (middleware then no-ops). Cached for the
// lifetime of the process.
let TIMESTAMP_COL = null;

async function detectTimestampColumn(conn) {
  const candidates = ['created_at', 'logged_at', 'event_time', 'ts', 'timestamp'];
  const [rows] = await conn.execute(
    `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = 'app_auth_logs'
        AND COLUMN_NAME IN (?, ?, ?, ?, ?)
      LIMIT 1`,
    candidates
  );
  if (rows && rows.length) return rows[0].COLUMN_NAME;
  return false;
}

module.exports = async function loginLockout(req, res, next) {
  if (req.method !== 'POST') return next();

  let body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  const identifier = String(body?.identifier || '').trim();
  if (!identifier) return next();

  let conn;
  try {
    conn = await pool.getConnection();

    if (TIMESTAMP_COL === null) {
      try {
        TIMESTAMP_COL = await detectTimestampColumn(conn);
        if (TIMESTAMP_COL === false) {
          console.warn(
            'LOGIN_LOCKOUT_DISABLED: app_auth_logs has no recognized ' +
            'timestamp column (created_at/logged_at/event_time/ts). ' +
            'In-memory rate limiter still applies.'
          );
        }
      } catch (e) {
        console.error('LOGIN_LOCKOUT_DETECT_FAILED:', e.message);
        TIMESTAMP_COL = false;
      }
    }

    if (!TIMESTAMP_COL) return next();

    const identifierHash = authLogHash(identifier);

    // Column name is from a fixed allow-list, safe to interpolate.
    const [rows] = await conn.execute(
      `SELECT COUNT(*) AS fail_count,
              MAX(\`${TIMESTAMP_COL}\`) AS last_fail
         FROM app_auth_logs
        WHERE event_type = 'login_failed'
          AND identifier_hash = ?
          AND \`${TIMESTAMP_COL}\` >= (NOW() - INTERVAL ? MINUTE)`,
      [identifierHash, LOCKOUT_WINDOW_MIN]
    );

    const failCount = rows && rows[0] ? Number(rows[0].fail_count) : 0;

    if (failCount >= LOCKOUT_THRESHOLD) {
      const lastFail = rows[0].last_fail
        ? new Date(rows[0].last_fail)
        : new Date();
      const unlockAt = new Date(
        lastFail.getTime() + LOCKOUT_WINDOW_MIN * 60 * 1000
      );
      const secondsLeft = Math.max(
        1,
        Math.ceil((unlockAt - Date.now()) / 1000)
      );

      return res.status(423).json({
        ok: false,
        error: 'Account temporarily locked. Try again later.',
        retry_after_seconds: secondsLeft,
      });
    }

    return next();
  } catch (e) {
    console.error('LOGIN_LOCKOUT_CHECK_FAILED:', e.message);
    // Fail-open so a DB hiccup doesn't take auth offline. Rate limiter still applies.
    return next();
  } finally {
    if (conn) conn.release();
  }
};
