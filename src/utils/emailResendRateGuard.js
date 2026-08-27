"use strict";

/**
 * emailResendRateGuard.js
 *
 * Durable Email Bombing / resend abuse protection.
 *
 * IMPORTANT:
 * - Reuses the EXISTING `otp_verifications` table.
 * - No new DB table is required.
 * - No DB schema change is required.
 * - Works across multiple AWS Lambda instances because state is stored in MySQL.
 *
 * Existing otp_verifications columns used:
 *
 * email
 *   -> HMAC marker, NOT the real email address
 *
 * otp_code
 *   -> HMAC digest used as an internal marker
 *
 * purpose
 *   -> email_resend_target
 *   -> email_resend_actor
 *
 * attempts
 *   -> number of resend attempts in the current window
 *
 * created_at
 *   -> start of the rate-limit window
 *
 * verified_at
 *   -> time of the latest allowed resend
 *
 * expires_at
 *   -> end of the current rate-limit window
 *
 * DEFAULT POLICY
 * ---------------------------------------------------------
 * Same recipient:
 *   - minimum 60 seconds between resend emails
 *   - maximum 3 resend emails per hour
 *
 * Same authenticated actor:
 *   - maximum 30 resend emails per hour
 *
 * All values can be overridden using Lambda environment variables.
 */

const crypto = require("crypto");

const TABLE = "otp_verifications";

const PURPOSE_TARGET = "email_resend_target";
const PURPOSE_ACTOR = "email_resend_actor";

const TARGET_PREFIX = "ert:";
const ACTOR_PREFIX = "era:";

// otp_verifications.email is varchar(100)
const EMAIL_COLUMN_MAX = 100;


/* ============================================================================
 * Configuration
 * ============================================================================
 */

function intEnv(name, fallback, min, max) {
  const parsed = Number.parseInt(
    process.env[name],
    10
  );

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.min(
    max,
    Math.max(min, parsed)
  );
}


const POLICY = Object.freeze({

  // Same recipient cannot receive another resend before this cooldown.
  cooldownSeconds: intEnv(
    "EMAIL_RESEND_COOLDOWN_SECONDS",
    60,
    10,
    3600
  ),

  // Fixed rate-limit window.
  windowSeconds: intEnv(
    "EMAIL_RESEND_WINDOW_SECONDS",
    60 * 60,
    60,
    24 * 60 * 60
  ),

  // Maximum resend emails to one recipient during the window.
  targetMaxPerWindow: intEnv(
    "EMAIL_RESEND_TARGET_MAX_PER_WINDOW",
    3,
    1,
    100
  ),

  // Maximum total resend emails one authenticated actor may trigger.
  actorMaxPerWindow: intEnv(
    "EMAIL_RESEND_ACTOR_MAX_PER_WINDOW",
    30,
    1,
    1000
  ),

});


/* ============================================================================
 * Helpers
 * ============================================================================
 */

function normalize(value) {
  return String(
    value == null
      ? ""
      : value
  )
    .trim()
    .toLowerCase();
}


/**
 * We already have SECURITY_PEPPER / JWT_SECRET in the project.
 *
 * lambda.js hydrates secrets from AWS Secrets Manager before loading
 * the application, so this will be available in production.
 *
 * We intentionally fail closed if neither secret exists.
 */
function getSecurityPepper() {

  const pepper =
    process.env.SECURITY_PEPPER ||
    process.env.JWT_SECRET ||
    "";

  if (!pepper) {

    throw new Error(
      "EMAIL_RESEND_RATE_GUARD_CONFIG_ERROR: " +
      "SECURITY_PEPPER/JWT_SECRET is not configured"
    );

  }

  return pepper;
}


/**
 * HMAC-SHA256 prevents the real email address from being stored
 * in the rate-limit row.
 */
function hmac(value) {

  return crypto
    .createHmac(
      "sha256",
      getSecurityPepper()
    )
    .update(
      String(value),
      "utf8"
    )
    .digest("hex");

}


/**
 * Example:
 *
 * recipient:
 * ert:4f7894f1....
 *
 * actor:
 * era:2198a337....
 *
 * 4-char prefix + 64-char hash = 68 characters,
 * safely inside varchar(100).
 */
function marker(prefix, value) {

  const normalized =
    normalize(value);

  if (!normalized) {
    return "";
  }

  const digest =
    hmac(normalized);

  const result =
    `${prefix}${digest}`;

  if (
    result.length >
    EMAIL_COLUMN_MAX
  ) {

    throw new Error(
      "EMAIL_RESEND_RATE_GUARD_MARKER_TOO_LONG"
    );

  }

  return result;
}


/* ============================================================================
 * Counter creation
 * ============================================================================
 */

/**
 * Ensure one rate-limit counter exists.
 *
 * otp_verifications already contains:
 *
 * UNIQUE KEY unique_email_purpose (email, purpose)
 *
 * Because of that, two simultaneous Lambda requests cannot create two
 * independent counters for the same recipient.
 *
 * Request A:
 *
 * INSERT -> succeeds
 *
 * Request B:
 *
 * INSERT -> duplicate key
 *        -> existing row reused
 *
 * MySQL handles the concurrency for us.
 */
async function ensureCounterRow(
  db,
  keyMarker,
  digest,
  purpose
) {

  await db.execute(
    `
      INSERT INTO ${TABLE}
      (
        email,
        otp_code,
        purpose,
        is_verified,
        attempts,
        expires_at,
        created_at,
        verified_at
      )
      VALUES
      (
        ?,
        ?,
        ?,
        0,
        0,
        DATE_ADD(
          NOW(),
          INTERVAL ? SECOND
        ),
        NOW(),
        NULL
      )

      ON DUPLICATE KEY UPDATE
        id = id
    `,
    [
      keyMarker,
      digest,
      purpose,
      POLICY.windowSeconds
    ]
  );

}


/* ============================================================================
 * Counter locking
 * ============================================================================
 */

/**
 * Load the counter using SELECT ... FOR UPDATE.
 *
 * This is the important concurrency protection.
 *
 * If Burp fires 10 requests simultaneously:
 *
 * Request 1 locks row
 * Request 2 waits
 * Request 3 waits
 * Request 4 waits
 * ...
 *
 * Therefore they cannot all observe attempts = 0.
 */
async function lockCounterRow(
  db,
  keyMarker,
  digest,
  purpose
) {

  const [rows] =
    await db.execute(
      `
        SELECT
          id,
          attempts,
          expires_at,
          verified_at,

          (
            expires_at <= NOW()
          ) AS window_expired,

          GREATEST(
            0,
            TIMESTAMPDIFF(
              SECOND,
              NOW(),
              expires_at
            )
          ) AS window_remaining_seconds,

          CASE

            WHEN verified_at IS NULL
            THEN 0

            ELSE GREATEST(
              0,
              TIMESTAMPDIFF(
                SECOND,
                NOW(),
                DATE_ADD(
                  verified_at,
                  INTERVAL ? SECOND
                )
              )
            )

          END AS cooldown_remaining_seconds

        FROM ${TABLE}

        WHERE
          email = ?
          AND purpose = ?

        LIMIT 1

        FOR UPDATE
      `,
      [
        POLICY.cooldownSeconds,
        keyMarker,
        purpose
      ]
    );


  if (
    !rows ||
    !rows.length
  ) {

    throw new Error(
      "EMAIL_RESEND_RATE_GUARD_COUNTER_NOT_FOUND"
    );

  }


  let row =
    rows[0];


  /**
   * If the one-hour window has finished,
   * reset the counter.
   */
  if (
    Number(
      row.window_expired
    ) === 1
  ) {

    await db.execute(
      `
        UPDATE ${TABLE}

        SET
          otp_code = ?,
          is_verified = 0,
          attempts = 0,
          created_at = NOW(),
          verified_at = NULL,

          expires_at =
            DATE_ADD(
              NOW(),
              INTERVAL ? SECOND
            )

        WHERE id = ?

        LIMIT 1
      `,
      [
        digest,
        POLICY.windowSeconds,
        Number(row.id)
      ]
    );


    row = {
      ...row,

      attempts: 0,

      verified_at: null,

      window_expired: 0,

      window_remaining_seconds:
        POLICY.windowSeconds,

      cooldown_remaining_seconds:
        0
    };

  }


  return row;

}


/**
 * Creates the row when needed and then locks it.
 */
async function prepareCounter(
  db,
  keyMarker,
  purpose
) {

  // Remove ert: or era:
  const digest =
    keyMarker.slice(4);

  await ensureCounterRow(
    db,
    keyMarker,
    digest,
    purpose
  );

  return lockCounterRow(
    db,
    keyMarker,
    digest,
    purpose
  );

}


/**
 * Convert MySQL numbers safely.
 */
function positiveSeconds(
  value,
  fallback = 1
) {

  const number =
    Math.ceil(
      Number(value)
    );

  if (
    Number.isFinite(number) &&
    number > 0
  ) {

    return number;

  }

  return fallback;
}


/* ============================================================================
 * Main rate-limit function
 * ============================================================================
 */

/**
 * Atomically checks and reserves one email resend slot.
 *
 * IMPORTANT:
 *
 * This function MUST be called while the controller already has
 * an active MySQL transaction.
 *
 * Correct usage:
 *
 * await conn.beginTransaction();
 *
 * const rateLimit =
 *   await reserveEmailResendSlot(
 *     conn,
 *     {
 *       targetEmail: invitationEmail,
 *       actorUserId: actorEmail
 *     }
 *   );
 *
 * if (!rateLimit.allowed) {
 *   await conn.rollback();
 *
 *   return res
 *     .status(429)
 *     .json(...);
 * }
 *
 * await conn.commit();
 *
 * // Only AFTER commit:
 * await sendEmail(...);
 *
 *
 * WHY THE SLOT IS RESERVED BEFORE SEND
 * -------------------------------------
 *
 * If the external email provider fails, we still consume the attempt.
 *
 * Otherwise an attacker could deliberately generate provider failures
 * and obtain unlimited retry attempts.
 */
async function reserveEmailResendSlot(
  db,
  {
    targetEmail,
    actorUserId
  }
) {

  /* --------------------------------------------------------------------------
   * Validate DB connection
   * --------------------------------------------------------------------------
   */

  if (
    !db ||
    typeof db.execute !==
      "function"
  ) {

    throw new TypeError(
      "A transactional MySQL connection is required"
    );

  }


  /* --------------------------------------------------------------------------
   * Normalize identities
   * --------------------------------------------------------------------------
   */

  const target =
    normalize(
      targetEmail
    );

  const actor =
    normalize(
      actorUserId
    );


  if (!target) {

    throw new TypeError(
      "targetEmail is required for email resend rate limiting"
    );

  }


  if (!actor) {

    throw new TypeError(
      "actorUserId is required for email resend rate limiting"
    );

  }


  /* --------------------------------------------------------------------------
   * Generate anonymous DB identifiers
   * --------------------------------------------------------------------------
   */

  const targetMarker =
    marker(
      TARGET_PREFIX,
      target
    );


  const actorMarker =
    marker(
      ACTOR_PREFIX,
      actor
    );


  /* ==========================================================================
   * RECIPIENT RATE LIMIT
   * ==========================================================================
   *
   * Lock recipient FIRST.
   *
   * Every request follows this same locking order:
   *
   * recipient
   *    ↓
   * actor
   *
   * This reduces transaction deadlock risk.
   */

  const targetRow =
    await prepareCounter(
      db,
      targetMarker,
      PURPOSE_TARGET
    );


  /* --------------------------------------------------------------------------
   * Check 60-second recipient cooldown
   * --------------------------------------------------------------------------
   */

  const cooldownRemaining =
    positiveSeconds(
      targetRow
        .cooldown_remaining_seconds,
      0
    );


  if (
    cooldownRemaining > 0
  ) {

    return {

      allowed: false,

      reason:
        "recipient_cooldown",

      retryAfterSeconds:
        cooldownRemaining,

      policy:
        POLICY

    };

  }


  /* --------------------------------------------------------------------------
   * Check maximum recipient resends per window
   * --------------------------------------------------------------------------
   */

  const targetAttempts =
    Number(
      targetRow.attempts
    ) || 0;


  if (
    targetAttempts >=
    POLICY.targetMaxPerWindow
  ) {

    return {

      allowed: false,

      reason:
        "recipient_window_limit",

      retryAfterSeconds:
        positiveSeconds(
          targetRow
            .window_remaining_seconds,

          POLICY.windowSeconds
        ),

      policy:
        POLICY

    };

  }


  /* ==========================================================================
   * ACTOR RATE LIMIT
   * ==========================================================================
   */

  const actorRow =
    await prepareCounter(
      db,
      actorMarker,
      PURPOSE_ACTOR
    );


  const actorAttempts =
    Number(
      actorRow.attempts
    ) || 0;


  if (
    actorAttempts >=
    POLICY.actorMaxPerWindow
  ) {

    return {

      allowed: false,

      reason:
        "actor_window_limit",

      retryAfterSeconds:
        positiveSeconds(
          actorRow
            .window_remaining_seconds,

          POLICY.windowSeconds
        ),

      policy:
        POLICY

    };

  }


  /* ==========================================================================
   * RESERVE THE EMAIL SLOT
   * ==========================================================================
   *
   * Both checks passed.
   *
   * Increment both counters while the rows are still locked.
   */


  /* --------------------------------------------------------------------------
   * Recipient counter
   * --------------------------------------------------------------------------
   */

  await db.execute(
    `
      UPDATE ${TABLE}

      SET
        attempts =
          attempts + 1,

        verified_at =
          NOW()

      WHERE id = ?

      LIMIT 1
    `,
    [
      Number(
        targetRow.id
      )
    ]
  );


  /* --------------------------------------------------------------------------
   * Actor counter
   * --------------------------------------------------------------------------
   */

  await db.execute(
    `
      UPDATE ${TABLE}

      SET
        attempts =
          attempts + 1,

        verified_at =
          NOW()

      WHERE id = ?

      LIMIT 1
    `,
    [
      Number(
        actorRow.id
      )
    ]
  );


  /* ==========================================================================
   * Allowed
   * ==========================================================================
   */

  return {

    allowed:
      true,

    reason:
      null,

    retryAfterSeconds:
      0,

    policy:
      POLICY

  };

}


/* ============================================================================
 * Exports
 * ============================================================================
 */

module.exports = {

  POLICY,

  PURPOSE_TARGET,

  PURPOSE_ACTOR,

  reserveEmailResendSlot

};