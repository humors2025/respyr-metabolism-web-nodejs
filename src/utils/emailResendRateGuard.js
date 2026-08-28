"use strict";

/**
 * emailResendRateGuard.js
 *
 * Email Bombing / resend abuse protection.
 *
 * Reuses the EXISTING `otp_verifications` MySQL table.
 *
 * No new DB table is required.
 * No DB schema change is required.
 *
 * DEFAULT POLICY
 * --------------------------------------------------------------------------
 *
 * Same recipient:
 *   - Minimum 60 seconds between resend emails
 *   - Maximum 3 resend attempts per 1-hour window
 *
 * Same authenticated actor:
 *   - Maximum 30 resend attempts per 1-hour window
 *
 * The values can optionally be overridden using environment variables:
 *
 * EMAIL_RESEND_COOLDOWN_SECONDS
 * EMAIL_RESEND_WINDOW_SECONDS
 * EMAIL_RESEND_TARGET_MAX_PER_WINDOW
 * EMAIL_RESEND_ACTOR_MAX_PER_WINDOW
 *
 * IMPORTANT:
 *
 * This utility expects the controller to already have an ACTIVE
 * MySQL transaction.
 *
 * The utility does NOT commit or rollback.
 *
 * Transaction management stays with the controller.
 */

const crypto = require("crypto");

/* ============================================================================
 * Constants
 * ============================================================================
 */

const TABLE =
  "otp_verifications";

const PURPOSE_TARGET =
  "email_resend_target";

const PURPOSE_ACTOR =
  "email_resend_actor";

const TARGET_PREFIX =
  "ert:";

const ACTOR_PREFIX =
  "era:";

/**
 * otp_verifications.email is VARCHAR(100).
 *
 * Prefix = 4 chars
 * SHA-256 hex digest = 64 chars
 *
 * Total = 68 chars
 */
const EMAIL_COLUMN_MAX =
  100;


/* ============================================================================
 * Configuration
 * ============================================================================
 */

/**
 * Safely read an integer environment variable.
 */
function intEnv(
  name,
  fallback,
  min,
  max
) {
  const parsed =
    Number.parseInt(
      process.env[name],
      10
    );

  if (
    !Number.isFinite(
      parsed
    )
  ) {
    return fallback;
  }

  return Math.min(
    max,
    Math.max(
      min,
      parsed
    )
  );
}


/**
 * Email resend security policy.
 */
const POLICY =
  Object.freeze({

    /*
    |--------------------------------------------------------------------------
    | Recipient cooldown
    |--------------------------------------------------------------------------
    |
    | Default:
    |
    | Same recipient cannot receive another resend for 60 seconds.
    |--------------------------------------------------------------------------
    */

    cooldownSeconds:
      intEnv(
        "EMAIL_RESEND_COOLDOWN_SECONDS",
        60,
        10,
        3600
      ),


    /*
    |--------------------------------------------------------------------------
    | Rate-limit window
    |--------------------------------------------------------------------------
    |
    | Default:
    |
    | 1 hour
    |--------------------------------------------------------------------------
    */

    windowSeconds:
      intEnv(
        "EMAIL_RESEND_WINDOW_SECONDS",
        60 * 60,
        60,
        24 * 60 * 60
      ),


    /*
    |--------------------------------------------------------------------------
    | Recipient maximum
    |--------------------------------------------------------------------------
    |
    | Default:
    |
    | Maximum 3 resend attempts per recipient during the current window.
    |--------------------------------------------------------------------------
    */

    targetMaxPerWindow:
      intEnv(
        "EMAIL_RESEND_TARGET_MAX_PER_WINDOW",
        3,
        1,
        100
      ),


    /*
    |--------------------------------------------------------------------------
    | Actor maximum
    |--------------------------------------------------------------------------
    |
    | Default:
    |
    | Maximum 30 resend attempts by one authenticated actor during the
    | current window.
    |--------------------------------------------------------------------------
    */

    actorMaxPerWindow:
      intEnv(
        "EMAIL_RESEND_ACTOR_MAX_PER_WINDOW",
        30,
        1,
        1000
      ),

  });


/* ============================================================================
 * Generic helpers
 * ============================================================================
 */

/**
 * Normalize email / actor identifiers.
 */
function normalize(
  value
) {
  return String(
    value ??
    ""
  )
    .trim()
    .toLowerCase();
}


/**
 * Get cryptographic pepper.
 *
 * SECURITY_PEPPER is preferred.
 * JWT_SECRET is used as fallback.
 *
 * We fail closed if neither exists.
 */
function getSecurityPepper() {

  const pepper =
    process.env.SECURITY_PEPPER ||
    process.env.JWT_SECRET ||
    "";

  if (
    !pepper
  ) {
    throw new Error(
      "EMAIL_RESEND_RATE_GUARD_CONFIG_ERROR: " +
      "SECURITY_PEPPER/JWT_SECRET is not configured"
    );
  }

  return pepper;
}


/**
 * HMAC-SHA256 identifier.
 *
 * The actual recipient email / actor email is not stored in the rate-limit
 * record.
 */
function hmac(
  value
) {
  return crypto
    .createHmac(
      "sha256",
      getSecurityPepper()
    )
    .update(
      String(
        value
      ),
      "utf8"
    )
    .digest(
      "hex"
    );
}


/**
 * Create anonymous database marker.
 *
 * Example recipient:
 *
 * ert:abcdef....
 *
 * Example actor:
 *
 * era:abcdef....
 */
function marker(
  prefix,
  value
) {

  const normalized =
    normalize(
      value
    );

  if (
    !normalized
  ) {
    return "";
  }

  const result =
    `${prefix}${hmac(normalized)}`;

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


/**
 * Convert a DB duration safely to a positive integer.
 */
function positiveSeconds(
  value,
  fallback = 1
) {

  const number =
    Math.ceil(
      Number(
        value
      )
    );

  if (
    Number.isFinite(
      number
    ) &&
    number > 0
  ) {
    return number;
  }

  return fallback;
}


/* ============================================================================
 * Counter creation
 * ============================================================================
 */

/**
 * Ensure a rate-limit row exists.
 *
 * Existing DB constraint:
 *
 * UNIQUE(email, purpose)
 *
 * means only one recipient/actor counter can exist for each purpose.
 *
 * This also provides protection when multiple Lambda instances try to create
 * the same counter simultaneously.
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
          UTC_TIMESTAMP(),
          INTERVAL ? SECOND
        ),

        UTC_TIMESTAMP(),

        NULL
      )

      ON DUPLICATE KEY UPDATE
        id = id
    `,
    [
      keyMarker,
      digest,
      purpose,
      POLICY.windowSeconds,
    ]
  );
}


/* ============================================================================
 * Counter lock
 * ============================================================================
 */

/**
 * Read + lock counter.
 *
 * SELECT ... FOR UPDATE is the main concurrency control.
 *
 * Example:
 *
 * Burp sends several requests at the same time.
 *
 * Request 1:
 *   obtains the row lock
 *
 * Request 2:
 *   waits
 *
 * Request 3:
 *   waits
 *
 * Request 1:
 *   increments counter + commits
 *
 * Request 2:
 *   sees updated counter/cooldown
 *
 * Therefore simultaneous requests cannot all see attempts = 0.
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

          CASE

            WHEN expires_at <=
                 UTC_TIMESTAMP()

            THEN 1

            ELSE 0

          END
          AS window_expired,


          GREATEST(
            0,

            TIMESTAMPDIFF(
              SECOND,

              UTC_TIMESTAMP(),

              expires_at
            )
          )
          AS window_remaining_seconds,


          CASE

            WHEN verified_at IS NULL

            THEN 0

            ELSE GREATEST(
              0,

              TIMESTAMPDIFF(
                SECOND,

                UTC_TIMESTAMP(),

                DATE_ADD(
                  verified_at,
                  INTERVAL ? SECOND
                )
              )
            )

          END
          AS cooldown_remaining_seconds

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
        purpose,
      ]
    );


  if (
    !rows ||
    rows.length === 0
  ) {
    throw new Error(
      "EMAIL_RESEND_RATE_GUARD_COUNTER_NOT_FOUND"
    );
  }


  let row =
    rows[0];


  /*
  |--------------------------------------------------------------------------
  | Reset expired window
  |--------------------------------------------------------------------------
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

          created_at =
            UTC_TIMESTAMP(),

          verified_at =
            NULL,

          expires_at =
            DATE_ADD(
              UTC_TIMESTAMP(),
              INTERVAL ? SECOND
            )

        WHERE id = ?

        LIMIT 1
      `,
      [
        digest,
        POLICY.windowSeconds,
        Number(
          row.id
        ),
      ]
    );


    /*
    |--------------------------------------------------------------------------
    | Reflect the reset locally
    |--------------------------------------------------------------------------
    */

    row = {
      ...row,

      attempts:
        0,

      verified_at:
        null,

      window_expired:
        0,

      window_remaining_seconds:
        POLICY.windowSeconds,

      cooldown_remaining_seconds:
        0,
    };

  }


  return row;
}


/* ============================================================================
 * Counter preparation
 * ============================================================================
 */

/**
 * Ensure + lock a particular counter.
 */
async function prepareCounter(
  db,
  keyMarker,
  purpose
) {

  /*
  |--------------------------------------------------------------------------
  | Strip marker prefix
  |--------------------------------------------------------------------------
  |
  | ert: = 4 chars
  | era: = 4 chars
  |--------------------------------------------------------------------------
  */

  const digest =
    keyMarker.slice(
      4
    );


  /*
  |--------------------------------------------------------------------------
  | Ensure counter exists
  |--------------------------------------------------------------------------
  */

  await ensureCounterRow(
    db,
    keyMarker,
    digest,
    purpose
  );


  /*
  |--------------------------------------------------------------------------
  | Lock counter
  |--------------------------------------------------------------------------
  */

  return lockCounterRow(
    db,
    keyMarker,
    digest,
    purpose
  );
}


/* ============================================================================
 * Main Email Bombing rate-limit function
 * ============================================================================
 */

/**
 * Atomically check and reserve one email resend slot.
 *
 * IMPORTANT:
 *
 * `db` must be a mysql2 connection that already has an ACTIVE transaction.
 *
 *
 * Example:
 *
 * await conn.beginTransaction();
 *
 * const rateLimit =
 *   await reserveEmailResendSlot(
 *     conn,
 *     {
 *       targetEmail: recipientEmail,
 *       actorUserId: actorEmail,
 *     }
 *   );
 *
 *
 * if (!rateLimit.allowed) {
 *
 *   await conn.rollback();
 *
 *   return res
 *     .status(429)
 *     .json(...);
 * }
 *
 *
 * await conn.commit();
 *
 * await sendEmail(...);
 *
 *
 * This utility does NOT:
 *
 * - commit
 * - rollback
 * - send email
 * - send HTTP responses
 *
 * Those responsibilities stay with the controller.
 */
async function reserveEmailResendSlot(
  db,
  {
    targetEmail,
    actorUserId,
  }
) {

  /* --------------------------------------------------------------------------
   * Validate connection
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


  if (
    !target
  ) {
    throw new TypeError(
      "targetEmail is required for email resend rate limiting"
    );
  }


  if (
    !actor
  ) {
    throw new TypeError(
      "actorUserId is required for email resend rate limiting"
    );
  }


  /* --------------------------------------------------------------------------
   * Generate anonymous keys
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
   * Recipient protection
   * ==========================================================================
   */

  /*
  |--------------------------------------------------------------------------
  | Lock recipient FIRST
  |--------------------------------------------------------------------------
  |
  | All requests follow the same lock order:
  |
  | recipient
  |    ↓
  | actor
  |
  | This helps reduce DB deadlock risk.
  |--------------------------------------------------------------------------
  */

  const targetRow =
    await prepareCounter(
      db,
      targetMarker,
      PURPOSE_TARGET
    );


  /* --------------------------------------------------------------------------
   * Recipient cooldown
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

      allowed:
        false,

      reason:
        "recipient_cooldown",

      retryAfterSeconds:
        cooldownRemaining,

      policy:
        POLICY,

    };
  }


  /* --------------------------------------------------------------------------
   * Recipient window limit
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

      allowed:
        false,

      reason:
        "recipient_window_limit",

      retryAfterSeconds:
        positiveSeconds(
          targetRow
            .window_remaining_seconds,

          POLICY.windowSeconds
        ),

      policy:
        POLICY,

    };
  }


  /* ==========================================================================
   * Actor protection
   * ==========================================================================
   */

  const actorRow =
    await prepareCounter(
      db,
      actorMarker,
      PURPOSE_ACTOR
    );


  /* --------------------------------------------------------------------------
   * Actor window limit
   * --------------------------------------------------------------------------
   */

  const actorAttempts =
    Number(
      actorRow.attempts
    ) || 0;


  if (
    actorAttempts >=
    POLICY.actorMaxPerWindow
  ) {
    return {

      allowed:
        false,

      reason:
        "actor_window_limit",

      retryAfterSeconds:
        positiveSeconds(
          actorRow
            .window_remaining_seconds,

          POLICY.windowSeconds
        ),

      policy:
        POLICY,

    };
  }


  /* ==========================================================================
   * Reserve allowed resend
   * ==========================================================================
   */

  /*
  |--------------------------------------------------------------------------
  | Recipient counter
  |--------------------------------------------------------------------------
  |
  | verified_at is reused as the most recent allowed resend reservation time.
  |--------------------------------------------------------------------------
  */

  await db.execute(
    `
      UPDATE ${TABLE}

      SET
        attempts =
          attempts + 1,

        verified_at =
          UTC_TIMESTAMP()

      WHERE id = ?

      LIMIT 1
    `,
    [
      Number(
        targetRow.id
      ),
    ]
  );


  /*
  |--------------------------------------------------------------------------
  | Actor counter
  |--------------------------------------------------------------------------
  */

  await db.execute(
    `
      UPDATE ${TABLE}

      SET
        attempts =
          attempts + 1,

        verified_at =
          UTC_TIMESTAMP()

      WHERE id = ?

      LIMIT 1
    `,
    [
      Number(
        actorRow.id
      ),
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
      POLICY,

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

  reserveEmailResendSlot,

};