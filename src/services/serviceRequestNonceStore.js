"use strict";

/**
 * serviceRequestNonceStore.js  (MySQL-backed, reuses the existing `otp_verifications` table)
 *
 * Single-use nonce store backing replay protection for HMAC-signed service-to-service
 * requests (see middlewares/serviceAuthMiddleware.js).
 *
 * WHY MYSQL (not Redis)
 * ---------------------
 * Same reason dietitianOtpStore.js is MySQL-backed: on AWS Lambda the ioredis client
 * in config/redis.js has no reachable Redis, so every command burns its retry budget
 * and surfaces as a 500 / ~30s timeout. RDS/MySQL is already reachable and reliable
 * from this function, so nonce state lives in MySQL.
 *
 * WHY `otp_verifications` (not a new table)
 * -----------------------------------------
 * Follows the precedent the project owner already chose for the OTP flow: reuse the
 * generic `otp_verifications` table rather than adding one. Rows for this flow live
 * under purpose = 'service_nonce' and every statement here filters on it, so other
 * purposes ('login', 'password_reset', ...) are never touched.
 *
 * STORAGE MODEL
 *   email      -> "svc:" + sha256(keyId ":" nonce)   (69 chars, fits varchar(100))
 *   otp_code   -> sha256(keyId ":" nonce)            — the raw nonce is never stored
 *   purpose    -> 'service_nonce'
 *   expires_at -> NOW() + SERVICE_AUTH_NONCE_TTL_SECONDS (DB clock, so app/DB skew
 *                 is never a factor)
 *
 * ATOMICITY — the unique index IS the gate
 * -----------------------------------------
 * `otp_verifications` carries a UNIQUE index over (email, purpose) — the OTP flow's
 * "one live code per user per purpose" rule. The previous revision of this store put
 * the KEY ID in `email`, which meant the second nonce a key ever presented collided
 * on that index: MySQL raised ER_DUP_ENTRY, consumeNonce() read that as a replay,
 * and every request after the first was rejected with 409 forever.
 *
 * Putting the NONCE HASH in `email` instead turns that same index from a landmine
 * into exactly the atomic "insert if absent" primitive this store always wanted:
 *
 *   INSERT succeeds        -> first presentation -> accept
 *   INSERT hits DUP_ENTRY  -> nonce already live -> replay -> reject
 *
 * No insert-then-count race, no cross-connection read-visibility hazard, and two
 * concurrent duplicates cannot both pass — the index admits exactly one row.
 *
 * A replayed presentation leaves no second row (the index refuses it), and the
 * original row stays burned for its full TTL. MySQL does not auto-expire rows, so
 * pruneExpired() removes dead ones opportunistically.
 *
 * EXPIRY NOTE: a burned nonce blocks re-insertion until its row is pruned, even
 * past expires_at. For 256-bit random nonces an honest collision is impossible, so
 * the only party affected is a replayer — which is the point.
 */

const crypto = require("crypto");
const pool = require("../config/db");

const TABLE = "otp_verifications";
const PURPOSE = "service_nonce";

// email is varchar(100); "svc:" + 64 hex chars = 69. Enforced here anyway so a
// future hash change cannot silently truncate and weaken the uniqueness gate.
const MARKER_PREFIX = "svc:";
const MARKER_MAX_LENGTH = 100;

// ─── Config ───────────────────────────────────────────────────────────────────

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  if (typeof min === "number" && v < min) return min;
  if (typeof max === "number" && v > max) return max;
  return v;
}

/**
 * How long a nonce stays burned. MUST comfortably exceed twice the signature clock-skew
 * window, otherwise a nonce could expire while its timestamp is still considered fresh —
 * which would re-open the replay window this store exists to close.
 */
const NONCE_TTL_SECONDS = intEnv("SERVICE_AUTH_NONCE_TTL_SECONDS", 900, 120, 3600);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function sha256(value) {
  return crypto.createHash("sha256").update(String(value)).digest("hex");
}

/**
 * Best-effort removal of THIS FLOW's expired rows (never other purposes such as
 * 'login' or 'password_reset'). Replaces Redis auto-expiry. Never throws into the
 * caller — a request must not fail because housekeeping failed.
 */
async function pruneExpired() {
  try {
    await pool.execute(
      `DELETE FROM ${TABLE}
        WHERE purpose = ?
          AND expires_at <= NOW()`,
      [PURPOSE]
    );
  } catch (err) {
    console.error("SERVICE_NONCE_PRUNE_FAILED:", err?.code || err?.message);
  }
}

// ─── Consume ──────────────────────────────────────────────────────────────────

/**
 * Burn a nonce for a given key id. Returns { ok: true } the first time the pair is
 * seen and { ok: false } for every subsequent presentation.
 *
 * Throws only on genuine infrastructure failure, which the caller MUST treat as a
 * denial — never as a pass.
 */
async function consumeNonce(keyId, nonce) {
  const hash = sha256(`${String(keyId)}:${String(nonce)}`);
  const marker = (MARKER_PREFIX + hash).slice(0, MARKER_MAX_LENGTH);

  try {
    await pool.execute(
      `INSERT INTO ${TABLE}
         (email, otp_code, purpose, is_verified, attempts, expires_at)
       VALUES
         (?, ?, ?, 0, 0, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
      [marker, hash, PURPOSE, NONCE_TTL_SECONDS]
    );
  } catch (err) {
    // The unique index over (email, purpose) refused a second row for this nonce:
    // it is already live -> replay. This is the atomic gate, not an error.
    if (err?.code === "ER_DUP_ENTRY") return { ok: false };
    throw err;
  }

  // Opportunistic housekeeping; never blocks the request.
  pruneExpired().catch(() => {});

  return { ok: true };
}

module.exports = {
  NONCE_TTL_SECONDS,
  consumeNonce,
  pruneExpired,
};











// "use strict";

// /**
//  * serviceRequestNonceStore.js  (MySQL-backed, reuses the existing `otp_verifications` table)
//  *
//  * Single-use nonce store backing replay protection for HMAC-signed service-to-service
//  * requests (see middlewares/serviceAuthMiddleware.js).
//  *
//  * WHY MYSQL (not Redis)
//  * ---------------------
//  * Same reason dietitianOtpStore.js is MySQL-backed: on AWS Lambda the ioredis client
//  * in config/redis.js has no reachable Redis, so every command burns its retry budget
//  * and surfaces as a 500 / ~30s timeout. config/redis.js is currently imported by
//  * nothing. RDS/MySQL is already reachable and reliable from this function, so nonce
//  * state lives in MySQL.
//  *
//  * WHY `otp_verifications` (not a new table)
//  * -----------------------------------------
//  * Follows the precedent the project owner already chose for the OTP flow: reuse the
//  * generic `otp_verifications` table rather than adding one. It is a one-row-per-token
//  * design with a `purpose` discriminator, so this flow stores its own rows under a
//  * dedicated purpose and NEVER touches rows of other purposes — every statement here
//  * filters on purpose = 'service_nonce'.
//  *
//  * STORAGE MODEL
//  *   email      -> the presented key id (non-secret; scopes the nonce to one caller)
//  *   otp_code   -> sha256(keyId + ":" + nonce)   — the raw nonce is never stored
//  *   purpose    -> 'service_nonce'
//  *   expires_at -> NOW() + SERVICE_AUTH_NONCE_TTL_SECONDS (DB clock, so app/DB skew
//  *                 is never a factor)
//  * MySQL does not auto-expire, so every read filters on `expires_at > NOW()` (expired
//  * == absent) and pruneExpired() removes dead rows.
//  *
//  * ATOMICITY — the insert-then-count pattern
//  * -----------------------------------------
//  * `otp_verifications` has no unique index on otp_code, so "insert if absent" cannot be
//  * done atomically by the DB. Instead: INSERT unconditionally, then COUNT live rows for
//  * that nonce hash. A first, honest request sees exactly 1 → accepted. A replay sees 2
//  * (the original plus its own) → rejected. Two concurrent duplicates both see 2 → both
//  * rejected, which is fail-closed and therefore the safe direction.
//  *
//  * Rejected inserts are deliberately NOT deleted. Leaving the row means the nonce stays
//  * burned for its full TTL, so an attacker cannot force a double-rejection race and then
//  * replay the (now unburned) nonce afterwards. The rows are TTL'd and pruned anyway.
//  *
//  * OPTIONAL HARDENING
//  *   ALTER TABLE otp_verifications ADD UNIQUE KEY uq_service_nonce (purpose, otp_code(64));
//  * With that index the INSERT itself becomes the atomic gate (ER_DUP_ENTRY == replay) and
//  * the COUNT scan disappears. consumeNonce() already treats ER_DUP_ENTRY as a replay, so
//  * adding the index is a drop-in upgrade requiring no code change. Left optional because
//  * it is a schema change to a table another flow shares.
//  */

// const crypto = require("crypto");
// const pool = require("../config/db");

// const TABLE = "otp_verifications";
// const PURPOSE = "service_nonce";

// // ─── Config ───────────────────────────────────────────────────────────────────

// function intEnv(name, def, min, max) {
//   const v = parseInt(process.env[name], 10);
//   if (!Number.isFinite(v)) return def;
//   if (typeof min === "number" && v < min) return min;
//   if (typeof max === "number" && v > max) return max;
//   return v;
// }

// /**
//  * How long a nonce stays burned. MUST comfortably exceed twice the signature clock-skew
//  * window, otherwise a nonce could expire while its timestamp is still considered fresh —
//  * which would re-open the replay window this store exists to close.
//  */
// const NONCE_TTL_SECONDS = intEnv("SERVICE_AUTH_NONCE_TTL_SECONDS", 900, 120, 3600);

// // ─── Helpers ──────────────────────────────────────────────────────────────────

// function sha256(value) {
//   return crypto.createHash("sha256").update(String(value)).digest("hex");
// }

// /**
//  * Best-effort removal of THIS FLOW's expired rows (never other purposes such as
//  * 'login' or 'password_reset'). Replaces Redis auto-expiry. Never throws into the
//  * caller — a request must not fail because housekeeping failed.
//  */
// async function pruneExpired() {
//   try {
//     await pool.execute(
//       `DELETE FROM ${TABLE}
//         WHERE purpose = ?
//           AND expires_at <= NOW()`,
//       [PURPOSE]
//     );
//   } catch (err) {
//     console.error("SERVICE_NONCE_PRUNE_FAILED:", err?.code || err?.message);
//   }
// }

// // ─── Consume ──────────────────────────────────────────────────────────────────

// /**
//  * Burn a nonce for a given key id. Returns { ok: true } the first time the pair is
//  * seen and { ok: false } for every subsequent presentation inside the TTL.
//  *
//  * Throws only on genuine infrastructure failure, which the caller MUST treat as a
//  * denial — never as a pass.
//  */
// async function consumeNonce(keyId, nonce) {
//   const hash = sha256(`${String(keyId)}:${String(nonce)}`);

//   let insertedId = null;

//   try {
//     const [result] = await pool.execute(
//       `INSERT INTO ${TABLE}
//          (email, otp_code, purpose, is_verified, attempts, expires_at)
//        VALUES
//          (?, ?, ?, 0, 0, DATE_ADD(NOW(), INTERVAL ? SECOND))`,
//       [String(keyId).slice(0, 100), hash, PURPOSE, NONCE_TTL_SECONDS]
//     );
//     insertedId = result.insertId;
//   } catch (err) {
//     // Present only once the optional UNIQUE index above is added: the DB itself
//     // caught the replay.
//     if (err?.code === "ER_DUP_ENTRY") return { ok: false };
//     throw err;
//   }

//   const [rows] = await pool.execute(
//     `SELECT COUNT(*) AS hits
//        FROM ${TABLE}
//       WHERE purpose = ?
//         AND otp_code = ?
//         AND expires_at > NOW()`,
//     [PURPOSE, hash]
//   );

//   const hits = Number(rows?.[0]?.hits || 0);

//   // >1 means this nonce was already live before we inserted → replay. Our row stays
//   // on purpose (see the ATOMICITY note above): deleting it would unburn the nonce.
//   if (hits > 1) {
//     return { ok: false };
//   }

//   // 0 should be impossible (we just inserted). Treat it as a store malfunction and
//   // fail closed rather than assume freshness.
//   if (hits < 1) {
//     console.error("SERVICE_NONCE_STORE_INCONSISTENT:", { insertedId });
//     return { ok: false };
//   }

//   // Opportunistic housekeeping; never blocks the request.
//   pruneExpired().catch(() => {});

//   return { ok: true };
// }

// module.exports = {
//   NONCE_TTL_SECONDS,
//   consumeNonce,
//   pruneExpired,
// };
