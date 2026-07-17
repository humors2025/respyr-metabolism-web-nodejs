"use strict";

/**
 * serviceAuthMiddleware.js
 *
 * Machine-to-machine authentication for endpoints called by backend services
 * (the AI meal-plan generator, automation flows, cron jobs) rather than by a
 * signed-in dietitian. Those callers hold no dietitian JWT, so authMiddleware
 * cannot apply — but HIPAA §164.312(d) still requires the entity to be
 * authenticated before it touches PHI. This middleware is that control.
 *
 * It is deliberately modelled on AWS SigV4 / Stripe webhook signing, which are
 * the shapes a pentester expects to see:
 *
 *   x-respyr-key-id      non-secret key identifier (selects the shared secret)
 *   x-respyr-timestamp   unix seconds; request is rejected outside ±skew
 *   x-respyr-nonce       caller-generated random value, single-use
 *   x-respyr-signature   "sha256=" + HMAC-SHA256(secret, canonical string)
 *
 * Canonical string (newline-joined, signed by the caller):
 *
 *   v1
 *   <HTTP METHOD, upper-case>
 *   <request path, no query, no trailing slash>
 *   <canonical query string, or "" when there is none>
 *   <timestamp>
 *   <nonce>
 *   <sha256 hex of the RAW request body, or of "" for a bodyless request>
 *
 * Signing the body hash — not the parsed body — means the bytes that were
 * authenticated are exactly the bytes that get parsed, closing the JSON-parser
 * differential that body-reserialisation would open. This requires index.js to
 * stash the raw buffer via express.json({ verify }); a request that declares a
 * body we did not capture is rejected rather than waved through.
 *
 * The query is signed for the same reason the body is: a GET carries its entire
 * input there. See canonicalQuery() for the normalisation rules.
 *
 * Empty-string sha256 (useful when hand-testing a GET):
 *   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 *
 * VAPT properties:
 *  - Secrets never travel on the wire; only a signature over them does.
 *  - Signature comparison is constant-time (crypto.timingSafeEqual).
 *  - The timestamp window bounds the replay surface; the single-use nonce closes
 *    it (serviceRequestNonceStore.js). A store failure denies — it never passes.
 *  - Every failure is audited to app_auth_logs with IP/UA/identifier HMAC-hashed.
 *  - Fails closed: no keys configured → 503, not "open".
 *  - Client-facing errors are deliberately coarse ("Invalid request signature")
 *    so probing cannot distinguish a bad key from a bad signature from a replay.
 *    The precise reason goes to the audit log and server logs only.
 *  - Optional IP allowlist and per-key dietician scoping (minimum necessary).
 *
 * ── Configuration ────────────────────────────────────────────────────────────
 *
 * SERVICE_API_KEYS — JSON object, key id → secret (or → descriptor). Required.
 *
 *   Simple:
 *     {"plan-generator":"<64+ hex chars of CSPRNG output>"}
 *
 *   With least-privilege scoping and a label for the audit trail:
 *     {
 *       "plan-generator": {
 *         "secret": "<64+ hex chars>",
 *         "name": "AI weekly plan generator",
 *         "dietician_codes": ["RESPYRD05", "RESPYRD09"]
 *       }
 *     }
 *
 *   dietician_codes omitted (or ["*"]) means the key may act for any dietician.
 *   Prefer an explicit list — it is the difference between a leaked key exposing
 *   two practices and it exposing every practice on the platform.
 *
 * SERVICE_AUTH_MAX_SKEW_SECONDS  default 300 (±5 min), clamped to [30, 900]
 * SERVICE_AUTH_IP_ALLOWLIST      optional CSV of exact client IPs
 * SERVICE_AUTH_NONCE_TTL_SECONDS see serviceRequestNonceStore.js
 *
 * Generate a secret with:  openssl rand -hex 32
 * Store SERVICE_API_KEYS in AWS Secrets Manager, not plaintext Lambda env —
 * it is a PHI-write credential and belongs with the other secrets already
 * queued for migration.
 */

const crypto = require("crypto");
const pool = require("../config/db");
const { consumeNonce } = require("../services/serviceRequestNonceStore");

// ─── Constants ───────────────────────────────────────────────────────────────

const SECURITY_PEPPER =
  process.env.SECURITY_PEPPER || process.env.JWT_SECRET || "";

const SIGNATURE_VERSION = "v1";
const SIGNATURE_PREFIX = "sha256=";

// Bounds on presented header values — reject absurd input before doing any work.
const KEY_ID_MAX_LENGTH = 100;
const NONCE_MIN_LENGTH = 16;
const NONCE_MAX_LENGTH = 128;

// A nonce must look like a random token. Anything else is a caller bug or a probe.
const NONCE_PATTERN = /^[A-Za-z0-9_-]+$/;

function intEnv(name, def, min, max) {
  const v = parseInt(process.env[name], 10);
  if (!Number.isFinite(v)) return def;
  if (typeof min === "number" && v < min) return min;
  if (typeof max === "number" && v > max) return max;
  return v;
}

const MAX_SKEW_SECONDS = intEnv("SERVICE_AUTH_MAX_SKEW_SECONDS", 300, 30, 900);

// ─── Key registry (parsed once, at cold start) ───────────────────────────────

/**
 * Parse SERVICE_API_KEYS into Map<keyId, { secret, name, dieticianCodes|null }>.
 * dieticianCodes === null means unrestricted.
 *
 * A malformed or weak registry yields an EMPTY map, which makes every request
 * 503 rather than silently authenticating against a half-loaded config.
 */
function loadServiceKeys() {
  const registry = new Map();
  const raw = process.env.SERVICE_API_KEYS;

  if (!raw || String(raw).trim() === "") {
    console.warn("SERVICE_AUTH_NO_KEYS_CONFIGURED: SERVICE_API_KEYS is unset; service endpoints will 503");
    return registry;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    console.error("SERVICE_AUTH_KEYS_UNPARSEABLE:", err?.message);
    return registry;
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    console.error("SERVICE_AUTH_KEYS_INVALID: SERVICE_API_KEYS must be a JSON object");
    return registry;
  }

  for (const [keyId, value] of Object.entries(parsed)) {
    const id = String(keyId).trim();

    if (id === "" || id.length > KEY_ID_MAX_LENGTH) {
      console.error("SERVICE_AUTH_KEY_SKIPPED: key id missing or too long");
      continue;
    }

    const descriptor =
      value !== null && typeof value === "object" && !Array.isArray(value)
        ? value
        : { secret: value };

    const secret = String(descriptor.secret ?? "");

    // A short shared secret is a brute-forceable one. Refuse it at boot rather
    // than let it quietly protect a PHI write path.
    if (secret.length < 32) {
      console.error("SERVICE_AUTH_KEY_SKIPPED: secret too short (min 32 chars) for key id", id);
      continue;
    }

    let dieticianCodes = null;
    if (Array.isArray(descriptor.dietician_codes)) {
      const codes = descriptor.dietician_codes
        .map((c) => String(c).trim().toUpperCase())
        .filter((c) => c !== "");
      // ["*"] is an explicit, greppable "any practice" rather than an accident.
      dieticianCodes = codes.includes("*") ? null : new Set(codes);
    }

    registry.set(id, {
      secret,
      name: String(descriptor.name ?? id).slice(0, 100),
      dieticianCodes,
    });
  }

  if (registry.size === 0) {
    console.error("SERVICE_AUTH_NO_USABLE_KEYS: every entry in SERVICE_API_KEYS was rejected");
  }

  return registry;
}

const SERVICE_KEYS = loadServiceKeys();

// ─── IP allowlist (optional) ─────────────────────────────────────────────────

const IP_ALLOWLIST = new Set(
  String(process.env.SERVICE_AUTH_IP_ALLOWLIST || "")
    .split(",")
    .map((ip) => ip.trim())
    .filter((ip) => ip !== "")
);

// ─── Request helpers ─────────────────────────────────────────────────────────

function getClientIp(req) {
  const ip =
    (typeof req.ip === "string" && req.ip) ||
    req.socket?.remoteAddress ||
    req.connection?.remoteAddress ||
    "0.0.0.0";
  return String(ip).slice(0, 64);
}

function getUserAgent(req) {
  const ua =
    (typeof req.get === "function" && req.get("user-agent")) ||
    req.headers?.["user-agent"] ||
    "";
  return String(ua).slice(0, 500);
}

function header(req, name) {
  const value = req.headers?.[name];
  if (Array.isArray(value)) return String(value[0] ?? "").trim();
  return String(value ?? "").trim();
}

function authLogHash(value) {
  if (value === null || value === undefined) return null;
  return crypto
    .createHmac("sha256", SECURITY_PEPPER)
    .update(String(value).trim().toLowerCase())
    .digest("hex");
}

// ─── Audit log (fail-safe, HMAC-hashed PII) ──────────────────────────────────

async function writeAuthLogSafe(req, { eventType, userId, identifier, success, failureReason }) {
  try {
    await pool.execute(
      `INSERT INTO app_auth_logs (
         event_type,
         user_id,
         role,
         partner_code,
         identifier_hash,
         ip_hash,
         user_agent_hash,
         session_id_hash,
         success,
         failure_reason
       )
       VALUES (?, ?, 'service', NULL, ?, ?, ?, NULL, ?, ?)`,
      [
        String(eventType || "").slice(0, 60),
        userId !== null && userId !== undefined ? String(userId).slice(0, 191) : null,
        identifier !== null && identifier !== undefined ? authLogHash(identifier) : null,
        authLogHash(getClientIp(req)),
        authLogHash(getUserAgent(req)),
        success ? 1 : 0,
        failureReason !== null && failureReason !== undefined
          ? String(failureReason).slice(0, 255)
          : null,
      ]
    );
  } catch (err) {
    console.error("SERVICE_AUTH_AUDIT_FAILED:", err?.code || err?.message);
  }
}

// ─── Signature ───────────────────────────────────────────────────────────────

/**
 * The path as Express sees it AFTER index.js strips the API Gateway stage prefix,
 * with any trailing slash removed. This is what the caller must sign.
 */
function canonicalPath(req) {
  const path = String(req.path || "/").split("?")[0];
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

/** RFC-3986 encoding — encodeURIComponent leaves !'()* unescaped. */
function rfc3986(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()
  );
}

/**
 * Canonical query string: every pair decoded, re-encoded, and sorted by key then
 * value. Sorting and re-encoding mean two equivalent spellings of the same query
 * (?b=2&a=1 vs ?a=1&b=2, %7E vs ~) produce one signature, so a caller cannot be
 * broken by a proxy or client library reordering or re-escaping its params.
 *
 * The query MUST be signed. GET endpoints carry their entire input here, so
 * leaving it out would let anyone who observes one signed URL alter its
 * parameters at will and still present a valid signature.
 *
 * Throws on malformed percent-encoding; the caller turns that into a rejection.
 */
function canonicalQuery(req) {
  const url = String(req.url || "");
  const idx = url.indexOf("?");
  if (idx === -1) return "";

  const raw = url.slice(idx + 1);
  if (raw === "") return "";

  const pairs = raw
    .split("&")
    .filter((part) => part !== "")
    .map((part) => {
      const eq = part.indexOf("=");
      const key = eq === -1 ? part : part.slice(0, eq);
      const value = eq === -1 ? "" : part.slice(eq + 1);
      // decodeURIComponent throws on malformed input (e.g. "%zz") — intentional.
      return [rfc3986(decodeURIComponent(key)), rfc3986(decodeURIComponent(value))];
    });

  pairs.sort((a, b) => (a[0] === b[0] ? (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0) : a[0] < b[0] ? -1 : 1));

  return pairs.map(([k, v]) => `${k}=${v}`).join("&");
}

function buildCanonicalString(req, timestamp, nonce, rawBody) {
  const bodyHash = crypto.createHash("sha256").update(rawBody).digest("hex");
  return [
    SIGNATURE_VERSION,
    String(req.method || "").toUpperCase(),
    canonicalPath(req),
    canonicalQuery(req),
    String(timestamp),
    String(nonce),
    bodyHash,
  ].join("\n");
}

function signCanonicalString(secret, canonicalString) {
  return crypto.createHmac("sha256", secret).update(canonicalString, "utf8").digest("hex");
}

/** Constant-time compare of two hex digests of known-equal length. */
function signaturesMatch(expectedHex, presentedHex) {
  const a = Buffer.from(expectedHex, "utf8");
  const b = Buffer.from(presentedHex, "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// ─── Middleware ──────────────────────────────────────────────────────────────

/**
 * Rejects with a deliberately uninformative body. `reason` is for the audit trail
 * and server logs only — never the client.
 *
 * The audit write is AWAITED rather than fired-and-forgotten: on Lambda the
 * execution environment may freeze the moment the response is flushed, so a
 * detached INSERT can simply never run. Losing the record of a rejected
 * authentication attempt is precisely the loss HIPAA §164.312(b) forbids, and it
 * would also erase the trail a brute-force attempt leaves behind. writeAuthLogSafe
 * swallows its own errors, so this can delay a denial but never block one.
 */
async function deny(req, res, { status, clientMessage, code, reason, keyId }) {
  console.warn("SERVICE_AUTH_DENIED:", {
    path: canonicalPath(req),
    keyId: keyId || null,
    reason,
  });

  await writeAuthLogSafe(req, {
    eventType: "service_auth_denied",
    userId: keyId || null,
    identifier: canonicalPath(req),
    success: false,
    failureReason: reason,
  });

  return res.status(status).json({
    success: false,
    message: clientMessage,
    error: { code },
  });
}

const serviceAuthMiddleware = async (req, res, next) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  try {
    // ── 0. Fail closed if the service is misconfigured ──────────────────────
    if (SERVICE_KEYS.size === 0) {
      return deny(req, res, {
        status: 503,
        clientMessage: "Service authentication is not configured",
        code: "SERVICE_AUTH_UNAVAILABLE",
        reason: "no usable keys in SERVICE_API_KEYS",
      });
    }

    if (!SECURITY_PEPPER) {
      return deny(req, res, {
        status: 503,
        clientMessage: "Service authentication is not configured",
        code: "SERVICE_AUTH_UNAVAILABLE",
        reason: "SECURITY_PEPPER/JWT_SECRET unset — audit hashing would be unkeyed",
      });
    }

    // ── 1. Network-level allowlist (optional, cheap, first) ─────────────────
    if (IP_ALLOWLIST.size > 0 && !IP_ALLOWLIST.has(getClientIp(req))) {
      return deny(req, res, {
        status: 403,
        clientMessage: "Forbidden",
        code: "FORBIDDEN",
        reason: "client IP not in SERVICE_AUTH_IP_ALLOWLIST",
      });
    }

    // ── 2. Required headers ─────────────────────────────────────────────────
    const keyId = header(req, "x-respyr-key-id");
    const timestampRaw = header(req, "x-respyr-timestamp");
    const nonce = header(req, "x-respyr-nonce");
    const signatureRaw = header(req, "x-respyr-signature");

    if (keyId === "" || timestampRaw === "" || nonce === "" || signatureRaw === "") {
      return deny(req, res, {
        status: 401,
        clientMessage: "Invalid request signature",
        code: "UNAUTHENTICATED",
        reason: "missing one or more signature headers",
      });
    }

    if (keyId.length > KEY_ID_MAX_LENGTH) {
      return deny(req, res, {
        status: 401,
        clientMessage: "Invalid request signature",
        code: "UNAUTHENTICATED",
        reason: "key id too long",
      });
    }

    if (
      nonce.length < NONCE_MIN_LENGTH ||
      nonce.length > NONCE_MAX_LENGTH ||
      !NONCE_PATTERN.test(nonce)
    ) {
      return deny(req, res, {
        status: 401,
        clientMessage: "Invalid request signature",
        code: "UNAUTHENTICATED",
        reason: "nonce missing, too short, or malformed",
        keyId,
      });
    }

    // ── 3. Freshness — bounds the replay window ─────────────────────────────
    if (!/^\d{1,19}$/.test(timestampRaw)) {
      return deny(req, res, {
        status: 401,
        clientMessage: "Invalid request signature",
        code: "UNAUTHENTICATED",
        reason: "timestamp not a unix-seconds integer",
        keyId,
      });
    }

    const timestamp = Number(timestampRaw);
    const skew = Math.abs(Math.floor(Date.now() / 1000) - timestamp);

    if (!Number.isSafeInteger(timestamp) || skew > MAX_SKEW_SECONDS) {
      return deny(req, res, {
        status: 401,
        clientMessage: "Request timestamp is outside the accepted window",
        code: "STALE_REQUEST",
        reason: `clock skew ${skew}s exceeds ${MAX_SKEW_SECONDS}s`,
        keyId,
      });
    }

    // ── 4. Raw body — the bytes that were actually signed ───────────────────
    // index.js stashes this via express.json({ verify }). A bodyless request (GET)
    // legitimately has none and signs the hash of the empty string. But a request
    // that DECLARES a body we failed to capture — wrong content-type, parser
    // misconfiguration — is unverifiable, and we must never sign around bytes we
    // did not see. Distinguishing the two is what stops an attacker smuggling an
    // unsigned body past a signature computed over "empty".
    let rawBody = req.rawBody;

    if (!Buffer.isBuffer(rawBody)) {
      const declaredLength = Number(req.headers["content-length"] || 0);
      const isChunked = String(req.headers["transfer-encoding"] || "").trim() !== "";

      if (declaredLength > 0 || isChunked) {
        return deny(req, res, {
          status: 400,
          clientMessage: "Request body must be sent as application/json",
          code: "INVALID_BODY",
          reason: "body present but not captured — cannot verify signature",
          keyId,
        });
      }

      rawBody = Buffer.alloc(0);
    }

    // ── 5. Verify the signature ─────────────────────────────────────────────
    const client = SERVICE_KEYS.get(keyId);

    // An unknown key id and a bad signature must be indistinguishable to the
    // caller, and must cost the same. Sign against a decoy secret so the
    // unknown-key path does the same HMAC work as the real one.
    const secret = client ? client.secret : crypto.randomBytes(32).toString("hex");

    // canonicalQuery() throws on malformed percent-encoding. That is a bad request,
    // not a server fault — catch it here so the outer handler cannot mislabel it 503.
    let canonicalString;
    try {
      canonicalString = buildCanonicalString(req, timestamp, nonce, rawBody);
    } catch (err) {
      return deny(req, res, {
        status: 400,
        clientMessage: "Malformed query string",
        code: "INVALID_QUERY",
        reason: "query string is not valid percent-encoding",
        keyId,
      });
    }

    const expected = signCanonicalString(secret, canonicalString);

    const presented = signatureRaw.startsWith(SIGNATURE_PREFIX)
      ? signatureRaw.slice(SIGNATURE_PREFIX.length)
      : signatureRaw;

    const matched = signaturesMatch(expected, presented);

    if (!client || !matched) {
      return deny(req, res, {
        status: 401,
        clientMessage: "Invalid request signature",
        code: "UNAUTHENTICATED",
        reason: client ? "signature mismatch" : "unknown key id",
        keyId,
      });
    }

    // ── 6. Burn the nonce — closes the replay window the skew allowance opens ─
    let nonceResult;
    try {
      nonceResult = await consumeNonce(keyId, nonce);
    } catch (err) {
      // The store is unreachable. Without it we cannot detect replay, so deny.
      console.error("SERVICE_AUTH_NONCE_STORE_ERROR:", {
        code: err?.code,
        errno: err?.errno,
        sqlState: err?.sqlState,
        message: err?.message,
      });
      return deny(req, res, {
        status: 503,
        clientMessage: "Service temporarily unavailable",
        code: "SERVICE_AUTH_UNAVAILABLE",
        reason: "nonce store unavailable — failing closed",
        keyId,
      });
    }

    if (!nonceResult.ok) {
      return deny(req, res, {
        status: 409,
        clientMessage: "Request has already been processed",
        code: "REPLAYED_REQUEST",
        reason: "nonce already used",
        keyId,
      });
    }

    // ── 7. Authenticated. Hand the caller identity to the controller ────────
    req.serviceClient = {
      keyId,
      name: client.name,
      dieticianCodes: client.dieticianCodes, // null === unrestricted
    };

    return next();
  } catch (err) {
    console.error("SERVICE_AUTH_ERROR:", {
      code: err?.code,
      message: err?.message,
    });
    return deny(req, res, {
      status: 503,
      clientMessage: "Service temporarily unavailable",
      code: "SERVICE_AUTH_UNAVAILABLE",
      reason: err?.code || "internal_error",
    });
  }
};

/**
 * Is this authenticated service key permitted to act for `dieticianId`?
 * Controllers call this to enforce per-key scoping (HIPAA minimum necessary).
 */
function serviceKeyCanUseDieticianCode(serviceClient, dieticianId) {
  if (!serviceClient) return false;
  if (serviceClient.dieticianCodes === null) return true;
  return serviceClient.dieticianCodes.has(String(dieticianId).trim().toUpperCase());
}

module.exports = serviceAuthMiddleware;
module.exports.serviceAuthMiddleware = serviceAuthMiddleware;
module.exports.serviceKeyCanUseDieticianCode = serviceKeyCanUseDieticianCode;
module.exports.buildCanonicalString = buildCanonicalString;
module.exports.MAX_SKEW_SECONDS = MAX_SKEW_SECONDS;
