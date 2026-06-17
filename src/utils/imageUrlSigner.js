const crypto = require("crypto");
const { normalizeId, normalizeDieticianId } = require("./accessControl");

/**
 * Short-lived, unforgeable signing for profile-image URLs so they can be loaded
 * directly in browser <img> tags (which cannot send an Authorization header)
 * without exposing PHI to enumeration.
 *
 * The signature binds dietician_id + profile_id + expiry with an HMAC over a
 * server secret. get_profile_image verifies the signature instead of a JWT, so
 * only links minted by the (already JWT-authenticated) dashboard endpoints work,
 * and only until they expire.
 */

const DEFAULT_TTL_SECONDS = 60 * 60; // 1 hour — matches image Cache-Control max-age

const getSecret = () => {
  const secret = process.env.IMAGE_URL_SECRET || process.env.JWT_SECRET;
  if (!secret) {
    throw new Error("IMAGE_URL_SECRET_MISSING");
  }
  return secret;
};

const computeSignature = (dieticianId, profileId, exp) => {
  const payload = `${dieticianId}|${profileId}|${exp}`;
  return crypto.createHmac("sha256", getSecret()).update(payload).digest("hex");
};

/**
 * Build a signed absolute URL for a client's profile image.
 * Returns null when ids are invalid or no base URL is available.
 */
const signProfileImageUrl = (
  baseUrl,
  dieticianId,
  profileId,
  ttlSeconds = DEFAULT_TTL_SECONDS
) => {
  const normalizedDietician = normalizeDieticianId(dieticianId);
  const normalizedProfile = normalizeId(profileId);

  if (!normalizedDietician || !normalizedProfile) return null;
  if (!baseUrl) return null;

  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const sig = computeSignature(normalizedDietician, normalizedProfile, exp);

  return (
    `${baseUrl}/dietitian/api/web/get_profile_image` +
    `?dietician_id=${encodeURIComponent(normalizedDietician)}` +
    `&profile_id=${encodeURIComponent(normalizedProfile)}` +
    `&exp=${exp}&sig=${sig}`
  );
};

/**
 * Verify a signed profile-image request. Returns { valid, dieticianId,
 * profileId } on success, or { valid:false } on any failure (bad ids, missing
 * params, expired, or signature mismatch).
 */
const verifyProfileImageSignature = (query) => {
  const dieticianId = normalizeDieticianId(query?.dietician_id);
  const profileId = normalizeId(query?.profile_id);
  const exp = Number(query?.exp);
  const sig = typeof query?.sig === "string" ? query.sig : "";

  if (!dieticianId || !profileId || !Number.isFinite(exp) || !sig) {
    return { valid: false };
  }

  if (exp < Math.floor(Date.now() / 1000)) {
    return { valid: false };
  }

  const expected = computeSignature(dieticianId, profileId, exp);

  const sigBuf = Buffer.from(sig, "hex");
  const expectedBuf = Buffer.from(expected, "hex");

  if (
    sigBuf.length !== expectedBuf.length ||
    !crypto.timingSafeEqual(sigBuf, expectedBuf)
  ) {
    return { valid: false };
  }

  return { valid: true, dieticianId, profileId };
};

module.exports = {
  DEFAULT_TTL_SECONDS,
  signProfileImageUrl,
  verifyProfileImageSignature,
};
