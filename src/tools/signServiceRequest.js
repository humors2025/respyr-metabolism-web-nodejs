"use strict";

/**
 * signServiceRequest.js — dev/test helper (NOT part of the running app)
 *
 * Generates the four x-respyr-* headers for a service-signed request, so you can
 * call an HMAC-protected endpoint (e.g. get_latest_72hr_tests) from curl/Postman.
 *
 * It reuses the SERVER's own buildCanonicalString() from serviceAuthMiddleware, so
 * the string being signed here is byte-for-byte what the middleware verifies. If
 * this signs it, the middleware accepts it.
 *
 * Usage (from the project root) — PREFER the single --url form:
 *
 *   node src/tools/signServiceRequest.js \
 *     --key-id  plan-generator \
 *     --secret  <the 64-hex secret from SERVICE_API_KEYS> \
 *     --url     "https://api.respyr.ai/dietitian/api/web/get_latest_72hr_tests?limit=100&cursor=0"
 *
 * WHY --url and not --path: on Windows Git Bash (MSYS), any argument that starts
 * with "/" — like a bare --path /dietitian/... — is silently rewritten into a
 * Windows path (C:/Program Files/Git/dietitian/...). That would sign the WRONG
 * path and still yield 401. A full https:// URL never starts with "/", so no
 * shell mangles it. (--path/--base still work in PowerShell/cmd; a bare --path
 * that looks mangled is rejected below.)
 *
 * If you omit --secret, it is read from SERVICE_API_KEYS (the descriptor matching
 * --key-id), so `node -r dotenv/config ...` picks it up from your .env.
 *
 *   --url     full request URL incl. query; path + query are derived from it
 *   --method  defaults to GET
 *   --path    alternative to --url: the request path (no scheme/host)
 *   --query   with --path: the raw query WITHOUT the leading "?"; order does not
 *             matter, it is canonicalised (sorted) exactly as the server does
 *   --base    with --path: origin (e.g. https://api.respyr.ai) for the curl line
 *   --body    optional JSON string for POST/PUT (the body hash is signed)
 *
 * It prints the canonical string, the four headers, and a ready-to-paste curl line.
 */

const crypto = require("crypto");
const {
  buildCanonicalString,
} = require("../middlewares/serviceAuthMiddleware");

// ─── tiny arg parser (--flag value) ───────────────────────────────────────────
function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("--")) {
        out[key] = true;
      } else {
        out[key] = next;
        i += 1;
      }
    }
  }
  return out;
}

/** Look up a key's secret from SERVICE_API_KEYS (simple or descriptor form). */
function secretFromEnv(keyId) {
  const raw = process.env.SERVICE_API_KEYS;
  if (!raw) return null;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  const entry = parsed?.[keyId];
  if (entry === undefined) return null;
  if (typeof entry === "string") return entry;
  if (entry && typeof entry === "object") return String(entry.secret ?? "") || null;
  return null;
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  const keyId = args["key-id"];
  const method = String(args.method || "GET").toUpperCase();
  const bodyStr = typeof args.body === "string" ? args.body : "";
  const secret = args.secret && args.secret !== true ? args.secret : secretFromEnv(keyId);

  // Resolve path / query / base from either --url or the --path/--query/--base trio.
  let path;
  let query;
  let base;

  if (typeof args.url === "string") {
    let parsed;
    try {
      parsed = new URL(args.url);
    } catch {
      console.error(`--url is not a valid absolute URL: ${args.url}`);
      process.exit(1);
    }
    path = parsed.pathname;
    query = parsed.search.startsWith("?") ? parsed.search.slice(1) : parsed.search;
    base = parsed.origin;
  } else {
    path = args.path;
    query = typeof args.query === "string" ? args.query : "";
    base = typeof args.base === "string" ? args.base : "";
  }

  if (!keyId || !path) {
    console.error(
      "Missing required args. Provide --key-id and either --url or --path.\n" +
        "See the header comment in this file for full usage."
    );
    process.exit(1);
  }

  // Guard against Git Bash (MSYS) having rewritten a leading-slash --path into a
  // Windows path. If we see a drive letter, the path was mangled — refuse rather
  // than sign a wrong string that fails with an opaque 401.
  if (/^[A-Za-z]:[\\/]/.test(String(path))) {
    console.error(
      `--path looks mangled by the shell: "${path}"\n` +
        "This is the Git Bash MSYS path-conversion bug. Use --url with a full\n" +
        'https:// URL instead, or prefix the command with MSYS_NO_PATHCONV=1.'
    );
    process.exit(1);
  }
  if (!secret) {
    console.error(
      `No secret for key-id "${keyId}". Pass --secret <value>, or set SERVICE_API_KEYS ` +
        "and run with `node -r dotenv/config src/tools/signServiceRequest.js ...`."
    );
    process.exit(1);
  }

  // Build a minimal req-shaped object with exactly the fields buildCanonicalString reads.
  const url = query ? `${path}?${query}` : path;
  const req = { method, path, url };

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomBytes(24).toString("hex"); // 48 chars, matches NONCE_PATTERN
  const rawBody = Buffer.from(bodyStr, "utf8");

  const canonicalString = buildCanonicalString(req, timestamp, nonce, rawBody);
  const signature =
    "sha256=" +
    crypto.createHmac("sha256", secret).update(canonicalString, "utf8").digest("hex");

  const headers = {
    "x-respyr-key-id": keyId,
    "x-respyr-timestamp": timestamp,
    "x-respyr-nonce": nonce,
    "x-respyr-signature": signature,
  };

  console.log("\n── Canonical string (what both sides sign) ──");
  console.log(JSON.stringify(canonicalString)); // JSON-quoted so the \n are visible
  console.log("\n── Headers ──");
  for (const [k, v] of Object.entries(headers)) console.log(`${k}: ${v}`);

  if (base) {
    const fullUrl = `${base.replace(/\/$/, "")}${url}`;
    const hdr = Object.entries(headers)
      .map(([k, v]) => `-H "${k}: ${v}"`)
      .join(" ");
    const bodyPart = bodyStr
      ? ` -H "Content-Type: application/json" --data '${bodyStr}'`
      : "";
    console.log("\n── curl ──");
    console.log(`curl -sS -X ${method} ${hdr}${bodyPart} "${fullUrl}"`);
  }

  console.log(
    "\nNote: the nonce is single-use. Re-run this to get a fresh one before each request " +
      "(a replayed nonce returns 409 REPLAYED_REQUEST), and send the request within " +
      "±5 min of --timestamp or you get 401 STALE_REQUEST.\n"
  );
}

main();
