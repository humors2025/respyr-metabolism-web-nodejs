"use strict";

/**
 * check-phi-access-control.js
 *
 * CI guard (HIPAA §164.312(a)(1) / VAPT API1:2023 BOLA).
 *
 * Fails the build if any controller that queries a PHI table does NOT route
 * through the shared access-control module. This is the cross-platform Node
 * replacement for the original bash one-liner (which used `comm`/`grep` and does
 * not run on Windows), and it recognizes BOTH families of access control:
 *
 *   - single-tenant : requireProfileAccess / requireDieticianSelfAccess
 *   - hierarchical  : resolveActorFromToken / resolveActorByDieticianId /
 *                     resolveActorByEmail / actorCanAccessCode /
 *                     requireNetworkAccess
 *
 * A PHI controller passes when it imports ../utils/accessControl (the single
 * audited choke point) OR references one of the access-control helpers above.
 *
 * Usage:  node scripts/check-phi-access-control.js
 * Exit 0 = clean, Exit 1 = one or more unguarded PHI controllers.
 */

const fs = require("fs");
const path = require("path");

const CONTROLLERS_DIR = path.join(__dirname, "..", "src", "controllers");

// PHI tables whose presence means the file handles protected health info.
const PHI_TABLE_RE = /\b(table_clients|table_test_data)\b/;

// Any of these in the file's text counts as "has access control".
const ACCESS_MARKERS = [
  "utils/accessControl",        // imports the shared module
  "requireProfileAccess",
  "requireDieticianSelfAccess",
  "resolveActorFromToken",
  "resolveActorByDieticianId",
  "resolveActorByEmail",
  "actorCanAccessCode",
  "requireNetworkAccess",
];

// True if the text contains a raw control byte (NUL, etc.) that would blind a
// text-based scanner. Tab/newline/carriage-return are allowed.
function hasControlByte(text) {
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c < 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) return true;
  }
  return false;
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else if (entry.isFile() && entry.name.endsWith(".js")) out.push(full);
  }
  return out;
}

function main() {
  if (!fs.existsSync(CONTROLLERS_DIR)) {
    console.error(`PHI access-control check: controllers dir not found: ${CONTROLLERS_DIR}`);
    process.exit(2);
  }

  const offenders = [];
  let phiFiles = 0;

  for (const file of walk(CONTROLLERS_DIR)) {
    const src = fs.readFileSync(file, "utf8");

    // Reject stray control bytes (e.g. embedded NUL) that blind scanners.
    if (hasControlByte(src)) {
      offenders.push({ file, reason: "contains raw control byte(s) — re-save as clean UTF-8" });
      continue;
    }

    if (!PHI_TABLE_RE.test(src)) continue;
    phiFiles++;

    const guarded = ACCESS_MARKERS.some((m) => src.includes(m));
    if (!guarded) {
      offenders.push({ file, reason: "queries a PHI table but calls no access-control helper" });
    }
  }

  const rel = (f) => path.relative(path.join(__dirname, ".."), f).replace(/\\/g, "/");

  if (offenders.length) {
    console.error(
      `\nx PHI access-control check FAILED - ${offenders.length} controller(s) of ${phiFiles} PHI controller(s):\n`
    );
    for (const o of offenders) console.error(`  - ${rel(o.file)}\n      ${o.reason}`);
    console.error(
      "\nEvery PHI controller must route through src/utils/accessControl " +
        "(requireProfileAccess for single-tenant, or resolveActorFromToken + " +
        "actorCanAccessCode for hierarchical/network endpoints).\n"
    );
    process.exit(1);
  }

  console.log(`PHI access-control check passed - ${phiFiles} PHI controller(s) all guarded.`);
}

main();
