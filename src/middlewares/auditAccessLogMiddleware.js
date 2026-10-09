"use strict";

/**
 * Global API access audit — guarantees that every request this backend
 * handles leaves at least one row in app_auth_logs, without writing a second
 * row for requests whose controller already audits itself.
 *
 * How: the middleware opens a per-request context (src/config/auditContext.js).
 * The database pool (src/config/db.js) marks that context the moment any code
 * issues an INSERT INTO app_auth_logs, whichever controller or helper does it
 * and whether or not it awaits the insert. When the response ends, the
 * middleware writes a generic access row only if nothing was marked.
 *
 * There is no hand-maintained list of "self-auditing" routes any more. The
 * old list went stale within weeks (routes added after it was written were
 * logged twice, and routes on it whose controllers only logged their failures
 * left no row on success). Now a new route is covered by default, a route
 * that gains its own audit write stops being double-logged by itself, and a
 * failure-only logger still gets an access row on success.
 *
 * Never audited: the two health checks, the audit log's own live-poll
 * endpoint (it reads the log every few seconds and writes nothing on
 * purpose), CORS preflights, and 404s (a scanner probing unknown URLs would
 * otherwise flood the table).
 *
 * Lambda constraint (the reason for the res.end interception): lambda.js sets
 * callbackWaitsForEmptyEventLoop = false, so any DB write still in flight when
 * the response goes out can be frozen with the container and lost. The insert
 * therefore runs BEFORE the original res.end is invoked, bounded by
 * AUDIT_WRITE_TIMEOUT_MS so a DB stall can never hang responses. The same
 * "audit before respond" ordering is what the self-auditing controllers do.
 *
 * Mount order matters: after the /v1 strip (so paths are canonical) and after
 * the body parsers (so the request context reaches every handler); index.js
 * does both.
 *
 * PII policy matches writeAuthLogSafe: ip / user-agent / identifier / sid are
 * HMAC-hashed with SECURITY_PEPPER; user_id carries the same value the JWT
 * carries (email), consistent with the existing rows in the table.
 */

const pool = require("../config/db");
const auditContext = require("../config/auditContext");
const {
  authLogHash,
  getClientIp,
  getUserAgent,
} = require("../controllers/dietitian/api/web/auth_common");

const AUDIT_WRITE_TIMEOUT_MS = 1500;

// Never audited: health checks and the audit log's own live poll.
const NEVER_AUDITED = new Set([
  "/",
  "/health",
  "/dietitian/api/web/audit-logs/live",
]);

/** "/dietitian/api/web/create-checkout-session" -> "create_checkout_session" */
function eventTypeFromPath(path) {
  const segments = String(path || "").split("/").filter(Boolean);
  const slug = segments.slice(-1)[0] || "root";
  return slug.replace(/[^a-zA-Z0-9]+/g, "_").toLowerCase().slice(0, 60);
}

function normalizePath(path) {
  const clean = String(path || "/").split("?")[0];
  return clean.length > 1 && clean.endsWith("/") ? clean.slice(0, -1) : clean;
}

function shouldAudit(req, res) {
  if (req.method === "OPTIONS") return false;

  const path = normalizePath(req.path);
  if (NEVER_AUDITED.has(path)) return false;

  // Unknown routes: 404 probes from scanners would flood the table.
  if (res.statusCode === 404) return false;

  return true;
}

async function writeAccessLog(req, res) {
  const user = req.user || null;
  const userId = user?.user_id || user?.dietician_id || null;

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
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      eventTypeFromPath(req.path),
      userId !== null ? String(userId).slice(0, 191) : null,
      user?.role ? String(user.role).slice(0, 60) : null,
      user?.partner_code ? String(user.partner_code).toUpperCase().slice(0, 60) : null,
      userId !== null ? authLogHash(userId) : null,
      authLogHash(getClientIp(req)),
      authLogHash(getUserAgent(req)),
      user?.sid ? authLogHash(String(user.sid)) : null,
      res.statusCode < 400 ? 1 : 0,
      res.statusCode < 400 ? null : `HTTP ${res.statusCode}`,
    ]
  );
}

module.exports = (req, res, next) => {
  const store = auditContext.createStore();
  const originalEnd = res.end;
  let intercepted = false;

  res.end = function (...args) {
    if (intercepted) {
      return originalEnd.apply(this, args);
    }
    intercepted = true;

    // The controller already wrote its own row for this request.
    if (store.auditWritten || !shouldAudit(req, res)) {
      return originalEnd.apply(this, args);
    }

    const finish = () => originalEnd.apply(this, args);

    // Bounded: a slow/unreachable DB must never hang API responses, and a
    // failed audit write must never fail the request (same fail-safe stance
    // as writeAuthLogSafe).
    Promise.race([
      writeAccessLog(req, res),
      new Promise((resolve) =>
        setTimeout(resolve, AUDIT_WRITE_TIMEOUT_MS).unref?.()
      ),
    ]).then(finish, (err) => {
      console.error("ACCESS_AUDIT_FAILED:", err?.code || err?.message);
      finish();
    });

    return this;
  };

  // Everything downstream runs inside this request's audit context.
  auditContext.run(store, next);
};
