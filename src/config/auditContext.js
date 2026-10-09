"use strict";

/**
 * Per-request audit bookkeeping shared by the access-log middleware
 * (src/middlewares/auditAccessLogMiddleware.js) and the database pool
 * (src/config/db.js).
 *
 * The middleware opens a store for each request. The pool flips
 * `auditWritten` the moment any INSERT INTO app_auth_logs is issued inside
 * that request, whichever controller or helper issued it. When the response
 * ends, the middleware adds its generic access row only if the flag is still
 * false. Result: every request leaves exactly one row unless its controller
 * wrote a richer one itself.
 *
 * AsyncLocalStorage follows the request through awaits and promise chains,
 * so no handler has to pass anything around. If a request ever ran outside
 * a store (it cannot, as long as the middleware is mounted after the body
 * parsers), markAuditWritten() is a no-op and the middleware falls back to
 * writing its row: the failure direction is a duplicate, never a gap.
 */

const { AsyncLocalStorage } = require("async_hooks");

const storage = new AsyncLocalStorage();

function createStore() {
  return { auditWritten: false };
}

function run(store, fn) {
  return storage.run(store, fn);
}

function markAuditWritten() {
  const store = storage.getStore();
  if (store) store.auditWritten = true;
}

module.exports = { createStore, run, markAuditWritten };
