"use strict";

/**
 * POST /dietitian/api/web/facility-edit-logs      (super_admin, admin)
 *
 * The edit history of one facility: every name / owner-name change made
 * through update-facility — old and new value, who edited and when
 * (facility_edit_logs, migration 007). Newest first, capped at 100 rows.
 *
 * Body: { "facility_id": 12 }
 *
 * Scope (BOLA guard): admin may only read facilities whose
 * parent_admin_user_id is themselves; super_admin may read any. Out-of-scope
 * and not-found are indistinguishable (404), mirroring update-facility.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const ALLOWED_ROLES = ["super_admin", "admin"];
const MAX_ROWS = 100;

function toMysqlDateTime(v) {
  if (!v) return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString().slice(0, 19).replace("T", " ");
}

const facilityEditLogs = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await H.resolveActorFromToken(req, ALLOWED_ROLES);
    if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
    const { actor, actorEmail } = resolved;
    const isSuper = String(actor.role) === "super_admin";

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const facilityId = Number.parseInt(body.facility_id, 10);
    if (!Number.isInteger(facilityId) || facilityId <= 0) {
      return res.status(422).json({ ok: false, message: "facility_id is required" });
    }

    const [facRows] = await pool.execute(
      `SELECT id, name, parent_admin_user_id FROM facilities WHERE id = ? LIMIT 1`,
      [facilityId]
    );
    const facility = facRows[0];
    const inScope =
      facility &&
      (isSuper || String(facility.parent_admin_user_id || "").toLowerCase() === actorEmail);
    if (!inScope) {
      return res.status(404).json({ ok: false, message: "Facility not found" });
    }

    const [rows] = await pool.execute(
      `
        SELECT id, field, old_value, new_value, edited_by, edited_role, edited_at
        FROM facility_edit_logs
        WHERE facility_id = ?
        ORDER BY id DESC
        LIMIT ${MAX_ROWS}
      `,
      [facilityId]
    );

    return res.status(200).json({
      ok: true,
      facility_id: Number(facility.id),
      facility_name: facility.name,
      edits: rows.map((r) => ({
        id: Number(r.id),
        field: r.field, // name | owner_name
        old_value: r.old_value,
        new_value: r.new_value,
        edited_by: String(r.edited_by).toLowerCase(),
        edited_role: r.edited_role,
        edited_at: toMysqlDateTime(r.edited_at),
      })),
    });
  } catch (err) {
    console.error("FACILITY_EDIT_LOGS_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { facilityEditLogs };
