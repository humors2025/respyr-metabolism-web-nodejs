"use strict";

/**
 * POST /dietitian/api/web/update-facility        (super_admin, admin)
 *
 * Edit a facility's display name and/or the owner's display name from the
 * Facilities page.
 *
 * Body:
 *  {
 *    "facility_id": 12,
 *    "name":        "New facility name",   // optional
 *    "owner_name":  "New owner name"       // optional — at least one of the two
 *  }
 *
 * Scope (BOLA guard): admin may only touch facilities whose
 * parent_admin_user_id is themselves; super_admin may touch any. Out-of-scope
 * and not-found are indistinguishable (404) so an admin cannot probe ids.
 *
 * `owner_name` is the owner's profile name (table_dietician.name for the
 * facility_admin_user_id email) — the same field list-facilities joins in as
 * owner_name — so the new name shows everywhere that user appears.
 *
 * Every changed field is appended to facility_edit_logs (migration 007) —
 * old/new value, who edited and when — which drives the "Edited" tag and the
 * edit history shown on the Facilities page.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");

const ALLOWED_ROLES = ["super_admin", "admin"];
const MAX_NAME = 150;

// Trimmed string or an error message; `undefined` when the field was not sent.
function parseName(raw, label) {
  if (raw == null) return { value: undefined };
  if (typeof raw !== "string") return { error: `${label} must be a string` };
  const v = raw.trim().replace(/\s+/g, " ");
  if (v === "") return { error: `${label} cannot be empty` };
  if (v.length > MAX_NAME) return { error: `${label} must be at most ${MAX_NAME} characters` };
  return { value: v };
}

const updateFacility = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  let actorEmail = null;
  let actorRole = null;

  try {
    const resolved = await H.resolveActorFromToken(req, ALLOWED_ROLES);
    if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);
    const isSuper = actorRole === "super_admin";

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const facilityId = Number.parseInt(body.facility_id, 10);
    if (!Number.isInteger(facilityId) || facilityId <= 0) {
      return res.status(422).json({ ok: false, message: "facility_id is required" });
    }

    const name = parseName(body.name, "name");
    if (name.error) return res.status(422).json({ ok: false, message: name.error });
    const ownerName = parseName(body.owner_name, "owner_name");
    if (ownerName.error) return res.status(422).json({ ok: false, message: ownerName.error });
    if (name.value === undefined && ownerName.value === undefined) {
      return res.status(422).json({ ok: false, message: "Nothing to update — send name and/or owner_name" });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [rows] = await conn.execute(
        `
          SELECT id, name, facility_admin_user_id, parent_admin_user_id
          FROM facilities
          WHERE id = ?
          LIMIT 1
          FOR UPDATE
        `,
        [facilityId]
      );
      const facility = rows[0];

      const inScope =
        facility &&
        (isSuper || String(facility.parent_admin_user_id || "").toLowerCase() === actorEmail);
      if (!inScope) {
        await conn.rollback();
        return res.status(404).json({ ok: false, message: "Facility not found" });
      }

      const changes = [];
      const logRows = []; // [field, old_value, new_value]

      if (name.value !== undefined && name.value !== facility.name) {
        await conn.execute(`UPDATE facilities SET name = ? WHERE id = ?`, [name.value, facility.id]);
        changes.push(`name "${facility.name}" -> "${name.value}"`);
        logRows.push(["name", facility.name || null, name.value]);
      }

      let previousOwnerName = null;
      if (ownerName.value !== undefined) {
        const [ownerRows] = await conn.execute(
          `
            SELECT id, name FROM table_dietician
            WHERE LOWER(email) = LOWER(?)
            LIMIT 1
            FOR UPDATE
          `,
          [facility.facility_admin_user_id]
        );
        const owner = ownerRows[0];
        if (!owner) {
          // Owner invited but not signed up yet — there is no profile to rename.
          await conn.rollback();
          return res.status(409).json({ ok: false, message: "The owner has not completed sign-up yet, so their name cannot be edited" });
        }
        previousOwnerName = owner.name || null;
        if (ownerName.value !== previousOwnerName) {
          await conn.execute(`UPDATE table_dietician SET name = ? WHERE id = ?`, [ownerName.value, owner.id]);
          changes.push(`owner_name "${previousOwnerName || ""}" -> "${ownerName.value}"`);
          logRows.push(["owner_name", previousOwnerName, ownerName.value]);
        }
      }

      for (const [field, oldValue, newValue] of logRows) {
        await conn.execute(
          `
            INSERT INTO facility_edit_logs
              (facility_id, field, old_value, new_value, edited_by, edited_role)
            VALUES (?, ?, ?, ?, ?, ?)
          `,
          [facility.id, field, oldValue, newValue, actorEmail, actorRole]
        );
      }

      await conn.commit();

      if (changes.length) {
        await H.writeAuthLogSafe(req, {
          eventType: "facility_updated",
          userId: actorEmail,
          role: actorRole,
          partnerCode: actor.partner_code ?? null,
          identifier: String(facility.facility_admin_user_id).toLowerCase(),
          success: true,
          failureReason: `facility ${facility.id}: ${changes.join("; ")}`,
        });
      }

      return res.status(200).json({
        ok: true,
        message: changes.length ? "Facility updated" : "No changes",
        data: {
          facility_id: facility.id == null ? null : Number(facility.id),
          name: name.value !== undefined ? name.value : facility.name,
          owner_name: ownerName.value !== undefined ? ownerName.value : previousOwnerName,
          updated_by: actorEmail,
        },
      });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("UPDATE_FACILITY_ERROR:", { code: err?.code, errno: err?.errno, message: err?.message });

    await H.writeAuthLogSafe(req, {
      eventType: "facility_update_error",
      userId: actorEmail,
      role: actorRole,
      partnerCode: null,
      identifier: actorEmail,
      success: false,
      failureReason: err?.code || "internal_error",
    });

    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { updateFacility };
