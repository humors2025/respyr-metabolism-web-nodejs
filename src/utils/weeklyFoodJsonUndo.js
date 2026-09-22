"use strict";

/**
 * weeklyFoodJsonUndo.js
 *
 * One step back for weekly_food_json_suggestions_newtest — the server-side
 * twin of push_undo() / undo_depth() in the FitChef trainer dashboard.
 *
 * "Undo" and "Reset" are different questions. Reset throws the week away
 * and returns to original_food_json. Undo takes back the LAST thing the
 * dietitian did — the swap they regret, not the afternoon's work. So every
 * write to food_json snapshots the row first, into
 * weekly_food_json_undo_newtest (migration 006), and the undo endpoint pops
 * the newest snapshot back into the row.
 *
 * All three functions take the caller's OPEN connection and run inside the
 * caller's transaction, so a snapshot is committed with the write it
 * protects and rolled back with it: there can never be a snapshot of a
 * write that did not happen, nor a write without its snapshot.
 *
 * `undoGroup`: the dashboard saves one edit as several sequential writes
 * (one food per call). It sends the same group token with each, and only
 * the FIRST write of a group is snapshotted — so one Undo takes back the
 * whole Save, which is what the dietitian pressed.
 */

const UNDO_DEPTH = 25;

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The stored column as text, whatever mysql2 handed back. */
function foodJsonAsText(columnValue) {
  if (columnValue === null || columnValue === undefined) return null;
  if (Buffer.isBuffer(columnValue)) return columnValue.toString("utf8");
  if (isPlainObject(columnValue) || Array.isArray(columnValue)) return JSON.stringify(columnValue);
  return String(columnValue);
}

/**
 * Snapshot the row as it is NOW, before the caller changes it.
 *
 * @param connection   open mysql2 connection, inside a transaction
 * @param opts.recordId      weekly_food_json_suggestions_newtest.id
 * @param opts.dieticianId   normalized dietitian id (owner of the row)
 * @param opts.profileId     normalized profile id
 * @param opts.foodJson      the row's food_json column value BEFORE the write
 * @param opts.label         what the write is about to do (shown by Undo)
 * @param opts.undoGroup     optional token; consecutive writes sharing it are one step
 * @returns {Promise<boolean>} true if a snapshot was written
 */
async function pushUndoSnapshot(connection, opts) {
  // BEST EFFORT. A snapshot that cannot be written (the table not migrated
  // yet, say) must degrade to "no undo", never to "no saves" — the write it
  // protects is the dietitian's work; the snapshot is a convenience.
  try {
    return await writeUndoSnapshot(connection, opts);
  } catch (err) {
    console.error("WEEKLY_FOOD_JSON_UNDO_SNAPSHOT_FAILED:", err?.code || err?.message);
    return false;
  }
}

async function writeUndoSnapshot(connection, { recordId, dieticianId, profileId, foodJson, label, undoGroup }) {
  const text = foodJsonAsText(foodJson);
  if (!text) return false;
  const group = undoGroup ? String(undoGroup).slice(0, 64) : null;

  if (group) {
    const [last] = await connection.execute(
      `SELECT undo_group FROM weekly_food_json_undo_newtest
        WHERE record_id = ? ORDER BY id DESC LIMIT 1`,
      [recordId]
    );
    if (last.length && last[0].undo_group === group) return false; // same Save, already snapshotted
  }

  await connection.execute(
    `INSERT INTO weekly_food_json_undo_newtest
       (record_id, dietician_id, profile_id, label, undo_group, food_json)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [recordId, String(dieticianId).slice(0, 64), String(profileId).slice(0, 64), label ? String(label).slice(0, 120) : null, group, text]
  );

  // keep the last N, so a long session cannot fill the table
  await connection.execute(
    `DELETE FROM weekly_food_json_undo_newtest
      WHERE record_id = ?
        AND id NOT IN (
          SELECT id FROM (
            SELECT id FROM weekly_food_json_undo_newtest
             WHERE record_id = ? ORDER BY id DESC LIMIT ${UNDO_DEPTH}
          ) keep
        )`,
    [recordId, recordId]
  );
  return true;
}

/** The newest snapshot for a row, or null. Locked, so two Undos cannot pop the same step. */
async function peekUndoSnapshot(connection, recordId) {
  const [rows] = await connection.execute(
    `SELECT id, label, undo_group, food_json, created_at
       FROM weekly_food_json_undo_newtest
      WHERE record_id = ? ORDER BY id DESC LIMIT 1 FOR UPDATE`,
    [recordId]
  );
  return rows.length ? rows[0] : null;
}

async function deleteUndoSnapshot(connection, snapshotId) {
  await connection.execute(`DELETE FROM weekly_food_json_undo_newtest WHERE id = ? LIMIT 1`, [snapshotId]);
}

/** Reset puts the week back to what was generated; nothing to step back to is the truth after it. */
async function clearUndoSnapshots(connection, recordId) {
  try {
    await connection.execute(`DELETE FROM weekly_food_json_undo_newtest WHERE record_id = ?`, [recordId]);
  } catch (err) {
    console.error("WEEKLY_FOOD_JSON_UNDO_CLEAR_FAILED:", err?.code || err?.message);
  }
}

/** How many steps back are available, so the button can say. */
async function undoDepth(executor, recordId) {
  const [rows] = await executor.execute(
    `SELECT COUNT(*) AS n, MAX(label) AS last_label FROM weekly_food_json_undo_newtest WHERE record_id = ?`,
    [recordId]
  );
  const n = rows.length ? Number(rows[0].n) || 0 : 0;
  let lastLabel = null;
  if (n > 0) {
    const [last] = await executor.execute(
      `SELECT label FROM weekly_food_json_undo_newtest WHERE record_id = ? ORDER BY id DESC LIMIT 1`,
      [recordId]
    );
    lastLabel = last.length ? last[0].label : null;
  }
  return { depth: n, lastLabel };
}

module.exports = {
  UNDO_DEPTH,
  pushUndoSnapshot,
  peekUndoSnapshot,
  deleteUndoSnapshot,
  clearUndoSnapshots,
  undoDepth,
};
