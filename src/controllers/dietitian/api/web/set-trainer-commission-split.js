"use strict";

/**
 * POST /dietitian/api/web/set-trainer-commission-split
 *
 * The facility admin decides what share (0–100 %) of the facility's referral
 * commission each of their trainers receives. No default is imposed — it is
 * entirely the owner's call (product decision, 11 Sep 2026).
 *
 * The value is a *future* rule: the commission ledger snapshots the split in
 * force when an invoice is paid, so changing it never rewrites history.
 *
 * Body:
 *  {
 *    "trainer_user_id": "<trainer email>",
 *    "split_pct":       50          // number, 0..100, at most 2 decimals
 *  }
 *
 * Scope (BOLA guard): a facility_admin may only touch trainers whose
 * parent_user_id is themselves AND whose facility_id matches their own.
 * super_admin may set any trainer's split (support / correction path) and the
 * change is audited either way.
 */

const pool = require("../../../../config/db");
const {
  _helpers: H,
} = require("./admin-invite-trainer");

const ALLOWED_ROLES = ["facility_admin", "super_admin"];

function parseSplitPct(raw) {
  if (typeof raw === "string" && raw.trim() !== "") {
    raw = Number(raw);
  }

  if (typeof raw !== "number" || !Number.isFinite(raw)) {
    return { ok: false, message: "split_pct must be a number" };
  }

  if (raw < 0 || raw > 100) {
    return { ok: false, message: "split_pct must be between 0 and 100" };
  }

  // Reject more than two decimals rather than silently rounding money rules.
  if (Math.round(raw * 100) !== raw * 100) {
    return { ok: false, message: "split_pct may have at most 2 decimal places" };
  }

  return { ok: true, value: raw };
}

const setTrainerCommissionSplit = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  if (req.method !== "POST") {
    return res.status(405).json({ ok: false, message: "Method not allowed" });
  }

  let actorEmail = null;
  let actorRole = null;

  try {
    const resolved = await H.resolveActorFromToken(req, ALLOWED_ROLES);

    if (resolved.error) {
      return res.status(resolved.error.status).json(resolved.error.body);
    }

    const { actor } = resolved;
    actorEmail = resolved.actorEmail;
    actorRole = String(actor.role);

    const trainerUserId = H.normalizeEmail(req.body?.trainer_user_id);

    if (trainerUserId === "" || trainerUserId.length > 150) {
      return res.status(422).json({ ok: false, message: "trainer_user_id is required" });
    }

    const split = parseSplitPct(req.body?.split_pct);

    if (!split.ok) {
      return res.status(422).json({ ok: false, message: split.message });
    }

    const conn = await pool.getConnection();

    try {
      await conn.beginTransaction();

      // Lock the trainer row so two concurrent edits cannot interleave.
      const [rows] = await conn.execute(
        `
          SELECT
            id,
            user_id,
            role,
            status,
            parent_user_id,
            facility_id,
            commission_split_pct
          FROM app_user_roles
          WHERE LOWER(user_id) = LOWER(?)
          LIMIT 1
          FOR UPDATE
        `,
        [trainerUserId]
      );

      const trainer = rows[0];

      // Out-of-scope and not-found are deliberately indistinguishable so a
      // facility admin cannot probe which emails exist elsewhere.
      const inScope =
        trainer &&
        String(trainer.role) === "trainer" &&
        (actorRole === "super_admin" ||
          (String(trainer.parent_user_id || "").toLowerCase() === actorEmail &&
            actor.facility_id != null &&
            trainer.facility_id != null &&
            Number(trainer.facility_id) === Number(actor.facility_id)));

      if (!inScope) {
        await conn.rollback();
        return res.status(404).json({ ok: false, message: "Trainer not found" });
      }

      if (String(trainer.status) !== "active") {
        await conn.rollback();
        return res.status(409).json({
          ok: false,
          message: "Commission split can only be set for an active trainer",
        });
      }

      const previous = Number(trainer.commission_split_pct || 0);

      await conn.execute(
        `
          UPDATE app_user_roles
          SET
            commission_split_pct        = ?,
            commission_split_updated_at = UTC_TIMESTAMP(),
            commission_split_updated_by = ?,
            updated_at                  = UTC_TIMESTAMP()
          WHERE id = ?
          LIMIT 1
        `,
        [split.value.toFixed(2), actorEmail, trainer.id]
      );

      await conn.commit();

      await H.writeAuthLogSafe(req, {
        eventType: "trainer_commission_split_set",
        userId: actorEmail,
        role: actorRole,
        partnerCode: actor.partner_code ?? null,
        identifier: trainerUserId,
        success: true,
        failureReason: `split ${previous} -> ${split.value} for ${trainerUserId}`,
      });

      return res.status(200).json({
        ok: true,
        message: "Commission split updated",
        data: {
          trainer_user_id: trainerUserId,
          facility_id: trainer.facility_id == null ? null : Number(trainer.facility_id),
          previous_split_pct: previous,
          split_pct: split.value,
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
    console.error("SET_TRAINER_COMMISSION_SPLIT_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await H.writeAuthLogSafe(req, {
      eventType: "trainer_commission_split_error",
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

module.exports = { setTrainerCommissionSplit };
