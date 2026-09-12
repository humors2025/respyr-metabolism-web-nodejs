"use strict";

/**
 * Platform commission rate (Rysflo -> facility), managed by super_admin.
 *
 *  POST /dietitian/api/web/get-commission-rate   (super_admin, admin, facility_admin, trainer)
 *       -> { ok, current: { rate_pct, effective_from }, history: [...] }
 *          history is returned to super_admin only.
 *
 *  POST /dietitian/api/web/set-commission-rate   (super_admin only)
 *       body { rate_pct: 18, effective_from?: "2026-10-01 00:00:00", note?: "..." }
 *       Append-only: a new row is inserted; nothing historical changes and the
 *       ledger keeps the rate each invoice was paid under.
 */

const pool = require("../../../../config/db");
const { _helpers: H } = require("./admin-invite-trainer");
const { escapeHtml } = require("../../../../utils/securityValidation");

const READ_ROLES = ["super_admin", "admin", "facility_admin", "trainer"];
const MYSQL_DT = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/;

async function currentRate(conn) {
  const [rows] = await conn.execute(
    `
      SELECT rate_pct, effective_from, set_by_user_id, note
      FROM commission_rates
      WHERE effective_from <= UTC_TIMESTAMP()
      ORDER BY effective_from DESC, id DESC
      LIMIT 1
    `
  );
  return rows[0] || null;
}

const getCommissionRate = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await H.resolveActorFromToken(req, READ_ROLES);
    if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);

    const cur = await currentRate(pool);
    const out = {
      ok: true,
      current: cur
        ? { rate_pct: Number(cur.rate_pct), effective_from: cur.effective_from }
        : null,
    };

    if (String(resolved.actor.role) === "super_admin") {
      const [history] = await pool.execute(
        `
          SELECT rate_pct, effective_from, set_by_user_id, note, created_at
          FROM commission_rates
          ORDER BY effective_from DESC, id DESC
          LIMIT 50
        `
      );
      out.history = history.map((r) => ({ ...r, rate_pct: Number(r.rate_pct) }));
    }

    return res.status(200).json(out);
  } catch (err) {
    console.error("GET_COMMISSION_RATE_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

const setCommissionRate = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ ok: false, message: "Method not allowed" });

  try {
    const resolved = await H.resolveActorFromToken(req, "super_admin");
    if (resolved.error) return res.status(resolved.error.status).json(resolved.error.body);
    const actorEmail = resolved.actorEmail;

    let rate = req.body?.rate_pct;
    if (typeof rate === "string" && rate.trim() !== "") rate = Number(rate);
    if (typeof rate !== "number" || !Number.isFinite(rate) || rate < 0 || rate > 100) {
      return res.status(422).json({ ok: false, message: "rate_pct must be a number between 0 and 100" });
    }
    if (Math.round(rate * 100) !== rate * 100) {
      return res.status(422).json({ ok: false, message: "rate_pct may have at most 2 decimal places" });
    }

    let effectiveFrom = req.body?.effective_from;
    if (effectiveFrom == null || effectiveFrom === "") {
      effectiveFrom = null; // now
    } else if (typeof effectiveFrom !== "string" || !MYSQL_DT.test(effectiveFrom)) {
      return res.status(422).json({ ok: false, message: "effective_from must be 'YYYY-MM-DD HH:MM:SS' (UTC)" });
    }

    let note = typeof req.body?.note === "string" ? req.body.note.trim() : "";
    note = escapeHtml(note.replace(/[\r\n\t\x00-\x1F\x7F]/g, " ").slice(0, 255)) || null;

    const previous = await currentRate(pool);

    await pool.execute(
      `
        INSERT INTO commission_rates (rate_pct, effective_from, set_by_user_id, note)
        VALUES (?, COALESCE(?, UTC_TIMESTAMP()), ?, ?)
      `,
      [rate.toFixed(2), effectiveFrom, actorEmail, note]
    );

    await H.writeAuthLogSafe(req, {
      eventType: "commission_rate_set",
      userId: actorEmail,
      role: "super_admin",
      partnerCode: null,
      identifier: actorEmail,
      success: true,
      failureReason: `rate ${previous ? previous.rate_pct : "none"} -> ${rate} from ${effectiveFrom || "now"}`,
    });

    return res.status(200).json({
      ok: true,
      message: "Commission rate updated",
      data: {
        previous_rate_pct: previous ? Number(previous.rate_pct) : null,
        rate_pct: rate,
        effective_from: effectiveFrom || "now",
      },
    });
  } catch (err) {
    console.error("SET_COMMISSION_RATE_ERROR:", { code: err?.code, message: err?.message });
    return res.status(500).json({ ok: false, message: "Internal server error" });
  }
};

module.exports = { getCommissionRate, setCommissionRate };
