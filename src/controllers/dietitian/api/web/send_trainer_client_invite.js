"use strict";

/**
 * send_trainer_client_invite.js
 *
 * Converted from: send_trainer_client_invite.php
 *                 (shared helpers via client-subscription-action-common.js)
 * Platform      : Respyr Dietitian API (api.respyr.ai)
 * Security      : VAPT-hardened, HIPAA-aligned
 *
 * Endpoint   : POST /dietitian/api/web/send_trainer_client_invite
 * Auth       : Bearer JWT (authMiddleware must run before this handler)
 * Authorized : super_admin | admin | trainer — but ONLY for a trainer code the
 *              actor is allowed to use (own code, or a child trainer's code).
 *
 * Behaviour parity with the PHP (Free-Trial-only flow):
 *  - No plan_code is accepted from the frontend. Every invite is a Free Trial
 *    (FREE_TRIAL_DAYS=7, MAX_FREE_TRIAL_DAYS=15). The redeem code expires after
 *    FREE_TRIAL_DAYS (NOT the generic 30-day window).
 *  - Rejects a duplicate ACTIVE pending free-trial invite for the same
 *    (trainer_code, client_email) — i.e. status='sent', subscription_status=
 *    'pending', code not yet expired → 409 (with the existing code + expiry).
 *  - Creates a trainer_client_plan_subscriptions row (unique RSP###### redeem
 *    code + 7-day expiry). Optional trial_* columns are populated only if they
 *    exist (detected via INFORMATION_SCHEMA, exactly like the PHP).
 *  - Upserts the latest trainer_client_invites row WITHOUT clobbering an
 *    already-accepted invite (matched by trainer_id OR trainer_code + email).
 *  - Sends the invite email via the SAME Resend template payload as the PHP
 *    (template id + variables incl. TRIAL_DAYS / MAX_TRIAL_DAYS).
 *  - Writes the email result back to both rows (the invite row update is guarded
 *    against the accepted state).
 *  - Response shape matches the PHP: { status, ok, message, data{...} } with the
 *    trial_started_at / trial_expires_at / trial_days_total / max_trial_days
 *    fields.
 *
 * VAPT hardening (beyond the PHP — the point of the sprint):
 *  - Token-bound identity. The PHP only checked authorization when the caller
 *    chose to send body.actor_user_id; with no actor_user_id ANY caller could
 *    invite clients under ANY trainer_id (a textbook IDOR / privilege-escalation
 *    hole). Here the actor is ALWAYS resolved from the verified JWT and re-checked
 *    (role + status), and MUST always be allowed to use the requested trainer
 *    code — there is no unauthenticated / unauthorized path. body.actor_user_id is
 *    still accepted for frontend back-compat but is only cross-checked against the
 *    token identity (mismatch → 403); it can never select another user.
 *  - Every query is fully parameterized; redeem codes use a CSPRNG. The only
 *    interpolated SQL identifiers are the optional trial column names, chosen
 *    from a hardcoded whitelist (never raw user input).
 *  - Internal error / email-provider details are suppressed in production
 *    (gated behind APP_DEBUG). The PHP forced API_DEBUG=true and echoed file/
 *    line/message — an info-disclosure finding closed here.
 *  - Cache-Control: no-store, Pragma: no-cache on every response.
 *
 * HIPAA controls:
 *  - Minimum-necessary columns; PHI in audit logs (client email, IP, UA) is
 *    HMAC-SHA256 hashed with SECURITY_PEPPER — never stored in clear text.
 *  - Every invite (success / failure / denial) is recorded in app_auth_logs.
 *
 * Shared logic (scalar helpers, actor resolution, allowed codes, redeem code,
 * email, audit) lives in client-subscription-action-common.js. Only the
 * send-invite-specific SQL (dup-check, subscription/invite creation) stays here.
 *
 * NOTE: No DB tables are added or removed vs. the PHP — same table_dietician,
 * app_user_roles, trainer_client_invites, trainer_client_plan_subscriptions,
 * app_auth_logs.
 */

const pool = require("../../../../config/db");
const csi  = require("./client-subscription-action-common");

const {
  ApiError,
  APP_DEBUG,
  RESEND_API_KEY,
} = csi;

// ─── Endpoint-specific constants (was the define()s) ──────────────────────────

const FREE_TRIAL_DAYS = Math.max(
  1,
  parseInt(process.env.FREE_TRIAL_DAYS, 10) || 7
);
const MAX_FREE_TRIAL_DAYS = Math.max(
  FREE_TRIAL_DAYS,
  parseInt(process.env.MAX_FREE_TRIAL_DAYS, 10) || 15
);

// The fixed backend Free-Trial plan (PHP getDefaultFreeTrialPlan()).
const FREE_TRIAL_PLAN = {
  plan_code: "free_trial",
  plan_name: "Free Trial",
  plan_price_label: "Free",
};

// Optional trial columns that are populated only when present in the table.
// Hardcoded whitelist — these identifiers are the only ones interpolated into
// SQL, and they never come from user input.
const OPTIONAL_TRIAL_COLUMNS = [
  "trial_started_at",
  "trial_expires_at",
  "trial_days_total",
  "trial_extended_days",
  "trial_extended_at",
  "trial_extended_by_user_id",
];

// ─── Endpoint-specific helpers ────────────────────────────────────────────────

/** normalizeMobile — strip all whitespace (PHP preg_replace('/\s+/', '', ...)). */
function normalizeMobile(mobile) {
  return csi.clean(mobile).replace(/\s+/g, "");
}

/** Format a mysql2 DATETIME (Date or string) for the 409 passthrough response. */
function formatDbDateTime(val) {
  if (val === null || val === undefined) return null;
  if (val instanceof Date) {
    if (Number.isNaN(val.getTime())) return null;
    const pad = (n) => String(n).padStart(2, "0");
    return (
      `${val.getFullYear()}-${pad(val.getMonth() + 1)}-${pad(val.getDate())} ` +
      `${pad(val.getHours())}:${pad(val.getMinutes())}:${pad(val.getSeconds())}`
    );
  }
  return String(val);
}

/** @phpparity tableColumns — set of column names that exist on a table. */
async function tableColumns(conn, tableName) {
  const [rows] = await conn.execute(
    `SELECT COLUMN_NAME
       FROM INFORMATION_SCHEMA.COLUMNS
      WHERE TABLE_SCHEMA = DATABASE()
        AND TABLE_NAME = ?`,
    [tableName]
  );
  const cols = new Set();
  for (const row of rows) cols.add(row.COLUMN_NAME);
  return cols;
}

/** @phpparity getTrainerByCode */
async function getTrainerByCode(conn, trainerCode) {
  const [rows] = await conn.execute(
    `SELECT
       td.id, td.dietician_id, td.name, td.email, td.phone_no, td.location,
       aur.user_id, aur.role, aur.partner_code, aur.parent_user_id,
       aur.status AS role_status
     FROM table_dietician td
     LEFT JOIN app_user_roles aur
       ON LOWER(aur.user_id) = LOWER(td.email)
     WHERE UPPER(td.dietician_id) = UPPER(?)
        OR UPPER(aur.partner_code) = UPPER(?)
     ORDER BY
       CASE WHEN aur.status = 'active' THEN 0 ELSE 1 END,
       td.id DESC
     LIMIT 1`,
    [trainerCode, trainerCode]
  );
  return rows[0] || null;
}

/**
 * @phpparity findExistingLatestInvite — latest invite for this client under the
 * trainer, matched by trainer_id OR trainer_code (the new PHP widened this).
 */
async function findExistingLatestInvite(conn, trainerId, trainerCode, clientEmail) {
  const [rows] = await conn.execute(
    `SELECT *
       FROM trainer_client_invites
      WHERE (
              UPPER(trainer_id) = UPPER(?)
           OR UPPER(trainer_code) = UPPER(?)
      )
        AND LOWER(client_email) = LOWER(?)
      ORDER BY id DESC
      LIMIT 1`,
    [trainerId, trainerCode, clientEmail]
  );
  return rows[0] || null;
}

/**
 * @phpparity hasPendingFreeTrial — an ACTIVE (not-yet-expired) pending free-trial
 * invite for this (trainer_code, client_email). Used to reject duplicates (409).
 */
async function hasPendingFreeTrial(conn, trainerCode, clientEmail) {
  const [rows] = await conn.execute(
    `SELECT id, redeem_code, created_at, code_expires_at
       FROM trainer_client_plan_subscriptions
      WHERE UPPER(trainer_code) = UPPER(?)
        AND LOWER(client_email) = LOWER(?)
        AND plan_code = 'free_trial'
        AND status = 'sent'
        AND subscription_status = 'pending'
        AND (
              code_expires_at IS NULL
           OR code_expires_at > NOW()
        )
      ORDER BY id DESC
      LIMIT 1`,
    [trainerCode, clientEmail]
  );
  return rows[0] || null;
}

/**
 * @phpparity createPlanSubscription — insert the free-trial subscription/history
 * row (unique redeem code + 7-day expiry). Optional trial_* columns are only
 * written when the table has them. Returns the trial metadata for the response.
 */
async function createPlanSubscription(
  conn, sourceInviteId, trainerId, trainerCode,
  clientName, clientMobile, clientEmail, selectedPlan, createdByUserId
) {
  const redeemCode = await csi.uniqueRedeemCode(conn);

  // Free trial is FREE_TRIAL_DAYS days; code expiry == trial expiry. IST wall-clock.
  const trialStartedAt = csi.istMysqlDateTime(new Date());
  const expiresAt = csi.istMysqlDateTime(
    new Date(Date.now() + FREE_TRIAL_DAYS * 24 * 60 * 60 * 1000)
  );
  const paymentStatus = "not_required";

  const subscriptionCols = await tableColumns(conn, "trainer_client_plan_subscriptions");

  // Base columns / value-placeholders / params (kept in lockstep, parity with PHP).
  const columns = [
    "source_invite_id",
    "trainer_id",
    "trainer_code",
    "client_name",
    "client_mobile",
    "client_email",
    "plan_code",
    "plan_name",
    "plan_price_label",
    "redeem_code",
    "code_expires_at",
    "status",
    "subscription_status",
    "payment_status",
    "email_status",
    "resend_email_id",
    "accepted_profile_id",
    "accepted_at",
    "error_message",
    "created_by_user_id",
    "created_at",
    "updated_at",
  ];
  const values = [
    "?", "?", "?", "?", "?", "?", "?", "?", "?", "?", "?",
    "'failed'",            // status
    "'pending'",           // subscription_status
    "?",                   // payment_status
    "'failed'",            // email_status
    "NULL",                // resend_email_id
    "NULL",                // accepted_profile_id
    "NULL",                // accepted_at
    "'Email sending started'", // error_message
    "?",                   // created_by_user_id
    "NOW()",               // created_at
    "NOW()",               // updated_at
  ];
  const params = [
    sourceInviteId,
    trainerId,
    trainerCode,
    clientName,
    clientMobile !== "" ? clientMobile : null,
    clientEmail,
    selectedPlan.plan_code,
    selectedPlan.plan_name,
    selectedPlan.plan_price_label,
    redeemCode,
    expiresAt,
    paymentStatus,
    createdByUserId,
  ];

  // Optional trial columns — appended only when the column exists. The literal
  // values (NOW()/0/NULL) carry no params; the bound ones push to params.
  if (subscriptionCols.has("trial_started_at")) {
    columns.push("trial_started_at");
    values.push("NOW()");
  }
  if (subscriptionCols.has("trial_expires_at")) {
    columns.push("trial_expires_at");
    values.push("?");
    params.push(expiresAt);
  }
  if (subscriptionCols.has("trial_days_total")) {
    columns.push("trial_days_total");
    values.push("?");
    params.push(FREE_TRIAL_DAYS);
  }
  if (subscriptionCols.has("trial_extended_days")) {
    columns.push("trial_extended_days");
    values.push("0");
  }
  if (subscriptionCols.has("trial_extended_at")) {
    columns.push("trial_extended_at");
    values.push("NULL");
  }
  if (subscriptionCols.has("trial_extended_by_user_id")) {
    columns.push("trial_extended_by_user_id");
    values.push("NULL");
  }

  const sql =
    `INSERT INTO trainer_client_plan_subscriptions (\n  ${columns.join(",\n  ")}\n)\n` +
    `VALUES (\n  ${values.join(",\n  ")}\n)`;

  const [result] = await conn.execute(sql, params);

  return {
    subscription_id: Number(result.insertId),
    redeem_code: redeemCode,
    code_expires_at: expiresAt,
    payment_status: paymentStatus,
    trial_started_at: trialStartedAt,
    trial_expires_at: expiresAt,
    trial_days_total: FREE_TRIAL_DAYS,
    max_trial_days: MAX_FREE_TRIAL_DAYS,
  };
}

/**
 * @phpparity insertOrUpdateLatestInviteIfSafe — upsert the latest invite row
 * WITHOUT clobbering an already-accepted invite. Returns the invite id.
 */
async function insertOrUpdateLatestInviteIfSafe(
  conn, existingInvite, subscriptionId, trainerId, trainerCode,
  clientName, clientMobile, clientEmail, selectedPlan
) {
  if (existingInvite) {
    const oldStatus = String(existingInvite.status || "").toLowerCase();
    const acceptedProfileId = csi.clean(existingInvite.accepted_profile_id ?? "");

    if (oldStatus === "accepted" || acceptedProfileId !== "") {
      return Number(existingInvite.id);
    }

    await conn.execute(
      `UPDATE trainer_client_invites
          SET trainer_code = ?,
              client_name = ?,
              client_mobile = ?,
              plan_code = ?,
              plan_name = ?,
              plan_price_label = ?,
              latest_subscription_id = ?,
              status = 'failed',
              email_status = 'failed',
              resend_email_id = NULL,
              error_message = 'Email sending started',
              updated_at = NOW()
        WHERE id = ?
        LIMIT 1`,
      [
        trainerCode,
        clientName,
        clientMobile !== "" ? clientMobile : null,
        selectedPlan.plan_code,
        selectedPlan.plan_name,
        selectedPlan.plan_price_label,
        subscriptionId,
        Number(existingInvite.id),
      ]
    );

    return Number(existingInvite.id);
  }

  const [result] = await conn.execute(
    `INSERT INTO trainer_client_invites (
       trainer_id, trainer_code, client_name, client_mobile, client_email,
       plan_code, plan_name, plan_price_label, latest_subscription_id,
       status, email_status, resend_email_id, error_message, created_at, updated_at
     )
     VALUES (
       ?, ?, ?, ?, ?, ?, ?, ?, ?,
       'failed', 'failed', NULL, 'Email sending started', NOW(), NOW()
     )`,
    [
      trainerId,
      trainerCode,
      clientName,
      clientMobile !== "" ? clientMobile : null,
      clientEmail,
      selectedPlan.plan_code,
      selectedPlan.plan_name,
      selectedPlan.plan_price_label,
      subscriptionId,
    ]
  );

  return Number(result.insertId);
}

/** @phpparity updateSubscriptionResult */
async function updateSubscriptionResult(conn, subscriptionId, status, emailStatus, resendEmailId, errorMessage) {
  await conn.execute(
    `UPDATE trainer_client_plan_subscriptions
        SET status = ?,
            email_status = ?,
            resend_email_id = ?,
            error_message = ?,
            updated_at = NOW()
      WHERE id = ?
      LIMIT 1`,
    [status, emailStatus, resendEmailId, errorMessage, subscriptionId]
  );
}

/** @phpparity updateLatestInviteResultIfNotAccepted */
async function updateLatestInviteResultIfNotAccepted(
  conn, sourceInviteId, subscriptionId, status, emailStatus, resendEmailId, errorMessage
) {
  if (!sourceInviteId) return;
  await conn.execute(
    `UPDATE trainer_client_invites
        SET status = ?,
            email_status = ?,
            resend_email_id = ?,
            error_message = ?,
            latest_subscription_id = ?,
            updated_at = NOW()
      WHERE id = ?
        AND status <> 'accepted'
        AND accepted_profile_id IS NULL
      LIMIT 1`,
    [status, emailStatus, resendEmailId, errorMessage, subscriptionId, sourceInviteId]
  );
}

// ─── Controller ───────────────────────────────────────────────────────────────

/**
 * POST /dietitian/api/web/send_trainer_client_invite
 *
 * Headers: Authorization: Bearer <JWT>
 * Body:
 *   {
 *     "trainer_id": "RespyrD03",       // required — trainer/partner code
 *     "client_name": "Jane Doe",       // required
 *     "client_mobile": "+15551234567", // optional
 *     "client_email": "jane@x.com",    // required, valid email
 *     "actor_user_id": ""              // optional; if set, must match token email
 *   }
 *
 * Note: plan_code is intentionally ignored — every invite is a Free Trial.
 */
const sendTrainerClientInvite = async (req, res) => {
  // HIPAA: never let intermediaries cache invite responses.
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");

  // VAPT: method gate (matches the PHP REQUEST_METHOD check).
  if (req.method !== "POST") {
    return res.status(405).json({ status: false, ok: false, message: "Only POST method is allowed" });
  }

  const body =
    req.body && typeof req.body === "object" && !Array.isArray(req.body) ? req.body : {};

  let conn = null;
  let actorEmail = null;
  let actorRole = null;
  let trainerCode = null;

  try {
    if (!RESEND_API_KEY) {
      throw new ApiError(500, "RESEND_API_KEY is not configured");
    }

    // ── 1. Parse + validate the payload ──────────────────────────────────────
    const actorUserId    = csi.email(body.actor_user_id ?? "");
    const trainerIdInput = csi.code(body.trainer_id ?? "");
    const clientName     = csi.clean(body.client_name ?? "");
    const clientMobile   = normalizeMobile(body.client_mobile ?? "");
    const clientEmail    = csi.email(body.client_email ?? "");

    // Backend always uses the Free-Trial plan; no plan_code from the frontend.
    const selectedPlan = FREE_TRIAL_PLAN;

    if (trainerIdInput === "") {
      throw new ApiError(400, "trainer_id is required");
    }
    if (clientName === "") {
      throw new ApiError(400, "client_name is required");
    }
    if (clientEmail === "" || !csi.isValidEmail(clientEmail)) {
      throw new ApiError(400, "Valid client_email is required");
    }
    if (clientMobile !== "" && !/^\+?[0-9]{10,15}$/.test(clientMobile)) {
      throw new ApiError(400, "Invalid client_mobile");
    }

    // ── 2. DB connection (IST session time zone, parity with PHP) ────────────
    conn = await pool.getConnection();
    await conn.query("SET time_zone = '+05:30'");

    // ── 3. Token-bound authorization (closes the PHP IDOR hole) ──────────────
    const { actor, actorEmail: resolvedEmail } = await csi.resolveActorFromToken(conn, req);
    actorEmail = resolvedEmail;
    actorRole = String(actor.role);

    // Optional actor_user_id is cross-checked, never trusted to select a user.
    if (actorUserId !== "" && actorUserId !== actorEmail) {
      await csi.audit(
        pool, req, "client_free_trial_invite_denied",
        actorEmail, actorRole, csi.effectiveCode(actor),
        clientEmail, false, "actor_user_id does not match token identity"
      );
      throw new ApiError(403, "actor_user_id does not match the authenticated user");
    }

    const allowedCodes = await csi.allowedCodes(conn, actor, actorEmail);

    if (!csi.canAccessCode(allowedCodes, trainerIdInput)) {
      await csi.audit(
        pool, req, "client_free_trial_invite_denied",
        actorEmail, actorRole, csi.effectiveCode(actor),
        clientEmail, false, "actor not allowed to use this trainer code"
      );
      throw new ApiError(403, "You are not allowed to invite clients using this trainer code");
    }

    // ── 4. Resolve the trainer the invite is sent under ──────────────────────
    const trainer = await getTrainerByCode(conn, trainerIdInput);

    if (!trainer) {
      throw new ApiError(404, "Trainer/admin code not found");
    }
    if (trainer.role_status !== null && trainer.role_status !== undefined &&
        String(trainer.role_status) !== "active") {
      throw new ApiError(403, "Trainer/admin account is not active");
    }

    const trainerId = csi.clean(trainer.dietician_id);
    trainerCode = csi.effectiveCode(trainer);
    if (trainerCode === null || String(trainerCode).trim() === "") {
      trainerCode = trainerId;
    }

    let trainerName = csi.clean(trainer.name ?? "");
    if (trainerName === "") trainerName = "Your trainer";

    const trainerRole =
      trainer.role !== null && trainer.role !== undefined ? trainer.role : "trainer";

    // Token-bound: the creator is always the authenticated actor.
    const createdByUserId = actorEmail;

    // ── 5. Reject a duplicate ACTIVE pending free-trial invite ───────────────
    const pendingFreeTrial = await hasPendingFreeTrial(conn, trainerCode, clientEmail);

    if (pendingFreeTrial) {
      throw new ApiError(409, "This client already has a pending free trial invite", {
        data: {
          subscription_id: Number(pendingFreeTrial.id),
          redeem_code: pendingFreeTrial.redeem_code,
          created_at: formatDbDateTime(pendingFreeTrial.created_at),
          code_expires_at: formatDbDateTime(pendingFreeTrial.code_expires_at),
          plan_code: "free_trial",
        },
      });
    }

    // ── 6. Create the subscription/history row first ─────────────────────────
    const existingInvite = await findExistingLatestInvite(
      conn, trainerId, trainerCode, clientEmail
    );
    let sourceInviteId = existingInvite ? Number(existingInvite.id) : null;

    const subscriptionMeta = await createPlanSubscription(
      conn, sourceInviteId, trainerId, trainerCode,
      clientName, clientMobile, clientEmail, selectedPlan, createdByUserId
    );

    const subscriptionId = subscriptionMeta.subscription_id;
    const redeemCode     = subscriptionMeta.redeem_code;
    const codeExpiresAt  = subscriptionMeta.code_expires_at;
    const paymentStatus  = subscriptionMeta.payment_status;

    // ── 7. Upsert the latest invite row (never clobbers an accepted one) ─────
    sourceInviteId = await insertOrUpdateLatestInviteIfSafe(
      conn, existingInvite, subscriptionId, trainerId, trainerCode,
      clientName, clientMobile, clientEmail, selectedPlan
    );

    if (sourceInviteId !== null) {
      await conn.execute(
        `UPDATE trainer_client_plan_subscriptions
            SET source_invite_id = ?,
                updated_at = NOW()
          WHERE id = ?
          LIMIT 1`,
        [sourceInviteId, subscriptionId]
      );
    }

    // ── 8. Send the invite email (SAME template payload as the PHP) ──────────
    const emailResult = await csi.sendEmail({
      client_email: clientEmail,
      client_name: clientName,
      trainer_name: trainerName,
      trainer_code: trainerCode,
      redeem_code: redeemCode,
      code_expires_at: codeExpiresAt,
      plan_code: selectedPlan.plan_code,
      plan_name: selectedPlan.plan_name,
      plan_price_label: selectedPlan.plan_price_label,
      // Free-trial-specific template variables (additive, see sendEmail).
      extra_variables: {
        TRIAL_DAYS: FREE_TRIAL_DAYS,
        MAX_TRIAL_DAYS: MAX_FREE_TRIAL_DAYS,
      },
    });

    const inviteStatus  = emailResult.success ? "sent" : "failed";
    const emailStatus   = emailResult.success ? "sent" : "failed";
    const resendEmailId = emailResult.resend_email_id;
    const errorMessage  = emailResult.error;

    await updateSubscriptionResult(
      conn, subscriptionId, inviteStatus, emailStatus, resendEmailId, errorMessage
    );

    await updateLatestInviteResultIfNotAccepted(
      conn, sourceInviteId, subscriptionId, inviteStatus, emailStatus, resendEmailId, errorMessage
    );

    // ── 9. Audit ─────────────────────────────────────────────────────────────
    await csi.audit(
      pool, req,
      emailResult.success ? "client_free_trial_invite_sent" : "client_free_trial_invite_failed",
      createdByUserId, trainerRole, trainerCode,
      clientEmail, emailResult.success,
      emailResult.success ? "Client free trial invite sent" : "Client free trial invite failed"
    );

    // ── 10. Respond (matches the PHP JSON shape) ─────────────────────────────
    return res.status(emailResult.success ? 200 : 500).json({
      status: emailResult.success,
      ok: emailResult.success,
      message: emailResult.success
        ? "Free trial invite email sent successfully"
        : "Free trial invite saved but email sending failed",
      data: {
        subscription_id: subscriptionId,
        source_invite_id: sourceInviteId,

        redeem_code: redeemCode,
        code_expires_at: codeExpiresAt,

        trial_started_at: subscriptionMeta.trial_started_at,
        trial_expires_at: subscriptionMeta.trial_expires_at,
        trial_days_total: subscriptionMeta.trial_days_total,
        max_trial_days: subscriptionMeta.max_trial_days,

        trainer_id: trainerId,
        trainer_name: trainerName,
        trainer_code: trainerCode,
        partner_code: trainerCode,

        client_name: clientName,
        client_mobile: clientMobile,
        client_email: clientEmail,

        plan_code: "free_trial",
        plan_name: "Free Trial",
        plan_price_label: "Free",

        subscription_status: "pending",
        payment_status: paymentStatus,

        invite_status: inviteStatus,
        email_status: emailStatus,
        resend_email_id: resendEmailId,
        // VAPT: provider error is suppressed from clients in production.
        error_message: APP_DEBUG ? errorMessage : (emailResult.success ? null : "Email sending failed"),
      },
    });
  } catch (err) {
    if (err instanceof ApiError) {
      return res.status(err.status).json(err.payload);
    }

    console.error("SEND_TRAINER_CLIENT_INVITE_ERROR:", {
      code: err?.code,
      errno: err?.errno,
      sqlState: err?.sqlState,
      message: err?.message,
    });

    await csi.audit(
      pool, req, "client_free_trial_invite_error",
      actorEmail, actorRole, trainerCode,
      csi.email(body.client_email ?? ""), false, err?.code || "internal_error"
    );

    return res.status(500).json({
      status: false,
      ok: false,
      message: "Internal server error",
      ...(APP_DEBUG && { debug_error: err?.message }),
    });
  } finally {
    if (conn) {
      try {
        conn.release();
      } catch (_) {
        /* ignore */
      }
    }
  }
};

module.exports = { sendTrainerClientInvite };
