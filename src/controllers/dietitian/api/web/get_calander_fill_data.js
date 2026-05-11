const pool = require("../../../../config/db");

const {
  requireDieticianSelfAccess,
} = require("../../../../utils/accessControl");

const isProduction = process.env.NODE_ENV === "production";

/**
 * Optional audit logging.
 *
 * Enable only after creating api_audit_logs table:
 * ENABLE_DB_AUDIT_LOGS=true
 *
 * Do not store PHI, request body, token, Authorization header,
 * test values, diet plan JSON, phone, email, password, or OTP.
 */
const writeAuditLog = async ({
  req,
  action,
  resourceType,
  resourceId,
  status,
  failureReason = null,
}) => {
  if (process.env.ENABLE_DB_AUDIT_LOGS !== "true") return;

  try {
    const actorId =
      req.user?.sub ||
      req.user?.dietician?.dietician_id ||
      null;

    const actorRole = req.user?.role
      ? String(req.user.role).toLowerCase()
      : null;

    const ipAddress =
      req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req.socket?.remoteAddress ||
      null;

    const userAgent = req.headers["user-agent"] || null;

    await pool.execute(
      `
        INSERT INTO api_audit_logs
          (
            actor_id,
            actor_role,
            action,
            resource_type,
            resource_id,
            ip_address,
            user_agent,
            status,
            failure_reason,
            created_at
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
      `,
      [
        actorId,
        actorRole,
        action,
        resourceType,
        resourceId,
        ipAddress,
        userAgent,
        status,
        failureReason,
      ]
    );
  } catch (auditError) {
    console.warn("AUDIT_LOG_FAILED", {
      action,
      status,
      message: auditError.message,
    });
  }
};

const get_calander_fill_data = async (req, res) => {
  let requestedDieticianId = null;

  try {
    const { dietician_id } = req.body || {};

    /**
     * Centralized VAPT access check.
     *
     * This confirms:
     * 1. JWT exists
     * 2. JWT has valid dietician ID
     * 3. Body dietician_id is valid
     * 4. Body dietician_id matches logged-in JWT dietician
     */
    const access = requireDieticianSelfAccess(req, dietician_id);

    if (!access.allowed) {
      await writeAuditLog({
        req,
        action: "VIEW_CALENDAR_FILL_DATA",
        resourceType: "dietician_calendar",
        resourceId: dietician_id || null,
        status: "failure",
        failureReason: "ACCESS_DENIED",
      });

      return res.status(access.statusCode).json({
        status: false,
        message:
          access.statusCode === 401
            ? "Invalid authentication token"
            : access.message,
      });
    }

    requestedDieticianId = access.dieticianId;

    /**
     * Role check.
     * This endpoint is for dietician dashboard only.
     */
    const role = req.user?.role ? String(req.user.role).toLowerCase() : null;

    if (role !== "dietician") {
      await writeAuditLog({
        req,
        action: "VIEW_CALENDAR_FILL_DATA",
        resourceType: "dietician_calendar",
        resourceId: requestedDieticianId,
        status: "failure",
        failureReason: "INVALID_ROLE",
      });

      return res.status(403).json({
        status: false,
        message: "Access denied",
      });
    }

    /**
     * Preserved your existing business logic:
     * - Last 3 months
     * - Group by test date
     * - Count distinct profiles tested per date
     *
     * pool.execute() keeps this SQL injection-safe.
     */
    const query = `
      SELECT
        DATE(tt.date_time) AS test_date,
        COUNT(DISTINCT tc.profile_id) AS total_tests
      FROM table_clients tc
      INNER JOIN table_test_data tt
        ON tt.profile_id = tc.profile_id
        AND UPPER(TRIM(tt.dietitian_id)) = ?
        AND tt.date_time >= DATE_SUB(CURDATE(), INTERVAL 3 MONTH)
      WHERE UPPER(TRIM(tc.dietician_id)) = ?
      GROUP BY DATE(tt.date_time)
      ORDER BY test_date ASC
    `;

    const [results] = await pool.execute(query, [
      requestedDieticianId,
      requestedDieticianId,
    ]);

    await writeAuditLog({
      req,
      action: "VIEW_CALENDAR_FILL_DATA",
      resourceType: "dietician_calendar",
      resourceId: requestedDieticianId,
      status: "success",
    });

    return res.status(200).json({
      status: true,
      message: "Success",
      dietician_id: requestedDieticianId,
      data: results,
    });
  } catch (error) {
    console.error("GET_CALANDER_FILL_DATA_FAILED", {
      message: error.message,
      endpoint: "/dietitian/api/web/get_calander_fill_data",
    });

    await writeAuditLog({
      req,
      action: "VIEW_CALENDAR_FILL_DATA",
      resourceType: "dietician_calendar",
      resourceId: requestedDieticianId,
      status: "failure",
      failureReason: "SERVER_ERROR",
    });

    return res.status(500).json({
      status: false,
      message: "Server error",
      ...(isProduction ? {} : { error: error.message }),
    });
  }
};

module.exports = { get_calander_fill_data };