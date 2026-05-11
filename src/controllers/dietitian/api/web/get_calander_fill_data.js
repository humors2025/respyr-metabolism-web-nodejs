const pool = require('../../../../config/db');

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Normalize dietician_id safely.
 * Example: " RespyrD01 " -> "RESPYRD01"
 */
const normalizeDieticianId = (value) => {
  if (value === undefined || value === null) return null;

  const normalized = String(value).trim().toUpperCase();

  // Allows IDs like RESPYRD01, RESPYR_D01, RESPYR-D01
  // Adjust max length if your production IDs are longer.
  if (!/^[A-Z0-9_-]{3,64}$/.test(normalized)) {
    return null;
  }

  return normalized;
};

/**
 * Adjust this only if your authMiddleware stores decoded token somewhere else.
 * Recommended: authMiddleware should set req.user = decodedJwt;
 */
const getAuthenticatedUser = (req) => {
  return req.user || req.authUser || req.decoded || null;
};

/**
 * Optional audit logging.
 * This will not break the API if audit table is missing or disabled.
 *
 * To enable:
 * ENABLE_DB_AUDIT_LOGS=true
 */
const writeAuditLog = async ({
  req,
  action,
  resourceType,
  resourceId,
  status,
  failureReason = null,
}) => {
  if (process.env.ENABLE_DB_AUDIT_LOGS !== 'true') return;

  try {
    const user = getAuthenticatedUser(req);

    const actorId = normalizeDieticianId(
      user?.sub || user?.dietician?.dietician_id
    );

    const actorRole = user?.role ? String(user.role).toLowerCase() : null;

    const ipAddress =
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      null;

    const userAgent = req.headers['user-agent'] || null;

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
    // Do not expose audit failures to client.
    // Do not log PHI or sensitive request body.
    console.warn('AUDIT_LOG_FAILED', {
      action,
      status,
      message: auditError.message,
    });
  }
};

const get_calander_fill_data = async (req, res) => {
  let requestedDieticianId = null;

  try {
    const user = getAuthenticatedUser(req);

    if (!user) {
      return res.status(401).json({
        status: false,
        message: 'Unauthorized access',
      });
    }

    const tokenDieticianId = normalizeDieticianId(
      user?.sub || user?.dietician?.dietician_id
    );

    const role = user?.role ? String(user.role).toLowerCase() : null;

    if (!tokenDieticianId) {
      await writeAuditLog({
        req,
        action: 'VIEW_CALENDAR_FILL_DATA',
        resourceType: 'dietician_calendar',
        resourceId: null,
        status: 'failure',
        failureReason: 'TOKEN_DIETICIAN_ID_MISSING',
      });

      return res.status(401).json({
        status: false,
        message: 'Invalid authentication token',
      });
    }

    if (role !== 'dietician') {
      await writeAuditLog({
        req,
        action: 'VIEW_CALENDAR_FILL_DATA',
        resourceType: 'dietician_calendar',
        resourceId: tokenDieticianId,
        status: 'failure',
        failureReason: 'INVALID_ROLE',
      });

      return res.status(403).json({
        status: false,
        message: 'Access denied',
      });
    }

    requestedDieticianId = normalizeDieticianId(req.body?.dietician_id);

    if (!requestedDieticianId) {
      await writeAuditLog({
        req,
        action: 'VIEW_CALENDAR_FILL_DATA',
        resourceType: 'dietician_calendar',
        resourceId: null,
        status: 'failure',
        failureReason: 'INVALID_OR_MISSING_DIETICIAN_ID',
      });

      return res.status(400).json({
        status: false,
        message: 'dietician_id is required',
      });
    }

    /**
     * Critical VAPT fix:
     * The logged-in dietitian can only access their own calendar data.
     */
    if (requestedDieticianId !== tokenDieticianId) {
      await writeAuditLog({
        req,
        action: 'VIEW_CALENDAR_FILL_DATA',
        resourceType: 'dietician_calendar',
        resourceId: requestedDieticianId,
        status: 'failure',
        failureReason: 'DIETICIAN_ID_MISMATCH',
      });

      return res.status(403).json({
        status: false,
        message: 'Access denied',
      });
    }

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
      action: 'VIEW_CALENDAR_FILL_DATA',
      resourceType: 'dietician_calendar',
      resourceId: requestedDieticianId,
      status: 'success',
    });

    return res.status(200).json({
      status: true,
      message: 'Success',
      dietician_id: requestedDieticianId,
      data: results,
    });
  } catch (error) {
    console.error('GET_CALANDER_FILL_DATA_FAILED', {
      message: error.message,
      endpoint: '/dietitian/api/web/get_calander_fill_data',
    });

    await writeAuditLog({
      req,
      action: 'VIEW_CALENDAR_FILL_DATA',
      resourceType: 'dietician_calendar',
      resourceId: requestedDieticianId,
      status: 'failure',
      failureReason: 'SERVER_ERROR',
    });

    return res.status(500).json({
      status: false,
      message: 'Server error',
      ...(isProduction ? {} : { error: error.message }),
    });
  }
};

module.exports = { get_calander_fill_data };