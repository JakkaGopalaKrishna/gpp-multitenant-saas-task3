const pool = require('../config/database');

const logAuditEvent = async (tenantId, userId, action, entityType, entityId, details = null, ipAddress = null) => {
  try {
    await pool.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, entity_type, entity_id, details, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [tenantId, userId, action, entityType, entityId, details ? JSON.stringify(details) : null, ipAddress]
    );
  } catch (error) {
    console.error('Audit logging error:', error);
  }
};

module.exports = { logAuditEvent };
