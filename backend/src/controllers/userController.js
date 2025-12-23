const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const pool = require('../config/database');
const { logAuditEvent } = require('../utils/auditLog');

const addUserToTenant = async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { email, password, fullName, role = 'user' } = req.body;
    const { tenantId: userTenantId, role: userRole, userId } = req.user;

    // Authorization: only tenant_admin
    if (userRole !== 'tenant_admin' || userTenantId !== tenantId) {
      return res.status(403).json({ success: false, message: 'Only tenant admin can add users' });
    }

    // Validation
    if (!email || !password || !fullName) {
      return res.status(400).json({ success: false, message: 'Missing required fields' });
    }

    if (password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters' });
    }

    // Check tenant exists
    const tenantResult = await pool.query(
      'SELECT max_users FROM tenants WHERE id = $1',
      [tenantId]
    );

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Tenant not found' });
    }

    const tenant = tenantResult.rows[0];

    // Check user limit
    const userCountResult = await pool.query(
      'SELECT COUNT(*) FROM users WHERE tenant_id = $1',
      [tenantId]
    );

    const currentCount = parseInt(userCountResult.rows[0].count);
    if (currentCount >= tenant.max_users) {
      return res.status(403).json({ success: false, message: 'Subscription limit reached: cannot add more users' });
    }

    // Check email uniqueness in tenant
    const emailCheckResult = await pool.query(
      'SELECT id FROM users WHERE tenant_id = $1 AND email = $2',
      [tenantId, email]
    );

    if (emailCheckResult.rows.length > 0) {
      return res.status(409).json({ success: false, message: 'Email already exists in this tenant' });
    }

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Create user
    const newUserId = uuidv4();
    await pool.query(
      `INSERT INTO users (id, tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, $6, true)`,
      [newUserId, tenantId, email, passwordHash, fullName, role]
    );

    await logAuditEvent(tenantId, userId, 'CREATE_USER', 'user', newUserId);

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      data: {
        id: newUserId,
        email,
        fullName,
        role,
        tenantId,
        isActive: true,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Add user error:', error);
    res.status(500).json({ success: false, message: 'Failed to create user' });
  }
};

const listTenantUsers = async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { search, role, page = 1, limit = 50 } = req.query;
    const { tenantId: userTenantId } = req.user;

    // Authorization
    if (userTenantId !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    const offset = (page - 1) * limit;
    let query = 'SELECT id, email, full_name, role, is_active, created_at FROM users WHERE tenant_id = $1';
    let countQuery = 'SELECT COUNT(*) FROM users WHERE tenant_id = $1';
    const values = [tenantId];
    let paramCount = 2;

    if (search) {
      const searchPattern = `%${search}%`;
      query += ` AND (full_name ILIKE $${paramCount} OR email ILIKE $${paramCount})`;
      countQuery += ` AND (full_name ILIKE $${paramCount} OR email ILIKE $${paramCount})`;
      values.push(searchPattern);
      paramCount++;
    }

    if (role) {
      query += ` AND role = $${paramCount}`;
      countQuery += ` AND role = $${paramCount}`;
      values.push(role);
      paramCount++;
    }

    const countResult = await pool.query(countQuery, values);
    const total = parseInt(countResult.rows[0].count);

    query += ` ORDER BY created_at DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
    values.push(limit, offset);

    const usersResult = await pool.query(query, values);

    const users = usersResult.rows.map(u => ({
      id: u.id,
      email: u.email,
      fullName: u.full_name,
      role: u.role,
      isActive: u.is_active,
      createdAt: u.created_at
    }));

    const totalPages = Math.ceil(total / limit);

    res.json({
      success: true,
      data: {
        users,
        total,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('List users error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch users' });
  }
};

const updateUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { fullName, role, isActive } = req.body;
    const { userId: currentUserId, tenantId: userTenantId, role: userRole } = req.user;

    // Get user to check tenant
    const userResult = await pool.query(
      'SELECT tenant_id FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const targetUserTenantId = userResult.rows[0].tenant_id;

    // Authorization
    if (userRole !== 'tenant_admin' || userTenantId !== targetUserTenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    let updates = [];
    let values = [userId];
    let paramCount = 2;

    if (fullName) {
      updates.push(`full_name = $${paramCount++}`);
      values.push(fullName);
    }

    if (role !== undefined && userRole === 'tenant_admin') {
      updates.push(`role = $${paramCount++}`);
      values.push(role);
    }

    if (isActive !== undefined && userRole === 'tenant_admin') {
      updates.push(`is_active = $${paramCount++}`);
      values.push(isActive);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = $1 RETURNING id, full_name, role, updated_at`;

    const updateResult = await pool.query(query, values);

    await logAuditEvent(userTenantId, currentUserId, 'UPDATE_USER', 'user', userId);

    res.json({
      success: true,
      message: 'User updated successfully',
      data: {
        id: updateResult.rows[0].id,
        fullName: updateResult.rows[0].full_name,
        role: updateResult.rows[0].role,
        updatedAt: updateResult.rows[0].updated_at
      }
    });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ success: false, message: 'Failed to update user' });
  }
};

const deleteUser = async (req, res) => {
  try {
    const { userId } = req.params;
    const { userId: currentUserId, tenantId: userTenantId, role: userRole } = req.user;

    // Cannot delete self
    if (userId === currentUserId) {
      return res.status(403).json({ success: false, message: 'Cannot delete yourself' });
    }

    // Get user to check tenant
    const userResult = await pool.query(
      'SELECT tenant_id FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const targetUserTenantId = userResult.rows[0].tenant_id;

    // Authorization
    if (userRole !== 'tenant_admin' || userTenantId !== targetUserTenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    // Set assigned_to to NULL for tasks
    await pool.query(
      'UPDATE tasks SET assigned_to = NULL WHERE assigned_to = $1',
      [userId]
    );

    // Delete user
    await pool.query('DELETE FROM users WHERE id = $1', [userId]);

    await logAuditEvent(userTenantId, currentUserId, 'DELETE_USER', 'user', userId);

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete user' });
  }
};

module.exports = { addUserToTenant, listTenantUsers, updateUser, deleteUser };
