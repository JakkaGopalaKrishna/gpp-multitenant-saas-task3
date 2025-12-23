const pool = require('../config/database');
const { logAuditEvent } = require('../utils/auditLog');

const getTenantDetails = async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { role, tenantId: userTenantId } = req.user;

    // Authorization check
    if (role !== 'super_admin' && userTenantId !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    const tenantResult = await pool.query(
      `SELECT id, name, subdomain, status, subscription_plan, max_users, max_projects, created_at
       FROM tenants WHERE id = $1`,
      [tenantId]
    );

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Tenant not found' });
    }

    const tenant = tenantResult.rows[0];

    // Get stats
    const usersCount = await pool.query(
      'SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role != $2',
      [tenantId, 'super_admin']
    );
    const projectsCount = await pool.query(
      'SELECT COUNT(*) FROM projects WHERE tenant_id = $1',
      [tenantId]
    );
    const tasksCount = await pool.query(
      'SELECT COUNT(*) FROM tasks WHERE tenant_id = $1',
      [tenantId]
    );

    res.json({
      success: true,
      data: {
        id: tenant.id,
        name: tenant.name,
        subdomain: tenant.subdomain,
        status: tenant.status,
        subscriptionPlan: tenant.subscription_plan,
        maxUsers: tenant.max_users,
        maxProjects: tenant.max_projects,
        createdAt: tenant.created_at,
        stats: {
          totalUsers: parseInt(usersCount.rows[0].count),
          totalProjects: parseInt(projectsCount.rows[0].count),
          totalTasks: parseInt(tasksCount.rows[0].count)
        }
      }
    });
  } catch (error) {
    console.error('Get tenant details error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch tenant' });
  }
};

const updateTenant = async (req, res) => {
  try {
    const { tenantId } = req.params;
    const { name, status, subscriptionPlan, maxUsers, maxProjects } = req.body;
    const { role, tenantId: userTenantId, userId } = req.user;

    // Authorization check
    if (role !== 'super_admin' && userTenantId !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    const tenantResult = await pool.query(
      'SELECT id FROM tenants WHERE id = $1',
      [tenantId]
    );

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Tenant not found' });
    }

    let updates = [];
    let values = [tenantId];
    let paramCount = 2;

    if (name && role === 'super_admin') {
      updates.push(`name = $${paramCount++}`);
      values.push(name);
    } else if (name && role === 'tenant_admin') {
      updates.push(`name = $${paramCount++}`);
      values.push(name);
    }

    if (status && role === 'super_admin') {
      updates.push(`status = $${paramCount++}`);
      values.push(status);
    } else if (status && role === 'tenant_admin') {
      return res.status(403).json({ success: false, message: 'Only super admin can update status' });
    }

    if (subscriptionPlan && role === 'super_admin') {
      updates.push(`subscription_plan = $${paramCount++}`);
      values.push(subscriptionPlan);
    } else if (subscriptionPlan && role === 'tenant_admin') {
      return res.status(403).json({ success: false, message: 'Only super admin can update subscription plan' });
    }

    if (maxUsers && role === 'super_admin') {
      updates.push(`max_users = $${paramCount++}`);
      values.push(maxUsers);
    } else if (maxUsers && role === 'tenant_admin') {
      return res.status(403).json({ success: false, message: 'Only super admin can update max users' });
    }

    if (maxProjects && role === 'super_admin') {
      updates.push(`max_projects = $${paramCount++}`);
      values.push(maxProjects);
    } else if (maxProjects && role === 'tenant_admin') {
      return res.status(403).json({ success: false, message: 'Only super admin can update max projects' });
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    const query = `UPDATE tenants SET ${updates.join(', ')} WHERE id = $1 RETURNING *`;

    const updateResult = await pool.query(query, values);

    await logAuditEvent(tenantId, userId, 'UPDATE_TENANT', 'tenant', tenantId);

    res.json({
      success: true,
      message: 'Tenant updated successfully',
      data: {
        id: updateResult.rows[0].id,
        name: updateResult.rows[0].name,
        updatedAt: updateResult.rows[0].updated_at
      }
    });
  } catch (error) {
    console.error('Update tenant error:', error);
    res.status(500).json({ success: false, message: 'Failed to update tenant' });
  }
};

const listAllTenants = async (req, res) => {
  try {
    const { role } = req.user;

    if (role !== 'super_admin') {
      return res.status(403).json({ success: false, message: 'Only super admin can view all tenants' });
    }

    const { page = 1, limit = 10, status, subscriptionPlan } = req.query;
    const offset = (page - 1) * limit;

    let query = 'SELECT * FROM tenants WHERE 1=1';
    let countQuery = 'SELECT COUNT(*) FROM tenants WHERE 1=1';
    const values = [];
    let paramCount = 1;

    if (status) {
      query += ` AND status = $${paramCount}`;
      countQuery += ` AND status = $${paramCount}`;
      values.push(status);
      paramCount++;
    }

    if (subscriptionPlan) {
      query += ` AND subscription_plan = $${paramCount}`;
      countQuery += ` AND subscription_plan = $${paramCount}`;
      values.push(subscriptionPlan);
      paramCount++;
    }

    countQuery += `;`;
    query += ` ORDER BY created_at DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;

    const countResult = await pool.query(countQuery, values);
    const totalTenants = parseInt(countResult.rows[0].count);

    const tenantsResult = await pool.query(query, [...values, limit, offset]);

    const tenants = await Promise.all(
      tenantsResult.rows.map(async (tenant) => {
        const usersCount = await pool.query(
          'SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND role != $2',
          [tenant.id, 'super_admin']
        );
        const projectsCount = await pool.query(
          'SELECT COUNT(*) FROM projects WHERE tenant_id = $1',
          [tenant.id]
        );

        return {
          id: tenant.id,
          name: tenant.name,
          subdomain: tenant.subdomain,
          status: tenant.status,
          subscriptionPlan: tenant.subscription_plan,
          totalUsers: parseInt(usersCount.rows[0].count),
          totalProjects: parseInt(projectsCount.rows[0].count),
          createdAt: tenant.created_at
        };
      })
    );

    const totalPages = Math.ceil(totalTenants / limit);

    res.json({
      success: true,
      data: {
        tenants,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          totalTenants,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('List tenants error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch tenants' });
  }
};

module.exports = { getTenantDetails, updateTenant, listAllTenants };
