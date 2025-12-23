const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const pool = require('../config/database');
const { validateInput } = require('../utils/validation');
const { logAuditEvent } = require('../utils/auditLog');

const registerTenant = async (req, res) => {
  const { tenantName, subdomain, adminEmail, adminPassword, adminFullName } = req.body;

  try {
    const errors = validateInput(req.body, {
      tenantName: { required: true },
      subdomain: { required: true, pattern: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/ },
      adminEmail: { required: true, type: 'email' },
      adminPassword: { required: true, minLength: 8 },
      adminFullName: { required: true }
    });

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ success: false, message: 'Validation failed', data: errors });
    }

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      // Check if subdomain exists
      const subdomainCheck = await client.query(
        'SELECT id FROM tenants WHERE subdomain = $1',
        [subdomain]
      );
      if (subdomainCheck.rows.length > 0) {
        return res.status(409).json({ success: false, message: 'Subdomain already exists' });
      }

      // Check if email exists
      const emailCheck = await client.query(
        'SELECT id FROM users WHERE email = $1',
        [adminEmail]
      );
      if (emailCheck.rows.length > 0) {
        return res.status(409).json({ success: false, message: 'Email already exists' });
      }

      // Create tenant
      const tenantId = uuidv4();
      await client.query(
        `INSERT INTO tenants (id, name, subdomain, status, subscription_plan, max_users, max_projects)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [tenantId, tenantName, subdomain, 'active', 'free', 5, 3]
      );

      // Hash password
      const passwordHash = await bcrypt.hash(adminPassword, 10);

      // Create admin user
      const userId = uuidv4();
      await client.query(
        `INSERT INTO users (id, tenant_id, email, password_hash, full_name, role, is_active)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [userId, tenantId, adminEmail, passwordHash, adminFullName, 'tenant_admin', true]
      );

      await client.query('COMMIT');

      res.status(201).json({
        success: true,
        message: 'Tenant registered successfully',
        data: {
          tenantId,
          subdomain,
          adminUser: {
            id: userId,
            email: adminEmail,
            fullName: adminFullName,
            role: 'tenant_admin'
          }
        }
      });
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error('Register tenant error:', error);
    res.status(500).json({ success: false, message: 'Registration failed' });
  }
};

const login = async (req, res) => {
  const { email, password, tenantSubdomain } = req.body;

  try {
    const errors = validateInput(req.body, {
      email: { required: true, type: 'email' },
      password: { required: true },
      tenantSubdomain: { required: true }
    });

    if (Object.keys(errors).length > 0) {
      return res.status(400).json({ success: false, message: 'Validation failed', data: errors });
    }

    // Find tenant
    const tenantResult = await pool.query(
      'SELECT id, name, subscription_plan, max_users, max_projects, status FROM tenants WHERE subdomain = $1',
      [tenantSubdomain]
    );

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Tenant not found' });
    }

    const tenant = tenantResult.rows[0];

    if (tenant.status !== 'active') {
      return res.status(403).json({ success: false, message: 'Tenant account is not active' });
    }

    // Find user
    const userResult = await pool.query(
      `SELECT id, email, full_name, password_hash, role, is_active, tenant_id
       FROM users WHERE email = $1 AND tenant_id = $2`,
      [email, tenant.id]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    const user = userResult.rows[0];

    if (!user.is_active) {
      return res.status(403).json({ success: false, message: 'User account is inactive' });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ success: false, message: 'Invalid credentials' });
    }

    // Generate JWT
    const token = jwt.sign(
      {
        userId: user.id,
        tenantId: user.tenant_id,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Audit log
    await logAuditEvent(tenant.id, user.id, 'LOGIN', 'user', user.id);

    res.json({
      success: true,
      data: {
        user: {
          id: user.id,
          email: user.email,
          fullName: user.full_name,
          role: user.role,
          tenantId: user.tenant_id
        },
        token,
        expiresIn: 86400
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Login failed' });
  }
};

const getCurrentUser = async (req, res) => {
  try {
    const userId = req.user.userId;
    const tenantId = req.user.tenantId;

    const userResult = await pool.query(
      'SELECT id, email, full_name, role, is_active FROM users WHERE id = $1',
      [userId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    const user = userResult.rows[0];

    let tenant = null;
    if (tenantId) {
      const tenantResult = await pool.query(
        'SELECT id, name, subdomain, subscription_plan, max_users, max_projects FROM tenants WHERE id = $1',
        [tenantId]
      );
      if (tenantResult.rows.length > 0) {
        tenant = tenantResult.rows[0];
      }
    }

    res.json({
      success: true,
      data: {
        id: user.id,
        email: user.email,
        fullName: user.full_name,
        role: user.role,
        isActive: user.is_active,
        tenant: tenant ? {
          id: tenant.id,
          name: tenant.name,
          subdomain: tenant.subdomain,
          subscriptionPlan: tenant.subscription_plan,
          maxUsers: tenant.max_users,
          maxProjects: tenant.max_projects
        } : null
      }
    });
  } catch (error) {
    console.error('Get current user error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch user' });
  }
};

const logout = async (req, res) => {
  try {
    const userId = req.user.userId;
    const tenantId = req.user.tenantId;

    await logAuditEvent(tenantId, userId, 'LOGOUT', 'user', userId);

    res.json({ success: true, message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ success: false, message: 'Logout failed' });
  }
};

module.exports = { registerTenant, login, getCurrentUser, logout };
