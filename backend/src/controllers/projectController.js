const { v4: uuidv4 } = require('uuid');
const pool = require('../config/database');
const { logAuditEvent } = require('../utils/auditLog');

const createProject = async (req, res) => {
  try {
    const { name, description, status = 'active' } = req.body;
    const { userId, tenantId } = req.user;

    if (!name) {
      return res.status(400).json({ success: false, message: 'Project name is required' });
    }

    // Check project limit
    const tenantResult = await pool.query(
      'SELECT max_projects FROM tenants WHERE id = $1',
      [tenantId]
    );

    if (tenantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Tenant not found' });
    }

    const projectCountResult = await pool.query(
      'SELECT COUNT(*) FROM projects WHERE tenant_id = $1',
      [tenantId]
    );

    const currentCount = parseInt(projectCountResult.rows[0].count);
    if (currentCount >= tenantResult.rows[0].max_projects) {
      return res.status(403).json({ success: false, message: 'Subscription limit reached: cannot create more projects' });
    }

    const projectId = uuidv4();
    await pool.query(
      `INSERT INTO projects (id, tenant_id, name, description, status, created_by)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [projectId, tenantId, name, description || null, status, userId]
    );

    await logAuditEvent(tenantId, userId, 'CREATE_PROJECT', 'project', projectId);

    res.status(201).json({
      success: true,
      data: {
        id: projectId,
        tenantId,
        name,
        description: description || null,
        status,
        createdBy: userId,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Create project error:', error);
    res.status(500).json({ success: false, message: 'Failed to create project' });
  }
};

const listProjects = async (req, res) => {
  try {
    const { status, search, page = 1, limit = 20 } = req.query;
    const { tenantId } = req.user;

    const offset = (page - 1) * limit;
    let query = `SELECT p.id, p.name, p.description, p.status, p.created_by, p.created_at,
                 u.full_name, COUNT(t.id) as task_count,
                 SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) as completed_task_count
                 FROM projects p
                 LEFT JOIN users u ON p.created_by = u.id
                 LEFT JOIN tasks t ON p.id = t.project_id
                 WHERE p.tenant_id = $1`;
    let countQuery = 'SELECT COUNT(*) FROM projects WHERE tenant_id = $1';
    const values = [tenantId];
    let paramCount = 2;

    if (status) {
      query += ` AND p.status = $${paramCount}`;
      countQuery += ` AND status = $${paramCount}`;
      values.push(status);
      paramCount++;
    }

    if (search) {
      const searchPattern = `%${search}%`;
      query += ` AND p.name ILIKE $${paramCount}`;
      countQuery += ` AND name ILIKE $${paramCount}`;
      values.push(searchPattern);
      paramCount++;
    }

    const countResult = await pool.query(countQuery, values);
    const total = parseInt(countResult.rows[0].count);

    query += ` GROUP BY p.id, p.name, p.description, p.status, p.created_by, p.created_at, u.full_name
               ORDER BY p.created_at DESC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
    values.push(limit, offset);

    const projectsResult = await pool.query(query, values);

    const projects = projectsResult.rows.map(p => ({
      id: p.id,
      name: p.name,
      description: p.description,
      status: p.status,
      createdBy: {
        id: p.created_by,
        fullName: p.full_name
      },
      taskCount: parseInt(p.task_count) || 0,
      completedTaskCount: parseInt(p.completed_task_count) || 0,
      createdAt: p.created_at
    }));

    const totalPages = Math.ceil(total / limit);

    res.json({
      success: true,
      data: {
        projects,
        total,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('List projects error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch projects' });
  }
};

const updateProject = async (req, res) => {
  try {
    const { projectId } = req.params;
    const { name, description, status } = req.body;
    const { userId, tenantId, role } = req.user;

    // Get project
    const projectResult = await pool.query(
      'SELECT created_by, tenant_id FROM projects WHERE id = $1',
      [projectId]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    const project = projectResult.rows[0];

    if (project.tenant_id !== tenantId) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    // Authorization: creator or tenant_admin
    if (role !== 'tenant_admin' && project.created_by !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    let updates = [];
    let values = [projectId];
    let paramCount = 2;

    if (name) {
      updates.push(`name = $${paramCount++}`);
      values.push(name);
    }

    if (description !== undefined) {
      updates.push(`description = $${paramCount++}`);
      values.push(description || null);
    }

    if (status) {
      updates.push(`status = $${paramCount++}`);
      values.push(status);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    const query = `UPDATE projects SET ${updates.join(', ')} WHERE id = $1 RETURNING *`;

    const updateResult = await pool.query(query, values);

    await logAuditEvent(tenantId, userId, 'UPDATE_PROJECT', 'project', projectId);

    res.json({
      success: true,
      message: 'Project updated successfully',
      data: {
        id: updateResult.rows[0].id,
        name: updateResult.rows[0].name,
        description: updateResult.rows[0].description,
        status: updateResult.rows[0].status,
        updatedAt: updateResult.rows[0].updated_at
      }
    });
  } catch (error) {
    console.error('Update project error:', error);
    res.status(500).json({ success: false, message: 'Failed to update project' });
  }
};

const deleteProject = async (req, res) => {
  try {
    const { projectId } = req.params;
    const { userId, tenantId, role } = req.user;

    // Get project
    const projectResult = await pool.query(
      'SELECT created_by, tenant_id FROM projects WHERE id = $1',
      [projectId]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    const project = projectResult.rows[0];

    if (project.tenant_id !== tenantId) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    // Authorization: creator or tenant_admin
    if (role !== 'tenant_admin' && project.created_by !== userId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    await pool.query('DELETE FROM projects WHERE id = $1', [projectId]);

    await logAuditEvent(tenantId, userId, 'DELETE_PROJECT', 'project', projectId);

    res.json({
      success: true,
      message: 'Project deleted successfully'
    });
  } catch (error) {
    console.error('Delete project error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete project' });
  }
};

module.exports = { createProject, listProjects, updateProject, deleteProject };
