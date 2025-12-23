const { v4: uuidv4 } = require('uuid');
const pool = require('../config/database');
const { logAuditEvent } = require('../utils/auditLog');

const createTask = async (req, res) => {
  try {
    const { projectId } = req.params;
    const { title, description, assignedTo, priority = 'medium', dueDate } = req.body;
    const { userId, tenantId } = req.user;

    if (!title) {
      return res.status(400).json({ success: false, message: 'Task title is required' });
    }

    // Get project and verify it belongs to tenant
    const projectResult = await pool.query(
      'SELECT tenant_id FROM projects WHERE id = $1',
      [projectId]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    if (projectResult.rows[0].tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Project does not belong to your tenant' });
    }

    const projectTenantId = projectResult.rows[0].tenant_id;

    // Verify assignedTo user belongs to same tenant
    if (assignedTo) {
      const userResult = await pool.query(
        'SELECT tenant_id FROM users WHERE id = $1',
        [assignedTo]
      );

      if (userResult.rows.length === 0 || userResult.rows[0].tenant_id !== projectTenantId) {
        return res.status(400).json({ success: false, message: 'Assigned user does not belong to this tenant' });
      }
    }

    const taskId = uuidv4();
    await pool.query(
      `INSERT INTO tasks (id, project_id, tenant_id, title, description, priority, assigned_to, due_date, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'todo')`,
      [taskId, projectId, projectTenantId, title, description || null, priority, assignedTo || null, dueDate || null]
    );

    await logAuditEvent(projectTenantId, userId, 'CREATE_TASK', 'task', taskId);

    res.status(201).json({
      success: true,
      data: {
        id: taskId,
        projectId,
        tenantId: projectTenantId,
        title,
        description: description || null,
        status: 'todo',
        priority,
        assignedTo: assignedTo || null,
        dueDate: dueDate || null,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ success: false, message: 'Failed to create task' });
  }
};

const listProjectTasks = async (req, res) => {
  try {
    const { projectId } = req.params;
    const { status, assignedTo, priority, search, page = 1, limit = 50 } = req.query;
    const { tenantId } = req.user;

    // Verify project belongs to tenant
    const projectResult = await pool.query(
      'SELECT tenant_id FROM projects WHERE id = $1',
      [projectId]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Project not found' });
    }

    if (projectResult.rows[0].tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    const offset = (page - 1) * limit;
    let query = `SELECT t.id, t.title, t.description, t.status, t.priority, t.assigned_to, t.due_date, t.created_at,
                 u.full_name, u.email
                 FROM tasks t
                 LEFT JOIN users u ON t.assigned_to = u.id
                 WHERE t.project_id = $1`;
    let countQuery = 'SELECT COUNT(*) FROM tasks WHERE project_id = $1';
    const values = [projectId];
    let paramCount = 2;

    if (status) {
      query += ` AND t.status = $${paramCount}`;
      countQuery += ` AND status = $${paramCount}`;
      values.push(status);
      paramCount++;
    }

    if (assignedTo) {
      query += ` AND t.assigned_to = $${paramCount}`;
      countQuery += ` AND assigned_to = $${paramCount}`;
      values.push(assignedTo);
      paramCount++;
    }

    if (priority) {
      query += ` AND t.priority = $${paramCount}`;
      countQuery += ` AND priority = $${paramCount}`;
      values.push(priority);
      paramCount++;
    }

    if (search) {
      const searchPattern = `%${search}%`;
      query += ` AND t.title ILIKE $${paramCount}`;
      countQuery += ` AND title ILIKE $${paramCount}`;
      values.push(searchPattern);
      paramCount++;
    }

    const countResult = await pool.query(countQuery, values);
    const total = parseInt(countResult.rows[0].count);

    query += ` ORDER BY t.priority DESC, t.due_date ASC LIMIT $${paramCount} OFFSET $${paramCount + 1}`;
    values.push(limit, offset);

    const tasksResult = await pool.query(query, values);

    const tasks = tasksResult.rows.map(t => ({
      id: t.id,
      title: t.title,
      description: t.description,
      status: t.status,
      priority: t.priority,
      assignedTo: t.assigned_to ? {
        id: t.assigned_to,
        fullName: t.full_name,
        email: t.email
      } : null,
      dueDate: t.due_date,
      createdAt: t.created_at
    }));

    const totalPages = Math.ceil(total / limit);

    res.json({
      success: true,
      data: {
        tasks,
        total,
        pagination: {
          currentPage: parseInt(page),
          totalPages,
          limit: parseInt(limit)
        }
      }
    });
  } catch (error) {
    console.error('List tasks error:', error);
    res.status(500).json({ success: false, message: 'Failed to fetch tasks' });
  }
};

const updateTaskStatus = async (req, res) => {
  try {
    const { taskId } = req.params;
    const { status } = req.body;
    const { userId, tenantId } = req.user;

    if (!status) {
      return res.status(400).json({ success: false, message: 'Status is required' });
    }

    // Get task
    const taskResult = await pool.query(
      'SELECT tenant_id FROM tasks WHERE id = $1',
      [taskId]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }

    if (taskResult.rows[0].tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    await pool.query(
      'UPDATE tasks SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
      [status, taskId]
    );

    await logAuditEvent(tenantId, userId, 'UPDATE_TASK_STATUS', 'task', taskId);

    res.json({
      success: true,
      data: {
        id: taskId,
        status,
        updatedAt: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('Update task status error:', error);
    res.status(500).json({ success: false, message: 'Failed to update task' });
  }
};

const updateTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const { title, description, status, priority, assignedTo, dueDate } = req.body;
    const { userId, tenantId } = req.user;

    // Get task
    const taskResult = await pool.query(
      'SELECT tenant_id FROM tasks WHERE id = $1',
      [taskId]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }

    if (taskResult.rows[0].tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    // Verify assignedTo user if provided
    if (assignedTo) {
      const userResult = await pool.query(
        'SELECT tenant_id FROM users WHERE id = $1',
        [assignedTo]
      );

      if (userResult.rows.length === 0 || userResult.rows[0].tenant_id !== tenantId) {
        return res.status(400).json({ success: false, message: 'Assigned user does not belong to this tenant' });
      }
    }

    let updates = [];
    let values = [taskId];
    let paramCount = 2;

    if (title) {
      updates.push(`title = $${paramCount++}`);
      values.push(title);
    }

    if (description !== undefined) {
      updates.push(`description = $${paramCount++}`);
      values.push(description || null);
    }

    if (status) {
      updates.push(`status = $${paramCount++}`);
      values.push(status);
    }

    if (priority) {
      updates.push(`priority = $${paramCount++}`);
      values.push(priority);
    }

    if (assignedTo !== undefined) {
      updates.push(`assigned_to = $${paramCount++}`);
      values.push(assignedTo || null);
    }

    if (dueDate !== undefined) {
      updates.push(`due_date = $${paramCount++}`);
      values.push(dueDate || null);
    }

    if (updates.length === 0) {
      return res.status(400).json({ success: false, message: 'No valid fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    const query = `UPDATE tasks SET ${updates.join(', ')} WHERE id = $1 
                   RETURNING id, title, description, status, priority, assigned_to, due_date, updated_at`;

    const updateResult = await pool.query(query, values);
    const task = updateResult.rows[0];

    // Get assigned user details if exists
    let assignedUserData = null;
    if (task.assigned_to) {
      const userResult = await pool.query(
        'SELECT id, full_name, email FROM users WHERE id = $1',
        [task.assigned_to]
      );
      if (userResult.rows.length > 0) {
        assignedUserData = {
          id: userResult.rows[0].id,
          fullName: userResult.rows[0].full_name,
          email: userResult.rows[0].email
        };
      }
    }

    await logAuditEvent(tenantId, userId, 'UPDATE_TASK', 'task', taskId);

    res.json({
      success: true,
      message: 'Task updated successfully',
      data: {
        id: task.id,
        title: task.title,
        description: task.description,
        status: task.status,
        priority: task.priority,
        assignedTo: assignedUserData,
        dueDate: task.due_date,
        updatedAt: task.updated_at
      }
    });
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ success: false, message: 'Failed to update task' });
  }
};

const deleteTask = async (req, res) => {
  try {
    const { taskId } = req.params;
    const { userId, tenantId } = req.user;

    // Get task
    const taskResult = await pool.query(
      'SELECT tenant_id FROM tasks WHERE id = $1',
      [taskId]
    );

    if (taskResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Task not found' });
    }

    if (taskResult.rows[0].tenant_id !== tenantId) {
      return res.status(403).json({ success: false, message: 'Unauthorized access' });
    }

    await pool.query('DELETE FROM tasks WHERE id = $1', [taskId]);

    await logAuditEvent(tenantId, userId, 'DELETE_TASK', 'task', taskId);

    res.json({
      success: true,
      message: 'Task deleted successfully'
    });
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ success: false, message: 'Failed to delete task' });
  }
};

module.exports = { createTask, listProjectTasks, updateTaskStatus, updateTask, deleteTask };
