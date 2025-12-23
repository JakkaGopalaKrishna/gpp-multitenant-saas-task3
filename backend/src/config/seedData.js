const bcrypt = require('bcryptjs');
const pool = require('./database');

async function seedDatabase() {
  const client = await pool.connect();
  
  try {
    // Check if data already exists
    const userCount = await client.query('SELECT COUNT(*) FROM users');
    if (parseInt(userCount.rows[0].count) > 0) {
      console.log('Database already seeded, skipping...');
      return;
    }

    await client.query('BEGIN');

    // Create Super Admin
    const superAdminHash = await bcrypt.hash('Admin@123', 10);
    await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES (NULL, $1, $2, $3, $4, true)`,
      ['superadmin@system.com', superAdminHash, 'Super Admin', 'super_admin']
    );

    // Create Demo Tenant
    const tenantResult = await client.query(
      `INSERT INTO tenants (name, subdomain, status, subscription_plan, max_users, max_projects)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id`,
      ['Demo Company', 'demo', 'active', 'pro', 25, 15]
    );
    const tenantId = tenantResult.rows[0].id;

    // Create Tenant Admin
    const adminHash = await bcrypt.hash('Demo@123', 10);
    const adminResult = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id`,
      [tenantId, 'admin@demo.com', adminHash, 'Demo Admin', 'tenant_admin']
    );
    const adminId = adminResult.rows[0].id;

    // Create Regular Users
    const userHash = await bcrypt.hash('User@123', 10);
    const user1Result = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id`,
      [tenantId, 'user1@demo.com', userHash, 'User One', 'user']
    );
    const user1Id = user1Result.rows[0].id;

    const user2Result = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id`,
      [tenantId, 'user2@demo.com', userHash, 'User Two', 'user']
    );
    const user2Id = user2Result.rows[0].id;

    // Create Projects
    const project1Result = await client.query(
      `INSERT INTO projects (tenant_id, name, description, status, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [tenantId, 'Website Redesign', 'Complete redesign of company website', 'active', adminId]
    );
    const project1Id = project1Result.rows[0].id;

    const project2Result = await client.query(
      `INSERT INTO projects (tenant_id, name, description, status, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [tenantId, 'Mobile App', 'Native mobile app development', 'active', adminId]
    );
    const project2Id = project2Result.rows[0].id;

    // Create Tasks (separate inserts to avoid parameter binding issues)
    await client.query(
      `INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [project1Id, tenantId, 'Design Homepage', 'Create high-fidelity design', 'in_progress', 'high', user1Id]
    );

    await client.query(
      `INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [project1Id, tenantId, 'Develop API', 'Backend API development', 'in_progress', 'high', user2Id]
    );

    await client.query(
      `INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES ($1, $2, $3, $4, $5, $6, NULL)`,
      [project1Id, tenantId, 'Setup Database', 'Database schema design', 'todo', 'medium']
    );

    await client.query(
      `INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [project2Id, tenantId, 'Create Login Screen', 'User authentication screen', 'todo', 'high', user1Id]
    );

    await client.query(
      `INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [project2Id, tenantId, 'Setup Firebase', 'Firebase configuration', 'completed', 'medium', user2Id]
    );

    await client.query('COMMIT');
    console.log('Database seeded successfully');
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.message.includes('duplicate') || error.message.includes('already exists')) {
      console.log('Data already exists, skipping seed...');
      return;
    }
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { seedDatabase };
