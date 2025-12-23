const bcrypt = require('bcryptjs');
const pool = require('../src/config/database');

async function seedDatabase() {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');

    // Create Super Admin
    const superAdminHash = await bcrypt.hash('Admin@123', 10);
    await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES (NULL, $1, $2, $3, $4, true)
       ON CONFLICT DO NOTHING`,
      ['superadmin@system.com', superAdminHash, 'Super Admin', 'super_admin']
    );
    console.log('✓ Super Admin created');

    // Create Demo Tenant
    const tenantResult = await client.query(
      `INSERT INTO tenants (name, subdomain, status, subscription_plan, max_users, max_projects)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (subdomain) DO UPDATE SET subdomain = $2
       RETURNING id`,
      ['Demo Company', 'demo', 'active', 'pro', 25, 15]
    );
    const tenantId = tenantResult.rows[0].id;
    console.log('✓ Demo Tenant created');

    // Create Tenant Admin
    const adminHash = await bcrypt.hash('Demo@123', 10);
    const adminResult = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       ON CONFLICT (tenant_id, email) DO UPDATE SET email = $2
       RETURNING id`,
      [tenantId, 'admin@demo.com', adminHash, 'Demo Admin', 'tenant_admin']
    );
    const adminId = adminResult.rows[0].id;
    console.log('✓ Tenant Admin created');

    // Create Regular Users
    const userHash = await bcrypt.hash('User@123', 10);
    const user1Result = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       ON CONFLICT (tenant_id, email) DO UPDATE SET email = $2
       RETURNING id`,
      [tenantId, 'user1@demo.com', userHash, 'User One', 'user']
    );
    const user1Id = user1Result.rows[0].id;

    const user2Result = await client.query(
      `INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       ON CONFLICT (tenant_id, email) DO UPDATE SET email = $2
       RETURNING id`,
      [tenantId, 'user2@demo.com', userHash, 'User Two', 'user']
    );
    const user2Id = user2Result.rows[0].id;
    console.log('✓ Regular Users created');

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
    console.log('✓ Projects created');

    // Create Tasks
    await client.query(
      `INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES 
       ($1, $2, $3, $4, $5, $6, $7),
       ($1, $2, $8, $9, $10, $11, $12),
       ($1, $2, $13, $14, $15, $16, NULL),
       ($17, $2, $18, $19, $20, $21, $22),
       ($17, $2, $23, $24, $25, $26, $27)`,
      [
        project1Id, tenantId, 'Design Homepage', 'Create high-fidelity design', 'in_progress', 'high', user1Id,
        'Develop API', 'Backend API development', 'in_progress', 'high', user2Id,
        'Setup Database', 'Database schema design', 'todo', 'medium',
        project2Id, tenantId, 'Create Login Screen', 'User authentication screen', 'todo', 'high', user1Id,
        'Setup Firebase', 'Firebase configuration', 'completed', 'medium', user2Id
      ]
    );
    console.log('✓ Tasks created');

    await client.query('COMMIT');
    console.log('✓ Database seeded successfully');
    process.exit(0);
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('✗ Seed error:', error.message);
    process.exit(1);
  } finally {
    client.release();
  }
}

seedDatabase().catch(error => {
  console.error('Seed error:', error);
  process.exit(1);
});
