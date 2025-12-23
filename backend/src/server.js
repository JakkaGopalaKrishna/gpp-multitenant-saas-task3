const express = require('express');
const cors = require('cors');
require('dotenv').config();
const pool = require('./config/database');

// Routes
const authRoutes = require('./routes/authRoutes');
const tenantRoutes = require('./routes/tenantRoutes');
const userRoutes = require('./routes/userRoutes');
const projectRoutes = require('./routes/projectRoutes');
const taskRoutes = require('./routes/taskRoutes');

const app = express();

// Middleware
const allowedOrigins = [
  process.env.FRONTEND_URL || 'http://frontend:3000',
  'http://localhost:3000'
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT 1');
    res.json({
      status: 'ok',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(503).json({
      status: 'error',
      database: 'disconnected',
      timestamp: new Date().toISOString()
    });
  }
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/tenants', tenantRoutes);
app.use('/api/tenants', userRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/projects', taskRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unexpected error:', err);
  res.status(500).json({
    success: false,
    message: 'An unexpected error occurred'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint not found'
  });
});

const PORT = process.env.PORT || 5000;

// Initialize database and start server
async function initializeDatabase() {
  try {
    console.log('Running database migrations...');
    const fs = require('fs');
    const path = require('path');
    const migrationsDir = path.join(__dirname, '../migrations');
    const files = fs.readdirSync(migrationsDir)
      .filter(f => f.endsWith('.sql'))
      .sort();

    for (const file of files) {
      const filePath = path.join(migrationsDir, file);
      const sql = fs.readFileSync(filePath, 'utf8');
      try {
        await pool.query(sql);
        console.log(`✓ Executed: ${file}`);
      } catch (error) {
        if (error.message.includes('already exists')) {
          console.log(`✓ Skipped: ${file} (already exists)`);
        } else {
          throw error;
        }
      }
    }
    console.log('✓ Database migrations completed');

    // Run seeds
    console.log('Running database seeds...');
    const seedsDir = path.join(__dirname, '../seeds');
    const seedFile = path.join(seedsDir, 'runSeeds.js');
    const { seedDatabase } = require('./config/seedData');
    await seedDatabase();
    console.log('✓ Database seeded');
  } catch (error) {
    console.error('Database initialization error:', error);
    process.exit(1);
  }
}

// Create seed data module
const seedDataContent = `const bcrypt = require('bcryptjs');
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
      \`INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES (NULL, $1, $2, $3, $4, true)\`,
      ['superadmin@system.com', superAdminHash, 'Super Admin', 'super_admin']
    );

    // Create Demo Tenant
    const tenantResult = await client.query(
      \`INSERT INTO tenants (name, subdomain, status, subscription_plan, max_users, max_projects)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id\`,
      ['Demo Company', 'demo', 'active', 'pro', 25, 15]
    );
    const tenantId = tenantResult.rows[0].id;

    // Create Tenant Admin
    const adminHash = await bcrypt.hash('Demo@123', 10);
    const adminResult = await client.query(
      \`INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id\`,
      [tenantId, 'admin@demo.com', adminHash, 'Demo Admin', 'tenant_admin']
    );
    const adminId = adminResult.rows[0].id;

    // Create Regular Users
    const userHash = await bcrypt.hash('User@123', 10);
    const user1Result = await client.query(
      \`INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id\`,
      [tenantId, 'user1@demo.com', userHash, 'User One', 'user']
    );
    const user1Id = user1Result.rows[0].id;

    const user2Result = await client.query(
      \`INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_active)
       VALUES ($1, $2, $3, $4, $5, true)
       RETURNING id\`,
      [tenantId, 'user2@demo.com', userHash, 'User Two', 'user']
    );
    const user2Id = user2Result.rows[0].id;

    // Create Projects
    const project1Result = await client.query(
      \`INSERT INTO projects (tenant_id, name, description, status, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id\`,
      [tenantId, 'Website Redesign', 'Complete redesign of company website', 'active', adminId]
    );
    const project1Id = project1Result.rows[0].id;

    const project2Result = await client.query(
      \`INSERT INTO projects (tenant_id, name, description, status, created_by)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id\`,
      [tenantId, 'Mobile App', 'Native mobile app development', 'active', adminId]
    );
    const project2Id = project2Result.rows[0].id;

    // Create Tasks
    await client.query(
      \`INSERT INTO tasks (project_id, tenant_id, title, description, status, priority, assigned_to)
       VALUES 
       ($1, $2, $3, $4, $5, $6, $7),
       ($1, $2, $8, $9, $10, $11, $12),
       ($1, $2, $13, $14, $15, $16, NULL),
       ($17, $2, $18, $19, $20, $21, $22),
       ($17, $2, $23, $24, $25, $26, $27)\`,
      [
        project1Id, tenantId, 'Design Homepage', 'Create high-fidelity design', 'in_progress', 'high', user1Id,
        'Develop API', 'Backend API development', 'in_progress', 'high', user2Id,
        'Setup Database', 'Database schema design', 'todo', 'medium',
        project2Id, tenantId, 'Create Login Screen', 'User authentication screen', 'todo', 'high', user1Id,
        'Setup Firebase', 'Firebase configuration', 'completed', 'medium', user2Id
      ]
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
`;

// Create the seed data file dynamically
const fs = require('fs');
const path = require('path');
const seedDataPath = path.join(__dirname, 'config/seedData.js');
if (!fs.existsSync(seedDataPath)) {
  fs.writeFileSync(seedDataPath, seedDataContent);
}

// Start server
app.listen(PORT, async () => {
  console.log(`Server is running on port ${PORT}`);
  await initializeDatabase();
});

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('Shutting down gracefully...');
  await pool.end();
  process.exit(0);
});
