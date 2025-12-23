# Development Guide

## Quick Start for Developers

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd gpp-task3

# Install backend dependencies
cd backend
npm install
cp .env.example .env

# Install frontend dependencies
cd ../frontend
npm install
```

### Start Development Servers

```bash
# Terminal 1: Start backend (with nodemon auto-reload)
cd backend
npm run dev

# Terminal 2: Start frontend (with hot reload)
cd frontend
npm start

# Terminal 3 (Optional): Start database for local development
# Using Docker
docker run -d --name postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=gpp_saas \
  -p 5432:5432 \
  postgres:15

# Run migrations and seeds
cd backend
npm run migrate
npm run seed
```

### Access Application

- **Frontend**: http://localhost:3000
- **Backend API**: http://localhost:5000/api
- **API Health Check**: http://localhost:5000/api/health

---

## Project Structure

### Backend Structure

```
backend/
├── src/
│   ├── config/
│   │   └── database.js              # PostgreSQL connection pool
│   ├── middleware/
│   │   ├── auth.js                  # JWT verification
│   │   └── authorization.js         # Role-based access control
│   ├── controllers/
│   │   ├── authController.js        # Authentication logic
│   │   ├── tenantController.js      # Tenant management
│   │   ├── userController.js        # User management
│   │   ├── projectController.js     # Project management
│   │   └── taskController.js        # Task management
│   ├── routes/
│   │   ├── authRoutes.js            # /api/auth/*
│   │   ├── tenantRoutes.js          # /api/tenants/*
│   │   ├── userRoutes.js            # /api/users/*
│   │   ├── projectRoutes.js         # /api/projects/*
│   │   └── taskRoutes.js            # /api/tasks/*
│   ├── utils/
│   │   ├── auditLog.js              # Audit logging
│   │   └── validation.js            # Input validation
│   └── server.js                    # Express server setup
├── migrations/
│   ├── 001_create_tenants.sql
│   ├── 002_create_users.sql
│   ├── 003_create_projects.sql
│   ├── 004_create_tasks.sql
│   ├── 005_create_audit_logs.sql
│   └── runMigrations.js             # Migration runner
├── seeds/
│   ├── seedData.js                  # Sample data
│   └── runSeeds.js                  # Seed runner
├── Dockerfile                       # Docker image
├── package.json                     # Dependencies & scripts
├── .env                             # Environment variables
└── .env.example                     # Example env file

Frontend Structure:

frontend/
├── public/
│   └── index.html                   # HTML entry point
├── src/
│   ├── context/
│   │   └── AuthContext.js           # Authentication state
│   ├── services/
│   │   └── api.js                   # Axios API client
│   ├── pages/
│   │   ├── Register.js              # Tenant registration
│   │   ├── Login.js                 # User login
│   │   ├── Dashboard.js             # Home page
│   │   ├── Projects.js              # Projects list
│   │   ├── ProjectDetails.js        # Project view
│   │   └── Users.js                 # User management
│   ├── components/
│   │   └── Navigation.js            # Header/navbar
│   ├── App.js                       # Main app component
│   ├── App.css                      # Global styles
│   └── index.js                     # React DOM render
├── Dockerfile                       # Docker image
├── package.json                     # Dependencies & scripts
└── .env                             # Environment variables
```

---

## Code Style & Standards

### JavaScript/Node.js Conventions

```javascript
// 1. Use camelCase for variables and functions
const getUserById = (userId) => { };
const userEmail = 'user@example.com';

// 2. Use PascalCase for classes and React components
class UserService { }
function Dashboard() { }

// 3. Use UPPER_SNAKE_CASE for constants
const MAX_USERS_PER_TENANT = 100;
const JWT_EXPIRY = '24h';

// 4. Always validate input
const validateEmail = (email) => {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
};

// 5. Use async/await for promises
async function fetchUser(userId) {
  try {
    const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    return result.rows[0];
  } catch (error) {
    logger.error('Failed to fetch user', error);
    throw error;
  }
}

// 6. Consistent error handling
try {
  // Operation
} catch (error) {
  logger.error('Operation failed', { error: error.message, userId });
  res.status(500).json({ success: false, message: 'Internal server error' });
}
```

### React Conventions

```javascript
// 1. Use hooks for state management
import { useState, useEffect, useContext } from 'react';

// 2. Component structure
function Component() {
  // 1. State
  const [state, setState] = useState('');
  
  // 2. Context
  const { user } = useContext(AuthContext);
  
  // 3. Effects
  useEffect(() => {
    // Load data
  }, []);
  
  // 4. Handlers
  const handleClick = () => { };
  
  // 5. Render
  return (
    <div className="component">
      {/* JSX content */}
    </div>
  );
}

// 3. Use PropTypes for type checking
import PropTypes from 'prop-types';

Component.propTypes = {
  userId: PropTypes.string.isRequired,
  onUpdate: PropTypes.func
};

// 4. Conditional rendering
{isAdmin && <AdminPanel />}
{loading ? <Spinner /> : <Content />}

// 5. List rendering with keys
{items.map((item) => (
  <div key={item.id}>{item.name}</div>
))}
```

### SQL Conventions

```sql
-- 1. Use uppercase for SQL keywords
SELECT * FROM users WHERE status = 'active';

-- 2. Parameterized queries (prevent SQL injection)
-- DO: Use $1, $2 placeholders
SELECT * FROM users WHERE id = $1 AND tenant_id = $2;
-- DON'T: String concatenation
SELECT * FROM users WHERE id = '${userId}';

-- 3. Use meaningful table names
-- DO: tenants, users, projects, tasks
-- DON'T: t1, tbl_user, user_tbl

-- 4. Add proper constraints
ALTER TABLE users ADD CONSTRAINT uk_users_email_tenant 
  UNIQUE (email, tenant_id);

-- 5. Create indexes for frequently queried columns
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
```

### API Response Format

```javascript
// Success response
res.status(200).json({
  success: true,
  message: 'Operation successful',
  data: { /* response data */ }
});

// Error response
res.status(400).json({
  success: false,
  message: 'Validation failed',
  data: { /* optional error details */ }
});

// Status codes to use:
// 200: GET success, general success
// 201: POST success, resource created
// 204: DELETE success, no content
// 400: Bad request, validation error
// 401: Unauthorized, authentication failed
// 403: Forbidden, insufficient permissions
// 404: Not found
// 409: Conflict, duplicate resource
// 500: Server error
```

---

## Common Development Tasks

### Adding a New API Endpoint

#### 1. Create Controller Method

File: `backend/src/controllers/projectController.js`

```javascript
// Add new controller method
const getProjectStats = async (req, res) => {
  try {
    const { projectId } = req.params;
    const { tenantId } = req.user; // From JWT

    // Validate
    if (!projectId) {
      return res.status(400).json({
        success: false,
        message: 'Project ID is required'
      });
    }

    // Authorize (verify project belongs to tenant)
    const project = await db.query(
      'SELECT * FROM projects WHERE id = $1 AND tenant_id = $2',
      [projectId, tenantId]
    );

    if (!project.rows.length) {
      return res.status(404).json({
        success: false,
        message: 'Project not found'
      });
    }

    // Fetch stats
    const stats = await db.query(`
      SELECT
        COUNT(*) as total_tasks,
        SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed_tasks,
        SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) as in_progress_tasks,
        SUM(CASE WHEN status = 'todo' THEN 1 ELSE 0 END) as todo_tasks
      FROM tasks
      WHERE project_id = $1
    `, [projectId]);

    // Audit log
    await auditLog({
      tenantId,
      userId: req.user.id,
      action: 'view_project_stats',
      entityType: 'project',
      entityId: projectId
    });

    res.json({
      success: true,
      data: stats.rows[0]
    });

  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch project stats',
      error: error.message
    });
  }
};
```

#### 2. Add Route

File: `backend/src/routes/projectRoutes.js`

```javascript
// Add route
router.get('/:projectId/stats', auth, async (req, res) => {
  // Authorization check (user must be in project's tenant)
  const { tenantId } = req.user;
  
  // Call controller
  await getProjectStats(req, res);
});
```

#### 3. Export Controller Function

```javascript
module.exports = {
  createProject,
  listProjects,
  updateProject,
  deleteProject,
  getProjectStats  // Add this export
};
```

#### 4. Test the Endpoint

```bash
# Using curl
curl -X GET http://localhost:5000/api/projects/550e8400-e29b-41d4-a716-446655440000/stats \
  -H "Authorization: Bearer <token>"

# Using Postman
GET http://localhost:5000/api/projects/{projectId}/stats
Headers: Authorization: Bearer <token>
```

### Adding a New Frontend Page

#### 1. Create React Component

File: `frontend/src/pages/ProjectStats.js`

```javascript
import React, { useState, useEffect, useContext } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { AuthContext } from '../context/AuthContext';
import api from '../services/api';

function ProjectStats() {
  const { projectId } = useParams();
  const navigate = useNavigate();
  const { user } = useContext(AuthContext);
  
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!user) return;
    
    fetchStats();
  }, [projectId, user]);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const response = await api.get(`/projects/${projectId}/stats`);
      
      if (response.data.success) {
        setStats(response.data.data);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch stats');
    } finally {
      setLoading(false);
    }
  };

  if (!user) return <div>Please login</div>;
  if (loading) return <div>Loading...</div>;
  if (error) return <div className="alert alert-danger">{error}</div>;

  return (
    <div className="container mt-4">
      <h2>Project Statistics</h2>
      <div className="row">
        <div className="col-md-3">
          <div className="card">
            <div className="card-body">
              <h5>Total Tasks</h5>
              <p className="h3">{stats?.total_tasks || 0}</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card">
            <div className="card-body">
              <h5>Completed</h5>
              <p className="h3 text-success">{stats?.completed_tasks || 0}</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card">
            <div className="card-body">
              <h5>In Progress</h5>
              <p className="h3 text-warning">{stats?.in_progress_tasks || 0}</p>
            </div>
          </div>
        </div>
        <div className="col-md-3">
          <div className="card">
            <div className="card-body">
              <h5>Todo</h5>
              <p className="h3 text-danger">{stats?.todo_tasks || 0}</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export default ProjectStats;
```

#### 2. Add Route

File: `frontend/src/App.js`

```javascript
import ProjectStats from './pages/ProjectStats';

// Inside router definition
<ProtectedRoute>
  <Route path="/projects/:projectId/stats" element={<ProjectStats />} />
</ProtectedRoute>
```

#### 3. Add Navigation Link

File: `frontend/src/components/Navigation.js`

```javascript
<Link className="nav-link" to="/projects/:projectId/stats">
  Project Stats
</Link>
```

---

## Database Query Examples

### Common Patterns

```javascript
// 1. Find single record
const result = await db.query(
  'SELECT * FROM users WHERE id = $1',
  [userId]
);
const user = result.rows[0];

// 2. Insert record
const result = await db.query(
  'INSERT INTO users (email, password_hash, tenant_id) VALUES ($1, $2, $3) RETURNING *',
  [email, hashedPassword, tenantId]
);
const newUser = result.rows[0];

// 3. Update record
const result = await db.query(
  'UPDATE users SET full_name = $1, updated_at = NOW() WHERE id = $2 RETURNING *',
  [fullName, userId]
);

// 4. Delete record
await db.query(
  'DELETE FROM users WHERE id = $1',
  [userId]
);

// 5. List with pagination
const offset = (page - 1) * limit;
const result = await db.query(
  'SELECT * FROM projects WHERE tenant_id = $1 LIMIT $2 OFFSET $3',
  [tenantId, limit, offset]
);

// 6. Count records
const result = await db.query(
  'SELECT COUNT(*) FROM projects WHERE tenant_id = $1',
  [tenantId]
);
const count = parseInt(result.rows[0].count, 10);

// 7. Join tables
const result = await db.query(`
  SELECT u.*, p.name as project_name
  FROM users u
  LEFT JOIN projects p ON u.id = p.created_by
  WHERE u.tenant_id = $1
`, [tenantId]);

// 8. Transaction
const client = await db.connect();
try {
  await client.query('BEGIN');
  
  await client.query('INSERT INTO tenants ...', []);
  await client.query('INSERT INTO users ...', []);
  
  await client.query('COMMIT');
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
}
```

---

## Testing

### Manual Testing Checklist

```javascript
// Test registration
POST /api/auth/register-tenant
{
  "tenantName": "Test Company",
  "subdomain": "testco",
  "adminEmail": "admin@testco.com",
  "adminPassword": "TestPass123",
  "adminFullName": "Test Admin"
}

// Test login
POST /api/auth/login
{
  "email": "admin@testco.com",
  "password": "TestPass123",
  "tenantSubdomain": "testco"
}

// Test protected endpoint
GET /api/auth/me
Headers: Authorization: Bearer <token>

// Test tenant isolation
// Login as different tenant
// Verify can't access other tenant's data
```

### Browser Testing

```javascript
// Test in browser console
// Check local storage
localStorage.getItem('authToken');
localStorage.getItem('user');

// Clear auth
localStorage.removeItem('authToken');
localStorage.removeItem('user');

// Check network requests
// Open DevTools → Network tab
// Look for Authorization header in requests
// Verify CORS headers in responses
```

---

## Debugging Tips

### Backend Debugging

```javascript
// Add console logs
console.log('User:', req.user);
console.log('Query result:', result.rows);

// Use debugger
// Add to code: debugger;
// Run with: node --inspect src/server.js
// Open: chrome://inspect

// Check environment variables
console.log('Database URL:', process.env.DATABASE_URL);
console.log('JWT Secret:', process.env.JWT_SECRET);

// Database query logging
const result = await db.query(sql, params);
console.log('Query:', sql);
console.log('Params:', params);
console.log('Result:', result.rows);
```

### Frontend Debugging

```javascript
// Use React DevTools extension
// Install: React Developer Tools from Chrome Web Store

// Check state in components
import { useContext } from 'react';
const { user, token } = useContext(AuthContext);
console.log('Auth State:', { user, token });

// API request/response logging
// In api.js, add interceptors
api.interceptors.response.use(
  response => {
    console.log('API Response:', response.config.url, response.data);
    return response;
  }
);

// Check localStorage
console.log('Stored token:', localStorage.getItem('authToken'));
console.log('Stored user:', localStorage.getItem('user'));
```

### Docker Debugging

```bash
# View container logs
docker logs container_name
docker logs -f container_name  # Follow logs

# Execute commands in container
docker exec container_name bash
docker exec database psql -U postgres -d gpp_saas

# Inspect container
docker inspect container_name

# Check resource usage
docker stats

# View network
docker network inspect gpp-task3_saas-network
```

---

## Common Issues & Solutions

### Issue: Module not found errors

```bash
# Solution: Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Clear npm cache
npm cache clean --force
npm install
```

### Issue: Port already in use

```bash
# Find process using port
lsof -i :5000  # macOS/Linux
netstat -ano | findstr :5000  # Windows

# Kill process
kill -9 pid_number  # macOS/Linux
taskkill /PID pid_number /F  # Windows

# Use different port
NODE_PORT=5001 npm start
```

### Issue: CORS errors

```javascript
// Check CORS configuration in backend
// In server.js:
app.use(cors({
  origin: process.env.FRONTEND_URL,
  credentials: true
}));

// Ensure FRONTEND_URL matches frontend's origin
// http://localhost:3000 for local development
```

### Issue: Token not working

```bash
# Check token exists in localStorage
localStorage.getItem('authToken')

# Check token is sent in Authorization header
# DevTools → Network → Select request → Headers
# Look for: Authorization: Bearer <token>

# Check token format
# Should be: Authorization: Bearer eyJhbGc...

# Regenerate token by logging in again
```

---

## Performance Tips

### Backend Optimization

- Use database indexes on frequently queried columns
- Implement pagination for large datasets
- Use connection pooling for database
- Cache frequently accessed data
- Avoid N+1 queries (use joins)
- Optimize database queries

### Frontend Optimization

- Use React.memo for expensive components
- Lazy load routes with React.lazy
- Minimize re-renders with useCallback
- Use proper key props in lists
- Split code into smaller bundles
- Cache API responses

---

## Resources

- [Express.js Documentation](https://expressjs.com/)
- [React Documentation](https://react.dev/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [JWT Documentation](https://jwt.io/)
- [Bootstrap Documentation](https://getbootstrap.com/docs/)

---

**Last Updated:** December 2024  
**Version:** 1.0
