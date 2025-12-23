# Multi-Tenant SaaS Platform - Project & Task Management

A production-ready, multi-tenant SaaS application built with Node.js, React, and PostgreSQL. Manage your organizations, teams, projects, and tasks with complete data isolation and role-based access control.

## 🎯 Key Features

- **Multi-Tenant Architecture**: Complete data isolation between organizations
- **Secure Authentication**: JWT-based authentication with 24-hour token expiry
- **Role-Based Access Control**: Super Admin, Tenant Admin, and User roles
- **Project Management**: Create and manage projects with full team collaboration
- **Task Management**: Track tasks with status, priority, and assignees
- **User Management**: Manage team members with different roles and permissions
- **Subscription Plans**: Free, Pro, and Enterprise plans with configurable limits
- **Audit Logging**: Complete audit trail of all important actions
- **Docker Containerization**: One-command deployment with docker-compose

## 🏗️ Architecture

### Multi-Tenancy Approach
This application uses **Shared Database + Shared Schema (with tenant_id)** approach:
- **Pros**: Simple implementation, cost-effective, easy data export per tenant
- **Cons**: Requires strict tenant_id filtering to prevent data leaks
- **Choice**: Selected for scalability and simplicity

### Technology Stack

**Backend**
- Node.js + Express.js
- PostgreSQL database
- JWT for authentication
- bcryptjs for password hashing

**Frontend**
- React 18
- React Router for navigation
- Axios for API calls
- Bootstrap 5 for styling

**Deployment**
- Docker & Docker Compose
- PostgreSQL 15

## 📦 Installation & Setup

### Prerequisites
- Node.js 18+
- Docker & Docker Compose
- PostgreSQL 15

### Local Development Setup

1. **Clone the repository**
   ```bash
   git clone <repo-url>
   cd gpp-task3
   ```

2. **Backend Setup**
   ```bash
   cd backend
   npm install
   cp .env.example .env
   npm run setup-db  # Runs migrations and seeds
   npm run dev      # Start backend in development mode
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   npm start        # Starts on http://localhost:3000
   ```

Backend will run on: http://localhost:5000
Frontend will run on: http://localhost:3000

### Docker Deployment

One-command deployment:
```bash
docker-compose up -d
```

This will:
- Create PostgreSQL database
- Build and start backend API
- Build and start React frontend
- Run migrations and seed data automatically

Access the application:
- Frontend: http://localhost:3000
- API: http://localhost:5000/api

## 🔐 Security Features

- **Data Isolation**: Every record is associated with a tenant_id
- **JWT Authentication**: Stateless, 24-hour expiry
- **Password Hashing**: bcryptjs with salt rounds 10
- **Role-Based Authorization**: API-level permission checks
- **SQL Injection Prevention**: Parameterized queries
- **CORS Configuration**: Restricted to frontend origin

## 📚 API Documentation

### Base URL
- Development: `http://localhost:5000/api`
- Docker: `http://backend:5000/api`

### Authentication Endpoints

#### Register Tenant
```
POST /api/auth/register-tenant
Body: {
  "tenantName": "string",
  "subdomain": "string",
  "adminEmail": "string",
  "adminPassword": "string (min 8 chars)",
  "adminFullName": "string"
}
Response: 201 - { "success": true, "data": { "tenantId", "subdomain", "adminUser" } }
```

#### Login
```
POST /api/auth/login
Body: {
  "email": "string",
  "password": "string",
  "tenantSubdomain": "string"
}
Response: 200 - { "success": true, "data": { "user", "token", "expiresIn" } }
```

#### Get Current User
```
GET /api/auth/me
Headers: Authorization: Bearer {token}
Response: 200 - { "success": true, "data": { "user info with tenant details" } }
```

#### Logout
```
POST /api/auth/logout
Headers: Authorization: Bearer {token}
Response: 200 - { "success": true, "message": "Logged out successfully" }
```

### Tenant Endpoints

#### Get Tenant Details
```
GET /api/tenants/:tenantId
Auth: Required
Response: 200 - { "success": true, "data": { "tenant with stats" } }
```

#### List All Tenants (Super Admin Only)
```
GET /api/tenants?page=1&limit=10&status=active&subscriptionPlan=pro
Auth: Required
Response: 200 - { "success": true, "data": { "tenants", "pagination" } }
```

#### Update Tenant
```
PUT /api/tenants/:tenantId
Auth: Required
Body: { "name", "status", "subscriptionPlan", "maxUsers", "maxProjects" }
Response: 200 - { "success": true, "data": { "updated tenant" } }
```

### User Management Endpoints

#### Add User to Tenant
```
POST /api/tenants/:tenantId/users
Auth: Required (tenant_admin only)
Body: {
  "email": "string",
  "password": "string (min 8 chars)",
  "fullName": "string",
  "role": "user|tenant_admin"
}
Response: 201 - { "success": true, "data": { "new user" } }
```

#### List Tenant Users
```
GET /api/tenants/:tenantId/users?search=query&role=user&page=1&limit=50
Auth: Required
Response: 200 - { "success": true, "data": { "users", "pagination" } }
```

#### Update User
```
PUT /api/users/:userId
Auth: Required (tenant_admin or self)
Body: { "fullName", "role", "isActive" }
Response: 200 - { "success": true, "data": { "updated user" } }
```

#### Delete User
```
DELETE /api/users/:userId
Auth: Required (tenant_admin only)
Response: 200 - { "success": true, "message": "User deleted successfully" }
```

### Project Endpoints

#### Create Project
```
POST /api/projects
Auth: Required
Body: { "name": "string", "description": "string (optional)" }
Response: 201 - { "success": true, "data": { "new project" } }
```

#### List Projects
```
GET /api/projects?status=active&search=query&page=1&limit=20
Auth: Required
Response: 200 - { "success": true, "data": { "projects", "pagination" } }
```

#### Update Project
```
PUT /api/projects/:projectId
Auth: Required (creator or tenant_admin)
Body: { "name", "description", "status" }
Response: 200 - { "success": true, "data": { "updated project" } }
```

#### Delete Project
```
DELETE /api/projects/:projectId
Auth: Required (creator or tenant_admin)
Response: 200 - { "success": true, "message": "Project deleted successfully" }
```

### Task Endpoints

#### Create Task
```
POST /api/projects/:projectId/tasks
Auth: Required
Body: {
  "title": "string",
  "description": "string (optional)",
  "assignedTo": "uuid (optional)",
  "priority": "low|medium|high",
  "dueDate": "YYYY-MM-DD (optional)"
}
Response: 201 - { "success": true, "data": { "new task" } }
```

#### List Project Tasks
```
GET /api/projects/:projectId/tasks?status=todo&priority=high&search=query&page=1&limit=50
Auth: Required
Response: 200 - { "success": true, "data": { "tasks", "pagination" } }
```

#### Update Task Status
```
PATCH /api/tasks/:taskId/status
Auth: Required
Body: { "status": "todo|in_progress|completed" }
Response: 200 - { "success": true, "data": { "updated task" } }
```

#### Update Task
```
PUT /api/tasks/:taskId
Auth: Required
Body: {
  "title": "string (optional)",
  "description": "string (optional)",
  "status": "todo|in_progress|completed (optional)",
  "priority": "low|medium|high (optional)",
  "assignedTo": "uuid (optional)",
  "dueDate": "YYYY-MM-DD (optional)"
}
Response: 200 - { "success": true, "data": { "updated task" } }
```

#### Delete Task
```
DELETE /api/tasks/:taskId
Auth: Required
Response: 200 - { "success": true, "message": "Task deleted successfully" }
```

### Health Check
```
GET /api/health
Response: 200 - { "status": "ok", "database": "connected" }
```

## 🧪 Test Credentials

### Super Admin
- Email: `superadmin@system.com`
- Password: `Admin@123`

### Demo Tenant
- Subdomain: `demo`
- Admin Email: `admin@demo.com`
- Admin Password: `Demo@123`

### Demo Users
- User 1: `user1@demo.com` / `User@123`
- User 2: `user2@demo.com` / `User@123`

## 📊 Database Schema

### Tables
- **tenants**: Organization information with subscription plans
- **users**: User accounts with role-based access
- **projects**: Project management
- **tasks**: Task tracking with priority and assignment
- **audit_logs**: Complete audit trail

### Key Features
- Foreign key constraints with CASCADE delete
- Composite unique constraints (tenant_id, email)
- Indexes on frequently queried columns
- JSONB support for audit log details

## 🚀 Deployment

### Docker Deployment Checklist
- [x] Dockerfile for backend
- [x] Dockerfile for frontend
- [x] docker-compose.yml with all services
- [x] Health check endpoints
- [x] Automatic database migrations
- [x] Automatic seed data loading
- [x] Environment variable configuration
- [x] Service networking and communication

### Production Considerations
- Use environment variables for secrets
- Set NODE_ENV=production for backend
- Configure HTTPS with reverse proxy
- Use environment-specific database URLs
- Set up automated backups for PostgreSQL
- Configure rate limiting on API endpoints
- Use CDN for static assets
- Set up monitoring and logging

## 📝 Project Structure

```
gpp-task3/
├── backend/
│   ├── src/
│   │   ├── controllers/    # Request handlers
│   │   ├── routes/         # API routes
│   │   ├── middleware/     # Auth, authorization
│   │   ├── utils/          # Validation, audit logging
│   │   ├── config/         # Database connection
│   │   └── server.js       # Express server
│   ├── migrations/         # Database migrations
│   ├── seeds/              # Database seed data
│   ├── package.json
│   ├── .env                # Environment variables
│   └── Dockerfile
├── frontend/
│   ├── public/
│   │   └── index.html
│   ├── src/
│   │   ├── pages/          # Page components
│   │   ├── components/     # Reusable components
│   │   ├── services/       # API calls
│   │   ├── context/        # Auth context
│   │   ├── App.js
│   │   ├── App.css
│   │   └── index.js
│   ├── package.json
│   └── Dockerfile
├── docs/
│   ├── research.md
│   ├── PRD.md
│   ├── architecture.md
│   ├── technical-spec.md
│   ├── API.md
│   └── images/
├── docker-compose.yml
├── README.md
└── submission.json
```

## 🔧 Environment Variables

### Backend (.env or docker-compose.yml)
```
DB_HOST=database
DB_PORT=5432
DB_NAME=saas_db
DB_USER=postgres
DB_PASSWORD=postgres

JWT_SECRET=your_jwt_secret_key_min_32_chars_here_2024
JWT_EXPIRES_IN=24h

PORT=5000
NODE_ENV=development

FRONTEND_URL=http://frontend:3000
```

### Frontend (.env)
```
REACT_APP_API_URL=http://localhost:5000/api
```

## 🐛 Troubleshooting

### Database Connection Issues
```bash
# Check if database is running
docker-compose ps

# View database logs
docker-compose logs database

# Rebuild database
docker-compose down
docker-compose up -d
```

### API Issues
```bash
# View backend logs
docker-compose logs backend

# Test health check
curl http://localhost:5000/api/health
```

### Frontend Issues
```bash
# Clear cache and reinstall
cd frontend
rm -rf node_modules
npm install
npm start
```

## 📄 License

ISC

## 👥 Contributors

Built as part of GPP Task 3 - Multi-Tenant SaaS Platform

---

**Ready to deploy?** Run `docker-compose up -d` and start building!
