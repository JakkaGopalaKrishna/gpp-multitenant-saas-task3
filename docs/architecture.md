# Architecture & System Design

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         Client Browser                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    HTTP/HTTPS Requests
                           │
        ┌──────────────────┴───────────────────┐
        │                                      │
        ▼                                      ▼
┌──────────────────┐                ┌──────────────────┐
│  React Frontend  │◄──── API Calls │  Express Backend │
│   (Port 3000)    │                │   (Port 5000)    │
└──────────────────┘                └────────┬─────────┘
                                             │
                                    SQL Queries
                                             │
                                    ┌────────▼─────────┐
                                    │   PostgreSQL     │
                                    │  (Port 5432)     │
                                    │                  │
                                    │ Multi-Tenant     │
                                    │ Database (13 TB) │
                                    └──────────────────┘
```

---

## Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Frontend (React)                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │               Pages                                      │ │
│  │ • Register        • Dashboard      • Projects           │ │
│  │ • Login           • ProjectDetails • Users              │ │
│  └─────────────────────────────────────────────────────────┘ │
│                           △                                   │
│                           │ Uses                              │
│                           │                                   │
│  ┌────────────────────────┴──────────────────────────────┐   │
│  │         Components (Reusable)                         │   │
│  │ • Navigation  • ProjectCard  • TaskModal  • UserTable │   │
│  └────────────────────────┬───────────────────────────────┘   │
│                           │ Imports                           │
│                           │                                   │
│  ┌─────────────────────────┴────────────────────────────┐    │
│  │     Services & Context                               │    │
│  │ • AuthContext  • API Service  • Storage Management   │    │
│  └──────────────────────────────────────────────────────┘    │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                           △
                           │ REST API Calls
                           │
┌─────────────────────────────────────────────────────────────┐
│                    Backend (Express)                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │              API Routes                                 │ │
│  │ • /api/auth       • /api/tenants   • /api/projects     │ │
│  │ • /api/auth/me    • /api/users     • /api/tasks        │ │
│  └──────────────────┬────────────────────────────────────┘   │
│                     │ Routes to                               │
│  ┌──────────────────┴────────────────────────────────────┐   │
│  │         Controllers                                    │   │
│  │ • authController  • projectController  • taskController  │ │
│  │ • tenantController• userController                     │   │
│  └──────────────┬──────────────────────────────────────┘     │
│                 │ Calls                                      │
│  ┌──────────────┴───────────────────────────────────────┐   │
│  │     Middleware & Utils                               │   │
│  │ • Auth Middleware        • Validation                │   │
│  │ • Authorization          • Audit Logging             │   │
│  └──────────────┬───────────────────────────────────────┘   │
│                 │ Uses                                      │
│  ┌──────────────┴───────────────────────────────────────┐   │
│  │       Database Connection Pool                       │   │
│  │ • Configuration  • Query Executor                    │   │
│  └───────────────────────────────────────────────────────┘   │
│                                                               │
└─────────────────────────────────────────────────────────────┘
                           △
                           │ TCP/IP
                           │
┌─────────────────────────────────────────────────────────────┐
│                    PostgreSQL Database                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │     Tables (Tenant Isolated)                           │ │
│  │ • tenants  (organization info)                         │ │
│  │ • users    (with tenant_id FK)                         │ │
│  │ • projects (with tenant_id FK)                         │ │
│  │ • tasks    (with tenant_id FK)                         │ │
│  │ • audit_logs (with tenant_id FK)                       │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │     Indexes & Constraints                              │ │
│  │ • tenant_id indexes for fast filtering                 │ │
│  │ • Composite UNIQUE (tenant_id, email)                  │ │
│  │ • Foreign keys with CASCADE delete                     │ │
│  └─────────────────────────────────────────────────────────┘ │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Database Entity Relationship Diagram (ERD)

```
┌──────────────────────────────────┐
│         tenants                  │
├──────────────────────────────────┤
│ PK  id (UUID)                    │
│     name (VARCHAR)               │
│ UQ  subdomain (VARCHAR)          │
│     status (ENUM)                │
│     subscription_plan (ENUM)     │
│     max_users (INTEGER)          │
│     max_projects (INTEGER)       │
│     created_at (TIMESTAMP)       │
│     updated_at (TIMESTAMP)       │
└──────────────────────────────────┘
         │
         │ 1:N
         │
         ▼
┌──────────────────────────────────┐
│         users                    │
├──────────────────────────────────┤
│ PK  id (UUID)                    │
│ FK  tenant_id (UUID) ─────────────┐ NULL for super_admin
│ UQ  (tenant_id, email)           │
│     email (VARCHAR)              │
│     password_hash (VARCHAR)      │
│     full_name (VARCHAR)          │
│     role (ENUM)                  │
│     is_active (BOOLEAN)          │
│     created_at (TIMESTAMP)       │
│     updated_at (TIMESTAMP)       │
└──────────────────────────────────┘
         │
         │ 1:N (created_by)
         │
         ▼
┌──────────────────────────────────┐
│       projects                   │
├──────────────────────────────────┤
│ PK  id (UUID)                    │
│ FK  tenant_id (UUID) ────────────┐ Denormalized for isolation
│ FK  created_by (UUID) ────────────┐ References users.id
│     name (VARCHAR)               │
│     description (TEXT)           │
│     status (ENUM)                │
│     created_at (TIMESTAMP)       │
│     updated_at (TIMESTAMP)       │
│     INDEX: tenant_id             │
└──────────────────────────────────┘
         │
         │ 1:N
         │
         ▼
┌──────────────────────────────────┐
│        tasks                     │
├──────────────────────────────────┤
│ PK  id (UUID)                    │
│ FK  project_id (UUID) ────────────┐ References projects.id
│ FK  tenant_id (UUID) ────────────┐ For isolation
│ FK  assigned_to (UUID) ──────────┐ References users.id, NULLABLE
│     title (VARCHAR)              │
│     description (TEXT)           │
│     status (ENUM)                │
│     priority (ENUM)              │
│     due_date (DATE)              │
│     created_at (TIMESTAMP)       │
│     updated_at (TIMESTAMP)       │
│     INDEX: (tenant_id, project_id) │
│     INDEX: assigned_to           │
└──────────────────────────────────┘

┌──────────────────────────────────┐
│      audit_logs                  │
├──────────────────────────────────┤
│ PK  id (UUID)                    │
│ FK  tenant_id (UUID) ────────────┐ References tenants.id
│ FK  user_id (UUID) ──────────────┐ References users.id, NULLABLE
│     action (VARCHAR)             │
│     entity_type (VARCHAR)        │
│     entity_id (VARCHAR)          │
│     ip_address (VARCHAR)         │
│     details (JSONB)              │
│     created_at (TIMESTAMP)       │
│     INDEX: tenant_id             │
│     INDEX: user_id               │
│     INDEX: action                │
└──────────────────────────────────┘

Key Design Decisions:
1. All tables except audit_logs have tenant_id for isolation
2. Composite UNIQUE(tenant_id, email) on users for per-tenant uniqueness
3. Indexes on tenant_id for efficient filtering
4. CASCADE DELETE to maintain referential integrity
5. JSONB for flexible audit log details
```

---

## API Architecture

### API Endpoint Organization

```
REST API Routes:

Authentication (/api/auth)
├── POST   /register-tenant    Create new organization
├── POST   /login              User login with subdomain
├── GET    /me                 Get current user
└── POST   /logout             Logout user

Tenants (/api/tenants)
├── GET    /                   List all tenants (super_admin)
├── GET    /:tenantId          Get tenant details
└── PUT    /:tenantId          Update tenant

Users (/api/tenants/:tenantId/users)
├── POST   /                   Add user to tenant
├── GET    /                   List tenant users
├── PUT    /users/:userId      Update user
└── DELETE /users/:userId      Delete user

Projects (/api/projects)
├── POST   /                   Create project
├── GET    /                   List projects
├── PUT    /:projectId         Update project
└── DELETE /:projectId         Delete project

Tasks (/api/projects/:projectId/tasks)
├── POST   /                   Create task
├── GET    /                   List project tasks
├── PATCH  /:taskId/status     Update task status
├── PUT    /:taskId            Update task details
└── DELETE /:taskId            Delete task

Health (/api)
└── GET    /health             System health check
```

---

## Authentication Flow

```
1. User Registration:
   Register Page → POST /auth/register-tenant
   → Create Tenant + Admin User (Transaction)
   → Return tenantId & admin user
   → Redirect to Login

2. User Login:
   Login Page → POST /auth/login
   → Verify Tenant Active
   → Verify User Exists + Password Match
   → Generate JWT Token: {userId, tenantId, role}
   → Store Token in localStorage
   → Redirect to Dashboard

3. Authenticated Request:
   API Call → Include: Authorization: Bearer {token}
   → Auth Middleware: Verify JWT Signature & Expiry
   → Extract: userId, tenantId, role
   → Authorization Middleware: Check role & tenant_id
   → Execute business logic with tenant isolation
   → Return response

4. Token Expiry:
   Token expires after 24 hours
   → API returns 401 Unauthorized
   → Frontend interceptor catches 401
   → Clear token from localStorage
   → Redirect to Login
   → User must login again
```

---

## Data Flow Examples

### Example 1: Create Project
```
Frontend:
1. User fills project form
2. Click "Create"
3. POST /api/projects {name, description}
4. Header: Authorization: Bearer {token}

Backend:
1. Auth Middleware: Extract userId, tenantId from token
2. Controller: Validate input
3. Query: Check project count vs max_projects
4. If limit exceeded: Return 403
5. Insert: projects table with tenant_id
6. Log: audit_logs CREATE_PROJECT action
7. Return: 201 {projectId, name, ...}

Frontend:
1. Show success toast
2. Add project to UI
3. Refresh project list
```

### Example 2: List Projects
```
Frontend:
GET /api/projects?status=active&page=1&limit=20
Header: Authorization: Bearer {token}

Backend:
1. Auth Middleware: Extract tenantId
2. Query: SELECT * FROM projects WHERE tenant_id = $1 AND status = $2
3. Pagination: LIMIT 20 OFFSET 0
4. Join: with users table for creator name
5. Return: {projects, pagination}

Frontend:
1. Display projects in cards
2. Show pagination
3. Enable filter/search
```

---

## Security Architecture

```
┌────────────────────────────────────────────────────────┐
│                  Request Layer                          │
│  - HTTPS/TLS Encryption                               │
│  - CORS validation                                     │
│  - Rate limiting (future)                             │
└──────────────────┬─────────────────────────────────────┘
                   │
┌──────────────────▼─────────────────────────────────────┐
│              Authentication Layer                       │
│  - JWT Token Verification                             │
│  - Token Signature Validation                         │
│  - Token Expiry Check                                 │
│  - Extract userId, tenantId, role                    │
└──────────────────┬─────────────────────────────────────┘
                   │
┌──────────────────▼─────────────────────────────────────┐
│             Authorization Layer                        │
│  - Role-based access control                          │
│  - Tenant ownership verification                      │
│  - Resource ownership check                           │
│  - Permission enforcement                            │
└──────────────────┬─────────────────────────────────────┘
                   │
┌──────────────────▼─────────────────────────────────────┐
│          Data Access Layer                             │
│  - Parameterized queries (SQL injection prevention)   │
│  - Tenant_id filtering in WHERE clause                │
│  - Foreign key constraints                            │
│  - Audit log recording                                │
└──────────────────┬─────────────────────────────────────┘
                   │
┌──────────────────▼─────────────────────────────────────┐
│             Database Layer                             │
│  - Row-level security (future)                        │
│  - Encryption at rest (future)                        │
│  - Backup encryption                                  │
│  - Access control lists                               │
└────────────────────────────────────────────────────────┘
```

---

## Deployment Architecture

```
┌─────────────────────────────────────────────────────┐
│            Docker Compose Network                    │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────┐  │
│  │   Frontend   │  │   Backend    │  │Database │  │
│  │ (Port 3000)  │  │ (Port 5000)  │  │(5432)  │  │
│  └──────────────┘  └──────────────┘  └─────────┘  │
│        │                  │                │       │
│        └──────────────────┼────────────────┘       │
│                           │                        │
│         Shared Network: saas-network              │
│                                                    │
│  Volume: db_data (PostgreSQL persistence)         │
│                                                    │
└─────────────────────────────────────────────────────┘

Service Communication:
- Frontend → Backend: http://backend:5000/api
- Backend → Database: postgresql://database:5432/saas_db
```

---

## Performance Optimization

1. **Database Level**
   - Indexes on tenant_id columns
   - Pagination for large datasets
   - Query optimization with EXPLAIN ANALYZE

2. **Application Level**
   - Connection pooling
   - Efficient query design
   - Caching headers in responses

3. **Frontend Level**
   - Code splitting with React.lazy
   - Asset compression
   - CDN for static files (future)

---

**Last Updated:** December 2024  
**Architecture Version:** 1.0
