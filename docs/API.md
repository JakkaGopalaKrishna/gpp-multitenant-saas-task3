# API Documentation

## Base URLs

- **Development**: `http://localhost:5000/api`
- **Docker**: `http://backend:5000/api`
- **Production**: `https://api.yourapp.com/api` (to be configured)

## Authentication

All endpoints except `/auth/register-tenant` and `/auth/login` require JWT authentication.

### Header Format
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

### Token Expiry
- Tokens expire after 24 hours
- Expired tokens return `401 Unauthorized`
- User must login again to get a new token

---

## Response Format

### Success Response
```json
{
  "success": true,
  "message": "Optional message",
  "data": {
    // Response data
  }
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description",
  "data": {
    // Optional validation errors
  }
}
```

---

## API Endpoints (19 Total)

### 1. Authentication Endpoints

#### 1.1 Register Tenant
```http
POST /auth/register-tenant
Content-Type: application/json

Request Body:
{
  "tenantName": "Acme Corporation",
  "subdomain": "acme",
  "adminEmail": "admin@acme.com",
  "adminPassword": "SecurePass123",
  "adminFullName": "John Doe"
}

Response (201):
{
  "success": true,
  "message": "Tenant registered successfully",
  "data": {
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "subdomain": "acme",
    "adminUser": {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "email": "admin@acme.com",
      "fullName": "John Doe",
      "role": "tenant_admin"
    }
  }
}

Error (409):
{
  "success": false,
  "message": "Subdomain already exists"
}
```

#### 1.2 Login
```http
POST /auth/login
Content-Type: application/json

Request Body:
{
  "email": "admin@demo.com",
  "password": "Demo@123",
  "tenantSubdomain": "demo"
}

Response (200):
{
  "success": true,
  "data": {
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "email": "admin@demo.com",
      "fullName": "Demo Admin",
      "role": "tenant_admin",
      "tenantId": "550e8400-e29b-41d4-a716-446655440001"
    },
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expiresIn": 86400
  }
}

Error (401):
{
  "success": false,
  "message": "Invalid credentials"
}
```

#### 1.3 Get Current User
```http
GET /auth/me
Authorization: Bearer <token>

Response (200):
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "admin@demo.com",
    "fullName": "Demo Admin",
    "role": "tenant_admin",
    "isActive": true,
    "tenant": {
      "id": "550e8400-e29b-41d4-a716-446655440001",
      "name": "Demo Company",
      "subdomain": "demo",
      "subscriptionPlan": "pro",
      "maxUsers": 25,
      "maxProjects": 15
    }
  }
}
```

#### 1.4 Logout
```http
POST /auth/logout
Authorization: Bearer <token>

Response (200):
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

### 2. Tenant Management Endpoints

#### 2.1 Get Tenant Details
```http
GET /tenants/{tenantId}
Authorization: Bearer <token>

Response (200):
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Demo Company",
    "subdomain": "demo",
    "status": "active",
    "subscriptionPlan": "pro",
    "maxUsers": 25,
    "maxProjects": 15,
    "createdAt": "2024-12-01T10:00:00Z",
    "stats": {
      "totalUsers": 5,
      "totalProjects": 3,
      "totalTasks": 15
    }
  }
}
```

#### 2.2 Update Tenant
```http
PUT /tenants/{tenantId}
Authorization: Bearer <token>
Content-Type: application/json

Request Body (optional fields):
{
  "name": "Updated Company Name",
  "status": "active",
  "subscriptionPlan": "enterprise",
  "maxUsers": 100,
  "maxProjects": 50
}

Response (200):
{
  "success": true,
  "message": "Tenant updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Updated Company Name",
    "updatedAt": "2024-12-15T15:30:00Z"
  }
}

Error (403):
{
  "success": false,
  "message": "Only super admin can update status"
}
```

#### 2.3 List All Tenants (Super Admin Only)
```http
GET /tenants?page=1&limit=10&status=active&subscriptionPlan=pro
Authorization: Bearer <token>

Query Parameters:
- page: integer, default: 1
- limit: integer, default: 10, max: 100
- status: enum (active, suspended, trial)
- subscriptionPlan: enum (free, pro, enterprise)

Response (200):
{
  "success": true,
  "data": {
    "tenants": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "name": "Demo Company",
        "subdomain": "demo",
        "status": "active",
        "subscriptionPlan": "pro",
        "totalUsers": 5,
        "totalProjects": 3,
        "createdAt": "2024-12-01T10:00:00Z"
      }
    ],
    "pagination": {
      "currentPage": 1,
      "totalPages": 5,
      "totalTenants": 47,
      "limit": 10
    }
  }
}

Error (403):
{
  "success": false,
  "message": "Only super admin can view all tenants"
}
```

---

### 3. User Management Endpoints

#### 3.1 Add User to Tenant
```http
POST /tenants/{tenantId}/users
Authorization: Bearer <token>
Content-Type: application/json

Request Body:
{
  "email": "newuser@demo.com",
  "password": "SecurePassword123",
  "fullName": "New User",
  "role": "user"
}

Response (201):
{
  "success": true,
  "message": "User created successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440003",
    "email": "newuser@demo.com",
    "fullName": "New User",
    "role": "user",
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "isActive": true,
    "createdAt": "2024-12-15T10:00:00Z"
  }
}

Error (403):
{
  "success": false,
  "message": "Subscription limit reached: cannot add more users"
}
```

#### 3.2 List Tenant Users
```http
GET /tenants/{tenantId}/users?search=John&role=user&page=1&limit=50
Authorization: Bearer <token>

Query Parameters:
- search: string (search by name or email)
- role: enum (super_admin, tenant_admin, user)
- page: integer, default: 1
- limit: integer, default: 50, max: 100

Response (200):
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "email": "admin@demo.com",
        "fullName": "Demo Admin",
        "role": "tenant_admin",
        "isActive": true,
        "createdAt": "2024-12-01T10:00:00Z"
      }
    ],
    "total": 5,
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "limit": 50
    }
  }
}
```

#### 3.3 Update User
```http
PUT /users/{userId}
Authorization: Bearer <token>
Content-Type: application/json

Request Body (optional fields):
{
  "fullName": "Updated Name",
  "role": "user",
  "isActive": true
}

Response (200):
{
  "success": true,
  "message": "User updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "fullName": "Updated Name",
    "role": "user",
    "updatedAt": "2024-12-15T15:30:00Z"
  }
}
```

#### 3.4 Delete User
```http
DELETE /users/{userId}
Authorization: Bearer <token>

Response (200):
{
  "success": true,
  "message": "User deleted successfully"
}

Error (403):
{
  "success": false,
  "message": "Cannot delete yourself"
}
```

---

### 4. Project Management Endpoints

#### 4.1 Create Project
```http
POST /projects
Authorization: Bearer <token>
Content-Type: application/json

Request Body:
{
  "name": "Website Redesign",
  "description": "Complete redesign of company website",
  "status": "active"
}

Response (201):
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440004",
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Website Redesign",
    "description": "Complete redesign of company website",
    "status": "active",
    "createdBy": "550e8400-e29b-41d4-a716-446655440001",
    "createdAt": "2024-12-15T10:00:00Z"
  }
}

Error (403):
{
  "success": false,
  "message": "Subscription limit reached: cannot create more projects"
}
```

#### 4.2 List Projects
```http
GET /projects?status=active&search=Website&page=1&limit=20
Authorization: Bearer <token>

Query Parameters:
- status: enum (active, archived, completed)
- search: string (search by project name)
- page: integer, default: 1
- limit: integer, default: 20, max: 100

Response (200):
{
  "success": true,
  "data": {
    "projects": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440004",
        "name": "Website Redesign",
        "description": "Complete redesign",
        "status": "active",
        "createdBy": {
          "id": "550e8400-e29b-41d4-a716-446655440001",
          "fullName": "Demo Admin"
        },
        "taskCount": 5,
        "completedTaskCount": 2,
        "createdAt": "2024-12-15T10:00:00Z"
      }
    ],
    "total": 3,
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "limit": 20
    }
  }
}
```

#### 4.3 Update Project
```http
PUT /projects/{projectId}
Authorization: Bearer <token>
Content-Type: application/json

Request Body:
{
  "name": "Website Redesign v2",
  "description": "Updated description",
  "status": "archived"
}

Response (200):
{
  "success": true,
  "message": "Project updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440004",
    "name": "Website Redesign v2",
    "description": "Updated description",
    "status": "archived",
    "updatedAt": "2024-12-15T15:30:00Z"
  }
}
```

#### 4.4 Delete Project
```http
DELETE /projects/{projectId}
Authorization: Bearer <token>

Response (200):
{
  "success": true,
  "message": "Project deleted successfully"
}
```

---

### 5. Task Management Endpoints

#### 5.1 Create Task
```http
POST /projects/{projectId}/tasks
Authorization: Bearer <token>
Content-Type: application/json

Request Body:
{
  "title": "Design homepage mockup",
  "description": "Create high-fidelity design",
  "assignedTo": "550e8400-e29b-41d4-a716-446655440002",
  "priority": "high",
  "dueDate": "2024-12-31"
}

Response (201):
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440005",
    "projectId": "550e8400-e29b-41d4-a716-446655440004",
    "tenantId": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Design homepage mockup",
    "description": "Create high-fidelity design",
    "status": "todo",
    "priority": "high",
    "assignedTo": "550e8400-e29b-41d4-a716-446655440002",
    "dueDate": "2024-12-31",
    "createdAt": "2024-12-15T10:00:00Z"
  }
}
```

#### 5.2 List Project Tasks
```http
GET /projects/{projectId}/tasks?status=todo&priority=high&page=1&limit=50
Authorization: Bearer <token>

Query Parameters:
- status: enum (todo, in_progress, completed)
- assignedTo: uuid (filter by assigned user)
- priority: enum (low, medium, high)
- search: string (search by task title)
- page: integer, default: 1
- limit: integer, default: 50, max: 100

Response (200):
{
  "success": true,
  "data": {
    "tasks": [
      {
        "id": "550e8400-e29b-41d4-a716-446655440005",
        "title": "Design homepage mockup",
        "description": "Create high-fidelity design",
        "status": "in_progress",
        "priority": "high",
        "assignedTo": {
          "id": "550e8400-e29b-41d4-a716-446655440002",
          "fullName": "User One",
          "email": "user1@demo.com"
        },
        "dueDate": "2024-12-31",
        "createdAt": "2024-12-15T10:00:00Z"
      }
    ],
    "total": 5,
    "pagination": {
      "currentPage": 1,
      "totalPages": 1,
      "limit": 50
    }
  }
}
```

#### 5.3 Update Task Status
```http
PATCH /tasks/{taskId}/status
Authorization: Bearer <token>
Content-Type: application/json

Request Body:
{
  "status": "in_progress"
}

Response (200):
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440005",
    "status": "in_progress",
    "updatedAt": "2024-12-15T15:30:00Z"
  }
}
```

#### 5.4 Update Task
```http
PUT /tasks/{taskId}
Authorization: Bearer <token>
Content-Type: application/json

Request Body:
{
  "title": "Updated task title",
  "description": "Updated description",
  "status": "in_progress",
  "priority": "high",
  "assignedTo": "550e8400-e29b-41d4-a716-446655440003",
  "dueDate": "2024-12-25"
}

Response (200):
{
  "success": true,
  "message": "Task updated successfully",
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440005",
    "title": "Updated task title",
    "description": "Updated description",
    "status": "in_progress",
    "priority": "high",
    "assignedTo": {
      "id": "550e8400-e29b-41d4-a716-446655440003",
      "fullName": "User Two",
      "email": "user2@demo.com"
    },
    "dueDate": "2024-12-25",
    "updatedAt": "2024-12-15T15:30:00Z"
  }
}
```

#### 5.5 Delete Task
```http
DELETE /tasks/{taskId}
Authorization: Bearer <token>

Response (200):
{
  "success": true,
  "message": "Task deleted successfully"
}
```

---

### 6. Health Check Endpoint

#### 6.1 System Health
```http
GET /health

Response (200):
{
  "status": "ok",
  "database": "connected",
  "timestamp": "2024-12-15T15:30:00Z"
}

Response (503):
{
  "status": "error",
  "database": "disconnected",
  "timestamp": "2024-12-15T15:30:00Z"
}
```

---

## Error Handling

### Common Error Codes

| Code | Status | Message | Solution |
|------|--------|---------|----------|
| 400 | Bad Request | Validation failed | Check request body format |
| 401 | Unauthorized | Invalid or expired token | Provide valid token or login again |
| 403 | Forbidden | Insufficient permissions | Verify user role or tenant access |
| 404 | Not Found | Resource not found | Check resource ID |
| 409 | Conflict | Duplicate resource | Email/subdomain already exists |
| 500 | Server Error | Internal error | Server-side issue, retry later |

---

## Testing the API

### Using cURL
```bash
# Register tenant
curl -X POST http://localhost:5000/api/auth/register-tenant \
  -H "Content-Type: application/json" \
  -d '{
    "tenantName": "Test Company",
    "subdomain": "test",
    "adminEmail": "admin@test.com",
    "adminPassword": "TestPass123",
    "adminFullName": "Test Admin"
  }'

# Login
curl -X POST http://localhost:5000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@demo.com",
    "password": "Demo@123",
    "tenantSubdomain": "demo"
  }'

# Get current user
curl -X GET http://localhost:5000/api/auth/me \
  -H "Authorization: Bearer <token>"
```

### Using Postman
1. Import the API endpoints
2. Set Authorization header with token
3. Test each endpoint with provided examples

---

**Last Updated:** December 2024  
**API Version:** 1.0
