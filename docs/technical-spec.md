# Technical Specification

## Project Structure

### Backend Structure

```
backend/
├── src/
│   ├── config/
│   │   ├── database.js           # PostgreSQL connection pool
│   │   └── seedData.js           # Seed data utilities
│   ├── controllers/
│   │   ├── authController.js     # Auth logic (register, login, logout)
│   │   ├── tenantController.js   # Tenant management
│   │   ├── userController.js     # User management
│   │   ├── projectController.js  # Project CRUD
│   │   └── taskController.js     # Task CRUD
│   ├── middleware/
│   │   ├── auth.js               # JWT verification middleware
│   │   └── authorization.js      # Role-based access control
│   ├── routes/
│   │   ├── authRoutes.js         # /api/auth endpoints
│   │   ├── tenantRoutes.js       # /api/tenants endpoints
│   │   ├── userRoutes.js         # /api/users endpoints
│   │   ├── projectRoutes.js      # /api/projects endpoints
│   │   └── taskRoutes.js         # /api/tasks endpoints
│   ├── utils/
│   │   ├── validation.js         # Input validation
│   │   └── auditLog.js           # Audit logging
│   └── server.js                 # Express app setup & initialization
├── migrations/
│   ├── 001_create_tenants.sql
│   ├── 002_create_users.sql
│   ├── 003_create_projects.sql
│   ├── 004_create_tasks.sql
│   ├── 005_create_audit_logs.sql
│   └── runMigrations.js          # Migration executor
├── seeds/
│   └── runSeeds.js               # Database seeding script
├── package.json                  # Dependencies
├── .env                          # Environment variables
├── Dockerfile                    # Container image
└── .gitignore
```

### Frontend Structure

```
frontend/
├── public/
│   └── index.html                # HTML entry point
├── src/
│   ├── components/
│   │   └── Navigation.js         # Top navbar component
│   ├── pages/
│   │   ├── Register.js           # Registration page
│   │   ├── Login.js              # Login page
│   │   ├── Dashboard.js          # Dashboard/home page
│   │   ├── Projects.js           # Projects list page
│   │   ├── ProjectDetails.js     # Single project view
│   │   └── Users.js              # Team members page
│   ├── services/
│   │   └── api.js                # Axios instance & API calls
│   ├── context/
│   │   └── AuthContext.js        # Authentication state
│   ├── App.js                    # Main app component
│   ├── App.css                   # Global styles
│   ├── index.js                  # React entry point
│   └── index.css
├── package.json                  # Dependencies
├── .env                          # Environment variables
├── Dockerfile                    # Container image
└── .gitignore
```

---

## Development Setup Guide

### Prerequisites

- **Node.js**: v18+ ([download](https://nodejs.org/))
- **PostgreSQL**: v15+ ([download](https://www.postgresql.org/download/))
- **Git**: ([download](https://git-scm.com/))
- **Docker**: (Optional, for containerized deployment)

### Local Development Installation

#### 1. Clone Repository
```bash
git clone https://github.com/yourusername/gpp-task3.git
cd gpp-task3
```

#### 2. Backend Setup
```bash
cd backend

# Install dependencies
npm install

# Copy and configure environment variables
cp .env.example .env

# Run database migrations
npm run migrate

# Seed initial data
npm run seed

# Start development server
npm run dev

# Backend will run on http://localhost:5000
```

#### 3. Frontend Setup (New Terminal)
```bash
cd frontend

# Install dependencies
npm install

# Create .env file
cat > .env << EOF
REACT_APP_API_URL=http://localhost:5000/api
EOF

# Start development server
npm start

# Frontend will open on http://localhost:3000
```

### Environment Variables

#### Backend (.env)
```
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=saas_db
DB_USER=postgres
DB_PASSWORD=postgres

# JWT Configuration
JWT_SECRET=your_jwt_secret_key_min_32_chars_here_2024
JWT_EXPIRES_IN=24h

# Server Configuration
PORT=5000
NODE_ENV=development

# CORS Configuration
FRONTEND_URL=http://localhost:3000
```

#### Frontend (.env)
```
REACT_APP_API_URL=http://localhost:5000/api
```

### Running Tests

```bash
# Backend tests (setup with Jest/Supertest)
cd backend
npm test

# Frontend tests (setup with React Testing Library)
cd frontend
npm test
```

### Database Management

```bash
# Reset database (fresh migrations + seeds)
npm run setup-db

# Run only migrations
npm run migrate

# Run only seeds
npm run seed

# PostgreSQL CLI access
psql -U postgres -h localhost -d saas_db
```

---

## API Response Format

All API responses follow a consistent format:

### Success Response
```json
{
  "success": true,
  "message": "Operation successful",
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
    // Optional error details
  }
}
```

### HTTP Status Codes
- `200 OK`: Successful GET/PUT/PATCH
- `201 Created`: Successful POST
- `400 Bad Request`: Validation error
- `401 Unauthorized`: Missing/invalid token
- `403 Forbidden`: Permission denied
- `404 Not Found`: Resource not found
- `409 Conflict`: Duplicate resource (email, subdomain)
- `500 Internal Server Error`: Server error

---

## Authentication & Authorization

### JWT Token Structure
```
Header: {
  "alg": "HS256",
  "typ": "JWT"
}

Payload: {
  "userId": "uuid",
  "tenantId": "uuid",
  "role": "super_admin|tenant_admin|user",
  "iat": 1234567890,
  "exp": 1234654290
}

Signature: HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), SECRET)
```

### Token Expiry
- Token valid for 24 hours
- Automatic 401 response when expired
- Frontend redirects to login on 401
- New token issued on re-login

### Role Permissions

#### Super Admin
- View all tenants
- Modify subscription plans
- Access all systems
- View all audit logs

#### Tenant Admin
- Manage own tenant
- Manage team members
- Create projects
- Manage projects and tasks
- View tenant audit logs

#### Regular User
- View assigned tasks
- Update task status
- View projects
- View team members

---

## Code Style & Standards

### JavaScript
- Use ES6+ features
- Const/let, arrow functions
- Consistent naming: camelCase for variables
- 2-space indentation

### Database
- SQL comments for complex queries
- Parameterized queries (prevent SQL injection)
- Indexes for frequent queries
- Foreign key constraints

### Error Handling
- Try-catch for async operations
- Meaningful error messages
- Log errors for debugging
- Return appropriate HTTP status

### Comments
- Comment complex logic
- Document API endpoints
- Explain non-obvious decisions

---

## Security Checklist

- [x] Password hashing with bcryptjs
- [x] JWT token authentication
- [x] CORS configured
- [x] SQL parameterized queries
- [x] Input validation
- [x] Role-based access control
- [x] Tenant isolation (tenant_id filtering)
- [x] Audit logging
- [ ] Rate limiting (future)
- [ ] HTTPS enforcement (production)

---

## Performance Optimization Checklist

- [x] Database indexes on tenant_id
- [x] Connection pooling
- [x] Pagination for large datasets
- [x] Efficient queries
- [ ] Caching (Redis) - future
- [ ] API response compression - future
- [ ] CDN for static files - future

---

## Deployment Checklist

- [x] Docker configuration
- [x] docker-compose setup
- [x] Environment variables
- [x] Health check endpoint
- [x] Database migrations automated
- [x] Seed data loading automated
- [ ] Production database backup
- [ ] Monitoring setup
- [ ] CI/CD pipeline

---

## Debugging Tips

### Backend Debugging
```bash
# Enable debug logs
DEBUG=* npm run dev

# Check database connection
psql -U postgres -h localhost -d saas_db -c "\dt"

# View running migrations
SELECT * FROM pg_migrations;
```

### Frontend Debugging
```bash
# React DevTools browser extension
# Redux DevTools for state management
# Network tab for API calls
# Console for JavaScript errors
```

---

## Common Issues & Solutions

### "connect ECONNREFUSED" Database Error
- Ensure PostgreSQL is running: `sudo service postgresql status`
- Check connection string in .env
- Verify database exists: `createdb saas_db`

### "CORS Error" on API Calls
- Check FRONTEND_URL in backend .env
- Ensure API headers include Content-Type
- Verify Access-Control headers in response

### "Invalid Token" Error
- Token may have expired (24h expiry)
- localStorage might be cleared
- Token format incorrect (missing "Bearer ")

---

**Last Updated:** December 2024  
**Version:** 1.0
