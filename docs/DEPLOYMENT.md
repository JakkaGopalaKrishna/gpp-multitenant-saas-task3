# Deployment Guide

## Table of Contents

1. [Local Development](#local-development)
2. [Docker Deployment](#docker-deployment)
3. [Production Deployment](#production-deployment)
4. [Environment Variables](#environment-variables)
5. [Database Setup](#database-setup)
6. [Scaling & Performance](#scaling--performance)
7. [Monitoring & Logging](#monitoring--logging)
8. [Troubleshooting](#troubleshooting)

---

## Local Development

### Prerequisites
- Node.js 18.x
- PostgreSQL 15+
- npm or yarn

### Setup Steps

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd gpp-task3
   ```

2. **Install dependencies**
   ```bash
   # Backend
   cd backend
   npm install

   # Frontend
   cd ../frontend
   npm install
   ```

3. **Setup environment variables**
   ```bash
   # Backend
   cd backend
   cp .env.example .env
   # Edit .env with your local configuration
   ```

4. **Create database**
   ```bash
   # Start PostgreSQL
   # Run migrations
   npm run migrate
   
   # Seed sample data
   npm run seed
   ```

5. **Start development servers**
   ```bash
   # Terminal 1 - Backend
   cd backend
   npm run dev

   # Terminal 2 - Frontend
   cd frontend
   npm start
   ```

6. **Access the application**
   - Frontend: `http://localhost:3000`
   - Backend API: `http://localhost:5000/api`
   - API Documentation: See [API.md](./API.md)

---

## Docker Deployment

### Quick Start

```bash
# From project root directory
docker-compose up -d

# Wait for services to start (30-60 seconds)
docker-compose ps

# View logs
docker-compose logs -f backend

# Stop services
docker-compose down
```

### Service Status Verification

```bash
# Check all services are running
docker-compose ps

# Expected output:
# NAME                COMMAND             STATUS              PORTS
# database            docker-entrypoint   Up (healthy)        5432->5432/tcp
# backend             node src/server.js  Up (healthy)        5000->5000/tcp
# frontend            npm start           Up                   3000->3000/tcp
```

### Health Checks

```bash
# Backend health endpoint
curl http://localhost:5000/api/health

# Expected response:
# {"status":"ok","database":"connected","timestamp":"..."}

# Frontend accessibility
curl http://localhost:3000

# Database connection
docker-compose exec database psql -U postgres -d gpp_saas -c "SELECT COUNT(*) FROM tenants;"
```

### Using Test Credentials

Login with the pre-seeded credentials:

**Super Admin Account**
- Email: `superadmin@system.com`
- Password: `Admin@123`
- Access: All tenants and system administration

**Demo Tenant Admin**
- Tenant Subdomain: `demo`
- Email: `admin@demo.com`
- Password: `Demo@123`
- Access: Demo tenant only

**Demo Tenant Users**
- Email: `user1@demo.com` or `user2@demo.com`
- Password: `User@123`
- Access: Demo tenant, limited permissions

### Docker Compose Configuration

```yaml
version: '3.8'
services:
  database:
    image: postgres:15
    environment:
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: postgres
      POSTGRES_DB: gpp_saas
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 10s
      timeout: 5s
      retries: 5

  backend:
    build: ./backend
    depends_on:
      database:
        condition: service_healthy
    environment:
      DATABASE_URL: postgresql://postgres:postgres@database:5432/gpp_saas
      NODE_ENV: production
      JWT_SECRET: your-secret-key-here
      FRONTEND_URL: http://frontend:3000
    ports:
      - "5000:5000"
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:5000/api/health"]
      interval: 10s
      timeout: 5s
      retries: 5

  frontend:
    build: ./frontend
    depends_on:
      - backend
    environment:
      REACT_APP_API_URL: http://backend:5000/api
    ports:
      - "3000:3000"
```

---

## Production Deployment

### Cloud Platform: AWS EC2

#### 1. Provision EC2 Instance

```bash
# Instance specifications
- AMI: Ubuntu 22.04 LTS
- Instance type: t3.medium or larger
- Storage: 30GB EBS
- Security groups: Allow ports 80, 443, 5432 (internal only)
```

#### 2. Install Docker & Docker Compose

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Verify installation
docker --version
docker-compose --version
```

#### 3. Setup Application

```bash
# Clone repository
git clone <repository-url>
cd gpp-task3

# Create production environment file
sudo cp backend/.env.example backend/.env
sudo nano backend/.env  # Edit with production values

# Build and start containers
docker-compose -f docker-compose.prod.yml up -d

# Verify services
docker-compose ps
```

#### 4. SSL/TLS Certificate

```bash
# Using Let's Encrypt with Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Configure nginx with SSL
# (Include in reverse proxy setup below)
```

#### 5. Nginx Reverse Proxy

Create `/etc/nginx/sites-available/gpp-saas`:

```nginx
# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$server_name$request_uri;
}

# HTTPS server configuration
server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    # SSL security
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Frontend (React)
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Backend API
    location /api {
        proxy_pass http://localhost:5000/api;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # CORS headers
        add_header 'Access-Control-Allow-Origin' '*' always;
        add_header 'Access-Control-Allow-Methods' 'GET, POST, PUT, DELETE, PATCH, OPTIONS' always;
        add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization' always;
        
        # Handle OPTIONS request
        if ($request_method = 'OPTIONS') {
            return 204;
        }
    }
}
```

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/gpp-saas /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Cloud Platform: Heroku

```bash
# Login to Heroku
heroku login

# Create app
heroku create gpp-saas-app

# Add PostgreSQL addon
heroku addons:create heroku-postgresql:standard-0

# Set environment variables
heroku config:set JWT_SECRET="your-secret-key"
heroku config:set NODE_ENV="production"

# Deploy
git push heroku main

# View logs
heroku logs -t

# Open app
heroku open
```

### Cloud Platform: Docker Hub + AWS ECS

```bash
# Build and push Docker images
docker build -t yourusername/gpp-backend backend/
docker build -t yourusername/gpp-frontend frontend/

docker push yourusername/gpp-backend
docker push yourusername/gpp-frontend

# Configure ECS task definition with container images
# Set environment variables in task definition
# Create ECS service with load balancer
# Configure auto-scaling policies
```

---

## Environment Variables

### Backend Environment Variables

```bash
# Database Configuration
DATABASE_URL=postgresql://user:password@localhost:5432/gpp_saas
DB_USER=postgres
DB_PASSWORD=securepassword
DB_HOST=database
DB_PORT=5432
DB_NAME=gpp_saas

# JWT Configuration
JWT_SECRET=your-super-secret-key-min-32-characters-long
JWT_EXPIRY=24h

# Application Settings
NODE_ENV=production
PORT=5000
FRONTEND_URL=http://frontend:3000

# Optional: Logging
LOG_LEVEL=info
LOG_FORMAT=json
```

### Frontend Environment Variables

```bash
# API Configuration
REACT_APP_API_URL=http://localhost:5000/api
REACT_APP_ENV=production

# Optional: Analytics
REACT_APP_ANALYTICS_ID=your-analytics-id
```

### Production Security Checklist

- [ ] Use strong JWT_SECRET (min 32 characters, random)
- [ ] Enable HTTPS/SSL
- [ ] Set NODE_ENV to production
- [ ] Configure CORS properly
- [ ] Use environment variables for all secrets
- [ ] Enable database backups
- [ ] Set up monitoring and alerting
- [ ] Configure rate limiting
- [ ] Enable database connection pooling
- [ ] Setup CDN for static assets

---

## Database Setup

### Automatic Initialization

The backend automatically initializes the database on startup:

```bash
# On container/server start:
1. Connects to PostgreSQL
2. Runs migrations (if tables don't exist)
3. Seeds sample data (if seeds haven't run)
4. Starts Express server
```

### Manual Database Operations

```bash
# Connect to database
docker-compose exec database psql -U postgres -d gpp_saas

# List tables
\dt

# View table structure
\d tenants

# Run custom query
SELECT * FROM tenants;

# Exit
\q
```

### Database Backup

```bash
# Create backup
docker-compose exec database pg_dump -U postgres gpp_saas > backup_$(date +%Y%m%d).sql

# Restore backup
docker-compose exec -T database psql -U postgres gpp_saas < backup_20240115.sql

# Setup automated daily backups
# Add to crontab: 0 2 * * * docker-compose exec -T database pg_dump -U postgres gpp_saas > /backups/db_$(date +\%Y\%m\%d).sql
```

---

## Scaling & Performance

### Database Optimization

```sql
-- Add indexes for frequently queried columns
CREATE INDEX idx_tenants_subdomain ON tenants(subdomain);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_projects_tenant_id ON projects(tenant_id);
CREATE INDEX idx_tasks_project_id ON tasks(project_id);
CREATE INDEX idx_tasks_assigned_to ON tasks(assigned_to);

-- Enable connection pooling (PgBouncer)
# Configuration in docker-compose.yml or external PgBouncer service
```

### Caching Strategy

```javascript
// Redis caching for frequently accessed data
// Add to backend configuration:
- User profile cache (TTL: 1 hour)
- Project list cache per tenant (TTL: 30 minutes)
- Task count cache (TTL: 5 minutes)
```

### Load Balancing

```yaml
# docker-compose.yml with multiple backend instances
backend-1:
  build: ./backend
  # ...

backend-2:
  build: ./backend
  # ...

# Use nginx upstream configuration
upstream backend {
    server backend-1:5000;
    server backend-2:5000;
}
```

### Database Connection Pooling

```javascript
// In backend configuration
const pool = new Pool({
  max: 20,              // Maximum connections
  min: 5,               // Minimum connections
  idle: 10000,          // Idle timeout
  connection_timeout: 2000
});
```

---

## Monitoring & Logging

### Application Logs

```bash
# View logs in Docker
docker-compose logs backend      # Last 100 lines
docker-compose logs -f backend   # Follow logs
docker-compose logs --tail=50    # Last 50 lines

# Log retention
# Configure in docker-compose.yml:
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "10"
```

### Health Monitoring

```bash
# Setup health check monitoring
# Add to backend service:
healthcheck:
  test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:5000/api/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s
```

### Metrics & Observability

```bash
# Add Prometheus metrics (optional)
# Backend: npm install prometheus-client

# Setup ELK Stack (Elasticsearch, Logstash, Kibana)
# For enterprise-grade logging

# Use CloudWatch (AWS) or similar for cloud deployments
```

### Database Monitoring

```sql
-- Monitor active connections
SELECT pid, usename, state FROM pg_stat_activity;

-- Monitor slow queries
SELECT query, calls, mean_exec_time FROM pg_stat_statements 
ORDER BY mean_exec_time DESC LIMIT 10;

-- Check database size
SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname)) 
FROM pg_database;
```

---

## Troubleshooting

### Common Issues & Solutions

#### Issue: Services Won't Start

```bash
# Check service logs
docker-compose logs backend
docker-compose logs database

# Verify ports are available
netstat -an | grep -E '3000|5000|5432'

# Remove old containers/volumes
docker-compose down -v
docker-compose up -d

# Check Docker daemon
sudo systemctl restart docker
```

#### Issue: Database Connection Error

```bash
# Verify database is healthy
docker-compose ps database

# Check connection string
echo $DATABASE_URL

# Test connection
psql $DATABASE_URL -c "SELECT 1;"

# Restart database service
docker-compose restart database

# Check PostgreSQL logs
docker-compose logs database
```

#### Issue: Frontend Can't Connect to Backend

```bash
# Verify API URL in frontend
echo $REACT_APP_API_URL

# Check backend is running
curl http://localhost:5000/api/health

# Check CORS configuration
# Frontend URL must match FRONTEND_URL env var in backend

# Clear browser cache
# Frontend might be using cached old API URL
```

#### Issue: Authentication Token Expires Immediately

```bash
# Check JWT_SECRET is set
echo $JWT_SECRET

# Verify token expiry setting
# Should be "24h" or similar

# Check system clock on server
date

# Re-login to get new token
```

#### Issue: Docker Compose Network Issues

```bash
# Inspect network
docker network ls
docker network inspect gpp-task3_saas-network

# Rebuild containers
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

#### Issue: Database Migrations Fail

```bash
# Check migration files exist
ls -la backend/migrations/

# Manual migration
docker-compose exec backend node migrations/runMigrations.js

# View database schema
docker-compose exec database psql -U postgres -d gpp_saas -c "\dt"

# Drop and recreate (development only)
docker-compose exec database psql -U postgres -d gpp_saas -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
```

### Performance Optimization Checklist

- [ ] Enable Redis caching
- [ ] Configure database connection pooling
- [ ] Setup CDN for static assets
- [ ] Enable gzip compression
- [ ] Optimize database queries
- [ ] Use pagination for large datasets
- [ ] Enable browser caching headers
- [ ] Minify and bundle frontend assets
- [ ] Use production-grade database
- [ ] Setup load balancing

---

## Maintenance Tasks

### Weekly
- [ ] Review error logs
- [ ] Monitor resource usage
- [ ] Backup database
- [ ] Update dependencies (non-breaking)

### Monthly
- [ ] Review performance metrics
- [ ] Optimize slow queries
- [ ] Update security patches
- [ ] Test disaster recovery

### Quarterly
- [ ] Capacity planning
- [ ] Security audit
- [ ] Load testing
- [ ] Documentation review

---

**Last Updated:** December 2024  
**Version:** 1.0
