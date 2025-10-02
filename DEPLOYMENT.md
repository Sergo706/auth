# Deployment Guide

This document provides comprehensive guidance for deploying the JWT Auth Library in production environments.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker Deployment](#docker-deployment)
- [Production Considerations](#production-considerations)
- [Environment Configuration](#environment-configuration)
- [Database Setup](#database-setup)
- [Security Hardening](#security-hardening)
- [Monitoring and Logging](#monitoring-and-logging)
- [Scaling and Load Balancing](#scaling-and-load-balancing)

## Quick Start

### Prerequisites

- Docker and Docker Compose
- MySQL 8.0+ database
- Valid email service API key (Resend)
- SSL certificates for HTTPS

### Rapid Deployment

1. **Clone and configure:**
   ```bash
   git clone <repository-url>
   cd auth
   # Start from the provided example and edit it
   cp config.dev.json config.json
   ```

2. **Edit configuration:**
   ```bash
   vim config.json  # Update with your settings
   ```

3. **Deploy:**
   ```bash
   chmod +x start.sh
   ./start.sh
   ```

4. **Verify:**
   ```bash
   curl http://localhost:10000/health
   # Expected: OK
   ```

## Docker Deployment

### Architecture Overview

The Docker deployment includes:
- **Hardened Container**: Ubuntu-based with security best practices
- **Secret Management**: Age encryption for configuration files
- **Health Monitoring**: Built-in health checks and logging
- **Resource Limits**: CPU, memory, and PID limits

### Deployment Script (`start.sh`)

The deployment script automates:

1. **SSH Key Setup**: Configures SSH agent for private dependencies
2. **Secret Generation**: Creates Age encryption keys
3. **Configuration Encryption**: Encrypts config.json with Age
4. **Container Build**: Builds Docker image with encrypted config
5. **Service Start**: Launches container with security policies

### Manual Docker Commands

If you prefer manual deployment:

```bash
# 1. Build the image
docker build -t jwtauth-service:latest .

# 2. Run with proper security
docker run -d \
  --name jwtauth \
  --read-only \
  --user 10001:10001 \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  --pids-limit 200 \
  -p 10000:10000 \
  -v ./app-logs:/app/logs:rw \
  -v ./detector-logs:/app/node_modules/@riavzon/botdetector/logs:rw \
  --tmpfs /run/app:rw,noexec,nosuid,nodev,uid=10001,gid=10001,size=1m \
  jwtauth-service:latest
```

### Docker Compose Configuration

```yaml
services:
  auth:
    image: jwtauth-service:latest
    build: 
      context: ./
      dockerfile: Dockerfile
      ssh:
        - default
    restart: unless-stopped
    read_only: true
    user: 10001:10001
    cap_drop: ["ALL"]
    security_opt: 
      - "no-new-privileges:true"
    pids_limit: 200
    ports: 
      - "10000:10000"
    volumes: 
      - ./app-logs:/app/logs:rw
      - ./detector-logs:/app/node_modules/@riavzon/botdetector/logs:rw
    tmpfs:
      - /run/app:rw,noexec,nosuid,nodev,uid=10001,gid=10001,size=1m
    healthcheck:
      test: ["CMD", "curl", "-f", "http://127.0.0.1:10000/health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 30s
```

## Production Considerations

### System Requirements

#### Minimum Requirements
- **CPU**: 1 vCPU
- **Memory**: 512 MB RAM
- **Disk**: 2 GB storage
- **Network**: 100 Mbps

#### Recommended for Production
- **CPU**: 2+ vCPUs
- **Memory**: 2+ GB RAM
- **Disk**: 10+ GB SSD storage
- **Network**: 1+ Gbps
- **Database**: Dedicated MySQL instance

### Resource Limits

Configure appropriate resource limits:

```yaml
services:
  auth:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.5'
          memory: 512M
```

### High Availability Setup

#### Multi-Instance Deployment

```yaml
services:
  auth:
    image: jwtauth-service:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
```

#### Load Balancer Configuration (Nginx)

```nginx
upstream auth_backend {
    least_conn;
    server auth1:10000 max_fails=3 fail_timeout=30s;
    server auth2:10000 max_fails=3 fail_timeout=30s;
    server auth3:10000 max_fails=3 fail_timeout=30s;
}

server {
    listen 443 ssl http2;
    server_name auth.yourcompany.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    
    location / {
        proxy_pass http://auth_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Health check
        proxy_next_upstream error timeout http_500 http_502 http_503;
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    location /health {
        proxy_pass http://auth_backend;
        access_log off;
    }
}
```

## Environment Configuration

### Production Environment Variables

```bash
# Application
NODE_ENV=production
CONFIG_PATH=/run/app/config.json

# Database
DB_HOST=prod-mysql-host.amazonaws.com
DB_PORT=3306
DB_USER=jwtauth_user
DB_PASSWORD=<secure-password>
DB_NAME=jwtauth_production
DB_SSL=true

# JWT Security
JWT_SECRET=<256-bit-cryptographically-random-key>
MAGIC_LINKS_SECRET=<256-bit-cryptographically-random-key>
PASSWORD_PEPPER=<256-bit-cryptographically-random-key>

# Email Service
RESEND_API_KEY=re_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
FROM_EMAIL=noreply@yourcompany.com

# External Services
TELEGRAM_BOT_TOKEN=<telegram-bot-token>
TELEGRAM_CHAT_ID=<monitoring-chat-id>

# Security
HMAC_SHARED_SECRET=<hmac-shared-secret>
HMAC_CLIENT_ID=<your-client-id>

# Proxy Configuration
TRUST_PROXY=true
TRUSTED_PROXY_IP=10.0.0.1
```

### Configuration File Structure

```json
{
  "store": {
    "main": {
      "host": "${DB_HOST}",
      "port": "${DB_PORT}",
      "user": "${DB_USER}",
      "password": "${DB_PASSWORD}",
      "database": "${DB_NAME}",
      "ssl": {
        "rejectUnauthorized": false
      },
      "acquireTimeout": 60000,
      "timeout": 60000,
      "reconnect": true
    }
  },
  "service": {
    "port": 10000,
    "ipAddress": "0.0.0.0",
    "proxy": {
      "trust": true,
      "ipToTrust": "${TRUSTED_PROXY_IP}"
    }
  }
}
```

## Database Setup

### MySQL Configuration

#### Production MySQL Settings

```sql
-- my.cnf additions for production
[mysqld]
# Performance
innodb_buffer_pool_size = 1G
innodb_log_file_size = 256M
innodb_flush_log_at_trx_commit = 1
sync_binlog = 1

# Security
bind-address = 127.0.0.1
ssl-ca = ca-cert.pem
ssl-cert = server-cert.pem
ssl-key = server-key.pem

# Connections
max_connections = 200
max_connect_errors = 10
```

#### Database User Setup

```sql
-- Create dedicated database user
CREATE DATABASE jwtauth_production CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'jwtauth_user'@'%' IDENTIFIED BY 'secure_password_here';

-- Grant minimal required permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON jwtauth_production.* TO 'jwtauth_user'@'%';
GRANT CREATE TEMPORARY TABLES ON jwtauth_production.* TO 'jwtauth_user'@'%';

FLUSH PRIVILEGES;
```

#### Schema Creation

```bash
# Using the built-in schema creation
npm run build
npm run build:createTables

# Or manually execute the schema
mysql -u jwtauth_user -p jwtauth_production < schema.sql
```

### Database Backup Strategy

#### Automated Backups

```bash
#!/bin/bash
# backup-auth-db.sh

BACKUP_DIR="/var/backups/jwtauth"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
DB_NAME="jwtauth_production"

# Create backup
mysqldump -u jwtauth_user -p${DB_PASSWORD} \
  --single-transaction \
  --routines \
  --triggers \
  --hex-blob \
  ${DB_NAME} | gzip > ${BACKUP_DIR}/jwtauth_${TIMESTAMP}.sql.gz

# Retention: keep 7 days of backups
find ${BACKUP_DIR} -name "jwtauth_*.sql.gz" -mtime +7 -delete
```

#### Restore Process

```bash
# Restore from backup
gunzip < /var/backups/jwtauth/jwtauth_20231215_120000.sql.gz | \
mysql -u jwtauth_user -p jwtauth_production
```

## Security Hardening

### Container Security

#### Dockerfile Security Features

```dockerfile
# Non-root user
RUN addgroup --system --gid 10001 appuser && \
    adduser --system --uid 10001 --gid 10001 appuser

# Read-only filesystem
VOLUME ["/app/logs", "/tmp"]

# Security labels
LABEL security.scan="enabled"
LABEL security.policy="restricted"

# Drop capabilities
USER 10001:10001
```

#### Runtime Security

```yaml
# docker-compose.yml security settings
services:
  auth:
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # Only if binding to privileged ports
```

### Network Security

#### Firewall Configuration (UFW)

```bash
# Default deny
ufw default deny incoming
ufw default allow outgoing

# SSH access
ufw allow from 192.168.1.0/24 to any port 22

# Application port (if exposed directly)
ufw allow from 10.0.0.0/8 to any port 10000

# Database access (if separate server)
ufw allow from 10.0.1.100 to any port 3306

ufw enable
```

#### TLS Configuration

```nginx
# Strong TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
ssl_prefer_server_ciphers off;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

# Additional security headers
add_header X-Frame-Options DENY always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy strict-origin-when-cross-origin always;
```

### Secret Management

#### Production Secret Rotation

```bash
#!/bin/bash
# rotate-secrets.sh

# Generate new JWT secret
NEW_JWT_SECRET=$(openssl rand -hex 32)

# Update configuration
sed -i "s/jwt_secret_key.*/jwt_secret_key\": \"$NEW_JWT_SECRET\",/" config.json

# Encrypt and deploy
age -a -e -r "$(cat public_key)" -o config.json.age config.json
docker-compose up -d --force-recreate
```

## Monitoring and Logging

### Application Logging

#### Log Configuration

```json
{
  "logLevel": "info",
  "service": {
    "logging": {
      "format": "json",
      "destination": "/app/logs/auth.log",
      "rotation": {
        "maxFiles": 10,
        "maxSize": "100MB"
      }
    }
  }
}
```

#### Log Aggregation (ELK Stack)

```yaml
# filebeat.yml
filebeat.inputs:
- type: log
  enabled: true
  paths:
    - /var/log/jwtauth/*.log
  json.keys_under_root: true
  json.add_error_key: true

output.elasticsearch:
  hosts: ["elasticsearch:9200"]
  index: "jwtauth-logs-%{+yyyy.MM.dd}"
```

### Health Monitoring

#### Prometheus Metrics

```javascript
// Custom metrics endpoint
app.get('/metrics', (req, res) => {
  const metrics = {
    auth_requests_total: authRequestsTotal,
    auth_success_rate: successRate,
    token_rotations_total: tokenRotationsTotal,
    rate_limit_blocks_total: rateLimitBlocksTotal
  };
  res.json(metrics);
});
```

#### Grafana Dashboard

Key metrics to monitor:
- Request rate and response times
- Authentication success/failure rates
- Token rotation frequency
- Rate limiting effectiveness
- Database connection pool usage
- Memory and CPU utilization

### Alerting

#### Critical Alerts

```yaml
# prometheus-alerts.yml
groups:
- name: jwtauth
  rules:
  - alert: HighAuthFailureRate
    expr: rate(auth_failures_total[5m]) > 0.1
    labels:
      severity: warning
    annotations:
      summary: "High authentication failure rate detected"
      
  - alert: ServiceDown
    expr: up{job="jwtauth"} == 0
    labels:
      severity: critical
    annotations:
      summary: "JWT Auth service is down"
```

## Scaling and Load Balancing

### Horizontal Scaling

#### Session Consistency

Since the library uses database-stored refresh tokens, multiple instances maintain session consistency automatically. No special session handling required.

#### Database Connection Scaling

```javascript
// Connection pool scaling for high load
const dbConfig = {
  host: 'db-cluster-endpoint',
  user: 'jwtauth_user',
  password: process.env.DB_PASSWORD,
  database: 'jwtauth_production',
  waitForConnections: true,
  connectionLimit: 20,        // Scale based on load
  queueLimit: 0,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true,
  multipleStatements: false
};
```

### Vertical Scaling

#### Resource Optimization

```yaml
# docker-compose.yml for high-traffic deployment
services:
  auth:
    deploy:
      resources:
        limits:
          cpus: '4.0'
          memory: 4G
        reservations:
          cpus: '2.0'
          memory: 2G
    environment:
      NODE_OPTIONS: '--max-old-space-size=3072'
```

### Performance Tuning

#### Application Optimizations

```json
{
  "jwt": {
    "access_tokens": {
      "maxCacheEntries": 10000,    // Increase for high traffic
      "expiresIn": "15m"           // Keep short for security
    }
  },
  "rate_limiters": {
    "cache": {
      "maxEntries": 50000,         // Large cache for rate limiting
      "ttl": 3600
    }
  }
}
```

#### Database Optimizations

```sql
-- Index optimization for high-traffic scenarios
CREATE INDEX idx_refresh_tokens_user_valid ON refresh_tokens(user_id, valid);
CREATE INDEX idx_visitors_ip_country ON visitors(ip_address, country);
CREATE INDEX idx_banned_ip ON banned(ip_address);

-- Partition large tables by date
ALTER TABLE visitors PARTITION BY RANGE (UNIX_TIMESTAMP(first_seen)) (
    PARTITION p_2023_12 VALUES LESS THAN (UNIX_TIMESTAMP('2024-01-01')),
    PARTITION p_2024_01 VALUES LESS THAN (UNIX_TIMESTAMP('2024-02-01')),
    -- Add more partitions as needed
);
```

## Deployment Checklist

### Pre-Deployment

- [ ] Database schema created and migrated
- [ ] All secrets generated and secured
- [ ] Configuration validated
- [ ] SSL certificates installed
- [ ] Firewall rules configured
- [ ] Monitoring setup completed
- [ ] Backup strategy implemented

### Post-Deployment

- [ ] Health checks passing
- [ ] Authentication flows tested
- [ ] Rate limiting verified
- [ ] Log aggregation working
- [ ] Monitoring alerts configured
- [ ] Performance baseline established
- [ ] Security scan completed

### Maintenance Tasks

- [ ] Regular secret rotation (monthly)
- [ ] Database backup verification (weekly)
- [ ] Log rotation and cleanup (daily)
- [ ] Security updates (as available)
- [ ] Performance monitoring (continuous)
- [ ] Capacity planning review (quarterly)

## Troubleshooting

### Common Issues

#### Service Won't Start
```bash
# Check logs
docker logs jwtauth

# Common causes:
# - Database connection failed
# - Configuration validation error
# - Missing secrets
# - Port already in use
```

#### High Memory Usage
```bash
# Monitor memory usage
docker stats jwtauth

# Potential solutions:
# - Reduce cache sizes
# - Increase swap space
# - Scale horizontally
```

#### Database Connection Issues
```bash
# Test database connectivity
mysql -h $DB_HOST -u $DB_USER -p $DB_NAME

# Check connection pool settings
# Verify firewall rules
# Monitor connection limits
```

### Emergency Procedures

#### Service Recovery
```bash
# Emergency restart
docker-compose down
docker-compose up -d

# Rollback to previous version
docker tag jwtauth-service:latest jwtauth-service:backup
docker pull jwtauth-service:previous
docker-compose up -d
```

#### Database Recovery
```bash
# Emergency read-only mode
mysql -e "SET GLOBAL read_only = ON;"

# Restore from backup
./restore-database.sh /path/to/latest/backup.sql.gz

# Re-enable writes
mysql -e "SET GLOBAL read_only = OFF;"
```
