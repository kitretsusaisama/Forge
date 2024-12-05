# Development Environment Manager - Installation Guide

## Table of Contents
- [System Requirements](#system-requirements)
- [Dependencies](#dependencies)
- [Quick Start Guide](#quick-start-guide)
- [Platform-Specific Installation](#platform-specific-installation)
- [AWS Integration](#aws-integration)
- [Rate Limiting Configuration](#rate-limiting-configuration)
- [Advanced Configuration](#advanced-configuration)
- [Troubleshooting](#troubleshooting)
- [Database Setup](#database-setup)

## System Requirements

### Minimum Hardware Requirements
- CPU: 2 cores
- RAM: 8GB
- Storage: 20GB free space
- Internet connection: Broadband (1Mbps+)

### Software Prerequisites
- Rust 1.70 or later
- Git 2.x+
- Python 3.8+
- OpenSSL 1.1.1+
- Docker 20.x+
- Kubernetes 1.20+ (optional)

### Platform-Specific Requirements
#### Unix Systems
- POSIX-compliant shell
- System user management capabilities
- `nix` system libraries

#### Windows
- PowerShell 5.1+
- WSL2 (for Docker integration)
- Visual Studio Build Tools

## Dependencies

### Core Dependencies
```toml
[dependencies]
# Async Runtime
tokio = { version = "1.0", features = ["full", "time"] }
anyhow = "1.0.71"
thiserror = "1.0"

# Serialization
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
serde_yaml = "0.9.25"

# Security
secrecy = { version = "0.8", features = ["serde"] }
jwt = "0.16"
sha2 = "0.10"

# AWS Integration
aws-config = "1.0"
aws-sdk-secretsmanager = "1.3"

# Rate Limiting
governor = "0.6"
nonzero_ext = "0.3"

[target.'cfg(unix)'.dependencies]
users = { version = "0.11", optional = true }
nix = { version = "0.27.0", optional = true }
```

## AWS Integration Setup

### Configuration
```bash
# AWS Credentials Setup
aws configure

# Environment Variables
export AWS_REGION=us-west-2
export AWS_SECRET_MANAGER_ENDPOINT=https://secretsmanager.us-west-2.amazonaws.com
```

### Secrets Manager Integration
```rust
// Example AWS Secrets Manager usage
use aws_sdk_secretsmanager::Client;

async fn get_secret(secret_name: &str) -> Result<String> {
    let config = aws_config::load_from_env().await;
    let client = Client::new(&config);
    
    let response = client
        .get_secret_value()
        .secret_id(secret_name)
        .send()
        .await?;
        
    Ok(response.secret_string().unwrap_or_default().to_string())
}
```

## Rate Limiting Configuration

### Basic Setup
```rust
use governor::{Quota, RateLimiter};
use nonzero_ext::*;

// Configure rate limiter
let rate_limiter = RateLimiter::direct(Quota::per_second(nonzero!(100u32)));
```

### Advanced Configuration
```yaml
# rate_limiting.yaml
endpoints:
  api:
    requests_per_second: 100
    burst_size: 50
  docker:
    requests_per_second: 50
    burst_size: 20
  kubernetes:
    requests_per_second: 30
    burst_size: 10
```

## Unix-Specific Features

### User Management
```rust
use users::{get_user_by_name, get_current_uid, get_current_username};

// Example user verification
fn verify_user() -> Result<()> {
    let current_user = get_current_username()?
        .ok_or_else(|| anyhow!("Could not determine current user"))?;
    
    let user = get_user_by_name(&current_user)?
        .ok_or_else(|| anyhow!("User not found"))?;
        
    Ok(())
}
```

### System Integration
```rust
use nix::sys::stat;
use nix::unistd::{Uid, Gid};

// Example permission check
fn check_permissions(path: &str) -> Result<()> {
    let metadata = stat::stat(path)?;
    let uid = Uid::current();
    let gid = Gid::current();
    
    // Check if current user has access
    if metadata.st_uid == uid.as_raw() || metadata.st_gid == gid.as_raw() {
        Ok(())
    } else {
        Err(anyhow!("Insufficient permissions"))
    }
}
```

## Environment Variables

### Core Configuration
```bash
# System Paths
export DEV_ENV_HOME=/opt/dev-env-manager
export DEV_ENV_CONFIG=/etc/dev-env-manager
export DEV_ENV_LOGS=/var/log/dev-env-manager

# AWS Configuration
export AWS_REGION=us-west-2
export AWS_PROFILE=dev-env-manager

# Rate Limiting
export RATE_LIMIT_DEFAULT=100
export RATE_LIMIT_BURST=50

# Database Configuration
export DATABASE_URL="postgresql://dev_env_user:password@localhost/dev_env_manager"
export DB_POOL_SIZE=5
export DB_MAX_CONNECTIONS=100
export DB_IDLE_TIMEOUT=300
```

## Security Considerations

### Secret Management
- AWS Secrets Manager integration for sensitive data
- Local secrets encrypted using `secrecy` crate
- JWT-based authentication for API endpoints

### Rate Limiting Protection
- Per-endpoint rate limiting
- Burst protection
- DDoS mitigation through `governor` crate

### Platform Security
- Unix user permission management
- File system access control
- Process isolation

## Troubleshooting

### Common Issues

#### 1. Installation Failures
```bash
# Reset installation
dev-env-manager reset --keep-config

# Verify system integrity
dev-env-manager verify --fix-permissions
```

#### 2. Network Issues
```bash
# Test connectivity
dev-env-manager network test --all-endpoints

# Reset network configuration
dev-env-manager network reset
```

#### 3. Resource Problems
```bash
# Check resource usage
dev-env-manager stats --all

# Clean up resources
dev-env-manager cleanup --all
```

### Platform-Specific Issues

#### Windows
```powershell
# Fix WSL issues
wsl --shutdown
wsl --unregister Ubuntu
wsl --install Ubuntu

# Reset Hyper-V
Get-VMSwitch | Remove-VMSwitch -Force
Get-VM | Remove-VM -Force
```

#### macOS
```bash
# Reset Docker Desktop
osascript -e 'quit app "Docker"'
rm -rf ~/Library/Group\ Containers/group.com.docker
rm -rf ~/Library/Containers/com.docker.docker
rm -rf ~/.docker
```

#### Linux
```bash
# Fix permissions
sudo chown -R $USER:$USER ~/.docker
sudo chmod -R g+rwx ~/.docker

# Reset containerd
sudo systemctl stop containerd
sudo rm -rf /var/lib/containerd
sudo systemctl start containerd
```

## Database Setup

### Prerequisites
- SQLx CLI tool
- Access to either PostgreSQL, MySQL, or SQLite
- Database credentials (if using PostgreSQL or MySQL)

### Database Installation

#### SQLite Setup
```bash
# Install SQLx CLI
cargo install sqlx-cli

# Create SQLite database
sqlx database create

# Run migrations
sqlx migrate run
```

#### PostgreSQL Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql -c "CREATE DATABASE dev_env_manager;"
sudo -u postgres psql -c "CREATE USER dev_env_user WITH ENCRYPTED PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dev_env_manager TO dev_env_user;"

# Run migrations
DATABASE_URL="postgres://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

#### MySQL Setup
```bash
# Install MySQL (Ubuntu/Debian)
sudo apt update
sudo apt install mysql-server

# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -e "CREATE DATABASE dev_env_manager;"
sudo mysql -e "CREATE USER 'dev_env_user'@'localhost' IDENTIFIED BY 'your_password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dev_env_manager.* TO 'dev_env_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Run migrations
DATABASE_URL="mysql://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

### Migration Management

#### Initial Setup
```bash
# Create migrations directory
mkdir -p migrations

# Create initial migration
sqlx migrate add initial_schema
```

#### Migration Files
```sql
-- migrations/20230101000000_initial_schema.sql
-- Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Environment Configs Table
CREATE TABLE IF NOT EXISTS environment_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    config_json JSONB NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

#### Managing Migrations
```bash
# List migrations
sqlx migrate info

# Run pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Check migration status
sqlx migrate status
```

### Environment Configuration

#### Environment Variables
Create a `.env` file in your project root:
```bash
# Database Configuration
DATABASE_URL="postgresql://dev_env_user:your_password@localhost/dev_env_manager"
# Or for SQLite:
# DATABASE_URL="sqlite:./dev-env-manager.db"

# Database Pool Configuration
DB_POOL_SIZE=5
DB_MAX_CONNECTIONS=100
DB_IDLE_TIMEOUT=300

# Migration Settings
MIGRATION_DIRECTORY="./migrations"
```

#### Database Connection Pool Configuration
```rust
// Example configuration in your Rust code
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(100)
    .connect(&std::env::var("DATABASE_URL")?)
    .await?;
```

### Troubleshooting Database Issues

#### Common Database Problems

1. **Connection Issues**
```bash
# Test database connection
sqlx database ping

# Check database status
systemctl status postgresql  # For PostgreSQL
systemctl status mysql      # For MySQL

# Verify network connectivity
nc -zv localhost 5432  # PostgreSQL default port
nc -zv localhost 3306  # MySQL default port
```

2. **Permission Issues**
```bash
# PostgreSQL
sudo -u postgres psql -c "\du"  # List users and their roles
sudo -u postgres psql -c "\l"   # List databases and their owners

# MySQL
mysql -u root -p -e "SHOW GRANTS FOR 'dev_env_user'@'localhost';"
```

3. **Migration Failures**
```bash
# Reset database (CAUTION: Deletes all data)
sqlx database reset

# Check migration logs
sqlx migrate info --verbose

# Verify migration files
find migrations -type f -name "*.sql" -exec sqlx migrate verify {} \;
```

#### Database Maintenance

1. **Backup and Restore**
```bash
# PostgreSQL
pg_dump -U dev_env_user dev_env_manager > backup.sql
psql -U dev_env_user dev_env_manager < backup.sql

# MySQL
mysqldump -u dev_env_user -p dev_env_manager > backup.sql
mysql -u dev_env_user -p dev_env_manager < backup.sql

# SQLite
sqlite3 dev-env-manager.db ".backup 'backup.db'"
sqlite3 dev-env-manager.db ".restore 'backup.db'"
```

2. **Performance Optimization**
```bash
# PostgreSQL vacuum and analyze
psql -U dev_env_user -d dev_env_manager -c "VACUUM ANALYZE;"

# MySQL optimize tables
mysqlcheck -u dev_env_user -p --optimize dev_env_manager

# SQLite vacuum
sqlite3 dev-env-manager.db "VACUUM;"
```

### Database Monitoring

#### Setup Monitoring Tools
```bash
# Install pgmetrics for PostgreSQL
cargo install pgmetrics

# Run metrics collection
pgmetrics --host localhost --port 5432 --username dev_env_user dev_env_manager

# Monitor MySQL performance
mysqladmin -u dev_env_user -p extended-status variables
```

#### Performance Metrics
```sql
-- Check slow queries (PostgreSQL)
SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY duration DESC;

-- Check table sizes
SELECT relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

```

### Automated Recovery Scripts

#### Auto-Recovery Configuration
```yaml
# auto-recovery.yaml
recovery_plans:
  docker_failure:
    detect:
      - condition: "service_status != running"
        service: "docker"
    actions:
      - restart_service:
          name: "docker"
          max_attempts: 3
          wait_between: 10s
      - verify_health:
          timeout: 30s
      - notify_admin:
          on_failure: true

  kubernetes_issues:
    detect:
      - condition: "node_status != ready"
        check_interval: 1m
    actions:
      - drain_node:
          timeout: 5m
      - reset_kubernetes:
          preserve_data: true
      - rejoin_cluster:
          verify: true

  network_failure:
    detect:
      - condition: "connectivity_loss"
        threshold: 3
    actions:
      - reset_network:
          preserve_config: true
      - rebuild_bridges:
          verify: true
      - restore_routing:
          backup_first: true
```

### Monitoring Integration

#### Prometheus Integration
```yaml
# prometheus-alerts.yaml
groups:
  - name: dev_env_manager_alerts
    rules:
      - alert: HighResourceUsage
        expr: dev_env_resource_usage > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "Resource usage exceeding 90% for 5 minutes"

      - alert: ServiceDown
        expr: dev_env_service_health == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          description: "Service {{ $labels.service }} is down"
```

## Health Checks

### Automated Health Check Script
```bash
#!/bin/bash
# health_check.sh

check_component() {
    local component=$1
    echo "Checking $component..."
    dev-env-manager check $component || return 1
}

components=(
    "docker"
    "kubernetes"
    "network"
    "storage"
    "permissions"
)

for component in "${components[@]}"; do
    if ! check_component $component; then
        echo "❌ $component check failed"
        dev-env-manager repair $component --auto
    else
        echo "✅ $component check passed"
    fi
done
```

## Backup and Recovery

### Backup Configuration
```bash
# Create backup
dev-env-manager backup create --include-data

# List backups
dev-env-manager backup list

# Restore from backup
dev-env-manager backup restore --latest
```

## Environment Variables

### Required Variables
```bash
# Core Configuration
export DEV_ENV_HOME=/opt/dev-env-manager
export DEV_ENV_CONFIG=/etc/dev-env-manager
export DEV_ENV_LOGS=/var/log/dev-env-manager

# Docker Configuration
export DOCKER_HOST=unix:///var/run/docker.sock
export DOCKER_CONFIG=${DEV_ENV_HOME}/.docker
export COMPOSE_PROJECT_NAME=dev-env

# Kubernetes Configuration
export KUBECONFIG=${DEV_ENV_CONFIG}/kubeconfig
export KUBE_CONTEXT=dev-env
```

### Optional Variables
```bash
# Performance Tuning
export DEV_ENV_MAX_MEMORY=8G
export DEV_ENV_CPU_LIMIT=4
export DEV_ENV_DISK_QUOTA=50G

# Network Configuration
export DEV_ENV_PORT=8080
export DEV_ENV_HOST=0.0.0.0
export DEV_ENV_PROXY=""
```

## Next Steps

1. ✅ Verify Installation
   ```bash
   dev-env-manager verify --all
   ```

2. ✅ Configure Environment
   ```bash
   dev-env-manager configure --interactive
   ```

3. ✅ Run Test Project
   ```bash
   dev-env-manager quickstart --template nodejs
   ```

4. ✅ Join Community
   - [Discord Community](https://discord.gg/dev-env-manager)
   - [GitHub Discussions](https://github.com/dev-env-manager/discussions)
   - [Documentation](https://docs.dev-env-manager.com)

## Getting Help

### Community Support
- 💬 [Discord Server](https://discord.gg/dev-env-manager)
- 📖 [Documentation](https://docs.dev-env-manager.com)
- 🐛 [Issue Tracker](https://github.com/dev-env-manager/issues)
- 📝 [Blog](https://blog.dev-env-manager.com)

### Enterprise Support
- 📧 Email: support@dev-env-manager.com
- 🔧 Priority Issue Resolution
- 📞 24/7 Phone Support
- 👥 Dedicated Support Team

## Database Setup and Migration

### Prerequisites
- SQLx CLI tool
- Access to either PostgreSQL, MySQL, or SQLite
- Database credentials (if using PostgreSQL or MySQL)

### Database Installation

#### SQLite Setup
```bash
# Install SQLx CLI
cargo install sqlx-cli

# Create SQLite database
sqlx database create

# Run migrations
sqlx migrate run
```

#### PostgreSQL Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql -c "CREATE DATABASE dev_env_manager;"
sudo -u postgres psql -c "CREATE USER dev_env_user WITH ENCRYPTED PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dev_env_manager TO dev_env_user;"

# Run migrations
DATABASE_URL="postgres://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

#### MySQL Setup
```bash
# Install MySQL (Ubuntu/Debian)
sudo apt update
sudo apt install mysql-server

# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -e "CREATE DATABASE dev_env_manager;"
sudo mysql -e "CREATE USER 'dev_env_user'@'localhost' IDENTIFIED BY 'your_password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dev_env_manager.* TO 'dev_env_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Run migrations
DATABASE_URL="mysql://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

### Migration Management

#### Initial Setup
```bash
# Create migrations directory
mkdir -p migrations

# Create initial migration
sqlx migrate add initial_schema
```

#### Migration Files
```sql
-- migrations/20230101000000_initial_schema.sql
-- Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Environment Configs Table
CREATE TABLE IF NOT EXISTS environment_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    config_json JSONB NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

#### Managing Migrations
```bash
# List migrations
sqlx migrate info

# Run pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Check migration status
sqlx migrate status
```

### Environment Configuration

#### Environment Variables
Create a `.env` file in your project root:
```bash
# Database Configuration
DATABASE_URL="postgresql://dev_env_user:your_password@localhost/dev_env_manager"
# Or for SQLite:
# DATABASE_URL="sqlite:./dev-env-manager.db"

# Database Pool Configuration
DB_POOL_SIZE=5
DB_MAX_CONNECTIONS=100
DB_IDLE_TIMEOUT=300

# Migration Settings
MIGRATION_DIRECTORY="./migrations"
```

#### Database Connection Pool Configuration
```rust
// Example configuration in your Rust code
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(100)
    .connect(&std::env::var("DATABASE_URL")?)
    .await?;
```

### Troubleshooting Database Issues

#### Common Database Problems

1. **Connection Issues**
```bash
# Test database connection
sqlx database ping

# Check database status
systemctl status postgresql  # For PostgreSQL
systemctl status mysql      # For MySQL

# Verify network connectivity
nc -zv localhost 5432  # PostgreSQL default port
nc -zv localhost 3306  # MySQL default port
```

2. **Permission Issues**
```bash
# PostgreSQL
sudo -u postgres psql -c "\du"  # List users and their roles
sudo -u postgres psql -c "\l"   # List databases and their owners

# MySQL
mysql -u root -p -e "SHOW GRANTS FOR 'dev_env_user'@'localhost';"
```

3. **Migration Failures**
```bash
# Reset database (CAUTION: Deletes all data)
sqlx database reset

# Check migration logs
sqlx migrate info --verbose

# Verify migration files
find migrations -type f -name "*.sql" -exec sqlx migrate verify {} \;
```

#### Database Maintenance

1. **Backup and Restore**
```bash
# PostgreSQL
pg_dump -U dev_env_user dev_env_manager > backup.sql
psql -U dev_env_user dev_env_manager < backup.sql

# MySQL
mysqldump -u dev_env_user -p dev_env_manager > backup.sql
mysql -u dev_env_user -p dev_env_manager < backup.sql

# SQLite
sqlite3 dev-env-manager.db ".backup 'backup.db'"
sqlite3 dev-env-manager.db ".restore 'backup.db'"
```

2. **Performance Optimization**
```bash
# PostgreSQL vacuum and analyze
psql -U dev_env_user -d dev_env_manager -c "VACUUM ANALYZE;"

# MySQL optimize tables
mysqlcheck -u dev_env_user -p --optimize dev_env_manager

# SQLite vacuum
sqlite3 dev-env-manager.db "VACUUM;"
```

### Database Monitoring

#### Setup Monitoring Tools
```bash
# Install pgmetrics for PostgreSQL
cargo install pgmetrics

# Run metrics collection
pgmetrics --host localhost --port 5432 --username dev_env_user dev_env_manager

# Monitor MySQL performance
mysqladmin -u dev_env_user -p extended-status variables
```

#### Performance Metrics
```sql
-- Check slow queries (PostgreSQL)
SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY duration DESC;

-- Check table sizes
SELECT relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

```

### Automated Recovery Scripts

#### Auto-Recovery Configuration
```yaml
# auto-recovery.yaml
recovery_plans:
  docker_failure:
    detect:
      - condition: "service_status != running"
        service: "docker"
    actions:
      - restart_service:
          name: "docker"
          max_attempts: 3
          wait_between: 10s
      - verify_health:
          timeout: 30s
      - notify_admin:
          on_failure: true

  kubernetes_issues:
    detect:
      - condition: "node_status != ready"
        check_interval: 1m
    actions:
      - drain_node:
          timeout: 5m
      - reset_kubernetes:
          preserve_data: true
      - rejoin_cluster:
          verify: true

  network_failure:
    detect:
      - condition: "connectivity_loss"
        threshold: 3
    actions:
      - reset_network:
          preserve_config: true
      - rebuild_bridges:
          verify: true
      - restore_routing:
          backup_first: true
```

### Monitoring Integration

#### Prometheus Integration
```yaml
# prometheus-alerts.yaml
groups:
  - name: dev_env_manager_alerts
    rules:
      - alert: HighResourceUsage
        expr: dev_env_resource_usage > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "Resource usage exceeding 90% for 5 minutes"

      - alert: ServiceDown
        expr: dev_env_service_health == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          description: "Service {{ $labels.service }} is down"
```

## Health Checks

### Automated Health Check Script
```bash
#!/bin/bash
# health_check.sh

check_component() {
    local component=$1
    echo "Checking $component..."
    dev-env-manager check $component || return 1
}

components=(
    "docker"
    "kubernetes"
    "network"
    "storage"
    "permissions"
)

for component in "${components[@]}"; do
    if ! check_component $component; then
        echo "❌ $component check failed"
        dev-env-manager repair $component --auto
    else
        echo "✅ $component check passed"
    fi
done
```

## Backup and Recovery

### Backup Configuration
```bash
# Create backup
dev-env-manager backup create --include-data

# List backups
dev-env-manager backup list

# Restore from backup
dev-env-manager backup restore --latest
```

## Environment Variables

### Required Variables
```bash
# Core Configuration
export DEV_ENV_HOME=/opt/dev-env-manager
export DEV_ENV_CONFIG=/etc/dev-env-manager
export DEV_ENV_LOGS=/var/log/dev-env-manager

# Docker Configuration
export DOCKER_HOST=unix:///var/run/docker.sock
export DOCKER_CONFIG=${DEV_ENV_HOME}/.docker
export COMPOSE_PROJECT_NAME=dev-env

# Kubernetes Configuration
export KUBECONFIG=${DEV_ENV_CONFIG}/kubeconfig
export KUBE_CONTEXT=dev-env
```

### Optional Variables
```bash
# Performance Tuning
export DEV_ENV_MAX_MEMORY=8G
export DEV_ENV_CPU_LIMIT=4
export DEV_ENV_DISK_QUOTA=50G

# Network Configuration
export DEV_ENV_PORT=8080
export DEV_ENV_HOST=0.0.0.0
export DEV_ENV_PROXY=""
```

## Next Steps

1. ✅ Verify Installation
   ```bash
   dev-env-manager verify --all
   ```

2. ✅ Configure Environment
   ```bash
   dev-env-manager configure --interactive
   ```

3. ✅ Run Test Project
   ```bash
   dev-env-manager quickstart --template nodejs
   ```

4. ✅ Join Community
   - [Discord Community](https://discord.gg/dev-env-manager)
   - [GitHub Discussions](https://github.com/dev-env-manager/discussions)
   - [Documentation](https://docs.dev-env-manager.com)

## Getting Help

### Community Support
- 💬 [Discord Server](https://discord.gg/dev-env-manager)
- 📖 [Documentation](https://docs.dev-env-manager.com)
- 🐛 [Issue Tracker](https://github.com/dev-env-manager/issues)
- 📝 [Blog](https://blog.dev-env-manager.com)

### Enterprise Support
- 📧 Email: support@dev-env-manager.com
- 🔧 Priority Issue Resolution
- 📞 24/7 Phone Support
- 👥 Dedicated Support Team

## Database Setup and Migration

### Prerequisites
- SQLx CLI tool
- Access to either PostgreSQL, MySQL, or SQLite
- Database credentials (if using PostgreSQL or MySQL)

### Database Installation

#### SQLite Setup
```bash
# Install SQLx CLI
cargo install sqlx-cli

# Create SQLite database
sqlx database create

# Run migrations
sqlx migrate run
```

#### PostgreSQL Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql -c "CREATE DATABASE dev_env_manager;"
sudo -u postgres psql -c "CREATE USER dev_env_user WITH ENCRYPTED PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dev_env_manager TO dev_env_user;"

# Run migrations
DATABASE_URL="postgres://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

#### MySQL Setup
```bash
# Install MySQL (Ubuntu/Debian)
sudo apt update
sudo apt install mysql-server

# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -e "CREATE DATABASE dev_env_manager;"
sudo mysql -e "CREATE USER 'dev_env_user'@'localhost' IDENTIFIED BY 'your_password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dev_env_manager.* TO 'dev_env_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Run migrations
DATABASE_URL="mysql://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

### Migration Management

#### Initial Setup
```bash
# Create migrations directory
mkdir -p migrations

# Create initial migration
sqlx migrate add initial_schema
```

#### Migration Files
```sql
-- migrations/20230101000000_initial_schema.sql
-- Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Environment Configs Table
CREATE TABLE IF NOT EXISTS environment_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    config_json JSONB NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

#### Managing Migrations
```bash
# List migrations
sqlx migrate info

# Run pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Check migration status
sqlx migrate status
```

### Environment Configuration

#### Environment Variables
Create a `.env` file in your project root:
```bash
# Database Configuration
DATABASE_URL="postgresql://dev_env_user:your_password@localhost/dev_env_manager"
# Or for SQLite:
# DATABASE_URL="sqlite:./dev-env-manager.db"

# Database Pool Configuration
DB_POOL_SIZE=5
DB_MAX_CONNECTIONS=100
DB_IDLE_TIMEOUT=300

# Migration Settings
MIGRATION_DIRECTORY="./migrations"
```

#### Database Connection Pool Configuration
```rust
// Example configuration in your Rust code
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(100)
    .connect(&std::env::var("DATABASE_URL")?)
    .await?;
```

### Troubleshooting Database Issues

#### Common Database Problems

1. **Connection Issues**
```bash
# Test database connection
sqlx database ping

# Check database status
systemctl status postgresql  # For PostgreSQL
systemctl status mysql      # For MySQL

# Verify network connectivity
nc -zv localhost 5432  # PostgreSQL default port
nc -zv localhost 3306  # MySQL default port
```

2. **Permission Issues**
```bash
# PostgreSQL
sudo -u postgres psql -c "\du"  # List users and their roles
sudo -u postgres psql -c "\l"   # List databases and their owners

# MySQL
mysql -u root -p -e "SHOW GRANTS FOR 'dev_env_user'@'localhost';"
```

3. **Migration Failures**
```bash
# Reset database (CAUTION: Deletes all data)
sqlx database reset

# Check migration logs
sqlx migrate info --verbose

# Verify migration files
find migrations -type f -name "*.sql" -exec sqlx migrate verify {} \;
```

#### Database Maintenance

1. **Backup and Restore**
```bash
# PostgreSQL
pg_dump -U dev_env_user dev_env_manager > backup.sql
psql -U dev_env_user dev_env_manager < backup.sql

# MySQL
mysqldump -u dev_env_user -p dev_env_manager > backup.sql
mysql -u dev_env_user -p dev_env_manager < backup.sql

# SQLite
sqlite3 dev-env-manager.db ".backup 'backup.db'"
sqlite3 dev-env-manager.db ".restore 'backup.db'"
```

2. **Performance Optimization**
```bash
# PostgreSQL vacuum and analyze
psql -U dev_env_user -d dev_env_manager -c "VACUUM ANALYZE;"

# MySQL optimize tables
mysqlcheck -u dev_env_user -p --optimize dev_env_manager

# SQLite vacuum
sqlite3 dev-env-manager.db "VACUUM;"
```

### Database Monitoring

#### Setup Monitoring Tools
```bash
# Install pgmetrics for PostgreSQL
cargo install pgmetrics

# Run metrics collection
pgmetrics --host localhost --port 5432 --username dev_env_user dev_env_manager

# Monitor MySQL performance
mysqladmin -u dev_env_user -p extended-status variables
```

#### Performance Metrics
```sql
-- Check slow queries (PostgreSQL)
SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY duration DESC;

-- Check table sizes
SELECT relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

```

### Automated Recovery Scripts

#### Auto-Recovery Configuration
```yaml
# auto-recovery.yaml
recovery_plans:
  docker_failure:
    detect:
      - condition: "service_status != running"
        service: "docker"
    actions:
      - restart_service:
          name: "docker"
          max_attempts: 3
          wait_between: 10s
      - verify_health:
          timeout: 30s
      - notify_admin:
          on_failure: true

  kubernetes_issues:
    detect:
      - condition: "node_status != ready"
        check_interval: 1m
    actions:
      - drain_node:
          timeout: 5m
      - reset_kubernetes:
          preserve_data: true
      - rejoin_cluster:
          verify: true

  network_failure:
    detect:
      - condition: "connectivity_loss"
        threshold: 3
    actions:
      - reset_network:
          preserve_config: true
      - rebuild_bridges:
          verify: true
      - restore_routing:
          backup_first: true
```

### Monitoring Integration

#### Prometheus Integration
```yaml
# prometheus-alerts.yaml
groups:
  - name: dev_env_manager_alerts
    rules:
      - alert: HighResourceUsage
        expr: dev_env_resource_usage > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "Resource usage exceeding 90% for 5 minutes"

      - alert: ServiceDown
        expr: dev_env_service_health == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          description: "Service {{ $labels.service }} is down"
```

## Health Checks

### Automated Health Check Script
```bash
#!/bin/bash
# health_check.sh

check_component() {
    local component=$1
    echo "Checking $component..."
    dev-env-manager check $component || return 1
}

components=(
    "docker"
    "kubernetes"
    "network"
    "storage"
    "permissions"
)

for component in "${components[@]}"; do
    if ! check_component $component; then
        echo "❌ $component check failed"
        dev-env-manager repair $component --auto
    else
        echo "✅ $component check passed"
    fi
done
```

## Backup and Recovery

### Backup Configuration
```bash
# Create backup
dev-env-manager backup create --include-data

# List backups
dev-env-manager backup list

# Restore from backup
dev-env-manager backup restore --latest
```

## Environment Variables

### Required Variables
```bash
# Core Configuration
export DEV_ENV_HOME=/opt/dev-env-manager
export DEV_ENV_CONFIG=/etc/dev-env-manager
export DEV_ENV_LOGS=/var/log/dev-env-manager

# Docker Configuration
export DOCKER_HOST=unix:///var/run/docker.sock
export DOCKER_CONFIG=${DEV_ENV_HOME}/.docker
export COMPOSE_PROJECT_NAME=dev-env

# Kubernetes Configuration
export KUBECONFIG=${DEV_ENV_CONFIG}/kubeconfig
export KUBE_CONTEXT=dev-env
```

### Optional Variables
```bash
# Performance Tuning
export DEV_ENV_MAX_MEMORY=8G
export DEV_ENV_CPU_LIMIT=4
export DEV_ENV_DISK_QUOTA=50G

# Network Configuration
export DEV_ENV_PORT=8080
export DEV_ENV_HOST=0.0.0.0
export DEV_ENV_PROXY=""
```

## Next Steps

1. ✅ Verify Installation
   ```bash
   dev-env-manager verify --all
   ```

2. ✅ Configure Environment
   ```bash
   dev-env-manager configure --interactive
   ```

3. ✅ Run Test Project
   ```bash
   dev-env-manager quickstart --template nodejs
   ```

4. ✅ Join Community
   - [Discord Community](https://discord.gg/dev-env-manager)
   - [GitHub Discussions](https://github.com/dev-env-manager/discussions)
   - [Documentation](https://docs.dev-env-manager.com)

## Getting Help

### Community Support
- 💬 [Discord Server](https://discord.gg/dev-env-manager)
- 📖 [Documentation](https://docs.dev-env-manager.com)
- 🐛 [Issue Tracker](https://github.com/dev-env-manager/issues)
- 📝 [Blog](https://blog.dev-env-manager.com)

### Enterprise Support
- 📧 Email: support@dev-env-manager.com
- 🔧 Priority Issue Resolution
- 📞 24/7 Phone Support
- 👥 Dedicated Support Team

## Database Setup and Migration

### Prerequisites
- SQLx CLI tool
- Access to either PostgreSQL, MySQL, or SQLite
- Database credentials (if using PostgreSQL or MySQL)

### Database Installation

#### SQLite Setup
```bash
# Install SQLx CLI
cargo install sqlx-cli

# Create SQLite database
sqlx database create

# Run migrations
sqlx migrate run
```

#### PostgreSQL Setup
```bash
# Install PostgreSQL (Ubuntu/Debian)
sudo apt update
sudo apt install postgresql postgresql-contrib

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql -c "CREATE DATABASE dev_env_manager;"
sudo -u postgres psql -c "CREATE USER dev_env_user WITH ENCRYPTED PASSWORD 'your_password';"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dev_env_manager TO dev_env_user;"

# Run migrations
DATABASE_URL="postgres://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

#### MySQL Setup
```bash
# Install MySQL (Ubuntu/Debian)
sudo apt update
sudo apt install mysql-server

# Secure MySQL installation
sudo mysql_secure_installation

# Create database and user
sudo mysql -e "CREATE DATABASE dev_env_manager;"
sudo mysql -e "CREATE USER 'dev_env_user'@'localhost' IDENTIFIED BY 'your_password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON dev_env_manager.* TO 'dev_env_user'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

# Run migrations
DATABASE_URL="mysql://dev_env_user:your_password@localhost/dev_env_manager" sqlx migrate run
```

### Migration Management

#### Initial Setup
```bash
# Create migrations directory
mkdir -p migrations

# Create initial migration
sqlx migrate add initial_schema
```

#### Migration Files
```sql
-- migrations/20230101000000_initial_schema.sql
-- Create Users Table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Environment Configs Table
CREATE TABLE IF NOT EXISTS environment_configs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL UNIQUE,
    config_json JSONB NOT NULL,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create Audit Logs Table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(255) NOT NULL,
    details JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
```

#### Managing Migrations
```bash
# List migrations
sqlx migrate info

# Run pending migrations
sqlx migrate run

# Revert last migration
sqlx migrate revert

# Check migration status
sqlx migrate status
```

### Environment Configuration

#### Environment Variables
Create a `.env` file in your project root:
```bash
# Database Configuration
DATABASE_URL="postgresql://dev_env_user:your_password@localhost/dev_env_manager"
# Or for SQLite:
# DATABASE_URL="sqlite:./dev-env-manager.db"

# Database Pool Configuration
DB_POOL_SIZE=5
DB_MAX_CONNECTIONS=100
DB_IDLE_TIMEOUT=300

# Migration Settings
MIGRATION_DIRECTORY="./migrations"
```

#### Database Connection Pool Configuration
```rust
// Example configuration in your Rust code
use sqlx::postgres::PgPoolOptions;

let pool = PgPoolOptions::new()
    .max_connections(100)
    .connect(&std::env::var("DATABASE_URL")?)
    .await?;
```

### Troubleshooting Database Issues

#### Common Database Problems

1. **Connection Issues**
```bash
# Test database connection
sqlx database ping

# Check database status
systemctl status postgresql  # For PostgreSQL
systemctl status mysql      # For MySQL

# Verify network connectivity
nc -zv localhost 5432  # PostgreSQL default port
nc -zv localhost 3306  # MySQL default port
```

2. **Permission Issues**
```bash
# PostgreSQL
sudo -u postgres psql -c "\du"  # List users and their roles
sudo -u postgres psql -c "\l"   # List databases and their owners

# MySQL
mysql -u root -p -e "SHOW GRANTS FOR 'dev_env_user'@'localhost';"
```

3. **Migration Failures**
```bash
# Reset database (CAUTION: Deletes all data)
sqlx database reset

# Check migration logs
sqlx migrate info --verbose

# Verify migration files
find migrations -type f -name "*.sql" -exec sqlx migrate verify {} \;
```

#### Database Maintenance

1. **Backup and Restore**
```bash
# PostgreSQL
pg_dump -U dev_env_user dev_env_manager > backup.sql
psql -U dev_env_user dev_env_manager < backup.sql

# MySQL
mysqldump -u dev_env_user -p dev_env_manager > backup.sql
mysql -u dev_env_user -p dev_env_manager < backup.sql

# SQLite
sqlite3 dev-env-manager.db ".backup 'backup.db'"
sqlite3 dev-env-manager.db ".restore 'backup.db'"
```

2. **Performance Optimization**
```bash
# PostgreSQL vacuum and analyze
psql -U dev_env_user -d dev_env_manager -c "VACUUM ANALYZE;"

# MySQL optimize tables
mysqlcheck -u dev_env_user -p --optimize dev_env_manager

# SQLite vacuum
sqlite3 dev-env-manager.db "VACUUM;"
```

### Database Monitoring

#### Setup Monitoring Tools
```bash
# Install pgmetrics for PostgreSQL
cargo install pgmetrics

# Run metrics collection
pgmetrics --host localhost --port 5432 --username dev_env_user dev_env_manager

# Monitor MySQL performance
mysqladmin -u dev_env_user -p extended-status variables
```

#### Performance Metrics
```sql
-- Check slow queries (PostgreSQL)
SELECT * FROM pg_stat_activity WHERE state = 'active' ORDER BY duration DESC;

-- Check table sizes
SELECT relname AS table_name,
       pg_size_pretty(pg_total_relation_size(relid)) AS total_size
FROM pg_catalog.pg_statio_user_tables
ORDER BY pg_total_relation_size(relid) DESC;

```

### Automated Recovery Scripts

#### Auto-Recovery Configuration
