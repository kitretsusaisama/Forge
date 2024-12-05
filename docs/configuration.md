# Configuration Reference

## Command Line Flags

### Environment Type
```bash
--type <docker|kubernetes>
```
Specifies the type of environment to create.

### Container Image
```bash
--image <image_name>
```
Specifies the Docker image or Kubernetes pod image.

### Environment File
```bash
--env-file <file_path>
```
Path to the environment variables file.

### Environment Name
```bash
--name <env_name>
```
Name for the environment or container.

### Port Configuration
```bash
--port <port_number>
```
Port number to expose or forward.

### Resource Allocation
```bash
--cpu <cpu_cores>
--memory <memory_size>
```
Resource limits for containers/pods.

### Scaling
```bash
--scale <replica_count>
```
Number of replicas for Kubernetes deployments.

### Storage
```bash
--volume <volume_path>
```
Mount path for persistent storage.

## Configuration Files

### Environment Variables
`.env` file format:
```dotenv
# Database Configuration
DATABASE_URL=postgres://user:password@localhost:5432/dbname
DATABASE_POOL_SIZE=10

# API Configuration
API_KEY=your-secret-key
API_ENDPOINT=https://api.example.com

# Resource Limits
MAX_MEMORY=4G
MAX_CPU_CORES=2
```

### Docker Configuration
`docker-config.yaml` example:
```yaml
version: '3'
services:
  app:
    image: node:14
    environment:
      - NODE_ENV=development
    ports:
      - "8080:8080"
    volumes:
      - ./:/app
```

### Kubernetes Configuration
`k8s-config.yaml` example:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
spec:
  containers:
  - name: main
    image: my-app-image
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
    ports:
    - containerPort: 8080
```

## Default Values

### Resource Limits
- CPU: 1 core
- Memory: 2GB
- Disk: 10GB

### Network
- Default Port: 8080
- Max Ports per Environment: 10
- Default Protocol: HTTP

### Timeouts
- Container Start: 30s
- Container Stop: 15s
- API Requests: 10s

## Environment Variables

### System Configuration
- `DEV_ENV_HOME`: Installation directory
- `DEV_ENV_CONFIG`: Configuration directory
- `DEV_ENV_LOGS`: Log directory

### Security
- `DEV_ENV_API_KEY`: API authentication key
- `DEV_ENV_SECRET_KEY`: Encryption key for secrets

### Networking
- `DEV_ENV_HOST`: Host address
- `DEV_ENV_PORT`: Default port
- `DEV_ENV_PROXY`: Proxy configuration
