# Usage Instructions

## CLI Commands

### Create Environment
```bash
dev-env-manager create --name my-dev-env
```
Creates a new development environment with specified configuration.

### Start Environment
```bash
dev-env-manager start my-dev-env
```
Starts an existing development environment.

### Stop Environment
```bash
dev-env-manager stop my-dev-env
```
Stops a running development environment.

### Port Forwarding
```bash
dev-env-manager port-forward 8080
```
Forwards a container's internal port to a public URL using ngrok or built-in alternative.

### Status Check
```bash
dev-env-manager status
```
Displays the status of all running containers and environments.

### List Environments
```bash
dev-env-manager list
```
Lists all active containers or environments.

### Delete Environment
```bash
dev-env-manager delete my-dev-env
```
Deletes a specific container or environment.

## Web Interface

### Dashboard Access
Access the web interface at `http://localhost:8080` or your configured custom port.

### Features
- Container Management
  - Start/Stop containers
  - View container logs
  - Monitor resource usage
- Port Forwarding
  - Set up port forwarding rules
  - View active forwarded ports
  - Generate public URLs
- Monitoring
  - Resource usage graphs
  - Error logs
  - Performance metrics

### Common Operations

#### Container Management
1. Navigate to the Containers tab
2. Select a container from the list
3. Use the action buttons to start, stop, or delete

#### Port Forwarding
1. Go to the Port Forwarding tab
2. Click "New Forward"
3. Enter container port and desired public port
4. Click "Create" to generate public URL

#### Monitoring
1. Access the Monitoring tab
2. View real-time metrics
3. Set up alerts for resource thresholds
