# API Reference

## Authentication

### JWT Authentication
```http
POST /auth/login
```

**Request Body:**
```json
{
    "username": "string",
    "password": "string"
}
```

**Response:**
```json
{
    "access_token": "string",
    "token_type": "Bearer",
    "expires_in": 3600
}
```

### Rate Limiting Headers
All API endpoints include rate limiting headers:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 99
X-RateLimit-Reset: 1640995200
```

## Environment Management

### Create Environment
```http
POST /api/v1/environments
```

**Rate Limit:** 100 requests per minute

**Request Body:**
```json
{
    "name": "string",
    "type": "docker|kubernetes",
    "config": {
        "image": "string",
        "ports": [number],
        "environment": {
            "key": "string"
        },
        "volumes": [
            {
                "source": "string",
                "target": "string"
            }
        ],
        "resources": {
            "cpu_limit": "string",
            "memory_limit": "string"
        }
    }
}
```

### List Environments
```http
GET /api/v1/environments
```

**Rate Limit:** 300 requests per minute

**Query Parameters:**
- `type`: Filter by environment type
- `status`: Filter by status
- `page`: Page number
- `per_page`: Items per page

### Get Environment Details
```http
GET /api/v1/environments/{id}
```

**Rate Limit:** 300 requests per minute

## Secret Management

### AWS Secrets Integration
```http
POST /api/v1/secrets/aws
```

**Rate Limit:** 50 requests per minute

**Request Body:**
```json
{
    "secret_name": "string",
    "secret_value": "string",
    "tags": {
        "key": "string"
    }
}
```

### List Secrets
```http
GET /api/v1/secrets
```

**Rate Limit:** 100 requests per minute

**Query Parameters:**
- `type`: Filter by secret type (aws, local)
- `page`: Page number
- `per_page`: Items per page

## Resource Management

### Get Resource Usage
```http
GET /api/v1/resources/usage
```

**Rate Limit:** 300 requests per minute

**Response:**
```json
{
    "cpu": {
        "usage_percent": number,
        "cores": number
    },
    "memory": {
        "usage_bytes": number,
        "total_bytes": number
    },
    "disk": {
        "usage_bytes": number,
        "total_bytes": number
    }
}
```

## System Administration

### Unix User Management
```http
POST /api/v1/system/users
```

**Rate Limit:** 20 requests per minute

**Request Body:**
```json
{
    "username": "string",
    "groups": ["string"],
    "shell": "string",
    "home_directory": "string"
}
```

### System Health Check
```http
GET /api/v1/system/health
```

**Rate Limit:** 300 requests per minute

**Response:**
```json
{
    "status": "healthy|degraded|unhealthy",
    "components": {
        "database": {
            "status": "string",
            "latency_ms": number
        },
        "aws": {
            "status": "string",
            "last_sync": "string"
        },
        "docker": {
            "status": "string",
            "version": "string"
        },
        "kubernetes": {
            "status": "string",
            "version": "string"
        }
    }
}
```

## Error Responses

### Standard Error Format
```json
{
    "error": {
        "code": "string",
        "message": "string",
        "details": {}
    }
}
```

### Rate Limit Exceeded
```json
{
    "error": {
        "code": "RATE_LIMIT_EXCEEDED",
        "message": "Rate limit exceeded. Please try again later.",
        "details": {
            "limit": number,
            "reset_at": "string"
        }
    }
}
```

### AWS Integration Errors
```json
{
    "error": {
        "code": "AWS_ERROR",
        "message": "AWS operation failed",
        "details": {
            "aws_error_code": "string",
            "aws_request_id": "string"
        }
    }
}
```

## Webhooks

### Webhook Format
```json
{
    "event": "string",
    "timestamp": "string",
    "data": {},
    "signature": "string"
}
```

### Webhook Events
- `environment.created`
- `environment.updated`
- `environment.deleted`
- `secret.created`
- `secret.updated`
- `secret.deleted`
- `system.alert`

## API Versioning

### Version Header
Include the API version in the request header:
```
Accept: application/json; version=1.0
```

### Deprecation Notice
Deprecated endpoints will include the header:
```
Deprecation: true
Sunset: Sat, 31 Dec 2024 23:59:59 GMT
Link: <https://api.dev-env-manager.com/v2/resource>; rel="successor-version"
```
