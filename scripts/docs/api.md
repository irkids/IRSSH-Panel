# IRSSH Panel API Documentation

## Authentication
### Login
```http
POST /api/auth/login
Content-Type: application/json

{
    "username": "string",
    "password": "string"
}

Response:
{
    "access_token": "string",
    "token_type": "bearer"
}
```

### Refresh Token
```http
POST /api/auth/refresh
Authorization: Bearer {token}

Response:
{
    "access_token": "string",
    "token_type": "bearer"
}
```

## User Management
### Get Users
```http
GET /api/users
Authorization: Bearer {token}

Response:
{
    "users": [
        {
            "id": "integer",
            "username": "string",
            "email": "string",
            "active": "boolean",
            "created_at": "datetime"
        }
    ]
}
```

### Create User
```http
POST /api/users
Authorization: Bearer {token}
Content-Type: application/json

{
    "username": "string",
    "email": "string",
    "password": "string",
    "protocols": ["ssh", "l2tp"]
}
```

## Protocol Management
### List Protocols
```http
GET /api/protocols
Authorization: Bearer {token}

Response:
{
    "protocols": [
        {
            "name": "string",
            "status": "string",
            "port": "integer",
            "active_users": "integer"
        }
    ]
}
```

### Configure Protocol
```http
PUT /api/protocols/{protocol_name}
Authorization: Bearer {token}
Content-Type: application/json

{
    "port": "integer",
    "settings": {
        "key": "value"
    }
}
```

## Monitoring API
### System Metrics
```http
GET /api/monitoring/system
Authorization: Bearer {token}

Response:
{
    "cpu_usage": "float",
    "memory_usage": "float",
    "disk_usage": "float",
    "network_stats": {
        "in": "float",
        "out": "float"
    }
}
```

### Active Users
```http
GET /api/monitoring/users
Authorization: Bearer {token}

Response:
{
    "total_users": "integer",
    "active_users": "integer",
    "connections": [
        {
            "username": "string",
            "protocol": "string",
            "connected_since": "datetime",
            "ip_address": "string"
        }
    ]
}
```

## Error Responses
```http
400 Bad Request
{
    "detail": "Error message"
}

401 Unauthorized
{
    "detail": "Invalid credentials"
}

403 Forbidden
{
    "detail": "Not enough permissions"
}

404 Not Found
{
    "detail": "Resource not found"
}

500 Internal Server Error
{
    "detail": "Internal server error"
}
```
