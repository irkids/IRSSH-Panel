# IRSSH Panel API Documentation

## Authentication
All API requests require authentication using JWT tokens.

### Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "string",
  "password": "string"
}
