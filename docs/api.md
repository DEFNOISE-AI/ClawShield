# ClawShield API Reference

Base URL: `http://localhost:3000`

All endpoints except `/health` and `/auth/*` require a Bearer token in the Authorization header.

---

## Health

### GET /health
Returns server liveness status.

**Response** `200 OK`
```json
{ "status": "ok", "timestamp": "2026-02-17T12:00:00.000Z", "uptime": 3600 }
```

### GET /health/ready
Returns readiness status including database and Redis checks.

**Response** `200 OK` or `503 Service Unavailable`
```json
{ "status": "ready", "checks": { "database": "ok", "redis": "ok" } }
```

---

## Authentication

### POST /auth/register
Create a new user account.

**Body**
```json
{
  "username": "admin",
  "password": "SecureP@ss1234",
  "role": "admin"
}
```

**Response** `201 Created`
```json
{
  "user": { "id": "uuid", "username": "admin", "role": "admin" },
  "accessToken": "eyJ...",
  "refreshToken": "eyJ..."
}
```

### POST /auth/login
Authenticate and receive tokens.

**Body**
```json
{ "username": "admin", "password": "SecureP@ss1234" }
```

### POST /auth/refresh
Exchange a refresh token for a new token pair.

**Body**
```json
{ "refreshToken": "eyJ..." }
```

### POST /auth/logout
Blacklist the current access token. Requires authentication.

---

## Agents

### GET /agents
List all registered agents.

### GET /agents/:id
Get agent details by ID.

### POST /agents
Register a new agent. Returns a one-time API key.

**Body**
```json
{
  "name": "my-agent",
  "endpoint": "https://agent.example.com",
  "permissions": ["read", "write"],
  "maxRequestsPerMinute": 100,
  "trustedDomains": ["api.example.com"]
}
```

### PUT /agents/:id
Update agent configuration.

### DELETE /agents/:id
Remove an agent.

### POST /agents/communication-rules
Create an agent-to-agent communication whitelist rule.

**Body**
```json
{
  "sourceAgentId": "uuid",
  "targetAgentId": "uuid",
  "enabled": true,
  "maxMessagesPerMinute": 50
}
```

---

## Firewall Rules

### GET /rules
List all firewall rules.

### GET /rules/:id
Get a specific rule.

### POST /rules
Create a new firewall rule.

**Body**
```json
{
  "name": "Block eval",
  "description": "Block skills using eval()",
  "type": "deny",
  "priority": 10,
  "enabled": true,
  "conditions": [{ "field": "code", "operator": "contains", "value": "eval(" }],
  "action": { "type": "deny", "message": "eval() is not allowed" }
}
```

### PUT /rules/:id
Update a rule.

### DELETE /rules/:id
Delete a rule.

---

## Skill Analysis

### POST /skills/analyze
Analyze a skill's code for security issues.

**Body**
```json
{
  "code": "function greet(name) { return 'Hello, ' + name; }",
  "language": "javascript",
  "timeout": 5000
}
```

**Response** `200 OK`
```json
{
  "cached": false,
  "result": {
    "safe": true,
    "riskScore": 0.0,
    "vulnerabilities": [],
    "patterns": [],
    "analysisTimeMs": 42
  }
}
```

### GET /skills/analysis/:hash
Retrieve a cached analysis result by code hash.

---

## Logs

### GET /logs/requests
Query request logs with pagination and filters.

**Query Parameters**: `page`, `limit`, `agentId`, `blocked`, `from`, `to`

### GET /logs/threats
Query threat events with pagination and filters.

**Query Parameters**: `page`, `limit`, `severity`, `resolved`

---

## Error Responses

All errors follow this format:
```json
{
  "error": {
    "message": "Description of the error",
    "code": "ERROR_CODE"
  },
  "requestId": "unique-request-id"
}
```

Common error codes:
- `VALIDATION_ERROR` (400)
- `AUTH_ERROR` (401)
- `FORBIDDEN` (403)
- `NOT_FOUND` (404)
- `RATE_LIMIT_EXCEEDED` (429)
- `FIREWALL_BLOCKED` (403)
- `INTERNAL_ERROR` (500)
