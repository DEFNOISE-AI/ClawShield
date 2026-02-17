# ClawShield Security Practices

## Input Validation

All inputs are validated using Zod schemas with `.strict()` mode. No manual string validation.

```typescript
const schema = z.object({ name: z.string().min(1).max(100) }).strict();
const validated = schema.parse(input); // Throws on invalid input
```

## SQL Injection Prevention

- All database access goes through Drizzle ORM with parameterized queries
- No string interpolation in any SQL
- Prepared statements are enabled by default

## Authentication

- JWT with RS256 algorithm (asymmetric, never HS256)
- Access tokens expire in 15 minutes
- Refresh tokens expire in 7 days
- Token blacklist via Redis for immediate revocation
- Passwords hashed with Argon2id (64MB memory, 3 iterations)

## Rate Limiting

- Global: 100 requests/minute per IP via Redis-backed @fastify/rate-limit
- Auth endpoints: 5 requests/minute per IP
- WebSocket: 5 connections per IP

## CORS

- Strict origin whitelist
- Credentials mode enabled
- Only GET/POST/PUT/DELETE methods allowed
- 24-hour preflight cache

## Security Headers (via @fastify/helmet)

- Content-Security-Policy with strict directives
- HSTS with 1-year max-age, includeSubDomains, preload
- X-Content-Type-Options: nosniff
- Strict-Origin-When-Cross-Origin referrer policy

## WebSocket Security

- Strict origin validation on upgrade
- JWT token required for connection
- Per-IP connection limits
- Message inspection through AgentFirewall

## Logging

- Pino with field-level redaction for sensitive data
- Redacted fields: password, apiKey, token, authorization, cookie, secret
- No stack traces in production error responses
- Structured JSON logging for SIEM integration

## Fail-Closed Design

The firewall follows a fail-closed principle: if any inspection step encounters an error, the request is **blocked** rather than allowed through.

## Dependency Security

- All dependencies pinned to exact versions
- CI runs `bun audit` and Snyk on every push
- Docker images scanned with Trivy
- Non-root user in production Docker container

## Credential Leak Detection

ResponseInterceptor scans outgoing responses for:
- API keys, passwords, secrets, tokens
- AWS credentials
- GitHub/Stripe tokens
- Private keys (PEM format)
- Stack traces in error responses
- Internal infrastructure details
