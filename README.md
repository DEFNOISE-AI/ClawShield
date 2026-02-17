# ClawShield

Agent-to-agent firewall for OpenClaw. Protects against malicious communications, compromised skills, prompt injections, data exfiltration, and WebSocket vulnerabilities.

## Quick Start

```bash
# First-time setup (generates keys, creates .env)
bash scripts/setup.sh

# Start PostgreSQL and Redis
cd docker && docker compose up -d postgres redis && cd ..

# Run database migrations
bun run db:migrate

# Start development server
bun run dev
```

## Stack

- **Runtime**: Bun / Node.js
- **Framework**: Fastify 5
- **Database**: PostgreSQL 17 + Drizzle ORM
- **Cache**: Redis 7.4
- **Auth**: JWT RS256 + Argon2id
- **Testing**: Vitest (143 tests)

## Commands

| Command | Description |
|---------|-------------|
| `bun run dev` | Start dev server with hot reload |
| `bun run build` | Build for production |
| `bun run start` | Start production server |
| `bun run test` | Run all tests |
| `bun run test:coverage` | Run tests with coverage report |
| `bun run lint` | Run ESLint |
| `bun run format` | Format with Prettier |
| `bun run typecheck` | TypeScript type checking |
| `bun run db:generate` | Generate Drizzle migrations |
| `bun run db:migrate` | Run database migrations |
| `bun run db:seed` | Seed initial data |

## Docker

```bash
# Full stack (app + PostgreSQL + Redis)
cd docker && docker compose up

# Production build
docker build -f docker/Dockerfile -t clawshield .
```

## Documentation

- [Architecture](docs/architecture.md)
- [Security Practices](docs/security.md)
- [API Reference](docs/api.md)

## Security Features

- Zod schema validation on all inputs
- AES-256-GCM encryption, JWT RS256
- Rate limiting (global + per-endpoint)
- Agent-to-agent communication whitelist
- Prompt injection detection (16 patterns + base64 recursion)
- Skill static analysis (AST) + dynamic sandboxed execution
- Credential leak detection in responses
- Fail-closed firewall design
- Non-root Docker container
