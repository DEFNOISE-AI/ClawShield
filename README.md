<div align="center">

![ClawShield](https://raw.githubusercontent.com/DEFNOISE-AI/ClawShield/master/assets/clawshield-banner.png)

# ClawShield

**Open-source security firewall for agent-to-agent AI communication**

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![CI](https://github.com/DEFNOISE-AI/ClawShield/actions/workflows/ci.yml/badge.svg)](https://github.com/DEFNOISE-AI/ClawShield/actions/workflows/ci.yml)
[![Security Scan](https://github.com/DEFNOISE-AI/ClawShield/actions/workflows/security-scan.yml/badge.svg)](https://github.com/DEFNOISE-AI/ClawShield/actions/workflows/security-scan.yml)

[Getting Started](#getting-started) · [Architecture](#architecture) · [API Reference](docs/api.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

## Why ClawShield?

AI agents are talking to each other at scale. But unlike human-to-human communication, **there is no firewall between agents**. A compromised agent can:

- **Inject malicious prompts** into other agents via crafted messages
- **Exfiltrate sensitive data** through API calls and WebSocket channels
- **Execute arbitrary code** via compromised skills and plugins
- **Hijack WebSocket connections** between agent sessions
- **Bypass access controls** by impersonating trusted agents

ClawShield sits between your AI agents and inspects every communication -- blocking threats before they reach your infrastructure.

> Built to protect [OpenClaw](https://github.com/open-claw) instances, works with any agent-to-agent protocol.

## Key Features

| Feature | Description |
|---------|-------------|
| **Agent Firewall** | Fail-closed inspection engine with configurable rule engine and threat scoring |
| **Prompt Injection Detection** | 16+ pattern signatures with recursive base64 decoding |
| **Skill Static Analysis** | AST-based code scanning using acorn/estree to detect dangerous patterns |
| **Skill Dynamic Analysis** | Sandboxed execution in restricted VM context with memory/time limits |
| **Credential Leak Detection** | Scans responses for API keys, tokens, private keys, and infrastructure details |
| **Agent Whitelisting** | Explicit agent-to-agent communication rules with rate limits |
| **WebSocket Protection** | Origin validation, JWT auth, per-IP connection limits, message inspection |
| **Encrypted Communications** | AES-256-GCM encryption, JWT RS256, automatic key rotation |

## Architecture

```
                     ┌──────────────────────┐
                     │   External Agents     │
                     └──────────┬───────────┘
                                │
                     ┌──────────▼───────────┐
                     │   ClawShield Proxy    │
                     │  (HTTP + WebSocket)   │
                     └──────────┬───────────┘
                                │
              ┌─────────────────┼─────────────────┐
              │                 │                   │
    ┌─────────▼──────┐  ┌──────▼───────┐  ┌───────▼──────┐
    │  Request        │  │    Agent     │  │    Skill     │
    │  Interceptor    │  │   Firewall   │  │   Analyzer   │
    └─────────┬──────┘  └──────┬───────┘  └───────┬──────┘
              │                │                   │
              │         ┌──────▼───────┐          │
              │         │ Rule Engine  │          │
              │         │ + Threat     │          │
              │         │   Detector   │          │
              │         └──────┬───────┘          │
              │                │                   │
              └────────────────┼───────────────────┘
                               │
                    ┌──────────▼───────────┐
                    │   OpenClaw Instance   │
                    └──────────────────────┘
```

Every request passes through the full inspection pipeline. If any step fails or detects a threat, the request is **blocked** (fail-closed design). See [docs/architecture.md](docs/architecture.md) for details.

## Getting Started

### Prerequisites

- [Bun](https://bun.sh/) >= 1.2.0 (or Node.js >= 22)
- [Docker](https://www.docker.com/) (for PostgreSQL and Redis)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/DEFNOISE-AI/ClawShield.git
cd ClawShield

# Run setup (generates keys, creates .env)
bash scripts/setup.sh

# Start PostgreSQL and Redis
cd docker && docker compose up -d postgres redis && cd ..

# Install dependencies
bun install

# Run database migrations
bun run db:migrate

# Start development server
bun run dev
```

ClawShield is now running on `http://localhost:3000`.

### Docker (Full Stack)

```bash
cd docker && docker compose up
```

This starts ClawShield + PostgreSQL + Redis in a single command.

### Production Build

```bash
docker build -f docker/Dockerfile -t clawshield .
```

## Usage

### Register an Agent

```bash
curl -X POST http://localhost:3000/agents \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-agent",
    "endpoint": "https://agent.example.com",
    "permissions": ["read", "write"],
    "maxRequestsPerMinute": 100
  }'
```

### Create a Firewall Rule

```bash
curl -X POST http://localhost:3000/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Block eval",
    "type": "deny",
    "priority": 10,
    "enabled": true,
    "conditions": [{"field": "code", "operator": "contains", "value": "eval("}],
    "action": {"type": "deny", "message": "eval() is not allowed"}
  }'
```

### Analyze a Skill

```bash
curl -X POST http://localhost:3000/skills/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "function greet(name) { return \"Hello, \" + name; }",
    "language": "javascript"
  }'
```

See the full [API Reference](docs/api.md) for all endpoints.

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

## Tech Stack

- **Runtime**: Bun / Node.js
- **Framework**: Fastify 5
- **Database**: PostgreSQL 17 + Drizzle ORM
- **Cache**: Redis 7.4
- **Auth**: JWT RS256 + Argon2id
- **Testing**: Vitest (181 tests)

## Documentation

- [Architecture](docs/architecture.md) -- System design and data flow
- [Security Practices](docs/security.md) -- How ClawShield secures itself
- [API Reference](docs/api.md) -- All endpoints and schemas

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a PR.

For security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

ClawShield is open source under the [AGPL-3.0 License](LICENSE).

For commercial licensing options, contact [contact@dnai.agency](mailto:contact@dnai.agency).
