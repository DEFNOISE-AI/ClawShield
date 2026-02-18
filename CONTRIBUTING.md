# Contributing to ClawShield

Thank you for your interest in contributing to ClawShield! This guide will help you get started.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

Before creating a bug report, please check [existing issues](https://github.com/DEFNOISE-AI/ClawShield/issues) to avoid duplicates.

When filing a bug report, use the **Bug Report** issue template and include:

- A clear, descriptive title
- Steps to reproduce the issue
- Expected vs actual behavior
- Your environment (OS, Node/Bun version, ClawShield version)
- Relevant logs (with sensitive data redacted)

**Security vulnerabilities** should NOT be reported via GitHub issues. See [SECURITY.md](SECURITY.md) instead.

### Suggesting Features

Use the **Feature Request** issue template and describe:

- The problem your feature would solve
- Your proposed solution
- Alternatives you've considered

### Pull Requests

1. Fork the repository
2. Create a feature branch from `master`:
   ```bash
   git checkout -b feat/your-feature
   ```
3. Make your changes
4. Ensure all checks pass:
   ```bash
   bun run lint
   bun run typecheck
   bun run test
   ```
5. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```
   feat: add websocket message size limit
   fix: correct rate limit window calculation
   docs: update API reference for /skills endpoint
   ```
6. Push and open a Pull Request against `master`

## Development Setup

### Prerequisites

- [Bun](https://bun.sh/) >= 1.2.0 (or Node.js >= 22)
- [Docker](https://www.docker.com/) (for PostgreSQL and Redis)

### Getting Started

```bash
# Clone your fork
git clone https://github.com/<your-username>/ClawShield.git
cd ClawShield

# Install dependencies
bun install

# Run setup script (generates keys, creates .env)
bash scripts/setup.sh

# Start PostgreSQL and Redis
cd docker && docker compose up -d postgres redis && cd ..

# Run database migrations
bun run db:migrate

# Start dev server
bun run dev
```

### Running Tests

```bash
# All tests
bun run test

# With coverage
bun run test:coverage

# Watch mode
bun run test:watch
```

### Code Style

- TypeScript strict mode is enforced
- ESLint and Prettier are configured, run `bun run lint` and `bun run format`
- Husky pre-commit hooks will check formatting automatically

## Branch Naming

| Prefix | Purpose |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation |
| `refactor/` | Code refactoring |
| `test/` | Adding or updating tests |
| `chore/` | Maintenance tasks |

## Review Process

1. All PRs require at least one approving review
2. CI must pass (lint, typecheck, tests)
3. Security-sensitive changes require review from a maintainer
4. Keep PRs focused -- one feature or fix per PR

## License

By contributing to ClawShield, you agree that your contributions will be licensed under the [AGPL-3.0 License](LICENSE).
