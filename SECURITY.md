# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | Yes       |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, report them via one of these channels:

- **Email**: [security@clawshield.io](mailto:security@clawshield.io)
- **GitHub Security Advisories**: [Report a vulnerability](https://github.com/DEFNOISE-AI/ClawShield/security/advisories/new)

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 5 business days
- **Fix timeline** communicated within 10 business days
- **Credit** in the security advisory (unless you prefer anonymity)

We will keep you informed throughout the process and coordinate disclosure timing with you.

## Disclosure Policy

- We follow [Coordinated Vulnerability Disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure)
- We aim to patch critical vulnerabilities within 72 hours
- Security advisories are published via [GitHub Security Advisories](https://github.com/DEFNOISE-AI/ClawShield/security/advisories)

## Security Best Practices for Deployment

- Always use the latest release
- Never expose the admin API without authentication
- Use TLS termination in front of ClawShield
- Rotate JWT keys regularly (ClawShield supports automatic key rotation)
- Monitor `/logs/threats` for suspicious activity
- Review firewall rules periodically
- Keep PostgreSQL and Redis access restricted to ClawShield only

## Security Architecture

For details on ClawShield's security design, see [docs/security.md](docs/security.md).
