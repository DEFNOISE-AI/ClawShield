# ClawShield Architecture

## Overview

ClawShield is an agent-to-agent firewall designed to protect OpenClaw instances from malicious communications, compromised skills, prompt injections, and data exfiltration.

## System Architecture

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
    │ Request         │  │ Agent        │  │ Skill        │
    │ Interceptor     │  │ Firewall     │  │ Analyzer     │
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

## Core Components

### Proxy Server (`src/core/proxy/`)

- **ProxyServer**: Fastify-based HTTP and WebSocket proxy
- **RequestInterceptor**: Pre-proxy request inspection, header injection
- **ResponseInterceptor**: Post-proxy response inspection, credential leak detection

### Agent Firewall (`src/core/firewall/`)

- **AgentFirewall**: Central inspection engine with fail-closed design
- **RuleEngine**: Evaluates configurable firewall rules from PostgreSQL
- **ThreatDetector**: Pattern-based threat scoring and anomaly detection

### Skill Analyzer (`src/core/analyzer/`)

- **SkillAnalyzer**: Orchestrates the full analysis pipeline
- **StaticAnalyzer**: AST-based code analysis using acorn + estree-walker
- **DynamicAnalyzer**: Sandboxed execution in restricted VM context
- **PromptInjectionDetector**: Pattern matching with base64 recursion

### Crypto Module (`src/core/crypto/`)

- **Encryptor**: AES-256-GCM encryption/decryption
- **TokenManager**: JWT RS256 with Redis-backed blacklist
- **KeyRotation**: Automated key rotation scheduler

## Data Flow

1. Agent sends request to ClawShield proxy
2. RequestInterceptor extracts metadata and agent ID
3. AgentFirewall runs inspection pipeline:
   - Rate limiting check (Redis)
   - Blacklist check (Redis)
   - Rule engine evaluation (PostgreSQL)
   - Threat scoring (pattern matching + anomaly detection)
4. If allowed, request is proxied to OpenClaw with injected headers
5. Response is inspected for credential leaks
6. All events are logged to PostgreSQL

## Technology Stack

- **Runtime**: Bun / Node.js
- **Framework**: Fastify 5 (HTTP) + @fastify/websocket (WS)
- **Database**: PostgreSQL 17 with Drizzle ORM
- **Cache**: Redis 7.4 via ioredis
- **Auth**: JWT RS256 + Argon2id password hashing
- **Testing**: Vitest with >90% coverage target
