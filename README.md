# Databricks Lakebase Node.js OAuth Token Rotator

Secure, automated OAuth token rotation for [Databricks Lakebase](https://docs.databricks.com/en/database-connections/lakebase/index.html) PostgreSQL connections. Built with TypeScript and hardened against SQL injection, DDoS, token theft, and other attack vectors.

## What It Does

Databricks Lakebase uses short-lived OAuth tokens (60-minute expiry) for PostgreSQL authentication. This tool automatically rotates tokens before they expire and writes them to `~/.pgpass` so any PostgreSQL client (`psql`, application drivers, BI tools) can connect seamlessly.

**Rotation cycle:** Acquire token → Decode JWT → Encrypt in memory → Update `~/.pgpass` atomically → Verify connection

## Features

- **Automatic Token Rotation** — Acquires OAuth tokens via M2M (Service Principal) or Databricks CLI fallback, on a configurable interval (default: 50 minutes)
- **Atomic PgPass Updates** — Writes to a temp file, sets `chmod 0600`, then renames — no partial writes, no race conditions
- **AES-256-GCM Token Vault** — Tokens are encrypted in memory with a per-process random key, never stored in plaintext
- **SQL Injection Guard** — 27+ regex patterns block dangerous SQL in connection parameters; all queries use parameterized execution only
- **Rate Limiting** — Token bucket algorithm prevents abuse of OAuth endpoints and health checks
- **TLS 1.2+ Enforcement** — Rejects insecure connections, supports optional certificate pinning
- **Connection Pool Guard** — Enforces max pool size, timeouts, and alerts at 80% capacity
- **Tamper-Evident Audit Logs** — HMAC-SHA256 chained log entries detect tampering
- **Graceful Shutdown** — SIGTERM/SIGINT handlers drain connections and flush logs before exit
- **Health Check Endpoint** — Optional HTTP `/health` on localhost for monitoring
- **OS Service Installation** — macOS LaunchAgent and Linux systemd unit generation

## Quick Start

### Prerequisites

- Node.js >= 20
- [Databricks CLI](https://docs.databricks.com/en/dev-tools/cli/index.html) configured with `databricks auth login`
- A Databricks Lakebase PostgreSQL instance

### Install

```bash
git clone https://github.com/suryasai87/databricks-lakebase-node-js-oauth-token-rotation.git
cd databricks-lakebase-node-js-oauth-token-rotation
npm install
npm run build
```

### Single Rotation (One-Shot)

```bash
node dist/cli.js --once \
  --workspace-url https://your-workspace.cloud.databricks.com \
  --pg-host instance-xxxx.database.cloud.databricks.com \
  --pg-username your.email@company.com \
  --test-connection
```

### Daemon Mode (Continuous)

```bash
node dist/cli.js \
  --workspace-url https://your-workspace.cloud.databricks.com \
  --pg-host instance-xxxx.database.cloud.databricks.com \
  --pg-username your.email@company.com \
  --test-connection \
  --interval 50
```

### With Service Principal (M2M OAuth)

```bash
node dist/cli.js \
  --workspace-url https://your-workspace.cloud.databricks.com \
  --client-id 12345678-1234-1234-1234-123456789012 \
  --client-secret your-client-secret \
  --pg-host instance-xxxx.database.cloud.databricks.com \
  --pg-username your.email@company.com
```

## CLI Options

| Option | Description | Default |
|--------|-------------|---------|
| `--once` | Run a single rotation and exit | — |
| `--workspace-url <url>` | Databricks workspace URL | `$DATABRICKS_HOST` |
| `--client-id <id>` | OAuth Service Principal client ID | `$DATABRICKS_CLIENT_ID` |
| `--client-secret <secret>` | OAuth client secret | `$DATABRICKS_CLIENT_SECRET` |
| `--pg-host <host>` | Lakebase PostgreSQL hostname | `$LAKEBASE_PG_HOST` |
| `--pg-port <port>` | PostgreSQL port | `5432` |
| `--pg-database <name>` | PostgreSQL database name | `databricks_postgres` |
| `--pg-username <email>` | PostgreSQL username | `$LAKEBASE_PG_USERNAME` |
| `--pgpass-file <path>` | Path to `.pgpass` file | `~/.pgpass` |
| `--log-file <path>` | Log file path | `~/.databricks/lakebase-rotator.log` |
| `--interval <minutes>` | Rotation interval | `50` |
| `--health-port <port>` | Health check HTTP port | — |
| `--test-connection` | Test DB connection after rotation | `false` |
| `--no-encrypt-tokens` | Disable in-memory token encryption | — |
| `--audit-log <path>` | Audit log file path | — |

## Environment Variables

All CLI options can be set via environment variables:

```bash
export DATABRICKS_HOST=https://your-workspace.cloud.databricks.com
export DATABRICKS_CLIENT_ID=12345678-1234-1234-1234-123456789012
export DATABRICKS_CLIENT_SECRET=your-secret
export LAKEBASE_PG_HOST=instance-xxxx.database.cloud.databricks.com
export LAKEBASE_PG_USERNAME=your.email@company.com
```

## Install as OS Service

### macOS (LaunchAgent)

```bash
node dist/cli.js install --launchd \
  --workspace-url https://your-workspace.cloud.databricks.com \
  --pg-host instance-xxxx.database.cloud.databricks.com \
  --pg-username your.email@company.com
```

### Linux (systemd)

```bash
node dist/cli.js install --systemd \
  --workspace-url https://your-workspace.cloud.databricks.com \
  --pg-host instance-xxxx.database.cloud.databricks.com \
  --pg-username your.email@company.com
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     CLI (Commander)                      │
├─────────────────────────────────────────────────────────┤
│                  Config (Zod Validated)                   │
├──────────┬──────────┬───────────┬───────────┬───────────┤
│   Auth   │  PgPass  │ Security  │ Database  │  Daemon   │
│          │          │           │           │           │
│ OAuth M2M│ Parser   │ SQL Guard │ Pool Mgr  │ Scheduler │
│ CLI Fall-│ Writer   │ Rate Lim  │ Query Exe │ Signals   │
│  back    │ Perms    │ TLS Enf   │ Conn Test │ Health    │
│ JWT Dec  │          │ Vault     │           │           │
│          │          │ Validator │           │           │
│          │          │ Pool Grd  │           │           │
│          │          │ Secrets   │           │           │
├──────────┴──────────┴───────────┴───────────┴───────────┤
│               Logging (Winston + Audit)                  │
└─────────────────────────────────────────────────────────┘
```

## Security Model

| Threat | Mitigation |
|--------|------------|
| Token theft (memory dump) | AES-256-GCM encrypted in-memory storage with per-process random key |
| SQL injection | Parameterized queries only + 27 regex pattern blocklist + Zod validation |
| DDoS / abuse | Token bucket rate limiter on OAuth endpoints and health checks |
| MITM attack | TLS 1.2+ enforcement, optional certificate pinning |
| PgPass race condition | Atomic write: temp file → chmod 0600 → rename |
| Log tampering | HMAC-SHA256 chained audit entries |
| Connection exhaustion | Pool size limits, timeouts, 80% capacity warnings |
| Command injection | `execFile` (no shell) for CLI fallback, never `exec` |
| Secret leakage | No secrets in logs, args, or environment after startup |

## Testing

The project includes **282 tests** across three categories:

```bash
# Run all tests
npm test

# Unit tests (136 tests) — module-level isolation
npm run test:unit

# Integration tests (15 tests) — end-to-end flows with mock OAuth server
npm run test:integration

# Security tests (131 tests) — attack simulation and hardening verification
npm run test:security

# All tests with coverage report
npm run test:all
```

### Security Test Suite

| Test Suite | Tests | What It Validates |
|------------|-------|-------------------|
| SQL Injection | 17 | 50+ injection vectors against all input validators |
| DDoS Simulation | 14 | Rate limiter under burst traffic, connection pool exhaustion |
| Token Security | 21 | AES-256-GCM encryption, memory isolation, vault lifecycle |
| TLS Enforcement | 17 | Cipher suites, protocol versions, cert pinning |
| Input Fuzzing | 25 | Unicode, path traversal, null bytes, oversized inputs |
| File Permissions | 11 | PgPass 0600 enforcement across create/update cycles |
| Auth Bypass | 16 | Expired tokens, tampered JWTs, missing claims |
| Penetration | 10 | Static analysis: no secrets in source, logs, or CLI args |

## Project Structure

```
src/
├── auth/                  # Token acquisition (OAuth M2M + CLI fallback)
├── config/                # Zod-validated configuration
├── daemon/                # Rotation scheduler, signal handling, health check
├── database/              # Secure pool manager, parameterized queries, connection tester
├── install/               # macOS LaunchAgent + Linux systemd installers
├── logging/               # Winston logger + HMAC-SHA256 audit chain
├── pgpass/                # Atomic ~/.pgpass management
├── security/              # SQL guard, rate limiter, TLS enforcer, token vault
└── types/                 # TypeScript interfaces

tests/
├── helpers/               # Mock OAuth server, temp files, 50+ attack payloads
├── unit/                  # Module-level tests
├── integration/           # End-to-end flow tests
└── security/              # Cybersecurity test suite
```

## Technology Stack

- **TypeScript** on Node.js 20+
- **Zod** — config and input validation
- **pg** (node-postgres) — PostgreSQL client with SSL
- **Winston** — structured logging with rotation
- **Commander** — CLI framework
- **Jest + ts-jest** — testing
- **Node.js `crypto`** — AES-256-GCM (zero external crypto dependencies)

## License

Apache-2.0
