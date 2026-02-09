// Core auth
export {
  OAuthM2MProvider,
  CliFallbackProvider,
  createTokenProviders,
  acquireToken,
  decodeToken,
  isTokenExpired,
  getTokenExpiryMinutes,
} from './auth/index.js';

// PgPass management
export {
  updatePgPass,
  parsePgPassLine,
  parsePgPassFile,
  formatPgPassEntry,
  checkPermissions,
} from './pgpass/index.js';

// Security
export {
  InputValidator,
  inputValidator,
  SqlInjectionGuard,
  sqlInjectionGuard,
  RateLimiter,
  TokenVault,
  TlsEnforcer,
  ConnectionPoolGuard,
  SecretManager,
} from './security/index.js';

// Database
export { PoolManager, QueryExecutor, testConnection } from './database/index.js';

// Daemon
export {
  RotationScheduler,
  SignalHandler,
  HealthCheckServer,
} from './daemon/index.js';

// Logging
export { createLogger, getLogger, AuditLogger } from './logging/index.js';

// Config
export { loadConfig, configSchema } from './config/index.js';

// Types
export type { RotatorConfig, TlsConfig, SecurityConfig } from './types/config.types.js';
export type { TokenInfo, TokenProvider, TokenResponse } from './types/token.types.js';
export type { PgPassEntry, PgPassUpdateResult } from './types/pgpass.types.js';
export type {
  RateLimitResult,
  AuditLogEntry,
  AuditEventType,
} from './types/security.types.js';
export { SecurityError } from './types/security.types.js';
