export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
}

export interface AuditLogEntry {
  timestamp: string;
  eventType: AuditEventType;
  details: string;
  prevHash: string;
  entryHash: string;
}

export type AuditEventType =
  | 'TOKEN_OBTAINED'
  | 'TOKEN_FAILED'
  | 'TOKEN_EXPIRED'
  | 'PGPASS_UPDATED'
  | 'PGPASS_FAILED'
  | 'CONNECTION_TEST'
  | 'RATE_LIMIT_HIT'
  | 'TLS_VIOLATION'
  | 'INPUT_REJECTED'
  | 'AUTH_ATTEMPT'
  | 'AUTH_FAILURE'
  | 'SERVICE_START'
  | 'SERVICE_STOP'
  | 'SQL_INJECTION_BLOCKED';

export class SecurityError extends Error {
  constructor(
    message: string,
    public readonly code: string,
  ) {
    super(message);
    this.name = 'SecurityError';
  }
}
