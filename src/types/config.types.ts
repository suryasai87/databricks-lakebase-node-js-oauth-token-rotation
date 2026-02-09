export interface TlsConfig {
  enforce: boolean;
  rejectUnauthorized: boolean;
  caCertPath?: string;
  certPinning: {
    enabled: boolean;
    fingerprints?: string[];
  };
}

export interface SecurityConfig {
  encryptTokensInMemory: boolean;
  rateLimitPerMinute: number;
  maxConnectionPoolSize: number;
  auditLogEnabled: boolean;
}

export interface RotatorConfig {
  workspaceUrl: string;
  clientId?: string;
  clientSecret?: string;
  pgHost: string;
  pgPort: number;
  pgDatabase: string;
  pgUsername: string;
  pgpassFile: string;
  logFile: string;
  rotationIntervalMinutes: number;
  healthCheckPort?: number;
  testConnection: boolean;
  auditLogPath?: string;
  tls: TlsConfig;
  security: SecurityConfig;
}
