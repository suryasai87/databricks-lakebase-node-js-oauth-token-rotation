export const CONFIG_DEFAULTS = {
  pgPort: 5432,
  pgDatabase: 'databricks_postgres',
  pgpassFile: '~/.pgpass',
  logFile: '~/.databricks_oauth_rotator.log',
  rotationIntervalMinutes: 50,
  tls: {
    enforce: true,
    rejectUnauthorized: true,
    certPinning: {
      enabled: false,
    },
  },
  security: {
    encryptTokensInMemory: true,
    rateLimitPerMinute: 60,
    maxConnectionPoolSize: 10,
    auditLogEnabled: true,
  },
} as const;

export const ENV_VAR_MAP = {
  workspaceUrl: 'DATABRICKS_HOST',
  clientId: 'DATABRICKS_CLIENT_ID',
  clientSecret: 'DATABRICKS_CLIENT_SECRET',
  pgHost: 'DATABRICKS_PG_HOST',
  pgPort: 'DATABRICKS_PG_PORT',
  pgDatabase: 'DATABRICKS_PG_DATABASE',
  pgUsername: 'DATABRICKS_PG_USERNAME',
  rotationIntervalMinutes: 'ROTATION_INTERVAL_MINUTES',
  healthCheckPort: 'HEALTH_CHECK_PORT',
  auditLogPath: 'AUDIT_LOG_PATH',
} as const;
