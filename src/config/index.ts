import { configSchema, type ValidatedConfig } from './schema.js';
import { ENV_VAR_MAP } from './defaults.js';

export type { ValidatedConfig } from './schema.js';
export { configSchema } from './schema.js';
export { CONFIG_DEFAULTS, ENV_VAR_MAP } from './defaults.js';

interface CliArgs {
  workspaceUrl?: string;
  clientId?: string;
  clientSecret?: string;
  pgHost?: string;
  pgPort?: number;
  pgDatabase?: string;
  pgUsername?: string;
  pgpassFile?: string;
  logFile?: string;
  interval?: number;
  healthPort?: number;
  testConnection?: boolean;
  auditLog?: string;
  noEncryptTokens?: boolean;
}

function getEnvValue(envKey: string): string | undefined {
  return process.env[envKey];
}

function getEnvNumber(envKey: string): number | undefined {
  const val = getEnvValue(envKey);
  if (val === undefined) return undefined;
  const num = parseInt(val, 10);
  return isNaN(num) ? undefined : num;
}

export function loadConfig(cliArgs: CliArgs = {}): ValidatedConfig {
  const raw = {
    workspaceUrl:
      cliArgs.workspaceUrl ?? getEnvValue(ENV_VAR_MAP.workspaceUrl),
    clientId: cliArgs.clientId ?? getEnvValue(ENV_VAR_MAP.clientId),
    clientSecret: cliArgs.clientSecret ?? getEnvValue(ENV_VAR_MAP.clientSecret),
    pgHost: cliArgs.pgHost ?? getEnvValue(ENV_VAR_MAP.pgHost),
    pgPort: cliArgs.pgPort ?? getEnvNumber(ENV_VAR_MAP.pgPort),
    pgDatabase: cliArgs.pgDatabase ?? getEnvValue(ENV_VAR_MAP.pgDatabase),
    pgUsername: cliArgs.pgUsername ?? getEnvValue(ENV_VAR_MAP.pgUsername),
    pgpassFile: cliArgs.pgpassFile,
    logFile: cliArgs.logFile,
    rotationIntervalMinutes:
      cliArgs.interval ?? getEnvNumber(ENV_VAR_MAP.rotationIntervalMinutes),
    healthCheckPort:
      cliArgs.healthPort ?? getEnvNumber(ENV_VAR_MAP.healthCheckPort),
    testConnection: cliArgs.testConnection,
    auditLogPath: cliArgs.auditLog ?? getEnvValue(ENV_VAR_MAP.auditLogPath),
    security: cliArgs.noEncryptTokens
      ? { encryptTokensInMemory: false }
      : undefined,
  };

  // Remove undefined keys so Zod defaults apply
  const cleaned = Object.fromEntries(
    Object.entries(raw).filter(([, v]) => v !== undefined),
  );

  const result = configSchema.safeParse(cleaned);
  if (!result.success) {
    const issues = result.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Configuration validation failed:\n${issues}`);
  }

  return result.data;
}
