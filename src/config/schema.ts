import { z } from 'zod';

const hostnameSchema = z
  .string()
  .min(1, 'Hostname is required')
  .max(253, 'Hostname too long')
  .regex(
    /^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$/,
    'Invalid hostname format - must be a valid DNS name',
  );

const portSchema = z.number().int().min(1).max(65535);

const databaseNameSchema = z
  .string()
  .min(1, 'Database name is required')
  .max(63, 'Database name too long')
  .regex(
    /^[a-zA-Z_][a-zA-Z0-9_]*$/,
    'Invalid database name - must start with letter/underscore, contain only alphanumeric/underscore',
  );

const workspaceUrlSchema = z
  .string()
  .url('Must be a valid URL')
  .refine((url) => url.startsWith('https://'), 'Workspace URL must use HTTPS')
  .transform((url) => url.replace(/\/+$/, ''));

const filePathSchema = z
  .string()
  .min(1)
  .refine((p) => !p.includes('\0'), 'Path must not contain null bytes')
  .refine(
    (p) => !p.includes('..') || p.startsWith('~'),
    'Path must not contain directory traversal',
  );

const tlsConfigSchema = z
  .object({
    enforce: z.boolean().default(true),
    rejectUnauthorized: z.boolean().default(true),
    caCertPath: filePathSchema.optional(),
    certPinning: z
      .object({
        enabled: z.boolean().default(false),
        fingerprints: z.array(z.string().regex(/^[a-fA-F0-9:]+$/)).optional(),
      })
      .default({}),
  })
  .default({});

const securityConfigSchema = z
  .object({
    encryptTokensInMemory: z.boolean().default(true),
    rateLimitPerMinute: z.number().int().min(1).max(1000).default(60),
    maxConnectionPoolSize: z.number().int().min(1).max(100).default(10),
    auditLogEnabled: z.boolean().default(true),
  })
  .default({});

export const configSchema = z.object({
  workspaceUrl: workspaceUrlSchema,
  clientId: z.string().uuid('Client ID must be a valid UUID').optional(),
  clientSecret: z.string().min(1).optional(),
  pgHost: hostnameSchema,
  pgPort: portSchema.default(5432),
  pgDatabase: databaseNameSchema.default('databricks_postgres'),
  pgUsername: z.string().min(1, 'Username is required'),
  pgpassFile: filePathSchema.default('~/.pgpass'),
  logFile: filePathSchema.default('~/.databricks_oauth_rotator.log'),
  rotationIntervalMinutes: z.number().int().min(1).max(59).default(50),
  healthCheckPort: portSchema.optional(),
  testConnection: z.boolean().default(false),
  auditLogPath: filePathSchema.optional(),
  tls: tlsConfigSchema,
  security: securityConfigSchema,
});

export type ValidatedConfig = z.infer<typeof configSchema>;

export {
  hostnameSchema,
  portSchema,
  databaseNameSchema,
  workspaceUrlSchema,
  filePathSchema,
};
