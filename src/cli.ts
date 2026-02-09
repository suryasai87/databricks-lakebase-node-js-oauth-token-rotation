#!/usr/bin/env node

import { Command } from 'commander';
import { loadConfig } from './config/index.js';
import { createLogger } from './logging/logger.js';
import { RotationScheduler } from './daemon/rotation-scheduler.js';
import { HealthCheckServer } from './daemon/health-check.js';

const program = new Command();

program
  .name('databricks-lakebase-rotator')
  .description(
    'Secure OAuth token rotation for Databricks Lakebase PostgreSQL',
  )
  .version('1.0.0')
  .option('--once', 'Run a single rotation and exit')
  .option('--workspace-url <url>', 'Databricks workspace URL')
  .option('--client-id <id>', 'OAuth client ID (Service Principal)')
  .option('--client-secret <secret>', 'OAuth client secret')
  .option('--pg-host <host>', 'Lakebase PostgreSQL hostname')
  .option('--pg-port <port>', 'PostgreSQL port', parseInt)
  .option('--pg-database <name>', 'PostgreSQL database name')
  .option('--pg-username <email>', 'PostgreSQL username')
  .option('--pgpass-file <path>', 'Path to .pgpass file')
  .option('--log-file <path>', 'Log file path')
  .option('--interval <minutes>', 'Rotation interval in minutes', parseInt)
  .option('--health-port <port>', 'Health check HTTP port', parseInt)
  .option('--test-connection', 'Test DB connection after rotation')
  .option('--no-encrypt-tokens', 'Disable in-memory token encryption')
  .option('--audit-log <path>', 'Audit log file path')
  .action(async (opts) => {
    try {
      const config = loadConfig({
        workspaceUrl: opts.workspaceUrl,
        clientId: opts.clientId,
        clientSecret: opts.clientSecret,
        pgHost: opts.pgHost,
        pgPort: opts.pgPort,
        pgDatabase: opts.pgDatabase,
        pgUsername: opts.pgUsername,
        pgpassFile: opts.pgpassFile,
        logFile: opts.logFile,
        interval: opts.interval,
        healthPort: opts.healthPort,
        testConnection: opts.testConnection,
        auditLog: opts.auditLog,
        noEncryptTokens: opts.encryptTokens === false,
      });

      createLogger(config.logFile);

      const scheduler = new RotationScheduler(config);

      if (opts.once) {
        const success = await scheduler.startOnce();
        process.exit(success ? 0 : 1);
      } else {
        // Start health check server if configured
        if (config.healthCheckPort) {
          const healthServer = new HealthCheckServer(
            scheduler,
            config.healthCheckPort,
            config.security.rateLimitPerMinute,
          );
          await healthServer.start();
        }

        await scheduler.start();
      }
    } catch (err) {
      console.error(
        `Fatal: ${err instanceof Error ? err.message : String(err)}`,
      );
      process.exit(1);
    }
  });

program.parse();
