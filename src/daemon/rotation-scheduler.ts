import type { ValidatedConfig } from '../config/index.js';
import { createTokenProviders, acquireToken, decodeToken } from '../auth/index.js';
import { TokenVault } from '../security/token-vault.js';
import { updatePgPass } from '../pgpass/index.js';
import { testConnection } from '../database/connection-tester.js';
import { AuditLogger } from '../logging/audit-logger.js';
import { getLogger } from '../logging/logger.js';
import { SignalHandler } from './signal-handler.js';

export class RotationScheduler {
  private config: ValidatedConfig;
  private tokenVault: TokenVault;
  private auditLogger: AuditLogger;
  private signalHandler: SignalHandler;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private lastRotation: Date | null = null;
  private nextRotation: Date | null = null;
  private tokenExpiresAt: string | null = null;

  constructor(config: ValidatedConfig) {
    this.config = config;
    this.tokenVault = new TokenVault(config.security.encryptTokensInMemory);
    this.auditLogger = new AuditLogger(
      config.auditLogPath,
      config.security.auditLogEnabled,
    );
    this.signalHandler = new SignalHandler();
  }

  async start(): Promise<void> {
    const logger = getLogger();
    const intervalMs = this.config.rotationIntervalMinutes * 60 * 1000;

    logger.info('========================================');
    logger.info('Starting OAuth token rotation service');
    logger.info(`Rotation interval: ${this.config.rotationIntervalMinutes} minutes`);
    logger.info(`Workspace: ${this.config.workspaceUrl}`);
    logger.info(`PG Host: ${this.config.pgHost}`);
    logger.info('========================================');

    this.auditLogger.log('SERVICE_START', `interval=${this.config.rotationIntervalMinutes}min`);

    // Install signal handlers
    this.signalHandler.onCleanup(async () => {
      this.stop();
      this.tokenVault.clear();
      this.auditLogger.log('SERVICE_STOP', 'graceful_shutdown');
    });
    this.signalHandler.install();

    // Initial rotation
    await this.rotate();

    // Schedule recurring rotations
    if (!this.signalHandler.isAborted()) {
      this.scheduleNext(intervalMs);
    }
  }

  async startOnce(): Promise<boolean> {
    const logger = getLogger();
    logger.info('Running single token rotation...');
    return this.rotate();
  }

  stop(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
  }

  getStatus(): {
    lastRotation: Date | null;
    nextRotation: Date | null;
    tokenExpiresAt: string | null;
    hasToken: boolean;
  } {
    return {
      lastRotation: this.lastRotation,
      nextRotation: this.nextRotation,
      tokenExpiresAt: this.tokenExpiresAt,
      hasToken: this.tokenVault.hasToken(),
    };
  }

  private async rotate(): Promise<boolean> {
    const logger = getLogger();

    logger.info('========================================');
    logger.info('Starting OAuth token rotation cycle');
    logger.info('========================================');

    try {
      // Acquire token
      const providers = createTokenProviders(this.config);
      const token = await acquireToken(providers);

      if (!token) {
        logger.error('Failed to acquire token from any provider');
        this.auditLogger.log('TOKEN_FAILED', 'all_providers_failed');
        return false;
      }

      // Decode and log token info
      const tokenInfo = decodeToken(token);
      logger.info('New token details:');
      logger.info(`  - Subject: ${tokenInfo.subject ?? 'unknown'}`);
      logger.info(`  - Expires at: ${tokenInfo.expiresAt ?? 'unknown'}`);
      logger.info(`  - Valid for: ${tokenInfo.expiresInMinutes?.toFixed(1) ?? 'unknown'} minutes`);
      logger.info(`  - Scopes: ${tokenInfo.scopes.join(', ') || 'none'}`);

      this.tokenExpiresAt = tokenInfo.expiresAt ?? null;
      this.auditLogger.log(
        'TOKEN_OBTAINED',
        `source=provider,expires_in=${tokenInfo.expiresInMinutes?.toFixed(1) ?? '?'}min`,
      );

      // Store encrypted
      this.tokenVault.store(token);

      // Update pgpass
      const decrypted = this.tokenVault.retrieve();
      if (!decrypted) {
        logger.error('Failed to retrieve token from vault');
        return false;
      }

      const result = updatePgPass(this.config.pgpassFile, {
        hostname: this.config.pgHost,
        port: String(this.config.pgPort),
        database: this.config.pgDatabase,
        username: this.config.pgUsername,
        password: decrypted,
      });

      if (!result.success) {
        logger.error(`pgpass update failed: ${result.error}`);
        this.auditLogger.log('PGPASS_FAILED', result.error ?? 'unknown');
        return false;
      }

      this.auditLogger.log('PGPASS_UPDATED', `file=${result.filePath},action=${result.action}`);

      // Optional connection test
      if (this.config.testConnection) {
        const testResult = await testConnection(this.config, decrypted);
        this.auditLogger.log(
          'CONNECTION_TEST',
          `result=${testResult.success ? 'success' : 'failed'},latency=${testResult.latencyMs}ms`,
        );
      }

      this.lastRotation = new Date();
      logger.info('Token rotation completed successfully');
      logger.info('========================================');
      return true;
    } catch (err) {
      logger.error(
        `Unexpected error during rotation: ${err instanceof Error ? err.message : String(err)}`,
      );
      return false;
    }
  }

  private scheduleNext(intervalMs: number): void {
    const logger = getLogger();
    this.nextRotation = new Date(Date.now() + intervalMs);
    logger.info(`Next rotation at: ${this.nextRotation.toISOString()}`);

    this.timer = setTimeout(async () => {
      if (!this.signalHandler.isAborted()) {
        try {
          await this.rotate();
        } catch (err) {
          logger.error(
            `Rotation failed: ${err instanceof Error ? err.message : String(err)}`,
          );
        }
        if (!this.signalHandler.isAborted()) {
          this.scheduleNext(intervalMs);
        }
      }
    }, intervalMs);

    // Allow the process to exit if this is the only thing keeping it alive
    if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
      // Don't unref - we want the daemon to keep running
    }
  }
}
