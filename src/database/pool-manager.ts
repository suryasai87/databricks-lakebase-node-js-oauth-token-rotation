import { Pool, type PoolConfig, type QueryResult } from 'pg';
import type { ValidatedConfig } from '../config/index.js';
import { TlsEnforcer } from '../security/tls-enforcer.js';
import { ConnectionPoolGuard } from '../security/connection-pool-guard.js';
import { getLogger } from '../logging/logger.js';

export class PoolManager {
  private pool: Pool | null = null;
  private config: ValidatedConfig;
  private tlsEnforcer: TlsEnforcer;
  private poolGuard: ConnectionPoolGuard;

  constructor(config: ValidatedConfig) {
    this.config = config;
    this.tlsEnforcer = new TlsEnforcer(config.tls);
    this.poolGuard = new ConnectionPoolGuard({
      maxConnections: config.security.maxConnectionPoolSize,
    });
  }

  createPool(password: string): Pool {
    const poolConfig = this.poolGuard.getPoolConfig();
    const sslConfig = this.tlsEnforcer.getPgSslConfig();

    const pgConfig: PoolConfig = {
      host: this.config.pgHost,
      port: this.config.pgPort,
      database: this.config.pgDatabase,
      user: this.config.pgUsername,
      password,
      ssl: sslConfig || undefined,
      max: poolConfig.max,
      connectionTimeoutMillis: poolConfig.connectionTimeoutMillis,
      idleTimeoutMillis: poolConfig.idleTimeoutMillis,
    };

    this.pool = new Pool(pgConfig);

    this.pool.on('connect', () => {
      this.poolGuard.onAcquire();
    });

    this.pool.on('remove', () => {
      this.poolGuard.onRelease();
    });

    this.pool.on('error', (err) => {
      const logger = getLogger();
      logger.error(`Pool error: ${err.message}`);
    });

    return this.pool;
  }

  getPool(): Pool | null {
    return this.pool;
  }

  getStats() {
    return this.poolGuard.getStats();
  }

  async drain(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }
}
