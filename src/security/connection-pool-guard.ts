import { SecurityError } from '../types/security.types.js';
import { getLogger } from '../logging/logger.js';

interface PoolGuardConfig {
  maxConnections: number;
  connectionTimeoutMs: number;
  idleTimeoutMs: number;
  warningThreshold: number; // Fraction (e.g., 0.8 = 80%)
}

const DEFAULT_CONFIG: PoolGuardConfig = {
  maxConnections: 10,
  connectionTimeoutMs: 30000,
  idleTimeoutMs: 600000,
  warningThreshold: 0.8,
};

export class ConnectionPoolGuard {
  private config: PoolGuardConfig;
  private activeConnections = 0;

  constructor(config: Partial<PoolGuardConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Check if a new connection can be acquired.
   */
  canAcquire(): boolean {
    return this.activeConnections < this.config.maxConnections;
  }

  /**
   * Register a new connection acquisition.
   */
  onAcquire(): void {
    if (!this.canAcquire()) {
      throw new SecurityError(
        `Connection pool exhausted: ${this.activeConnections}/${this.config.maxConnections}`,
        'POOL_EXHAUSTED',
      );
    }

    this.activeConnections++;
    const logger = getLogger();

    const threshold = Math.floor(
      this.config.maxConnections * this.config.warningThreshold,
    );
    if (this.activeConnections >= threshold) {
      logger.warn(
        `Connection pool at ${this.activeConnections}/${this.config.maxConnections} ` +
          `(${Math.round((this.activeConnections / this.config.maxConnections) * 100)}%)`,
      );
    }
  }

  /**
   * Register a connection release.
   */
  onRelease(): void {
    if (this.activeConnections > 0) {
      this.activeConnections--;
    }
  }

  getStats(): {
    active: number;
    max: number;
    available: number;
    utilizationPercent: number;
  } {
    return {
      active: this.activeConnections,
      max: this.config.maxConnections,
      available: this.config.maxConnections - this.activeConnections,
      utilizationPercent: Math.round(
        (this.activeConnections / this.config.maxConnections) * 100,
      ),
    };
  }

  getPoolConfig(): {
    max: number;
    connectionTimeoutMillis: number;
    idleTimeoutMillis: number;
  } {
    return {
      max: this.config.maxConnections,
      connectionTimeoutMillis: this.config.connectionTimeoutMs,
      idleTimeoutMillis: this.config.idleTimeoutMs,
    };
  }
}
