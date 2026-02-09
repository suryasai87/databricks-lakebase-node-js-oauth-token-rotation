import type { Pool, QueryResult } from 'pg';
import { sqlInjectionGuard } from '../security/sql-injection-guard.js';
import { SecurityError } from '../types/security.types.js';

export class QueryExecutor {
  private pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  /**
   * Execute a parameterized query. Only accepts $1, $2, ... placeholders.
   * Rejects any string interpolation patterns.
   */
  async execute(
    text: string,
    params: unknown[] = [],
  ): Promise<QueryResult> {
    // Validate query text for injection patterns
    sqlInjectionGuard.validateQuery(text);

    return this.pool.query(text, params);
  }

  /**
   * Execute a simple health check query.
   */
  async healthCheck(): Promise<{ success: boolean; latencyMs: number }> {
    const start = Date.now();
    try {
      await this.pool.query('SELECT 1 AS health_check');
      return { success: true, latencyMs: Date.now() - start };
    } catch {
      return { success: false, latencyMs: Date.now() - start };
    }
  }
}
