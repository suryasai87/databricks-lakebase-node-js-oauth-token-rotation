import { Pool } from 'pg';
import type { ValidatedConfig } from '../config/index.js';
import { TlsEnforcer } from '../security/tls-enforcer.js';
import { getLogger } from '../logging/logger.js';

export async function testConnection(
  config: ValidatedConfig,
  password: string,
): Promise<{ success: boolean; latencyMs: number; error?: string }> {
  const logger = getLogger();
  const tlsEnforcer = new TlsEnforcer(config.tls);
  const sslConfig = tlsEnforcer.getPgSslConfig();

  const pool = new Pool({
    host: config.pgHost,
    port: config.pgPort,
    database: config.pgDatabase,
    user: config.pgUsername,
    password,
    ssl: sslConfig || undefined,
    max: 1,
    connectionTimeoutMillis: 30000,
    idleTimeoutMillis: 5000,
  });

  const start = Date.now();
  try {
    const result = await pool.query('SELECT 1 AS connection_test');
    const latencyMs = Date.now() - start;
    logger.info(`Connection test passed (${latencyMs}ms)`);
    return { success: true, latencyMs };
  } catch (err) {
    const latencyMs = Date.now() - start;
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Connection test failed (${latencyMs}ms): ${message}`);
    return { success: false, latencyMs, error: message };
  } finally {
    await pool.end();
  }
}
