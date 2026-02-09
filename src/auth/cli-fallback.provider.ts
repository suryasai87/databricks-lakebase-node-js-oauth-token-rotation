import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { TokenProvider } from '../types/token.types.js';
import { getLogger } from '../logging/logger.js';

const execFileAsync = promisify(execFile);

const VERSION_TIMEOUT_MS = 10000;
const TOKEN_TIMEOUT_MS = 30000;
const LOGIN_TIMEOUT_MS = 60000;

export class CliFallbackProvider implements TokenProvider {
  readonly name = 'cli-fallback';
  private workspaceUrl: string;

  constructor(workspaceUrl: string) {
    this.workspaceUrl = workspaceUrl.replace(/\/+$/, '');
  }

  async isAvailable(): Promise<boolean> {
    const logger = getLogger();
    try {
      await execFileAsync('databricks', ['--version'], {
        timeout: VERSION_TIMEOUT_MS,
        encoding: 'utf-8',
      });
      logger.debug('Databricks CLI is available');
      return true;
    } catch {
      logger.debug('Databricks CLI is not available');
      return false;
    }
  }

  async getToken(): Promise<string | null> {
    const logger = getLogger();
    logger.info('Obtaining new token via Databricks CLI...');

    let token = await this.tryGetCliToken();
    if (token) return token;

    // Try to log in first, then retry
    logger.info('CLI token not available, attempting login...');
    const loginSuccess = await this.attemptLogin();
    if (!loginSuccess) {
      logger.error('Databricks CLI login failed');
      return null;
    }

    token = await this.tryGetCliToken();
    if (token) return token;

    logger.error('Failed to obtain token via CLI even after login');
    return null;
  }

  private async tryGetCliToken(): Promise<string | null> {
    const logger = getLogger();
    try {
      const { stdout } = await execFileAsync(
        'databricks',
        ['auth', 'token', '--host', this.workspaceUrl],
        { timeout: TOKEN_TIMEOUT_MS, encoding: 'utf-8' },
      );

      const trimmed = stdout.trim();

      // Check if output is a raw JWT (starts with eyJ)
      if (trimmed.startsWith('eyJ')) {
        logger.info('Successfully obtained token via CLI (raw JWT)');
        return trimmed;
      }

      // Try to parse as JSON
      try {
        const parsed = JSON.parse(trimmed) as { access_token?: string };
        if (parsed.access_token) {
          logger.info('Successfully obtained token via CLI (JSON format)');
          return parsed.access_token;
        }
      } catch {
        // Not JSON, check if it has a token-like format anywhere
        const jwtMatch = trimmed.match(/(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)/);
        if (jwtMatch?.[1]) {
          logger.info('Successfully obtained token via CLI (extracted)');
          return jwtMatch[1];
        }
      }

      logger.debug(`CLI output was not a recognizable token format`);
      return null;
    } catch (err) {
      logger.debug(
        `CLI token fetch failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return null;
    }
  }

  private async attemptLogin(): Promise<boolean> {
    const logger = getLogger();
    try {
      await execFileAsync(
        'databricks',
        ['auth', 'login', '--host', this.workspaceUrl],
        { timeout: LOGIN_TIMEOUT_MS, encoding: 'utf-8' },
      );
      logger.info('Databricks CLI login successful');
      return true;
    } catch (err) {
      logger.error(
        `Databricks CLI login failed: ${err instanceof Error ? err.message : String(err)}`,
      );
      return false;
    }
  }
}
