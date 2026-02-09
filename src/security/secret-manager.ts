import { getLogger } from '../logging/logger.js';

const REQUEST_TIMEOUT_MS = 15000;

export class SecretManager {
  private workspaceUrl: string;
  private authToken?: string;

  constructor(workspaceUrl: string, authToken?: string) {
    this.workspaceUrl = workspaceUrl.replace(/\/+$/, '');
    this.authToken = authToken;
  }

  /**
   * Retrieve a secret from Databricks secret scope.
   * Falls back to environment variable if API is unavailable.
   */
  async getSecret(
    scope: string,
    key: string,
    envFallback?: string,
  ): Promise<string | null> {
    const logger = getLogger();

    // Try Databricks Secrets API first
    if (this.authToken) {
      try {
        const url = `${this.workspaceUrl}/api/2.0/secrets/get?scope=${encodeURIComponent(scope)}&key=${encodeURIComponent(key)}`;

        const controller = new AbortController();
        const timeout = setTimeout(
          () => controller.abort(),
          REQUEST_TIMEOUT_MS,
        );

        try {
          const response = await fetch(url, {
            headers: {
              Authorization: `Bearer ${this.authToken}`,
            },
            signal: controller.signal,
          });

          if (response.ok) {
            const data = (await response.json()) as { value?: string };
            if (data.value) {
              logger.debug(`Secret ${scope}/${key} retrieved from Databricks`);
              return data.value;
            }
          } else {
            logger.debug(
              `Databricks secrets API returned ${response.status} for ${scope}/${key}`,
            );
          }
        } finally {
          clearTimeout(timeout);
        }
      } catch (err) {
        logger.debug(
          `Databricks secrets API unavailable: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // Fall back to environment variable
    if (envFallback) {
      const value = process.env[envFallback];
      if (value) {
        logger.debug(
          `Secret ${scope}/${key} loaded from env var ${envFallback}`,
        );
        return value;
      }
    }

    logger.warn(`Secret ${scope}/${key} not found in any source`);
    return null;
  }
}
