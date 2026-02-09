import type { TokenProvider, TokenResponse } from '../types/token.types.js';
import { getLogger } from '../logging/logger.js';

const REQUEST_TIMEOUT_MS = 30000;

export class OAuthM2MProvider implements TokenProvider {
  readonly name = 'oauth-m2m';
  private workspaceUrl: string;
  private clientId: string;
  private clientSecret: string;

  constructor(workspaceUrl: string, clientId: string, clientSecret: string) {
    this.workspaceUrl = workspaceUrl.replace(/\/+$/, '');
    this.clientId = clientId;
    this.clientSecret = clientSecret;
  }

  async isAvailable(): Promise<boolean> {
    return !!(this.clientId && this.clientSecret && this.workspaceUrl);
  }

  async getToken(): Promise<string | null> {
    const logger = getLogger();
    const tokenEndpoint = `${this.workspaceUrl}/oidc/v1/token`;

    logger.info('Obtaining new token via OAuth M2M flow...');
    logger.debug(`Token endpoint: ${tokenEndpoint}`);

    try {
      const credentials = Buffer.from(
        `${this.clientId}:${this.clientSecret}`,
      ).toString('base64');

      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        REQUEST_TIMEOUT_MS,
      );

      try {
        const response = await fetch(tokenEndpoint, {
          method: 'POST',
          headers: {
            Authorization: `Basic ${credentials}`,
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: 'grant_type=client_credentials&scope=all-apis',
          signal: controller.signal,
        });

        if (!response.ok) {
          const body = await response.text().catch(() => 'unknown');
          logger.error(
            `OAuth M2M request failed: ${response.status} ${response.statusText} - ${body}`,
          );
          return null;
        }

        const data = (await response.json()) as TokenResponse;
        if (!data.access_token) {
          logger.error('OAuth M2M response missing access_token');
          return null;
        }

        logger.info('Successfully obtained token via OAuth M2M');
        return data.access_token;
      } finally {
        clearTimeout(timeout);
      }
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        logger.error(
          `OAuth M2M request timed out after ${REQUEST_TIMEOUT_MS}ms`,
        );
      } else {
        logger.error(
          `OAuth M2M request failed: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
      return null;
    }
  }
}
