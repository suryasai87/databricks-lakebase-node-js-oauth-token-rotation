import type { TokenProvider } from '../types/token.types.js';
import type { ValidatedConfig } from '../config/index.js';
import { OAuthM2MProvider } from './oauth-m2m.provider.js';
import { CliFallbackProvider } from './cli-fallback.provider.js';
import { getLogger } from '../logging/logger.js';

export { OAuthM2MProvider } from './oauth-m2m.provider.js';
export { CliFallbackProvider } from './cli-fallback.provider.js';
export { decodeToken, isTokenExpired, getTokenExpiryMinutes } from './jwt-decoder.js';

export function createTokenProviders(config: ValidatedConfig): TokenProvider[] {
  const providers: TokenProvider[] = [];

  if (config.clientId && config.clientSecret) {
    providers.push(
      new OAuthM2MProvider(
        config.workspaceUrl,
        config.clientId,
        config.clientSecret,
      ),
    );
  }

  providers.push(new CliFallbackProvider(config.workspaceUrl));

  return providers;
}

export async function acquireToken(
  providers: TokenProvider[],
): Promise<string | null> {
  const logger = getLogger();

  for (const provider of providers) {
    const available = await provider.isAvailable();
    if (!available) {
      logger.debug(`Provider ${provider.name} is not available, skipping`);
      continue;
    }

    logger.debug(`Trying provider: ${provider.name}`);
    const token = await provider.getToken();
    if (token) {
      logger.info(`Token acquired via ${provider.name}`);
      return token;
    }
    logger.warn(`Provider ${provider.name} failed to provide a token`);
  }

  logger.error('All token providers failed');
  return null;
}
