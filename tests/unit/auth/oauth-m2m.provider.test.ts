import { OAuthM2MProvider } from '../../../src/auth/oauth-m2m.provider';
import { MockOAuthServer } from '../../helpers/mock-server';

// Silence logger output during tests
jest.mock('../../../src/logging/logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
}));

describe('OAuthM2MProvider', () => {
  let server: MockOAuthServer;
  let port: number;

  beforeEach(async () => {
    server = new MockOAuthServer();
    port = await server.start();
  });

  afterEach(async () => {
    await server.stop();
  });

  function createProvider(
    workspaceUrl?: string,
    clientId?: string,
    clientSecret?: string,
  ): OAuthM2MProvider {
    return new OAuthM2MProvider(
      workspaceUrl ?? `http://127.0.0.1:${port}`,
      clientId ?? 'test-client-id',
      clientSecret ?? 'test-client-secret',
    );
  }

  describe('isAvailable', () => {
    it('should return true when all credentials are provided', async () => {
      const provider = createProvider();
      expect(await provider.isAvailable()).toBe(true);
    });

    it('should return false when clientId is empty', async () => {
      const provider = createProvider(`http://127.0.0.1:${port}`, '', 'secret');
      expect(await provider.isAvailable()).toBe(false);
    });

    it('should return false when clientSecret is empty', async () => {
      const provider = createProvider(`http://127.0.0.1:${port}`, 'id', '');
      expect(await provider.isAvailable()).toBe(false);
    });

    it('should return false when workspaceUrl is empty', async () => {
      const provider = createProvider('', 'id', 'secret');
      expect(await provider.isAvailable()).toBe(false);
    });
  });

  describe('getToken', () => {
    it('should return a valid access token on success', async () => {
      const provider = createProvider();
      const token = await provider.getToken();

      expect(token).not.toBeNull();
      expect(token!).toMatch(/^eyJ/); // JWT prefix
      expect(server.requestCount).toBe(1);
    });

    it('should return null when server returns 401 unauthorized', async () => {
      server.setFailureMode('unauthorized');
      const provider = createProvider();
      const token = await provider.getToken();

      expect(token).toBeNull();
    });

    it('should return null when server returns 500 error', async () => {
      server.setFailureMode('server_error');
      const provider = createProvider();
      const token = await provider.getToken();

      expect(token).toBeNull();
    });

    it('should return null when server returns malformed JSON', async () => {
      server.setFailureMode('malformed');
      const provider = createProvider();
      const token = await provider.getToken();

      expect(token).toBeNull();
    });

    it('should return null when connecting to unreachable host', async () => {
      const provider = new OAuthM2MProvider(
        'http://127.0.0.1:1', // port 1 is almost certainly not listening
        'client-id',
        'client-secret',
      );
      const token = await provider.getToken();

      expect(token).toBeNull();
    });

    it('should strip trailing slashes from workspace URL', async () => {
      const provider = createProvider(`http://127.0.0.1:${port}///`);
      const token = await provider.getToken();

      // Should still work because trailing slashes are stripped
      expect(token).not.toBeNull();
      expect(token!).toMatch(/^eyJ/);
    });

    it('should have name property set to oauth-m2m', () => {
      const provider = createProvider();
      expect(provider.name).toBe('oauth-m2m');
    });
  });
});
