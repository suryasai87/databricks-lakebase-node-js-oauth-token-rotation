import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import jwt from 'jsonwebtoken';

interface MockServerConfig {
  port?: number;
  tokenExpiresInSeconds?: number;
  failureMode?: 'none' | 'unauthorized' | 'server_error' | 'timeout' | 'malformed';
  responseDelayMs?: number;
}

export function createMockJwt(expiresInSeconds = 3600): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'test-service-principal',
    client_id: '12345678-1234-1234-1234-123456789012',
    scope: 'all-apis',
    iss: 'https://oidc.databricks.com',
    aud: 'api',
    exp: now + expiresInSeconds,
    iat: now,
  };
  return jwt.sign(payload, 'test-secret');
}

export function createExpiredJwt(): string {
  return createMockJwt(-3600); // Expired 1 hour ago
}

export class MockOAuthServer {
  private server: Server | null = null;
  private config: Required<MockServerConfig>;
  public requestCount = 0;

  constructor(config: MockServerConfig = {}) {
    this.config = {
      port: config.port ?? 0,
      tokenExpiresInSeconds: config.tokenExpiresInSeconds ?? 3600,
      failureMode: config.failureMode ?? 'none',
      responseDelayMs: config.responseDelayMs ?? 0,
    };
  }

  async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
        this.requestCount++;
        this.handleRequest(req, res);
      });

      this.server.listen(this.config.port, '127.0.0.1', () => {
        const address = this.server!.address();
        if (address && typeof address === 'object') {
          resolve(address.port);
        } else {
          reject(new Error('Failed to get server port'));
        }
      });

      this.server.on('error', reject);
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  setFailureMode(mode: MockServerConfig['failureMode']): void {
    this.config.failureMode = mode ?? 'none';
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const respond = () => {
      if (req.url === '/oidc/v1/token' && req.method === 'POST') {
        this.handleTokenRequest(req, res);
      } else {
        res.writeHead(404);
        res.end('Not found');
      }
    };

    if (this.config.responseDelayMs > 0 && this.config.failureMode !== 'timeout') {
      setTimeout(respond, this.config.responseDelayMs);
    } else if (this.config.failureMode === 'timeout') {
      // Don't respond at all - simulate timeout
      return;
    } else {
      respond();
    }
  }

  private handleTokenRequest(_req: IncomingMessage, res: ServerResponse): void {
    switch (this.config.failureMode) {
      case 'unauthorized':
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid_client' }));
        break;

      case 'server_error':
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'internal_server_error' }));
        break;

      case 'malformed':
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('this is not valid json{{{');
        break;

      default: {
        const token = createMockJwt(this.config.tokenExpiresInSeconds);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          access_token: token,
          token_type: 'Bearer',
          expires_in: this.config.tokenExpiresInSeconds,
        }));
      }
    }
  }
}
