import { createServer, type Server } from 'node:http';
import { RateLimiter } from '../security/rate-limiter.js';
import { getLogger } from '../logging/logger.js';
import type { RotationScheduler } from './rotation-scheduler.js';

export class HealthCheckServer {
  private server: Server | null = null;
  private rateLimiter: RateLimiter;
  private scheduler: RotationScheduler;
  private port: number;

  constructor(scheduler: RotationScheduler, port: number, rateLimit = 60) {
    this.scheduler = scheduler;
    this.port = port;
    this.rateLimiter = new RateLimiter({ maxPerMinute: rateLimit });
  }

  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      const logger = getLogger();

      this.server = createServer((req, res) => {
        const clientIp = req.socket.remoteAddress ?? 'unknown';
        const limitResult = this.rateLimiter.checkLimit(clientIp);

        if (!limitResult.allowed) {
          res.writeHead(429, {
            'Content-Type': 'application/json',
            'Retry-After': String(
              Math.ceil((limitResult.retryAfterMs ?? 1000) / 1000),
            ),
          });
          res.end(JSON.stringify({ error: 'Too many requests' }));
          return;
        }

        if (req.url === '/health' && req.method === 'GET') {
          const status = this.scheduler.getStatus();
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(
            JSON.stringify({
              status: 'ok',
              lastRotation: status.lastRotation?.toISOString() ?? null,
              nextRotation: status.nextRotation?.toISOString() ?? null,
              tokenExpiresAt: status.tokenExpiresAt,
              hasToken: status.hasToken,
            }),
          );
        } else {
          res.writeHead(404, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Not found' }));
        }
      });

      // Bind only to localhost for security
      this.server.listen(this.port, '127.0.0.1', () => {
        logger.info(`Health check server listening on http://127.0.0.1:${this.port}/health`);
        resolve();
      });

      this.server.on('error', (err) => {
        logger.error(`Health check server error: ${err.message}`);
        reject(err);
      });
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
}
