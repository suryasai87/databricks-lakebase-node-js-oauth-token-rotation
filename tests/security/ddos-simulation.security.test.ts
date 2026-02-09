import { RateLimiter } from '../../src/security/rate-limiter';
import { ConnectionPoolGuard } from '../../src/security/connection-pool-guard';

describe('DDoS Simulation - Rate Limiting', () => {
  describe('RateLimiter', () => {
    it('should allow requests under the limit', () => {
      const limiter = new RateLimiter({ maxPerMinute: 10 });

      for (let i = 0; i < 10; i++) {
        const result = limiter.checkLimit('client-1');
        expect(result.allowed).toBe(true);
        expect(result.remaining).toBeGreaterThanOrEqual(0);
      }
    });

    it('should reject requests when limit is exceeded', () => {
      const limiter = new RateLimiter({ maxPerMinute: 5 });

      // Exhaust all tokens
      for (let i = 0; i < 5; i++) {
        const result = limiter.checkLimit('client-2');
        expect(result.allowed).toBe(true);
      }

      // Next request should be rejected
      const result = limiter.checkLimit('client-2');
      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfterMs).toBeDefined();
      expect(result.retryAfterMs).toBeGreaterThan(0);
    });

    it('should track limits independently per key', () => {
      const limiter = new RateLimiter({ maxPerMinute: 2 });

      // Exhaust client-A
      limiter.checkLimit('client-A');
      limiter.checkLimit('client-A');
      const resultA = limiter.checkLimit('client-A');
      expect(resultA.allowed).toBe(false);

      // client-B should still work
      const resultB = limiter.checkLimit('client-B');
      expect(resultB.allowed).toBe(true);
    });

    it('should refill tokens over time', () => {
      const limiter = new RateLimiter({ maxPerMinute: 60 });

      // Exhaust all tokens
      for (let i = 0; i < 60; i++) {
        limiter.checkLimit('client-3');
      }

      const exhausted = limiter.checkLimit('client-3');
      expect(exhausted.allowed).toBe(false);

      // Simulate time passing by manipulating the bucket directly
      // Since the token bucket refills based on elapsed time, we
      // use jest.spyOn to advance Date.now
      const originalDateNow = Date.now;
      try {
        // Advance time by 30 seconds (half a minute)
        // Should refill ~30 tokens (60 per minute / 2)
        jest.spyOn(Date, 'now').mockReturnValue(originalDateNow() + 30000);

        const refilled = limiter.checkLimit('client-3');
        expect(refilled.allowed).toBe(true);
        expect(refilled.remaining).toBeGreaterThan(0);
      } finally {
        jest.restoreAllMocks();
      }
    });

    it('should never exceed max tokens on refill', () => {
      const limiter = new RateLimiter({ maxPerMinute: 10 });

      // Use one token
      limiter.checkLimit('client-4');

      const originalDateNow = Date.now;
      try {
        // Advance time by 10 minutes - should not exceed max
        jest.spyOn(Date, 'now').mockReturnValue(originalDateNow() + 600000);

        const result = limiter.checkLimit('client-4');
        expect(result.allowed).toBe(true);
        // remaining should be at most maxPerMinute - 1 (just consumed one)
        expect(result.remaining).toBeLessThanOrEqual(9);
      } finally {
        jest.restoreAllMocks();
      }
    });

    it('should support reset for a specific key', () => {
      const limiter = new RateLimiter({ maxPerMinute: 2 });

      limiter.checkLimit('client-5');
      limiter.checkLimit('client-5');
      expect(limiter.checkLimit('client-5').allowed).toBe(false);

      limiter.reset('client-5');
      expect(limiter.checkLimit('client-5').allowed).toBe(true);
    });

    it('should support resetAll', () => {
      const limiter = new RateLimiter({ maxPerMinute: 1 });

      limiter.checkLimit('a');
      limiter.checkLimit('b');
      expect(limiter.checkLimit('a').allowed).toBe(false);
      expect(limiter.checkLimit('b').allowed).toBe(false);

      limiter.resetAll();
      expect(limiter.checkLimit('a').allowed).toBe(true);
      expect(limiter.checkLimit('b').allowed).toBe(true);
    });
  });

  describe('ConnectionPoolGuard', () => {
    it('should reject when pool is exhausted', () => {
      const guard = new ConnectionPoolGuard({ maxConnections: 3 });

      // Acquire all connections
      guard.onAcquire();
      guard.onAcquire();
      guard.onAcquire();

      // Pool is now full
      expect(guard.canAcquire()).toBe(false);
      expect(() => guard.onAcquire()).toThrow(/pool exhausted/i);
    });

    it('should allow connections after release', () => {
      const guard = new ConnectionPoolGuard({ maxConnections: 2 });

      guard.onAcquire();
      guard.onAcquire();
      expect(guard.canAcquire()).toBe(false);

      guard.onRelease();
      expect(guard.canAcquire()).toBe(true);
      expect(() => guard.onAcquire()).not.toThrow();
    });

    it('should provide correct stats at 0% utilization', () => {
      const guard = new ConnectionPoolGuard({ maxConnections: 10 });
      const stats = guard.getStats();

      expect(stats.active).toBe(0);
      expect(stats.max).toBe(10);
      expect(stats.available).toBe(10);
      expect(stats.utilizationPercent).toBe(0);
    });

    it('should provide correct stats at 50% utilization', () => {
      const guard = new ConnectionPoolGuard({ maxConnections: 10 });

      for (let i = 0; i < 5; i++) {
        guard.onAcquire();
      }

      const stats = guard.getStats();
      expect(stats.active).toBe(5);
      expect(stats.max).toBe(10);
      expect(stats.available).toBe(5);
      expect(stats.utilizationPercent).toBe(50);
    });

    it('should provide correct stats at 100% utilization', () => {
      const guard = new ConnectionPoolGuard({ maxConnections: 4 });

      for (let i = 0; i < 4; i++) {
        guard.onAcquire();
      }

      const stats = guard.getStats();
      expect(stats.active).toBe(4);
      expect(stats.max).toBe(4);
      expect(stats.available).toBe(0);
      expect(stats.utilizationPercent).toBe(100);
    });

    it('should not go below 0 active connections on over-release', () => {
      const guard = new ConnectionPoolGuard({ maxConnections: 5 });

      guard.onAcquire();
      guard.onRelease();
      guard.onRelease(); // Extra release should not go negative

      const stats = guard.getStats();
      expect(stats.active).toBe(0);
      expect(stats.available).toBe(5);
    });

    it('should return correct pool config', () => {
      const guard = new ConnectionPoolGuard({
        maxConnections: 20,
        connectionTimeoutMs: 15000,
        idleTimeoutMs: 300000,
      });

      const config = guard.getPoolConfig();
      expect(config.max).toBe(20);
      expect(config.connectionTimeoutMillis).toBe(15000);
      expect(config.idleTimeoutMillis).toBe(300000);
    });
  });
});
