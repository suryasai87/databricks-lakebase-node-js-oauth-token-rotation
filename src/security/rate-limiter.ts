import type { RateLimitResult } from '../types/security.types.js';

interface RateLimiterConfig {
  maxPerMinute: number;
}

interface TokenBucket {
  tokens: number;
  lastRefill: number;
}

export class RateLimiter {
  private maxPerMinute: number;
  private buckets = new Map<string, TokenBucket>();

  constructor(config: RateLimiterConfig) {
    this.maxPerMinute = config.maxPerMinute;
  }

  checkLimit(key: string): RateLimitResult {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: this.maxPerMinute, lastRefill: now };
      this.buckets.set(key, bucket);
    }

    // Refill tokens based on elapsed time
    const elapsedMs = now - bucket.lastRefill;
    const tokensToAdd = (elapsedMs / 60000) * this.maxPerMinute;
    bucket.tokens = Math.min(this.maxPerMinute, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now;

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
      };
    }

    // Calculate retry-after in ms
    const msPerToken = 60000 / this.maxPerMinute;
    const retryAfterMs = Math.ceil(msPerToken - (elapsedMs % msPerToken));

    return {
      allowed: false,
      remaining: 0,
      retryAfterMs,
    };
  }

  reset(key: string): void {
    this.buckets.delete(key);
  }

  resetAll(): void {
    this.buckets.clear();
  }
}
