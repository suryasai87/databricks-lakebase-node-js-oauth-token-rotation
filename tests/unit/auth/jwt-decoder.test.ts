import { decodeToken, isTokenExpired, getTokenExpiryMinutes } from '../../../src/auth/jwt-decoder';
import { createMockJwt, createExpiredJwt } from '../../helpers/mock-server';

describe('jwt-decoder', () => {
  describe('decodeToken', () => {
    it('should decode a valid JWT and return TokenInfo fields', () => {
      const token = createMockJwt(3600);
      const info = decodeToken(token);

      expect(info.subject).toBe('test-service-principal');
      expect(info.clientId).toBe('12345678-1234-1234-1234-123456789012');
      expect(info.scopes).toEqual(['all-apis']);
      expect(info.issuer).toBe('https://oidc.databricks.com');
      expect(info.audience).toBe('api');
      expect(info.isExpired).toBe(false);
      expect(info.expiresAt).toBeDefined();
      expect(info.issuedAt).toBeDefined();
    });

    it('should report an expired token as isExpired=true', () => {
      const token = createExpiredJwt();
      const info = decodeToken(token);

      expect(info.isExpired).toBe(true);
    });

    it('should return a positive expiresInMinutes for a valid token', () => {
      const token = createMockJwt(3600); // 1 hour from now
      const info = decodeToken(token);

      expect(info.expiresInMinutes).toBeDefined();
      expect(info.expiresInMinutes!).toBeGreaterThan(50); // roughly 60 minutes
      expect(info.expiresInMinutes!).toBeLessThanOrEqual(60);
    });

    it('should return a negative expiresInMinutes for an expired token', () => {
      const token = createExpiredJwt(); // expired 1 hour ago
      const info = decodeToken(token);

      expect(info.expiresInMinutes).toBeDefined();
      expect(info.expiresInMinutes!).toBeLessThan(0);
    });

    it('should return isExpired=true and empty scopes for a malformed token', () => {
      const info = decodeToken('not-a-valid-jwt');

      expect(info.isExpired).toBe(true);
      expect(info.scopes).toEqual([]);
      expect(info.subject).toBeUndefined();
      expect(info.clientId).toBeUndefined();
    });

    it('should return isExpired=true for an empty string token', () => {
      const info = decodeToken('');

      expect(info.isExpired).toBe(true);
      expect(info.scopes).toEqual([]);
    });

    it('should handle a token with no scope claim', () => {
      // Create a JWT with no scope by signing a custom payload
      const jwt = require('jsonwebtoken');
      const token = jwt.sign(
        { sub: 'user', exp: Math.floor(Date.now() / 1000) + 3600 },
        'secret',
      );
      const info = decodeToken(token);

      expect(info.scopes).toEqual([]);
      expect(info.subject).toBe('user');
      expect(info.isExpired).toBe(false);
    });

    it('should parse expiresAt as a valid ISO date string', () => {
      const token = createMockJwt(7200);
      const info = decodeToken(token);

      expect(info.expiresAt).toBeDefined();
      const date = new Date(info.expiresAt!);
      expect(date.getTime()).not.toBeNaN();
      expect(date.getTime()).toBeGreaterThan(Date.now());
    });
  });

  describe('isTokenExpired', () => {
    it('should return false for a valid non-expired token', () => {
      const token = createMockJwt(3600);
      expect(isTokenExpired(token)).toBe(false);
    });

    it('should return true for an expired token', () => {
      const token = createExpiredJwt();
      expect(isTokenExpired(token)).toBe(true);
    });

    it('should return true for a malformed token', () => {
      expect(isTokenExpired('garbage.token.value')).toBe(true);
    });
  });

  describe('getTokenExpiryMinutes', () => {
    it('should return remaining minutes for a valid token', () => {
      const token = createMockJwt(1800); // 30 minutes
      const minutes = getTokenExpiryMinutes(token);

      expect(minutes).toBeDefined();
      expect(minutes!).toBeGreaterThan(25);
      expect(minutes!).toBeLessThanOrEqual(30);
    });

    it('should return undefined for a malformed token', () => {
      const minutes = getTokenExpiryMinutes('not-a-jwt');
      expect(minutes).toBeUndefined();
    });
  });
});
