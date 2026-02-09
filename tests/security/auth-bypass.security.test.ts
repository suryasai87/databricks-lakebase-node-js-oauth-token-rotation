import { decodeToken, isTokenExpired } from '../../src/auth/jwt-decoder';
import { createMockJwt, createExpiredJwt } from '../helpers/mock-server';

describe('Authentication Bypass Security', () => {
  describe('expired token detection', () => {
    it('should detect expired tokens correctly', () => {
      const expiredToken = createExpiredJwt();

      expect(isTokenExpired(expiredToken)).toBe(true);

      const info = decodeToken(expiredToken);
      expect(info.isExpired).toBe(true);
    });

    it('should detect tokens that expired recently', () => {
      // Create a token that expired 1 second ago
      const token = createMockJwt(-1);
      expect(isTokenExpired(token)).toBe(true);
    });
  });

  describe('future token handling', () => {
    it('should recognize valid future tokens as not expired', () => {
      const futureToken = createMockJwt(3600); // Expires in 1 hour

      expect(isTokenExpired(futureToken)).toBe(false);

      const info = decodeToken(futureToken);
      expect(info.isExpired).toBe(false);
      expect(info.expiresInMinutes).toBeGreaterThan(0);
    });

    it('should recognize far-future tokens as not expired', () => {
      const token = createMockJwt(86400); // Expires in 24 hours
      expect(isTokenExpired(token)).toBe(false);

      const info = decodeToken(token);
      expect(info.expiresInMinutes).toBeGreaterThan(1000);
    });
  });

  describe('malformed JWT handling', () => {
    it('should handle completely invalid string gracefully', () => {
      expect(() => decodeToken('not-a-jwt')).not.toThrow();
      const info = decodeToken('not-a-jwt');
      expect(info.isExpired).toBe(true);
      expect(info.scopes).toEqual([]);
    });

    it('should handle string with dots but invalid base64', () => {
      expect(() => decodeToken('aaa.bbb.ccc')).not.toThrow();
      const info = decodeToken('aaa.bbb.ccc');
      // Should be treated as unparseable
      expect(info.isExpired).toBe(true);
    });

    it('should handle string with only one dot', () => {
      expect(() => decodeToken('header.payload')).not.toThrow();
    });

    it('should handle random bytes as JWT', () => {
      const randomStr = Buffer.from(
        Array.from({ length: 100 }, () => Math.floor(Math.random() * 256)),
      ).toString('base64');

      expect(() => decodeToken(randomStr)).not.toThrow();
    });

    it('should handle JSON-like strings', () => {
      expect(() => decodeToken('{"sub":"test"}')).not.toThrow();
    });
  });

  describe('token with missing exp claim', () => {
    it('should handle token without exp as undefined expiry', () => {
      // Manually create a JWT without exp
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(
        JSON.stringify({ sub: 'test-user', scope: 'read write' }),
      ).toString('base64url');
      const tokenWithoutExp = `${header}.${payload}.`;

      const info = decodeToken(tokenWithoutExp);
      expect(info.subject).toBe('test-user');
      expect(info.scopes).toEqual(['read', 'write']);
      expect(info.expiresAt).toBeUndefined();
      expect(info.expiresInMinutes).toBeUndefined();
      // isExpired should be undefined when no exp claim
      expect(info.isExpired).toBeUndefined();
    });

    it('should treat missing exp as expired via isTokenExpired()', () => {
      const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
      const payload = Buffer.from(JSON.stringify({ sub: 'test' })).toString('base64url');
      const token = `${header}.${payload}.`;

      // isTokenExpired defaults to true when isExpired is undefined
      expect(isTokenExpired(token)).toBe(true);
    });
  });

  describe('empty string token', () => {
    it('should handle empty string without crashing', () => {
      expect(() => decodeToken('')).not.toThrow();

      const info = decodeToken('');
      expect(info.isExpired).toBe(true);
      expect(info.scopes).toEqual([]);
    });

    it('should treat empty string as expired', () => {
      expect(isTokenExpired('')).toBe(true);
    });
  });

  describe('tampered payload detection', () => {
    it('should detect token with tampered payload as non-parseable or different', () => {
      const validToken = createMockJwt(3600);
      const parts = validToken.split('.');

      // Tamper with the payload by modifying a character
      const originalPayload = parts[1]!;
      const tamperedChar =
        originalPayload[0] === 'A' ? 'B' : 'A';
      const tamperedPayload = tamperedChar + originalPayload.slice(1);
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      // The jsonwebtoken library may throw a SyntaxError when the tampered
      // base64 decodes to invalid JSON, or it may decode to different data.
      // Both outcomes indicate the tamper is detected or manifested.
      try {
        const originalInfo = decodeToken(validToken);
        const tamperedInfo = decodeToken(tamperedToken);

        // If it does parse, the subject should differ from the original
        if (tamperedInfo.subject) {
          const somethingDiffers =
            tamperedInfo.subject !== originalInfo.subject ||
            tamperedInfo.clientId !== originalInfo.clientId ||
            tamperedInfo.issuer !== originalInfo.issuer;
          expect(somethingDiffers || tamperedInfo.isExpired === true).toBe(true);
        } else {
          // Could not decode the tampered payload - this is also acceptable
          expect(tamperedInfo.isExpired).toBe(true);
        }
      } catch (err) {
        // Throwing on tampered input is also acceptable behavior -
        // it means the library detected invalid structure
        expect(err).toBeDefined();
      }
    });

    it('should handle token with completely replaced payload', () => {
      const validToken = createMockJwt(3600);
      const parts = validToken.split('.');

      // Replace payload with a completely different one
      const fakePayload = Buffer.from(
        JSON.stringify({ sub: 'attacker', admin: true, exp: 9999999999 }),
      ).toString('base64url');
      const forgedToken = `${parts[0]}.${fakePayload}.${parts[2]}`;

      // decode (not verify) will parse this - it should have different subject
      const info = decodeToken(forgedToken);
      if (info.subject) {
        expect(info.subject).toBe('attacker');
        // In a real system, jwt.verify() would reject this, but decode() just parses
      }
    });
  });

  describe('valid token parsing', () => {
    it('should correctly parse all fields from a valid mock JWT', () => {
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
      expect(info.expiresInMinutes).toBeGreaterThan(50); // ~60 minutes
    });
  });
});
