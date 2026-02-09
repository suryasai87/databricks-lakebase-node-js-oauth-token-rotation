import { TlsEnforcer } from '../../src/security/tls-enforcer';
import type { TlsConfig } from '../../src/types/config.types';

function makeTlsConfig(overrides: Partial<TlsConfig> = {}): TlsConfig {
  return {
    enforce: true,
    rejectUnauthorized: true,
    certPinning: {
      enabled: false,
    },
    ...overrides,
  };
}

describe('TLS Enforcement', () => {
  describe('URL validation with TLS enforced', () => {
    it('should reject HTTP URLs when TLS is enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: true }));

      expect(() => enforcer.validateUrl('http://example.com')).toThrow(/TLS/i);
      expect(() => enforcer.validateUrl('http://localhost:5432')).toThrow(/TLS/i);
      expect(() => enforcer.validateUrl('http://my-host.databricks.com/api')).toThrow(/TLS/i);
    });

    it('should accept HTTPS URLs when TLS is enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: true }));

      expect(() => enforcer.validateUrl('https://example.com')).not.toThrow();
      expect(() => enforcer.validateUrl('https://my-host.databricks.com/api')).not.toThrow();
      expect(() => enforcer.validateUrl('https://localhost:8443')).not.toThrow();
    });

    it('should reject non-URL strings when TLS is enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: true }));

      expect(() => enforcer.validateUrl('ftp://example.com')).toThrow(/TLS/i);
      expect(() => enforcer.validateUrl('ws://example.com')).toThrow(/TLS/i);
      expect(() => enforcer.validateUrl('not-a-url')).toThrow(/TLS/i);
    });
  });

  describe('URL validation with TLS disabled', () => {
    it('should allow HTTP when TLS is not enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: false }));

      expect(() => enforcer.validateUrl('http://example.com')).not.toThrow();
      expect(() => enforcer.validateUrl('http://localhost:5432')).not.toThrow();
    });

    it('should also allow HTTPS when TLS is not enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: false }));

      expect(() => enforcer.validateUrl('https://example.com')).not.toThrow();
    });
  });

  describe('certificate pinning', () => {
    it('should accept matching fingerprint', () => {
      const fingerprint = 'AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89';
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: true,
            fingerprints: [fingerprint],
          },
        }),
      );

      expect(enforcer.validateCertFingerprint(fingerprint)).toBe(true);
    });

    it('should accept matching fingerprint with different case', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: true,
            fingerprints: ['ab:cd:ef:01:23:45:67:89'],
          },
        }),
      );

      expect(enforcer.validateCertFingerprint('AB:CD:EF:01:23:45:67:89')).toBe(true);
    });

    it('should accept matching fingerprint without colons', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: true,
            fingerprints: ['ABCDEF0123456789'],
          },
        }),
      );

      expect(enforcer.validateCertFingerprint('AB:CD:EF:01:23:45:67:89')).toBe(true);
    });

    it('should reject non-matching fingerprint', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: true,
            fingerprints: ['AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99'],
          },
        }),
      );

      expect(
        enforcer.validateCertFingerprint('11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00'),
      ).toBe(false);
    });

    it('should accept any fingerprint when pinning is disabled', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: false,
          },
        }),
      );

      expect(enforcer.validateCertFingerprint('anything')).toBe(true);
    });

    it('should accept any fingerprint when pinning enabled but no fingerprints configured', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: true,
            fingerprints: [],
          },
        }),
      );

      expect(enforcer.validateCertFingerprint('anything')).toBe(true);
    });

    it('should support multiple pinned fingerprints', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({
          certPinning: {
            enabled: true,
            fingerprints: [
              'AA:BB:CC:DD',
              'EE:FF:00:11',
              '22:33:44:55',
            ],
          },
        }),
      );

      expect(enforcer.validateCertFingerprint('EE:FF:00:11')).toBe(true);
      expect(enforcer.validateCertFingerprint('99:88:77:66')).toBe(false);
    });
  });

  describe('getPgSslConfig()', () => {
    it('should return TLS config with minVersion TLSv1.2 when enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: true }));
      const sslConfig = enforcer.getPgSslConfig();

      expect(sslConfig).not.toBe(false);
      if (sslConfig !== false) {
        expect(sslConfig.minVersion).toBe('TLSv1.2');
        expect(sslConfig.rejectUnauthorized).toBe(true);
      }
    });

    it('should return false when TLS is not enforced', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: false }));
      const sslConfig = enforcer.getPgSslConfig();

      expect(sslConfig).toBe(false);
    });

    it('should respect rejectUnauthorized setting', () => {
      const enforcer = new TlsEnforcer(
        makeTlsConfig({ enforce: true, rejectUnauthorized: false }),
      );
      const sslConfig = enforcer.getPgSslConfig();

      expect(sslConfig).not.toBe(false);
      if (sslConfig !== false) {
        expect(sslConfig.rejectUnauthorized).toBe(false);
      }
    });
  });

  describe('isEnforced()', () => {
    it('should return true when enforce is true', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: true }));
      expect(enforcer.isEnforced()).toBe(true);
    });

    it('should return false when enforce is false', () => {
      const enforcer = new TlsEnforcer(makeTlsConfig({ enforce: false }));
      expect(enforcer.isEnforced()).toBe(false);
    });
  });
});
