import { InputValidator } from '../../src/security/input-validator';
import {
  PATH_TRAVERSAL_PAYLOADS,
  UNICODE_ATTACK_PAYLOADS,
  HOSTNAME_ATTACK_PAYLOADS,
} from '../helpers/security-payloads';

describe('Input Fuzzing', () => {
  let validator: InputValidator;

  beforeEach(() => {
    validator = new InputValidator();
  });

  describe('path traversal attacks on file paths', () => {
    it('should reject path traversal payloads containing literal dot-dot or null bytes', () => {
      // The filePathSchema rejects paths containing literal '..' (unless
      // starting with ~) and paths containing null bytes.
      // URL-encoded variants like %2e%2e are not decoded by the schema
      // and thus not caught at this layer. Absolute paths like /etc/shadow
      // are syntactically valid paths.
      const literalDotDotOrNull = PATH_TRAVERSAL_PAYLOADS.filter(
        (p) => p.includes('..') || p.includes('\x00'),
      );
      expect(literalDotDotOrNull.length).toBeGreaterThan(0);

      for (const payload of literalDotDotOrNull) {
        expect(() => {
          validator.validateFilePath(payload);
        }).toThrow();
      }
    });

    it('should reject paths with null bytes', () => {
      expect(() => validator.validateFilePath('\x00/etc/passwd')).toThrow();
    });

    it('should accept valid file paths', () => {
      const validPaths = [
        '/home/user/.pgpass',
        '/etc/ssl/certs/ca.pem',
        '~/.pgpass',
        '/tmp/rotator.log',
        '/var/log/app.log',
      ];

      for (const path of validPaths) {
        expect(() => validator.validateFilePath(path)).not.toThrow();
      }
    });
  });

  describe('unicode attack payloads on hostnames', () => {
    it('should reject UNICODE_ATTACK_PAYLOADS with control characters', () => {
      // Filter to payloads that contain control characters or are otherwise
      // invalid hostnames (null bytes, SOH, backspace, DEL, RTL override, BOM, surrogates, long strings)
      for (const payload of UNICODE_ATTACK_PAYLOADS) {
        expect(() => {
          validator.validateHostname(payload);
        }).toThrow();
      }
    });
  });

  describe('hostname attack payloads', () => {
    it('should reject hostile hostname payloads with invalid characters or format', () => {
      // Some payloads like 'localhost' and '127.0.0.1' are syntactically valid
      // hostnames per DNS rules. The validator enforces format, not semantic safety.
      // Filter to payloads that contain invalid hostname characters or format.
      const invalidHostnames = HOSTNAME_ATTACK_PAYLOADS.filter(
        (p) =>
          p.includes('/') ||
          p.includes(' ') ||
          p.includes('<') ||
          p.includes('>') ||
          p.includes(';') ||
          p.includes('%') ||
          p.includes('://') ||
          p.startsWith('-') ||
          p.startsWith('::') ||
          p.length > 253,
      );
      expect(invalidHostnames.length).toBeGreaterThan(5);

      for (const payload of invalidHostnames) {
        expect(() => {
          validator.validateHostname(payload);
        }).toThrow();
      }
    });

    it('should reject hostnames with special shell characters', () => {
      expect(() => validator.validateHostname('host;rm -rf /.com')).toThrow();
      expect(() => validator.validateHostname('host<script>alert(1)</script>.com')).toThrow();
    });

    it('should reject excessively long hostnames', () => {
      expect(() => validator.validateHostname('a'.repeat(300))).toThrow();
    });
  });

  describe('empty string validation', () => {
    it('should reject empty hostname', () => {
      expect(() => validator.validateHostname('')).toThrow();
    });

    it('should reject empty database name', () => {
      expect(() => validator.validateDatabaseName('')).toThrow();
    });

    it('should reject empty file path', () => {
      expect(() => validator.validateFilePath('')).toThrow();
    });

    it('should reject empty username', () => {
      expect(() => validator.validateUsername('')).toThrow();
    });

    it('should reject empty workspace URL', () => {
      expect(() => validator.validateWorkspaceUrl('')).toThrow();
    });
  });

  describe('extremely long string validation', () => {
    it('should reject hostname longer than 253 characters', () => {
      const longHostname = 'a'.repeat(254);
      expect(() => validator.validateHostname(longHostname)).toThrow();
    });

    it('should reject database name longer than 63 characters', () => {
      const longDbName = 'a'.repeat(64);
      expect(() => validator.validateDatabaseName(longDbName)).toThrow();
    });

    it('should reject username longer than 256 characters', () => {
      const longUsername = 'a'.repeat(257) + '@example.com';
      expect(() => validator.validateUsername(longUsername)).toThrow();
    });
  });

  describe('valid input acceptance', () => {
    it('should accept proper hostnames', () => {
      const validHostnames = [
        'my-host.databricks.com',
        'db-server-01.example.com',
        'prod-lakebase.cloud.databricks.com',
        'a.b.c',
        'host123',
      ];

      for (const hostname of validHostnames) {
        expect(validator.validateHostname(hostname)).toBe(hostname);
      }
    });

    it('should accept valid ports', () => {
      const validPorts = [1, 80, 443, 5432, 8080, 65535];

      for (const port of validPorts) {
        expect(validator.validatePort(port)).toBe(port);
      }
    });

    it('should reject invalid ports', () => {
      expect(() => validator.validatePort(0)).toThrow();
      expect(() => validator.validatePort(-1)).toThrow();
      expect(() => validator.validatePort(65536)).toThrow();
      expect(() => validator.validatePort(1.5)).toThrow();
    });

    it('should accept valid email usernames', () => {
      const validEmails = [
        'user@example.com',
        'admin@databricks.com',
        'service+principal@domain.co.uk',
      ];

      for (const email of validEmails) {
        expect(validator.validateUsername(email)).toBe(email);
      }
    });

    it('should accept valid UUID usernames (service principals)', () => {
      const validUuids = [
        '12345678-1234-1234-1234-123456789012',
        'abcdef01-2345-6789-abcd-ef0123456789',
        'ABCDEF01-2345-6789-ABCD-EF0123456789',
      ];

      for (const uuid of validUuids) {
        expect(validator.validateUsername(uuid)).toBe(uuid);
      }
    });

    it('should accept valid database names', () => {
      const validNames = [
        'mydb',
        'databricks_postgres',
        '_internal_db',
        'DB_123',
      ];

      for (const name of validNames) {
        expect(validator.validateDatabaseName(name)).toBe(name);
      }
    });

    it('should accept valid workspace URLs', () => {
      // Note: workspaceUrlSchema transforms by stripping trailing slashes
      const result = validator.validateWorkspaceUrl('https://my-workspace.databricks.com');
      expect(result).toBe('https://my-workspace.databricks.com');
    });
  });

  describe('dangerous character detection', () => {
    it('should reject null bytes in database names', () => {
      expect(() => validator.validateDatabaseName('test\x00db')).toThrow();
    });

    it('should reject control characters in database names', () => {
      expect(() => validator.validateDatabaseName('test\x01db')).toThrow();
      expect(() => validator.validateDatabaseName('test\x08db')).toThrow();
    });

    it('should reject null bytes in usernames', () => {
      expect(() => validator.validateUsername('user\x00@example.com')).toThrow();
    });
  });
});
