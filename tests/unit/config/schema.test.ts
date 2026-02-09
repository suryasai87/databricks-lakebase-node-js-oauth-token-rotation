import {
  configSchema,
  hostnameSchema,
  portSchema,
  databaseNameSchema,
  workspaceUrlSchema,
} from '../../../src/config/schema';

describe('config schema validation', () => {
  describe('hostnameSchema', () => {
    it('should accept a valid hostname', () => {
      expect(hostnameSchema.parse('db.example.com')).toBe('db.example.com');
    });

    it('should accept a simple single-label hostname', () => {
      expect(hostnameSchema.parse('localhost')).toBe('localhost');
    });

    it('should reject an empty hostname', () => {
      expect(() => hostnameSchema.parse('')).toThrow();
    });

    it('should reject a hostname starting with a hyphen', () => {
      expect(() => hostnameSchema.parse('-invalid.com')).toThrow();
    });

    it('should reject a hostname longer than 253 characters', () => {
      const longHostname = 'a'.repeat(254);
      expect(() => hostnameSchema.parse(longHostname)).toThrow();
    });
  });

  describe('portSchema', () => {
    it('should accept port 5432', () => {
      expect(portSchema.parse(5432)).toBe(5432);
    });

    it('should accept port 1 (minimum)', () => {
      expect(portSchema.parse(1)).toBe(1);
    });

    it('should accept port 65535 (maximum)', () => {
      expect(portSchema.parse(65535)).toBe(65535);
    });

    it('should reject port 0', () => {
      expect(() => portSchema.parse(0)).toThrow();
    });

    it('should reject port 65536', () => {
      expect(() => portSchema.parse(65536)).toThrow();
    });

    it('should reject a non-integer port', () => {
      expect(() => portSchema.parse(5432.5)).toThrow();
    });
  });

  describe('databaseNameSchema', () => {
    it('should accept a valid database name', () => {
      expect(databaseNameSchema.parse('my_database')).toBe('my_database');
    });

    it('should accept a name starting with underscore', () => {
      expect(databaseNameSchema.parse('_private')).toBe('_private');
    });

    it('should reject a name starting with a digit', () => {
      expect(() => databaseNameSchema.parse('123db')).toThrow();
    });

    it('should reject a name with special characters', () => {
      expect(() => databaseNameSchema.parse('my-database')).toThrow();
      expect(() => databaseNameSchema.parse('my database')).toThrow();
    });

    it('should reject an empty database name', () => {
      expect(() => databaseNameSchema.parse('')).toThrow();
    });

    it('should reject a name longer than 63 characters', () => {
      const longName = 'a'.repeat(64);
      expect(() => databaseNameSchema.parse(longName)).toThrow();
    });
  });

  describe('workspaceUrlSchema', () => {
    it('should accept a valid HTTPS workspace URL', () => {
      const result = workspaceUrlSchema.parse('https://my-workspace.databricks.com');
      expect(result).toBe('https://my-workspace.databricks.com');
    });

    it('should strip trailing slashes', () => {
      const result = workspaceUrlSchema.parse('https://workspace.databricks.com///');
      expect(result).toBe('https://workspace.databricks.com');
    });

    it('should reject an HTTP URL', () => {
      expect(() =>
        workspaceUrlSchema.parse('http://workspace.databricks.com'),
      ).toThrow();
    });

    it('should reject a non-URL string', () => {
      expect(() => workspaceUrlSchema.parse('not-a-url')).toThrow();
    });
  });

  describe('configSchema (full config)', () => {
    const validConfig = {
      workspaceUrl: 'https://workspace.databricks.com',
      pgHost: 'db.example.com',
      pgUsername: 'admin',
    };

    it('should accept a minimal valid config with defaults applied', () => {
      const result = configSchema.parse(validConfig);

      expect(result.workspaceUrl).toBe('https://workspace.databricks.com');
      expect(result.pgHost).toBe('db.example.com');
      expect(result.pgPort).toBe(5432);
      expect(result.pgDatabase).toBe('databricks_postgres');
      expect(result.pgUsername).toBe('admin');
      expect(result.pgpassFile).toBe('~/.pgpass');
      expect(result.rotationIntervalMinutes).toBe(50);
      expect(result.testConnection).toBe(false);
    });

    it('should accept a full valid config with all optional fields', () => {
      const fullConfig = {
        ...validConfig,
        clientId: '12345678-1234-1234-1234-123456789012',
        clientSecret: 'my-secret',
        pgPort: 5433,
        pgDatabase: 'custom_db',
        rotationIntervalMinutes: 30,
        testConnection: true,
        healthCheckPort: 8080,
      };

      const result = configSchema.parse(fullConfig);
      expect(result.clientId).toBe('12345678-1234-1234-1234-123456789012');
      expect(result.pgPort).toBe(5433);
      expect(result.rotationIntervalMinutes).toBe(30);
      expect(result.healthCheckPort).toBe(8080);
    });

    it('should reject a config missing required workspaceUrl', () => {
      expect(() =>
        configSchema.parse({ pgHost: 'host', pgUsername: 'user' }),
      ).toThrow();
    });

    it('should reject a config missing required pgHost', () => {
      expect(() =>
        configSchema.parse({
          workspaceUrl: 'https://ws.databricks.com',
          pgUsername: 'user',
        }),
      ).toThrow();
    });

    it('should reject a config missing required pgUsername', () => {
      expect(() =>
        configSchema.parse({
          workspaceUrl: 'https://ws.databricks.com',
          pgHost: 'host',
        }),
      ).toThrow();
    });

    it('should reject an invalid clientId (not a UUID)', () => {
      expect(() =>
        configSchema.parse({
          ...validConfig,
          clientId: 'not-a-uuid',
        }),
      ).toThrow();
    });

    it('should reject rotationIntervalMinutes outside 1-59 range', () => {
      expect(() =>
        configSchema.parse({
          ...validConfig,
          rotationIntervalMinutes: 0,
        }),
      ).toThrow();

      expect(() =>
        configSchema.parse({
          ...validConfig,
          rotationIntervalMinutes: 60,
        }),
      ).toThrow();
    });

    it('should apply security defaults', () => {
      const result = configSchema.parse(validConfig);
      expect(result.security.encryptTokensInMemory).toBe(true);
      expect(result.security.rateLimitPerMinute).toBe(60);
      expect(result.security.maxConnectionPoolSize).toBe(10);
      expect(result.security.auditLogEnabled).toBe(true);
    });

    it('should apply TLS defaults', () => {
      const result = configSchema.parse(validConfig);
      expect(result.tls.enforce).toBe(true);
      expect(result.tls.rejectUnauthorized).toBe(true);
    });
  });
});
