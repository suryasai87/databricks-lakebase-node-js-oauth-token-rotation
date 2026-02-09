import { SqlInjectionGuard } from '../../src/security/sql-injection-guard';
import { SQL_INJECTION_PAYLOADS } from '../helpers/security-payloads';

describe('SqlInjectionGuard', () => {
  let guard: SqlInjectionGuard;

  beforeEach(() => {
    guard = new SqlInjectionGuard();
  });

  describe('validateIdentifier()', () => {
    it('should reject all SQL injection payloads except benign LIKE wildcards', () => {
      expect(SQL_INJECTION_PAYLOADS.length).toBeGreaterThanOrEqual(40);

      // 'admin_' is a LIKE wildcard character but also a valid identifier
      // (alphanumeric + underscore). The identifier validator correctly
      // accepts it since it contains no SQL injection patterns.
      const identifierUnsafe = SQL_INJECTION_PAYLOADS.filter(
        (p) => p !== 'admin_',
      );

      for (const payload of identifierUnsafe) {
        expect(() => {
          guard.validateIdentifier(payload, 'test_field');
        }).toThrow();
      }
    });

    it('should accept admin_ as a valid identifier (LIKE wildcard is not SQL injection)', () => {
      // 'admin_' matches the valid identifier regex [a-zA-Z_][a-zA-Z0-9_.]*
      expect(guard.validateIdentifier('admin_', 'field')).toBe('admin_');
    });

    it('should accept valid alphanumeric identifiers', () => {
      const validIdentifiers = [
        'users',
        'my_table',
        'schema1',
        'UPPER_CASE',
        'camelCase',
        '_leading_underscore',
        'schema.table',
        'catalog.schema.table',
        'a',
        'table_123',
      ];

      for (const id of validIdentifiers) {
        expect(guard.validateIdentifier(id, 'field')).toBe(id);
      }
    });

    it('should reject identifiers with special characters', () => {
      const invalidIdentifiers = [
        'table name',    // space
        'table;name',    // semicolon
        "table'name",    // single quote
        'table"name',    // double quote
        'table--name',   // comment
        '123start',      // starts with number
        'table$name',    // dollar sign
        'table@name',    // at sign
        'table!name',    // exclamation
      ];

      for (const id of invalidIdentifiers) {
        expect(() => {
          guard.validateIdentifier(id, 'field');
        }).toThrow();
      }
    });

    it('should reject DROP TABLE patterns', () => {
      expect(() => guard.validateIdentifier('DROP TABLE users', 'field')).toThrow();
    });

    it('should reject UNION SELECT patterns', () => {
      expect(() => guard.validateIdentifier('UNION SELECT foo', 'field')).toThrow();
    });
  });

  describe('validateConnectionStringValue()', () => {
    it('should reject the majority of SQL injection payloads', () => {
      let rejected = 0;
      for (const payload of SQL_INJECTION_PAYLOADS) {
        try {
          guard.validateConnectionStringValue(payload, 'test_field');
        } catch {
          rejected++;
        }
      }

      // The vast majority of SQL injection payloads contain dangerous chars
      // (quotes, semicolons, backslashes) or match SQL injection patterns.
      // A few URL-encoded or LIKE-wildcard-only payloads may pass the
      // connection string check since they lack literal dangerous characters.
      const rejectionRate = rejected / SQL_INJECTION_PAYLOADS.length;
      expect(rejectionRate).toBeGreaterThan(0.9);
    });

    it('should reject payloads with SQL metacharacters', () => {
      const payloadsWithMetachars = SQL_INJECTION_PAYLOADS.filter((p) =>
        /[;'"\\`\x00]/.test(p),
      );
      expect(payloadsWithMetachars.length).toBeGreaterThan(30);

      for (const payload of payloadsWithMetachars) {
        expect(() => {
          guard.validateConnectionStringValue(payload, 'test_field');
        }).toThrow();
      }
    });

    it('should reject values with dangerous characters', () => {
      const dangerousValues = [
        "value'with'quotes",
        'value;with;semicolons',
        'value"with"doublequotes',
        'value\\with\\backslashes',
        'value`with`backticks',
        'value\x00with\x00nulls',
      ];

      for (const value of dangerousValues) {
        expect(() => {
          guard.validateConnectionStringValue(value, 'field');
        }).toThrow();
      }
    });

    it('should accept safe connection string values', () => {
      const safeValues = [
        'myhost.example.com',
        '5432',
        'my_database',
        'simple-value',
        'user@domain.com',
        'value123',
      ];

      for (const value of safeValues) {
        expect(guard.validateConnectionStringValue(value, 'field')).toBe(value);
      }
    });
  });

  describe('validateQuery()', () => {
    it('should reject template literal interpolation', () => {
      expect(() => {
        guard.validateQuery('SELECT * FROM users WHERE id = ${userId}');
      }).toThrow();
    });

    it('should reject string concatenation with single quotes', () => {
      expect(() => {
        guard.validateQuery("SELECT * FROM users WHERE name = ' + userName");
      }).toThrow();
    });

    it('should reject string concatenation with double quotes', () => {
      expect(() => {
        guard.validateQuery('SELECT * FROM users WHERE name = " + userName');
      }).toThrow();
    });

    it('should reject reverse concatenation with single quote', () => {
      expect(() => {
        guard.validateQuery("SELECT * FROM users WHERE name = value + ' something");
      }).toThrow();
    });

    it('should reject reverse concatenation with double quote', () => {
      expect(() => {
        guard.validateQuery('SELECT * FROM users WHERE name = value + " something');
      }).toThrow();
    });

    it('should accept clean parameterized queries with $1, $2 placeholders', () => {
      const safeQueries = [
        'SELECT * FROM users WHERE id = $1',
        'INSERT INTO events (name, date) VALUES ($1, $2)',
        'UPDATE users SET name = $1, email = $2 WHERE id = $3',
        'DELETE FROM sessions WHERE expires_at < $1',
        'SELECT COUNT(*) FROM users WHERE role = $1 AND active = $2',
      ];

      for (const query of safeQueries) {
        expect(guard.validateQuery(query)).toBe(query);
      }
    });

    it('should accept plain static queries without parameters', () => {
      const staticQueries = [
        'SELECT 1',
        'SELECT NOW()',
        'SELECT * FROM pg_stat_activity',
      ];

      for (const query of staticQueries) {
        expect(guard.validateQuery(query)).toBe(query);
      }
    });
  });
});
