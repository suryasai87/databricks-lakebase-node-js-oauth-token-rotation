import {
  parsePgPassLine,
  parsePgPassFile,
  formatPgPassEntry,
  matchesEntry,
} from '../../../src/pgpass/pgpass-parser';
import type { PgPassEntry } from '../../../src/types/pgpass.types';

describe('pgpass-parser', () => {
  describe('parsePgPassLine', () => {
    it('should parse a standard pgpass line with 5 fields', () => {
      const entry = parsePgPassLine('hostname:5432:mydb:user:password');

      expect(entry).not.toBeNull();
      expect(entry!.hostname).toBe('hostname');
      expect(entry!.port).toBe('5432');
      expect(entry!.database).toBe('mydb');
      expect(entry!.username).toBe('user');
      expect(entry!.password).toBe('password');
    });

    it('should return null for comment lines', () => {
      expect(parsePgPassLine('# this is a comment')).toBeNull();
      expect(parsePgPassLine('  # indented comment')).toBeNull();
    });

    it('should return null for empty lines', () => {
      expect(parsePgPassLine('')).toBeNull();
      expect(parsePgPassLine('   ')).toBeNull();
      expect(parsePgPassLine('\t')).toBeNull();
    });

    it('should handle escaped colons in fields', () => {
      const entry = parsePgPassLine('host\\:name:5432:my\\:db:user:pass');

      expect(entry).not.toBeNull();
      expect(entry!.hostname).toBe('host:name');
      expect(entry!.database).toBe('my:db');
    });

    it('should handle wildcard fields', () => {
      const entry = parsePgPassLine('*:*:*:user:password');

      expect(entry).not.toBeNull();
      expect(entry!.hostname).toBe('*');
      expect(entry!.port).toBe('*');
      expect(entry!.database).toBe('*');
    });

    it('should return null for lines with fewer than 5 fields', () => {
      expect(parsePgPassLine('host:5432:db')).toBeNull();
      expect(parsePgPassLine('onlyonefield')).toBeNull();
    });

    it('should include colons in the password field (everything after 4th colon)', () => {
      const entry = parsePgPassLine('host:5432:db:user:pass:with:colons');

      expect(entry).not.toBeNull();
      expect(entry!.password).toBe('pass:with:colons');
    });

    it('should handle backslash not followed by colon as literal', () => {
      const entry = parsePgPassLine('host:5432:db:user\\name:pass');

      expect(entry).not.toBeNull();
      expect(entry!.username).toBe('user\\name');
    });
  });

  describe('parsePgPassFile', () => {
    it('should parse multiple entries from file content', () => {
      const content = [
        '# Comment line',
        'host1:5432:db1:user1:pass1',
        'host2:5433:db2:user2:pass2',
        '',
        'host3:5434:db3:user3:pass3',
      ].join('\n');

      const { entries, lines } = parsePgPassFile(content);

      expect(entries).toHaveLength(3);
      expect(entries[0]!.hostname).toBe('host1');
      expect(entries[1]!.hostname).toBe('host2');
      expect(entries[2]!.hostname).toBe('host3');
      expect(lines).toHaveLength(5);
    });

    it('should return empty entries for a file with only comments', () => {
      const content = '# comment 1\n# comment 2\n';
      const { entries, lines } = parsePgPassFile(content);

      expect(entries).toHaveLength(0);
      expect(lines.length).toBeGreaterThan(0);
    });

    it('should return empty entries for an empty file', () => {
      const { entries } = parsePgPassFile('');
      expect(entries).toHaveLength(0);
    });
  });

  describe('formatPgPassEntry', () => {
    it('should format a simple entry without special characters', () => {
      const entry: PgPassEntry = {
        hostname: 'host',
        port: '5432',
        database: 'db',
        username: 'user',
        password: 'pass',
      };

      expect(formatPgPassEntry(entry)).toBe('host:5432:db:user:pass');
    });

    it('should escape colons in hostname, port, database, and username', () => {
      const entry: PgPassEntry = {
        hostname: 'host:name',
        port: '5432',
        database: 'my:db',
        username: 'user:name',
        password: 'pass',
      };

      const formatted = formatPgPassEntry(entry);
      expect(formatted).toBe('host\\:name:5432:my\\:db:user\\:name:pass');
    });

    it('should NOT escape colons in the password field', () => {
      const entry: PgPassEntry = {
        hostname: 'host',
        port: '5432',
        database: 'db',
        username: 'user',
        password: 'token:with:colons',
      };

      const formatted = formatPgPassEntry(entry);
      expect(formatted).toBe('host:5432:db:user:token:with:colons');
    });
  });

  describe('matchesEntry', () => {
    const baseEntry: PgPassEntry = {
      hostname: 'myhost',
      port: '5432',
      database: 'mydb',
      username: 'user',
      password: 'pass',
    };

    it('should match when all fields are equal', () => {
      expect(matchesEntry(baseEntry, 'myhost', '5432', 'mydb')).toBe(true);
    });

    it('should not match when hostname differs', () => {
      expect(matchesEntry(baseEntry, 'otherhost', '5432', 'mydb')).toBe(false);
    });

    it('should not match when port differs', () => {
      expect(matchesEntry(baseEntry, 'myhost', '5433', 'mydb')).toBe(false);
    });

    it('should not match when database differs', () => {
      expect(matchesEntry(baseEntry, 'myhost', '5432', 'otherdb')).toBe(false);
    });

    it('should match wildcard hostname against any hostname', () => {
      const wildcardEntry = { ...baseEntry, hostname: '*' };
      expect(matchesEntry(wildcardEntry, 'anyhost', '5432', 'mydb')).toBe(true);
    });

    it('should match wildcard port against any port', () => {
      const wildcardEntry = { ...baseEntry, port: '*' };
      expect(matchesEntry(wildcardEntry, 'myhost', '9999', 'mydb')).toBe(true);
    });

    it('should match wildcard database against any database', () => {
      const wildcardEntry = { ...baseEntry, database: '*' };
      expect(matchesEntry(wildcardEntry, 'myhost', '5432', 'anydb')).toBe(true);
    });

    it('should match all wildcards against anything', () => {
      const allWild: PgPassEntry = {
        hostname: '*',
        port: '*',
        database: '*',
        username: 'user',
        password: 'pass',
      };
      expect(matchesEntry(allWild, 'anyhost', '1234', 'anydb')).toBe(true);
    });
  });
});
