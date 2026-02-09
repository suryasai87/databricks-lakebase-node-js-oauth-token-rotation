import { writeFileSync } from 'node:fs';
import { updatePgPass } from '../../../src/pgpass/pgpass-writer';
import { TempDir } from '../../helpers/temp-files';
import type { PgPassEntry } from '../../../src/types/pgpass.types';

// Silence logger output during tests
jest.mock('../../../src/logging/logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
}));

describe('pgpass-writer', () => {
  let tempDir: TempDir;

  const defaultEntry: PgPassEntry = {
    hostname: 'db.example.com',
    port: '5432',
    database: 'mydb',
    username: 'myuser',
    password: 'mytoken123',
  };

  beforeEach(() => {
    tempDir = new TempDir();
  });

  afterEach(() => {
    tempDir.cleanup();
  });

  it('should create a new pgpass file when none exists', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    const result = updatePgPass(pgpassPath, defaultEntry);

    expect(result.success).toBe(true);
    expect(result.action).toBe('created');
    expect(result.filePath).toBe(pgpassPath);

    const content = tempDir.readFile('pgpass');
    expect(content).toContain('db.example.com:5432:mydb:myuser:mytoken123');
  });

  it('should update an existing entry with matching host:port:database', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    writeFileSync(
      pgpassPath,
      'db.example.com:5432:mydb:myuser:oldtoken\n',
      { mode: 0o600 },
    );

    const result = updatePgPass(pgpassPath, {
      ...defaultEntry,
      password: 'newtoken',
    });

    expect(result.success).toBe(true);
    expect(result.action).toBe('updated');

    const content = tempDir.readFile('pgpass');
    expect(content).toContain('db.example.com:5432:mydb:myuser:newtoken');
    expect(content).not.toContain('oldtoken');
  });

  it('should append a new entry when no matching host:port:database exists', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    writeFileSync(
      pgpassPath,
      'other.host.com:5432:otherdb:user:token\n',
      { mode: 0o600 },
    );

    const result = updatePgPass(pgpassPath, defaultEntry);

    expect(result.success).toBe(true);
    expect(result.action).toBe('appended');

    const content = tempDir.readFile('pgpass');
    expect(content).toContain('other.host.com:5432:otherdb:user:token');
    expect(content).toContain('db.example.com:5432:mydb:myuser:mytoken123');
  });

  it('should preserve comments when updating', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    writeFileSync(
      pgpassPath,
      '# This is a comment\ndb.example.com:5432:mydb:myuser:oldtoken\n# Another comment\n',
      { mode: 0o600 },
    );

    const result = updatePgPass(pgpassPath, {
      ...defaultEntry,
      password: 'updated',
    });

    expect(result.success).toBe(true);
    expect(result.action).toBe('updated');

    const content = tempDir.readFile('pgpass');
    expect(content).toContain('# This is a comment');
    expect(content).toContain('# Another comment');
    expect(content).toContain('db.example.com:5432:mydb:myuser:updated');
  });

  it('should set file permissions to 0600 on the resulting file', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    updatePgPass(pgpassPath, defaultEntry);

    const mode = tempDir.fileMode('pgpass');
    expect(mode).toBe(0o600);
  });

  it('should perform atomic write using temp file and rename', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    const result = updatePgPass(pgpassPath, defaultEntry);

    expect(result.success).toBe(true);
    // The temp file (.tmp) should not remain
    expect(() => tempDir.readFile('pgpass.tmp')).toThrow();
  });

  it('should handle multiple entries in the file correctly', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    writeFileSync(
      pgpassPath,
      'host1:5432:db1:user1:pass1\nhost2:5432:db2:user2:pass2\ndb.example.com:5432:mydb:myuser:oldpass\n',
      { mode: 0o600 },
    );

    const result = updatePgPass(pgpassPath, {
      ...defaultEntry,
      password: 'newpass',
    });

    expect(result.success).toBe(true);
    expect(result.action).toBe('updated');

    const content = tempDir.readFile('pgpass');
    expect(content).toContain('host1:5432:db1:user1:pass1');
    expect(content).toContain('host2:5432:db2:user2:pass2');
    expect(content).toContain('db.example.com:5432:mydb:myuser:newpass');
    expect(content).not.toContain('oldpass');
  });

  it('should create parent directories if they do not exist', () => {
    const nestedPath = tempDir.filePath('nested/deep/pgpass');
    const result = updatePgPass(nestedPath, defaultEntry);

    expect(result.success).toBe(true);
    expect(result.action).toBe('created');
  });

  it('should handle password containing colons', () => {
    const pgpassPath = tempDir.filePath('pgpass');
    const result = updatePgPass(pgpassPath, {
      ...defaultEntry,
      password: 'token:with:colons:inside',
    });

    expect(result.success).toBe(true);
    const content = tempDir.readFile('pgpass');
    expect(content).toContain('token:with:colons:inside');
  });
});
