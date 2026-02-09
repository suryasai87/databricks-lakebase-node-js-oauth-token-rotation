import { TempDir } from '../helpers/temp-files';
import { createMockJwt } from '../helpers/mock-server';
import { updatePgPass } from '../../src/pgpass/pgpass-writer';
import { parsePgPassFile } from '../../src/pgpass/pgpass-parser';
import { checkPermissions } from '../../src/pgpass/file-permissions';
import { createLogger } from '../../src/logging/logger';
import { readFileSync, existsSync } from 'node:fs';

describe('PgPass Atomic Update (Integration)', () => {
  let tempDir: TempDir;

  beforeAll(() => {
    tempDir = new TempDir('pgpass-atomic-');
    createLogger(tempDir.filePath('test.log'));
  });

  afterAll(() => {
    tempDir.cleanup();
  });

  it('creates a new pgpass file atomically with correct permissions', () => {
    const pgpassPath = tempDir.filePath('.pgpass-new');
    expect(existsSync(pgpassPath)).toBe(false);

    const result = updatePgPass(pgpassPath, {
      hostname: 'test.database.cloud.databricks.com',
      port: '5432',
      database: 'databricks_postgres',
      username: 'test@databricks.com',
      password: createMockJwt(),
    });

    expect(result.success).toBe(true);
    expect(result.action).toBe('created');
    expect(existsSync(pgpassPath)).toBe(true);

    const perms = checkPermissions(pgpassPath);
    expect(perms.correct).toBe(true);
  });

  it('temp file does not remain after successful write', () => {
    const pgpassPath = tempDir.filePath('.pgpass-no-tmp');
    const tempPath = `${pgpassPath}.tmp`;

    updatePgPass(pgpassPath, {
      hostname: 'test.database.cloud.databricks.com',
      port: '5432',
      database: 'databricks_postgres',
      username: 'test@databricks.com',
      password: 'token123',
    });

    expect(existsSync(tempPath)).toBe(false);
    expect(existsSync(pgpassPath)).toBe(true);
  });

  it('handles concurrent updates to different entries safely', () => {
    const pgpassPath = tempDir.filePath('.pgpass-concurrent');

    // Write multiple entries sequentially (simulating concurrent rotations)
    for (let i = 0; i < 5; i++) {
      updatePgPass(pgpassPath, {
        hostname: `host-${i}.database.cloud.databricks.com`,
        port: '5432',
        database: 'databricks_postgres',
        username: `user-${i}@databricks.com`,
        password: `token-${i}`,
      });
    }

    const content = readFileSync(pgpassPath, 'utf-8');
    const { entries } = parsePgPassFile(content);

    expect(entries).toHaveLength(5);
    for (let i = 0; i < 5; i++) {
      expect(entries[i]!.hostname).toBe(
        `host-${i}.database.cloud.databricks.com`,
      );
    }
  });

  it('updates only the matching entry and preserves others', () => {
    const pgpassPath = tempDir.filePath('.pgpass-selective');
    const targetHost = 'target.database.cloud.databricks.com';

    // Create initial entries
    updatePgPass(pgpassPath, {
      hostname: 'other.database.cloud.databricks.com',
      port: '5432',
      database: 'databricks_postgres',
      username: 'other@databricks.com',
      password: 'other-token',
    });

    updatePgPass(pgpassPath, {
      hostname: targetHost,
      port: '5432',
      database: 'databricks_postgres',
      username: 'target@databricks.com',
      password: 'old-token',
    });

    // Update only the target entry
    const newToken = createMockJwt();
    updatePgPass(pgpassPath, {
      hostname: targetHost,
      port: '5432',
      database: 'databricks_postgres',
      username: 'target@databricks.com',
      password: newToken,
    });

    const content = readFileSync(pgpassPath, 'utf-8');
    const { entries } = parsePgPassFile(content);

    expect(entries).toHaveLength(2);
    expect(entries[0]!.hostname).toBe('other.database.cloud.databricks.com');
    expect(entries[0]!.password).toBe('other-token');
    expect(entries[1]!.hostname).toBe(targetHost);
    expect(entries[1]!.password).toBe(newToken);
  });

  it('maintains correct permissions after multiple updates', () => {
    const pgpassPath = tempDir.filePath('.pgpass-perms');

    for (let i = 0; i < 3; i++) {
      updatePgPass(pgpassPath, {
        hostname: 'perms.database.cloud.databricks.com',
        port: '5432',
        database: 'databricks_postgres',
        username: 'user@databricks.com',
        password: `token-round-${i}`,
      });

      const perms = checkPermissions(pgpassPath);
      expect(perms.correct).toBe(true);
      expect(perms.currentMode).toBe('0600');
    }
  });
});
