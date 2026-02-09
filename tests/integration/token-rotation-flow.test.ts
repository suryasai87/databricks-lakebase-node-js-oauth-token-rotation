import { MockOAuthServer, createMockJwt } from '../helpers/mock-server';
import { TempDir } from '../helpers/temp-files';
import { OAuthM2MProvider } from '../../src/auth/oauth-m2m.provider';
import { decodeToken } from '../../src/auth/jwt-decoder';
import { TokenVault } from '../../src/security/token-vault';
import { updatePgPass } from '../../src/pgpass/pgpass-writer';
import { parsePgPassFile } from '../../src/pgpass/pgpass-parser';
import { checkPermissions } from '../../src/pgpass/file-permissions';
import { createLogger } from '../../src/logging/logger';
import { readFileSync } from 'node:fs';

describe('Token Rotation Flow (Integration)', () => {
  let mockServer: MockOAuthServer;
  let serverPort: number;
  let tempDir: TempDir;

  beforeAll(async () => {
    tempDir = new TempDir('rotation-flow-');
    createLogger(tempDir.filePath('test.log'));
    mockServer = new MockOAuthServer({ tokenExpiresInSeconds: 3600 });
    serverPort = await mockServer.start();
  });

  afterAll(async () => {
    await mockServer.stop();
    tempDir.cleanup();
  });

  it('completes a full rotation cycle: acquire → decode → encrypt → pgpass', async () => {
    // Step 1: Acquire token from mock OAuth server
    const provider = new OAuthM2MProvider(
      `http://127.0.0.1:${serverPort}`,
      '12345678-1234-1234-1234-123456789012',
      'test-secret',
    );

    const token = await provider.getToken();
    expect(token).not.toBeNull();
    expect(token).toMatch(/^eyJ/);

    // Step 2: Decode JWT and verify claims
    const tokenInfo = decodeToken(token!);
    expect(tokenInfo.subject).toBe('test-service-principal');
    expect(tokenInfo.isExpired).toBe(false);
    expect(tokenInfo.expiresInMinutes).toBeGreaterThan(50);
    expect(tokenInfo.scopes).toContain('all-apis');

    // Step 3: Store in encrypted vault
    const vault = new TokenVault(true);
    vault.store(token!);
    expect(vault.hasToken()).toBe(true);

    const retrieved = vault.retrieve();
    expect(retrieved).toBe(token);

    // Step 4: Update pgpass atomically
    const pgpassPath = tempDir.filePath('.pgpass');
    const result = updatePgPass(pgpassPath, {
      hostname: 'instance-test.database.cloud.databricks.com',
      port: '5432',
      database: 'databricks_postgres',
      username: 'test@databricks.com',
      password: retrieved!,
    });

    expect(result.success).toBe(true);
    expect(result.action).toBe('created');

    // Step 5: Verify pgpass content and permissions
    const content = readFileSync(pgpassPath, 'utf-8');
    const { entries } = parsePgPassFile(content);
    expect(entries).toHaveLength(1);
    expect(entries[0]!.hostname).toBe('instance-test.database.cloud.databricks.com');
    expect(entries[0]!.password).toBe(token);

    const perms = checkPermissions(pgpassPath);
    expect(perms.correct).toBe(true);
    expect(perms.currentMode).toBe('0600');

    // Cleanup
    vault.clear();
  });

  it('handles token rotation update (replace existing entry)', async () => {
    const pgpassPath = tempDir.filePath('.pgpass-update');
    const host = 'instance-update.database.cloud.databricks.com';

    // First rotation
    const token1 = createMockJwt(3600);
    updatePgPass(pgpassPath, {
      hostname: host,
      port: '5432',
      database: 'databricks_postgres',
      username: 'user@databricks.com',
      password: token1,
    });

    // Second rotation (should update, not append)
    const token2 = createMockJwt(3600);
    const result = updatePgPass(pgpassPath, {
      hostname: host,
      port: '5432',
      database: 'databricks_postgres',
      username: 'user@databricks.com',
      password: token2,
    });

    expect(result.success).toBe(true);
    expect(result.action).toBe('updated');

    const content = readFileSync(pgpassPath, 'utf-8');
    const { entries } = parsePgPassFile(content);

    // Should only have ONE entry (updated, not duplicated)
    const matchingEntries = entries.filter((e) => e.hostname === host);
    expect(matchingEntries).toHaveLength(1);
    expect(matchingEntries[0]!.password).toBe(token2);
  });

  it('handles server failure gracefully', async () => {
    mockServer.setFailureMode('server_error');

    const provider = new OAuthM2MProvider(
      `http://127.0.0.1:${serverPort}`,
      '12345678-1234-1234-1234-123456789012',
      'test-secret',
    );

    const token = await provider.getToken();
    expect(token).toBeNull();

    // Reset for other tests
    mockServer.setFailureMode('none');
  });

  it('handles unauthorized response gracefully', async () => {
    mockServer.setFailureMode('unauthorized');

    const provider = new OAuthM2MProvider(
      `http://127.0.0.1:${serverPort}`,
      'bad-client-id',
      'bad-secret',
    );

    const token = await provider.getToken();
    expect(token).toBeNull();

    mockServer.setFailureMode('none');
  });

  it('preserves existing pgpass entries for other hosts', async () => {
    const pgpassPath = tempDir.filePath('.pgpass-preserve');

    // First entry for host A
    updatePgPass(pgpassPath, {
      hostname: 'host-a.database.cloud.databricks.com',
      port: '5432',
      database: 'databricks_postgres',
      username: 'user-a@databricks.com',
      password: 'token-a',
    });

    // Second entry for host B
    updatePgPass(pgpassPath, {
      hostname: 'host-b.database.cloud.databricks.com',
      port: '5432',
      database: 'databricks_postgres',
      username: 'user-b@databricks.com',
      password: 'token-b',
    });

    const content = readFileSync(pgpassPath, 'utf-8');
    const { entries } = parsePgPassFile(content);

    expect(entries).toHaveLength(2);
    expect(entries[0]!.hostname).toBe('host-a.database.cloud.databricks.com');
    expect(entries[1]!.hostname).toBe('host-b.database.cloud.databricks.com');
  });
});
