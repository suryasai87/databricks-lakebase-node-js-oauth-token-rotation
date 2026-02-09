import { RotationScheduler } from '../../../src/daemon/rotation-scheduler';
import type { ValidatedConfig } from '../../../src/config/schema';

// Mock all dependencies to isolate the scheduler
jest.mock('../../../src/logging/logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
  expandPath: (p: string) => p.replace(/^~\//, '/tmp/test-home/'),
}));

jest.mock('../../../src/auth/index', () => ({
  createTokenProviders: jest.fn(() => []),
  acquireToken: jest.fn(() => Promise.resolve('mock-token-value')),
  decodeToken: jest.fn(() => ({
    subject: 'test-sp',
    scopes: ['all-apis'],
    expiresAt: new Date(Date.now() + 3600000).toISOString(),
    expiresInMinutes: 60,
    isExpired: false,
  })),
}));

jest.mock('../../../src/pgpass/index', () => ({
  updatePgPass: jest.fn(() => ({
    success: true,
    action: 'created',
    filePath: '/tmp/test-pgpass',
  })),
}));

jest.mock('../../../src/database/connection-tester', () => ({
  testConnection: jest.fn(() =>
    Promise.resolve({ success: true, latencyMs: 50 }),
  ),
}));

jest.mock('../../../src/logging/audit-logger', () => ({
  AuditLogger: jest.fn().mockImplementation(() => ({
    log: jest.fn(),
    verifyChain: jest.fn(() => true),
    getLastHash: jest.fn(() => '0'.repeat(64)),
  })),
}));

jest.mock('../../../src/security/token-vault', () => ({
  TokenVault: jest.fn().mockImplementation(() => ({
    store: jest.fn(),
    retrieve: jest.fn(() => 'mock-decrypted-token'),
    clear: jest.fn(),
    hasToken: jest.fn(() => true),
  })),
}));

jest.mock('../../../src/daemon/signal-handler', () => ({
  SignalHandler: jest.fn().mockImplementation(() => ({
    onCleanup: jest.fn(),
    install: jest.fn(),
    isAborted: jest.fn(() => false),
    getAbortSignal: jest.fn(() => new AbortController().signal),
  })),
}));

function createTestConfig(overrides?: Partial<ValidatedConfig>): ValidatedConfig {
  return {
    workspaceUrl: 'https://test.databricks.com',
    pgHost: 'db.example.com',
    pgPort: 5432,
    pgDatabase: 'test_db',
    pgUsername: 'testuser',
    pgpassFile: '/tmp/test-pgpass',
    logFile: '/tmp/test.log',
    rotationIntervalMinutes: 50,
    testConnection: false,
    tls: {
      enforce: true,
      rejectUnauthorized: true,
      certPinning: { enabled: false },
    },
    security: {
      encryptTokensInMemory: true,
      rateLimitPerMinute: 60,
      maxConnectionPoolSize: 10,
      auditLogEnabled: true,
    },
    ...overrides,
  } as ValidatedConfig;
}

describe('RotationScheduler', () => {
  beforeEach(() => {
    jest.useFakeTimers();
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.useRealTimers();
  });

  it('should create an instance without errors', () => {
    const scheduler = new RotationScheduler(createTestConfig());
    expect(scheduler).toBeDefined();
  });

  it('should perform initial rotation on start', async () => {
    const { acquireToken } = require('../../../src/auth/index');
    const scheduler = new RotationScheduler(createTestConfig());

    await scheduler.start();
    scheduler.stop();

    expect(acquireToken).toHaveBeenCalledTimes(1);
  });

  it('should update status after successful rotation', async () => {
    const scheduler = new RotationScheduler(createTestConfig());

    await scheduler.start();
    scheduler.stop();

    const status = scheduler.getStatus();
    expect(status.lastRotation).toBeInstanceOf(Date);
    expect(status.hasToken).toBe(true);
    expect(status.tokenExpiresAt).toBeDefined();
  });

  it('should schedule next rotation after initial rotation', async () => {
    const config = createTestConfig({ rotationIntervalMinutes: 10 });
    const scheduler = new RotationScheduler(config);

    await scheduler.start();

    const status = scheduler.getStatus();
    expect(status.nextRotation).toBeInstanceOf(Date);
    // Next rotation should be approximately 10 minutes in the future
    const diffMs = status.nextRotation!.getTime() - Date.now();
    expect(diffMs).toBeGreaterThan(9 * 60 * 1000);
    expect(diffMs).toBeLessThanOrEqual(10 * 60 * 1000);

    scheduler.stop();
  });

  it('should stop the timer when stop() is called', async () => {
    const scheduler = new RotationScheduler(createTestConfig());

    await scheduler.start();
    scheduler.stop();

    // Advancing time should not trigger another rotation
    const { acquireToken } = require('../../../src/auth/index');
    acquireToken.mockClear();

    jest.advanceTimersByTime(60 * 60 * 1000); // 1 hour

    expect(acquireToken).not.toHaveBeenCalled();
  });

  it('should handle token acquisition failure gracefully', async () => {
    const { acquireToken } = require('../../../src/auth/index');
    acquireToken.mockResolvedValueOnce(null);

    const scheduler = new RotationScheduler(createTestConfig());

    await scheduler.start();
    scheduler.stop();

    const status = scheduler.getStatus();
    // lastRotation should be null because rotation failed
    expect(status.lastRotation).toBeNull();
  });

  it('should run single rotation with startOnce', async () => {
    const { acquireToken } = require('../../../src/auth/index');
    const scheduler = new RotationScheduler(createTestConfig());

    const result = await scheduler.startOnce();

    expect(result).toBe(true);
    expect(acquireToken).toHaveBeenCalledTimes(1);
  });

  it('should return initial status before any rotation', () => {
    const scheduler = new RotationScheduler(createTestConfig());
    const status = scheduler.getStatus();

    expect(status.lastRotation).toBeNull();
    expect(status.nextRotation).toBeNull();
    expect(status.tokenExpiresAt).toBeNull();
  });
});
