import { AuditLogger } from '../../../src/logging/audit-logger';
import { TempDir } from '../../helpers/temp-files';
import type { AuditLogEntry } from '../../../src/types/security.types';

// Mock expandPath from logger
jest.mock('../../../src/logging/logger', () => ({
  getLogger: () => ({
    info: jest.fn(),
    debug: jest.fn(),
    warn: jest.fn(),
    error: jest.fn(),
  }),
  expandPath: (p: string) => p.replace(/^~\//, '/tmp/test-home/'),
}));

describe('AuditLogger', () => {
  let tempDir: TempDir;

  beforeEach(() => {
    tempDir = new TempDir();
  });

  afterEach(() => {
    tempDir.cleanup();
  });

  it('should create an instance without errors', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);
    expect(logger).toBeDefined();
  });

  it('should return INITIAL_HASH (64 zeros) as initial lastHash', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);
    const hash = logger.getLastHash();

    expect(hash).toBe('0'.repeat(64));
  });

  it('should return a valid AuditLogEntry when logging', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    const entry = logger.log('TOKEN_OBTAINED', 'test detail');

    expect(entry.eventType).toBe('TOKEN_OBTAINED');
    expect(entry.details).toBe('test detail');
    expect(entry.prevHash).toBe('0'.repeat(64));
    expect(entry.entryHash).toHaveLength(64); // sha256 hex length
    expect(entry.timestamp).toBeDefined();
  });

  it('should chain hashes: each entry prevHash equals the prior entry entryHash', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    const entry1 = logger.log('SERVICE_START', 'started');
    const entry2 = logger.log('TOKEN_OBTAINED', 'got token');
    const entry3 = logger.log('PGPASS_UPDATED', 'file updated');

    expect(entry2.prevHash).toBe(entry1.entryHash);
    expect(entry3.prevHash).toBe(entry2.entryHash);
  });

  it('should update lastHash after each log call', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    expect(logger.getLastHash()).toBe('0'.repeat(64));

    const entry1 = logger.log('SERVICE_START', 'started');
    expect(logger.getLastHash()).toBe(entry1.entryHash);

    const entry2 = logger.log('TOKEN_OBTAINED', 'got token');
    expect(logger.getLastHash()).toBe(entry2.entryHash);
  });

  it('should verify a valid chain of entries', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    const entries: AuditLogEntry[] = [];
    entries.push(logger.log('SERVICE_START', 'started'));
    entries.push(logger.log('TOKEN_OBTAINED', 'token1'));
    entries.push(logger.log('PGPASS_UPDATED', 'updated'));

    expect(logger.verifyChain(entries)).toBe(true);
  });

  it('should detect tampering: modified details in an entry', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    const entries: AuditLogEntry[] = [];
    entries.push(logger.log('SERVICE_START', 'started'));
    entries.push(logger.log('TOKEN_OBTAINED', 'token1'));
    entries.push(logger.log('PGPASS_UPDATED', 'updated'));

    // Tamper with the second entry
    const tampered = [...entries];
    tampered[1] = { ...tampered[1]!, details: 'TAMPERED' };

    expect(logger.verifyChain(tampered)).toBe(false);
  });

  it('should detect tampering: modified entryHash', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    const entries: AuditLogEntry[] = [];
    entries.push(logger.log('SERVICE_START', 'started'));
    entries.push(logger.log('TOKEN_OBTAINED', 'token1'));

    const tampered = [...entries];
    tampered[0] = { ...tampered[0]!, entryHash: 'a'.repeat(64) };

    expect(logger.verifyChain(tampered)).toBe(false);
  });

  it('should detect broken chain: wrong prevHash on an entry', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    const entries: AuditLogEntry[] = [];
    entries.push(logger.log('SERVICE_START', 'started'));
    entries.push(logger.log('TOKEN_OBTAINED', 'token1'));

    const tampered = [...entries];
    tampered[1] = { ...tampered[1]!, prevHash: 'b'.repeat(64) };

    expect(logger.verifyChain(tampered)).toBe(false);
  });

  it('should verify an empty chain as valid', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    expect(logger.verifyChain([])).toBe(true);
  });

  it('should write entries to the log file when enabled', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, true);

    logger.log('SERVICE_START', 'started');
    logger.log('TOKEN_OBTAINED', 'got token');

    const content = tempDir.readFile('audit.log');
    const lines = content.trim().split('\n');

    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('SERVICE_START');
    expect(lines[1]).toContain('TOKEN_OBTAINED');
  });

  it('should not write to file when disabled', () => {
    const logPath = tempDir.filePath('audit.log');
    const logger = new AuditLogger(logPath, false);

    const entry = logger.log('SERVICE_START', 'started');

    // Entry should still be returned
    expect(entry.eventType).toBe('SERVICE_START');

    // But the file should not exist (or be empty)
    expect(() => tempDir.readFile('audit.log')).toThrow();
  });
});
