import { writeFileSync, chmodSync } from 'node:fs';
import { enforcePermissions, checkPermissions } from '../../src/pgpass/file-permissions';
import { TempDir } from '../helpers/temp-files';

describe('File Permission Security', () => {
  let tempDir: TempDir;

  beforeEach(() => {
    tempDir = new TempDir('file-perm-test-');
  });

  afterEach(() => {
    tempDir.cleanup();
  });

  describe('new pgpass file creation', () => {
    it('should create a file with 0600 permissions after enforcePermissions', () => {
      const filePath = tempDir.filePath('.pgpass');
      writeFileSync(filePath, 'host:5432:db:user:pass\n', { mode: 0o644 });

      enforcePermissions(filePath);

      const mode = tempDir.fileMode('.pgpass');
      expect(mode).toBe(0o600);
    });
  });

  describe('enforcePermissions()', () => {
    it('should fix permissions from 0644 to 0600', () => {
      const filePath = tempDir.filePath('pgpass-644');
      writeFileSync(filePath, 'content', { mode: 0o644 });

      expect(tempDir.fileMode('pgpass-644')).toBe(0o644);

      enforcePermissions(filePath);
      expect(tempDir.fileMode('pgpass-644')).toBe(0o600);
    });

    it('should fix permissions from 0777 to 0600', () => {
      const filePath = tempDir.filePath('pgpass-777');
      writeFileSync(filePath, 'content', { mode: 0o777 });

      enforcePermissions(filePath);
      expect(tempDir.fileMode('pgpass-777')).toBe(0o600);
    });

    it('should fix permissions from 0666 to 0600', () => {
      const filePath = tempDir.filePath('pgpass-666');
      writeFileSync(filePath, 'content', { mode: 0o666 });

      enforcePermissions(filePath);
      expect(tempDir.fileMode('pgpass-666')).toBe(0o600);
    });

    it('should leave already correct 0600 permissions unchanged', () => {
      const filePath = tempDir.filePath('pgpass-600');
      writeFileSync(filePath, 'content', { mode: 0o600 });

      enforcePermissions(filePath);
      expect(tempDir.fileMode('pgpass-600')).toBe(0o600);
    });

    it('should fix permissions from 0400 (read-only) to 0600', () => {
      const filePath = tempDir.filePath('pgpass-400');
      writeFileSync(filePath, 'content', { mode: 0o400 });

      enforcePermissions(filePath);
      expect(tempDir.fileMode('pgpass-400')).toBe(0o600);
    });
  });

  describe('checkPermissions()', () => {
    it('should detect wrong permissions (0644)', () => {
      const filePath = tempDir.filePath('check-644');
      writeFileSync(filePath, 'content', { mode: 0o644 });

      const result = checkPermissions(filePath);

      expect(result.correct).toBe(false);
      expect(result.currentMode).toBe('0644');
      expect(result.expectedMode).toBe('0600');
    });

    it('should detect wrong permissions when set wider than 0600', () => {
      const filePath = tempDir.filePath('check-wide');
      writeFileSync(filePath, 'content', { mode: 0o777 });

      const result = checkPermissions(filePath);

      // On macOS, umask may modify 0777 to 0755 for regular files.
      // Either way, the permissions should be detected as incorrect.
      expect(result.correct).toBe(false);
      expect(result.expectedMode).toBe('0600');
    });

    it('should detect wrong permissions (0755)', () => {
      const filePath = tempDir.filePath('check-755');
      writeFileSync(filePath, 'content', { mode: 0o755 });

      const result = checkPermissions(filePath);

      expect(result.correct).toBe(false);
      expect(result.currentMode).toBe('0755');
      expect(result.expectedMode).toBe('0600');
    });

    it('should confirm correct permissions (0600)', () => {
      const filePath = tempDir.filePath('check-600');
      writeFileSync(filePath, 'content', { mode: 0o600 });

      const result = checkPermissions(filePath);

      expect(result.correct).toBe(true);
      expect(result.currentMode).toBe('0600');
      expect(result.expectedMode).toBe('0600');
    });

    it('should detect permissions after chmod', () => {
      const filePath = tempDir.filePath('check-chmod');
      writeFileSync(filePath, 'content', { mode: 0o600 });

      // Sabotage permissions
      chmodSync(filePath, 0o644);

      const result = checkPermissions(filePath);
      expect(result.correct).toBe(false);

      // Fix and verify
      enforcePermissions(filePath);
      const resultAfterFix = checkPermissions(filePath);
      expect(resultAfterFix.correct).toBe(true);
    });
  });
});
