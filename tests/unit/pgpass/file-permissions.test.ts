import { writeFileSync } from 'node:fs';
import {
  enforcePermissions,
  checkPermissions,
  PGPASS_MODE,
} from '../../../src/pgpass/file-permissions';
import { TempDir } from '../../helpers/temp-files';

describe('file-permissions', () => {
  let tempDir: TempDir;

  beforeEach(() => {
    tempDir = new TempDir();
  });

  afterEach(() => {
    tempDir.cleanup();
  });

  describe('PGPASS_MODE', () => {
    it('should be 0o600', () => {
      expect(PGPASS_MODE).toBe(0o600);
    });
  });

  describe('enforcePermissions', () => {
    it('should set file permissions to 0600', () => {
      const filePath = tempDir.filePath('testfile');
      writeFileSync(filePath, 'content', { mode: 0o644 });

      enforcePermissions(filePath);

      const mode = tempDir.fileMode('testfile');
      expect(mode).toBe(0o600);
    });

    it('should fix overly permissive file (0644)', () => {
      const filePath = tempDir.filePath('permissive');
      writeFileSync(filePath, 'secret', { mode: 0o644 });

      expect(tempDir.fileMode('permissive')).toBe(0o644);

      enforcePermissions(filePath);

      expect(tempDir.fileMode('permissive')).toBe(0o600);
    });

    it('should fix world-readable file (0666)', () => {
      const filePath = tempDir.filePath('worldreadable');
      writeFileSync(filePath, 'secret', { mode: 0o666 });

      enforcePermissions(filePath);

      expect(tempDir.fileMode('worldreadable')).toBe(0o600);
    });

    it('should be a no-op if file already has 0600', () => {
      const filePath = tempDir.filePath('already-secure');
      writeFileSync(filePath, 'content', { mode: 0o600 });

      enforcePermissions(filePath);

      expect(tempDir.fileMode('already-secure')).toBe(0o600);
    });

    it('should throw an error for a non-existent file', () => {
      const filePath = tempDir.filePath('nonexistent');
      expect(() => enforcePermissions(filePath)).toThrow();
    });
  });

  describe('checkPermissions', () => {
    it('should return correct=true when file has 0600 permissions', () => {
      const filePath = tempDir.filePath('secure');
      writeFileSync(filePath, 'content', { mode: 0o600 });

      const result = checkPermissions(filePath);

      expect(result.correct).toBe(true);
      expect(result.currentMode).toBe('0600');
      expect(result.expectedMode).toBe('0600');
    });

    it('should return correct=false when file has 0644 permissions', () => {
      const filePath = tempDir.filePath('insecure');
      writeFileSync(filePath, 'content', { mode: 0o644 });

      const result = checkPermissions(filePath);

      expect(result.correct).toBe(false);
      expect(result.currentMode).toBe('0644');
      expect(result.expectedMode).toBe('0600');
    });

    it('should return correct=false when file has overly permissive permissions', () => {
      const filePath = tempDir.filePath('wide-open');
      writeFileSync(filePath, 'content', { mode: 0o777 });
      // Note: actual mode may be reduced by umask (e.g., 0o755 on macOS)

      const result = checkPermissions(filePath);

      expect(result.correct).toBe(false);
      expect(result.expectedMode).toBe('0600');
      // The current mode should be something other than 0600
      expect(result.currentMode).not.toBe('0600');
    });

    it('should throw for a non-existent file', () => {
      const filePath = tempDir.filePath('missing');
      expect(() => checkPermissions(filePath)).toThrow();
    });
  });
});
