import { mkdtempSync, rmSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import os from 'node:os';

export class TempDir {
  public readonly path: string;

  constructor(prefix = 'rotator-test-') {
    this.path = mkdtempSync(path.join(os.tmpdir(), prefix));
  }

  filePath(name: string): string {
    return path.join(this.path, name);
  }

  readFile(name: string): string {
    return readFileSync(this.filePath(name), 'utf-8');
  }

  fileMode(name: string): number {
    const stats = statSync(this.filePath(name));
    return stats.mode & 0o777;
  }

  cleanup(): void {
    rmSync(this.path, { recursive: true, force: true });
  }
}
