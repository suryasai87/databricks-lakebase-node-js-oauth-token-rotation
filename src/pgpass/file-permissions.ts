import { statSync, chmodSync } from 'node:fs';

const PGPASS_MODE = 0o600;

export function enforcePermissions(filePath: string): void {
  chmodSync(filePath, PGPASS_MODE);
}

export function checkPermissions(filePath: string): {
  correct: boolean;
  currentMode: string;
  expectedMode: string;
} {
  const stats = statSync(filePath);
  const mode = stats.mode & 0o777;
  return {
    correct: mode === PGPASS_MODE,
    currentMode: `0${mode.toString(8)}`,
    expectedMode: '0600',
  };
}

export { PGPASS_MODE };
