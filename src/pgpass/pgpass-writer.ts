import {
  readFileSync,
  writeFileSync,
  renameSync,
  existsSync,
  mkdirSync,
} from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import type { PgPassEntry, PgPassUpdateResult } from '../types/pgpass.types.js';
import { parsePgPassFile, formatPgPassEntry, matchesEntry } from './pgpass-parser.js';
import { enforcePermissions } from './file-permissions.js';
import { getLogger } from '../logging/logger.js';

function expandPath(filePath: string): string {
  if (filePath.startsWith('~/')) {
    return path.join(os.homedir(), filePath.slice(2));
  }
  return filePath;
}

export function updatePgPass(
  pgpassPath: string,
  entry: PgPassEntry,
): PgPassUpdateResult {
  const logger = getLogger();
  const resolvedPath = expandPath(pgpassPath);
  const tempPath = `${resolvedPath}.tmp`;
  const dir = path.dirname(resolvedPath);

  // Ensure directory exists
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  let action: 'created' | 'updated' | 'appended';
  let outputLines: string[];

  if (existsSync(resolvedPath)) {
    const content = readFileSync(resolvedPath, 'utf-8');
    const { lines } = parsePgPassFile(content);

    let found = false;
    outputLines = lines.map((line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) return line;

      // Check if this line matches our target host:port:database
      const parsed = parsePgPassFile(line);
      if (
        parsed.entries[0] &&
        matchesEntry(parsed.entries[0], entry.hostname, entry.port, entry.database)
      ) {
        found = true;
        return formatPgPassEntry(entry);
      }
      return line;
    });

    if (found) {
      action = 'updated';
    } else {
      // Ensure file ends with newline before appending
      if (outputLines.length > 0 && outputLines[outputLines.length - 1] !== '') {
        outputLines.push('');
      }
      outputLines.push(formatPgPassEntry(entry));
      action = 'appended';
    }
  } else {
    outputLines = [formatPgPassEntry(entry)];
    action = 'created';
  }

  const output = outputLines.join('\n') + (outputLines[outputLines.length - 1] !== '' ? '\n' : '');

  try {
    // Atomic write: temp file → chmod → rename
    writeFileSync(tempPath, output, { mode: 0o600 });
    enforcePermissions(tempPath);
    renameSync(tempPath, resolvedPath);

    logger.info(`Successfully ${action} ${resolvedPath}`);
    return { success: true, action, filePath: resolvedPath };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    logger.error(`Failed to update pgpass: ${message}`);
    return { success: false, action, filePath: resolvedPath, error: message };
  }
}
