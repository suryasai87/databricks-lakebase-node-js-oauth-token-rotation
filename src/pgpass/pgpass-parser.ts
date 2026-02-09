import type { PgPassEntry } from '../types/pgpass.types.js';

export function parsePgPassLine(line: string): PgPassEntry | null {
  const trimmed = line.trim();

  // Skip empty lines and comments
  if (!trimmed || trimmed.startsWith('#')) {
    return null;
  }

  // Split by unescaped colons
  const parts: string[] = [];
  let current = '';
  for (let i = 0; i < trimmed.length; i++) {
    if (trimmed[i] === '\\' && i + 1 < trimmed.length && trimmed[i + 1] === ':') {
      current += ':';
      i++; // skip the next colon
    } else if (trimmed[i] === ':') {
      parts.push(current);
      current = '';
    } else {
      current += trimmed[i];
    }
  }
  parts.push(current);

  if (parts.length < 5) {
    return null;
  }

  return {
    hostname: parts[0]!,
    port: parts[1]!,
    database: parts[2]!,
    username: parts[3]!,
    password: parts.slice(4).join(':'), // Password may contain colons
  };
}

export function parsePgPassFile(content: string): {
  entries: PgPassEntry[];
  lines: string[];
} {
  const lines = content.split('\n');
  const entries: PgPassEntry[] = [];

  for (const line of lines) {
    const entry = parsePgPassLine(line);
    if (entry) {
      entries.push(entry);
    }
  }

  return { entries, lines };
}

export function formatPgPassEntry(entry: PgPassEntry): string {
  const escape = (s: string) => s.replace(/:/g, '\\:');
  // Don't escape the password - it's a JWT token and colons in it are fine
  // as PostgreSQL treats everything after the 4th colon as the password
  return `${escape(entry.hostname)}:${escape(entry.port)}:${escape(entry.database)}:${escape(entry.username)}:${entry.password}`;
}

export function matchesEntry(
  entry: PgPassEntry,
  hostname: string,
  port: string,
  database: string,
): boolean {
  const matchField = (field: string, target: string) =>
    field === '*' || field === target;
  return (
    matchField(entry.hostname, hostname) &&
    matchField(entry.port, port) &&
    matchField(entry.database, database)
  );
}
