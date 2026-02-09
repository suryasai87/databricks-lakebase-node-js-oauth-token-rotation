import { SecurityError } from '../types/security.types.js';

// Dangerous SQL patterns that should never appear in identifiers
const SQL_INJECTION_PATTERNS = [
  /;\s*--/i,
  /'\s*OR\s+/i,
  /'\s*AND\s+/i,
  /UNION\s+SELECT/i,
  /UNION\s+ALL\s+SELECT/i,
  /DROP\s+TABLE/i,
  /DROP\s+DATABASE/i,
  /DELETE\s+FROM/i,
  /INSERT\s+INTO/i,
  /UPDATE\s+.*\s+SET/i,
  /ALTER\s+TABLE/i,
  /CREATE\s+TABLE/i,
  /TRUNCATE\s+TABLE/i,
  /EXEC(\s+|\()/i,
  /EXECUTE(\s+|\()/i,
  /xp_cmdshell/i,
  /INTO\s+OUTFILE/i,
  /INTO\s+DUMPFILE/i,
  /LOAD_FILE/i,
  /information_schema/i,
  /pg_shadow/i,
  /pg_catalog/i,
  /BENCHMARK\s*\(/i,
  /SLEEP\s*\(/i,
  /WAITFOR\s+DELAY/i,
  /CONVERT\s*\(/i,
  /CAST\s*\(/i,
  /@@version/i,
  /CHAR\s*\(\d+\)/i,
];

// String interpolation patterns that indicate unsafe query construction
const INTERPOLATION_PATTERNS = [
  /\$\{/, // Template literals: ${...}
  /'\s*\+/, // String concat: ' +
  /"\s*\+/, // String concat: " +
  /\+\s*'/, // String concat: + '
  /\+\s*"/, // String concat: + "
];

export class SqlInjectionGuard {
  /**
   * Validates that a database identifier (table name, column name, etc.)
   * does not contain SQL injection patterns.
   */
  validateIdentifier(value: string, fieldName: string): string {
    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        throw new SecurityError(
          `SQL injection pattern detected in ${fieldName}`,
          'SQL_INJECTION_BLOCKED',
        );
      }
    }

    // Identifiers must be alphanumeric + underscore + dot (for schema.table)
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(value)) {
      throw new SecurityError(
        `Invalid characters in ${fieldName} - only alphanumeric, underscore, and dot allowed`,
        'INVALID_IDENTIFIER',
      );
    }

    return value;
  }

  /**
   * Validates that a query string uses parameterized format ($1, $2, etc.)
   * and does not use string interpolation.
   */
  validateQuery(queryText: string): string {
    for (const pattern of INTERPOLATION_PATTERNS) {
      if (pattern.test(queryText)) {
        throw new SecurityError(
          'String interpolation detected in query text - use parameterized queries ($1, $2, ...)',
          'UNSAFE_QUERY',
        );
      }
    }

    return queryText;
  }

  /**
   * Validates that a value being used in a connection string is safe.
   */
  validateConnectionStringValue(value: string, fieldName: string): string {
    // Connection string values must not contain SQL metacharacters
    const dangerousChars = /[;'"\\`\x00]/;
    if (dangerousChars.test(value)) {
      throw new SecurityError(
        `Dangerous characters in ${fieldName} connection string value`,
        'UNSAFE_CONNECTION_STRING',
      );
    }

    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        throw new SecurityError(
          `SQL injection pattern detected in ${fieldName}`,
          'SQL_INJECTION_BLOCKED',
        );
      }
    }

    return value;
  }
}

export const sqlInjectionGuard = new SqlInjectionGuard();
