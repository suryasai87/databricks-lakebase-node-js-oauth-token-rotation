/**
 * Curated corpus of malicious inputs for security testing.
 * Organized by attack category.
 */

export const SQL_INJECTION_PAYLOADS = [
  // Classic SQL injection
  "'; DROP TABLE users; --",
  "1' OR '1'='1",
  "1' OR '1'='1' --",
  "1' OR '1'='1' /*",
  "admin'--",
  "admin' #",
  "' OR 1=1--",
  "' OR 'a'='a",

  // UNION-based injection
  "1 UNION SELECT * FROM pg_shadow",
  "1 UNION SELECT username, password FROM users",
  "' UNION SELECT NULL, NULL, NULL--",
  "1 UNION ALL SELECT 1,2,3--",

  // Stacked queries
  "1; DROP TABLE users",
  "1; DELETE FROM users WHERE 1=1",
  "1; INSERT INTO users VALUES('hacked','hacked')",
  "1; UPDATE users SET password='hacked'",

  // System table access
  "1' AND 1=1 UNION SELECT table_name FROM information_schema.tables--",
  "' UNION SELECT * FROM pg_shadow--",
  "' AND (SELECT COUNT(*) FROM pg_catalog.pg_tables) > 0--",

  // Time-based blind injection
  "1' AND SLEEP(5)--",
  "1'; WAITFOR DELAY '0:0:5'--",
  "1' AND pg_sleep(5)--",
  "1' AND BENCHMARK(1000000, SHA1('test'))--",

  // Error-based injection
  "1' AND 1=CONVERT(int, (SELECT TOP 1 table_name FROM information_schema.tables))--",
  "1' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())))--",

  // Second-order injection
  "admin'; DROP TABLE users; --",

  // Bypasses
  "1' oR '1'='1",
  "1' UnIoN SeLeCt * FrOm users--",
  "1'/**/OR/**/1=1--",
  "1' OR 1=1#",

  // PostgreSQL-specific
  "'; COPY pg_shadow TO '/tmp/shadow';--",
  "1; CREATE TABLE hacked (data text)",
  "'; ALTER TABLE users ADD COLUMN backdoor TEXT;--",
  "1; TRUNCATE TABLE users",

  // LIKE injection
  "admin%",
  "admin_",

  // Encoding attacks
  "1%27%20OR%201%3D1--",
  "1\\' OR 1=1--",

  // Nested attacks
  "1' AND (SELECT CASE WHEN (1=1) THEN 1 ELSE (SELECT 1 UNION SELECT 2) END)--",

  // Comment injection
  "1'/**/AND/**/1=1--",
  "1'-- ",

  // Batch injection
  "1; EXEC xp_cmdshell('dir')",
  "1; EXECUTE IMMEDIATE 'DROP TABLE users'",

  // Out-of-band
  "1' INTO OUTFILE '/tmp/test'--",
  "1' INTO DUMPFILE '/tmp/test'--",
  "LOAD_FILE('/etc/passwd')",
];

export const PATH_TRAVERSAL_PAYLOADS = [
  '../../../etc/passwd',
  '..\\..\\..\\windows\\system32\\config\\sam',
  '/etc/shadow',
  '....//....//....//etc/passwd',
  '..%2F..%2F..%2Fetc%2Fpasswd',
  '..%252F..%252F..%252Fetc%252Fpasswd',
  '%2e%2e/%2e%2e/%2e%2e/etc/passwd',
  '....\\....\\....\\etc\\passwd',
  '/proc/self/environ',
  '\x00/etc/passwd',
];

export const UNICODE_ATTACK_PAYLOADS = [
  '\x00',             // Null byte
  '\x01',             // SOH
  '\x08',             // Backspace
  '\x7f',             // DEL
  '\u202e',           // Right-to-left override
  '\ufeff',           // BOM
  '\ud800',           // High surrogate (invalid)
  'A'.repeat(10000),  // Long string
  'A'.repeat(100000), // Very long string
];

export const COMMAND_INJECTION_PAYLOADS = [
  '$(whoami)',
  '`whoami`',
  '| whoami',
  '; whoami',
  '&& whoami',
  '|| whoami',
  '\n whoami',
  'test; cat /etc/passwd',
  'test | cat /etc/passwd',
];

export const HOSTNAME_ATTACK_PAYLOADS = [
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '::1',
  'http://evil.com',
  'evil.com/../../etc/passwd',
  'evil.com%00.databricks.com',
  '-dangerous-hostname',
  'a'.repeat(300), // Over 253 chars
  'host name with spaces',
  'host<script>alert(1)</script>.com',
  'host;rm -rf /.com',
];
