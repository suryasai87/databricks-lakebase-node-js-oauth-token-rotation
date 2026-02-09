import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';

/**
 * Recursively collects all .ts files in a directory, excluding node_modules and dist.
 */
function collectTsFiles(dir: string): string[] {
  const results: string[] = [];
  const entries = readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === '.git') {
        continue;
      }
      results.push(...collectTsFiles(fullPath));
    } else if (entry.isFile() && entry.name.endsWith('.ts')) {
      results.push(fullPath);
    }
  }

  return results;
}

describe('Automated Penetration Tests', () => {
  const projectRoot = path.resolve(__dirname, '..', '..');
  const srcDir = path.join(projectRoot, 'src');
  let sourceFiles: string[];
  let sourceContents: Map<string, string>;

  beforeAll(() => {
    sourceFiles = collectTsFiles(srcDir);
    sourceContents = new Map();
    for (const file of sourceFiles) {
      sourceContents.set(file, readFileSync(file, 'utf-8'));
    }
  });

  it('should have found source files to analyze', () => {
    expect(sourceFiles.length).toBeGreaterThan(0);
  });

  describe('no eval() or Function() constructor usage', () => {
    it('should not contain eval() calls in source code', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        // Match eval( but not .evaluate or similar
        const evalPattern = /\beval\s*\(/g;
        if (evalPattern.test(content)) {
          const relativePath = path.relative(projectRoot, file);
          violations.push(relativePath);
        }
      }

      expect(violations).toEqual([]);
    });

    it('should not contain new Function() constructor usage', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        const functionConstructorPattern = /new\s+Function\s*\(/g;
        if (functionConstructorPattern.test(content)) {
          const relativePath = path.relative(projectRoot, file);
          violations.push(relativePath);
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('no child_process.exec() usage', () => {
    it('should not use child_process.exec() (only execFile is allowed)', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        // Match exec( but not execFile( or execute(
        // Look for: import { exec } from 'child_process', or .exec( patterns
        const execImportPattern = /\bexec\b(?!File|ute)/g;
        const lines = content.split('\n');

        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          // Skip comments
          if (line.trim().startsWith('//') || line.trim().startsWith('*')) {
            continue;
          }

          if (
            (line.includes('child_process') && execImportPattern.test(line)) ||
            (/\.exec\s*\(/.test(line) && line.includes('child_process'))
          ) {
            const relativePath = path.relative(projectRoot, file);
            violations.push(`${relativePath}:${i + 1}`);
          }
          // Reset regex lastIndex
          execImportPattern.lastIndex = 0;
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('no hardcoded secrets', () => {
    it('should not contain hardcoded password assignments', () => {
      const violations: string[] = [];
      // Patterns that suggest hardcoded secrets with actual values
      // Match: password = "...", password: "...", secret = "...", token = "..." etc.
      // But exclude: password = process.env..., password = config..., etc.
      const secretPatterns = [
        /(?:password|passwd|secret|api_key|apikey|private_key)\s*[:=]\s*['"][a-zA-Z0-9+/=]{8,}['"]/gi,
      ];

      for (const [file, content] of sourceContents) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          // Skip comments, test files, and type definitions
          if (
            line.trim().startsWith('//') ||
            line.trim().startsWith('*') ||
            line.trim().startsWith('/*') ||
            file.includes('/types/')
          ) {
            continue;
          }

          for (const pattern of secretPatterns) {
            pattern.lastIndex = 0;
            if (pattern.test(line)) {
              // Ignore common false positives: empty strings, placeholders, env vars
              if (
                line.includes('process.env') ||
                line.includes('config.') ||
                line.includes('getenv') ||
                line.includes('placeholder') ||
                line.includes('example') ||
                line.includes('test') ||
                line.includes('mock')
              ) {
                continue;
              }
              const relativePath = path.relative(projectRoot, file);
              violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
            }
          }
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('all outbound URLs use HTTPS', () => {
    it('should not contain http:// URLs in source code (except localhost references)', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          // Skip comments
          if (
            line.trim().startsWith('//') ||
            line.trim().startsWith('*') ||
            line.trim().startsWith('/*')
          ) {
            continue;
          }

          // Find http:// URLs
          const httpPattern = /http:\/\/[^\s'")`]+/g;
          let match;
          while ((match = httpPattern.exec(line)) !== null) {
            const url = match[0];
            // Allow localhost, 127.0.0.1, and 0.0.0.0 for local dev
            if (
              url.includes('localhost') ||
              url.includes('127.0.0.1') ||
              url.includes('0.0.0.0')
            ) {
              continue;
            }
            // Allow Apple DTD URLs (required in plist XML files)
            if (url.includes('apple.com/DTDs/')) {
              continue;
            }
            // Allow http:// in string checks (e.g., url.startsWith('https://'))
            if (line.includes("startsWith('http") || line.includes('startsWith("http')) {
              continue;
            }
            const relativePath = path.relative(projectRoot, file);
            violations.push(`${relativePath}:${i + 1}: ${url}`);
          }
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('no console.log in production code', () => {
    it('should not contain console.log in source files (except CLI)', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        // Skip CLI files - console output is expected there
        const relativePath = path.relative(projectRoot, file);
        if (relativePath.includes('cli') || relativePath.includes('install')) {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          // Skip comments
          if (
            line.trim().startsWith('//') ||
            line.trim().startsWith('*') ||
            line.trim().startsWith('/*')
          ) {
            continue;
          }

          if (/\bconsole\.(log|debug|info|warn|error)\s*\(/.test(line)) {
            violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
          }
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('no TODO security items in source', () => {
    it('should not contain TODO security comments in production code', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          // Look for TODO/FIXME/HACK comments mentioning security
          const todoSecurityPattern =
            /\b(TODO|FIXME|HACK|XXX)\b.*\b(security|auth|token|password|secret|cred|vuln|inject|xss|csrf)\b/i;

          if (todoSecurityPattern.test(line)) {
            const relativePath = path.relative(projectRoot, file);
            violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
          }
        }
      }

      expect(violations).toEqual([]);
    });
  });

  describe('additional security code patterns', () => {
    it('should not use require() for dynamic module loading', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          if (line.trim().startsWith('//') || line.trim().startsWith('*')) {
            continue;
          }

          // Match require() with variable argument (dynamic require)
          // e.g., require(variable) but not require('static-string')
          if (/\brequire\s*\([^'")\s]/.test(line)) {
            const relativePath = path.relative(projectRoot, file);
            violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
          }
        }
      }

      expect(violations).toEqual([]);
    });

    it('should not disable TypeScript strict checks with ts-ignore for security-related code', () => {
      const violations: string[] = [];

      for (const [file, content] of sourceContents) {
        // Only check security-related files
        if (!file.includes('/security/') && !file.includes('/auth/')) {
          continue;
        }

        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i]!;
          if (/@ts-ignore/.test(line) || /@ts-nocheck/.test(line)) {
            const relativePath = path.relative(projectRoot, file);
            violations.push(`${relativePath}:${i + 1}: ${line.trim()}`);
          }
        }
      }

      expect(violations).toEqual([]);
    });
  });
});
