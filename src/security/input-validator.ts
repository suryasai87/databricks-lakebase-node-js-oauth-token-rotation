import {
  hostnameSchema,
  portSchema,
  databaseNameSchema,
  workspaceUrlSchema,
  filePathSchema,
} from '../config/schema.js';
import { SecurityError } from '../types/security.types.js';

const JWT_PATTERN = /^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

const DANGEROUS_PATTERNS = [
  /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/, // Control characters (except \t, \n, \r)
  /\0/, // Null bytes
];

export class InputValidator {
  validateHostname(value: string): string {
    const result = hostnameSchema.safeParse(value);
    if (!result.success) {
      throw new SecurityError(
        `Invalid hostname: ${result.error.issues[0]?.message}`,
        'INVALID_HOSTNAME',
      );
    }
    return result.data;
  }

  validatePort(value: number): number {
    const result = portSchema.safeParse(value);
    if (!result.success) {
      throw new SecurityError(
        `Invalid port: ${result.error.issues[0]?.message}`,
        'INVALID_PORT',
      );
    }
    return result.data;
  }

  validateDatabaseName(value: string): string {
    this.checkDangerousPatterns(value, 'database name');
    const result = databaseNameSchema.safeParse(value);
    if (!result.success) {
      throw new SecurityError(
        `Invalid database name: ${result.error.issues[0]?.message}`,
        'INVALID_DATABASE_NAME',
      );
    }
    return result.data;
  }

  validateWorkspaceUrl(value: string): string {
    const result = workspaceUrlSchema.safeParse(value);
    if (!result.success) {
      throw new SecurityError(
        `Invalid workspace URL: ${result.error.issues[0]?.message}`,
        'INVALID_WORKSPACE_URL',
      );
    }
    return result.data;
  }

  validateFilePath(value: string): string {
    const result = filePathSchema.safeParse(value);
    if (!result.success) {
      throw new SecurityError(
        `Invalid file path: ${result.error.issues[0]?.message}`,
        'INVALID_FILE_PATH',
      );
    }
    return result.data;
  }

  validateUsername(value: string): string {
    this.checkDangerousPatterns(value, 'username');
    if (value.length === 0 || value.length > 256) {
      throw new SecurityError(
        'Username must be 1-256 characters',
        'INVALID_USERNAME',
      );
    }
    // Allow email format and service principal UUIDs
    const emailOrUuidPattern =
      /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!emailOrUuidPattern.test(value)) {
      throw new SecurityError(
        'Username must be a valid email or UUID',
        'INVALID_USERNAME',
      );
    }
    return value;
  }

  validateToken(value: string): string {
    if (!JWT_PATTERN.test(value)) {
      throw new SecurityError(
        'Token does not match JWT format',
        'INVALID_TOKEN_FORMAT',
      );
    }
    return value;
  }

  private checkDangerousPatterns(value: string, fieldName: string): void {
    for (const pattern of DANGEROUS_PATTERNS) {
      if (pattern.test(value)) {
        throw new SecurityError(
          `${fieldName} contains dangerous characters`,
          'DANGEROUS_INPUT',
        );
      }
    }
  }
}

export const inputValidator = new InputValidator();
