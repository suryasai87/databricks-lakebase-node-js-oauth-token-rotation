import { createHmac, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import type {
  AuditEventType,
  AuditLogEntry,
} from '../types/security.types.js';
import { expandPath } from './logger.js';

const INITIAL_HASH = '0'.repeat(64);

export class AuditLogger {
  private hmacKey: Buffer;
  private prevHash: string;
  private logPath: string;
  private enabled: boolean;

  constructor(logPath?: string, enabled = true) {
    this.hmacKey = randomBytes(32);
    this.prevHash = INITIAL_HASH;
    this.enabled = enabled;
    this.logPath = expandPath(logPath ?? '~/.databricks_audit.log');

    const dir = path.dirname(this.logPath);
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  }

  log(eventType: AuditEventType, details: string): AuditLogEntry {
    const timestamp = new Date().toISOString();
    const entryData = `${timestamp}|${eventType}|${details}|${this.prevHash}`;
    const entryHash = this.computeHmac(entryData);

    const entry: AuditLogEntry = {
      timestamp,
      eventType,
      details,
      prevHash: this.prevHash,
      entryHash,
    };

    if (this.enabled) {
      const line = `${timestamp}|${eventType}|${details}|${this.prevHash}|${entryHash}\n`;
      appendFileSync(this.logPath, line, { mode: 0o600 });
    }

    this.prevHash = entryHash;
    return entry;
  }

  verifyChain(entries: AuditLogEntry[]): boolean {
    let prevHash = INITIAL_HASH;
    for (const entry of entries) {
      if (entry.prevHash !== prevHash) {
        return false;
      }
      const entryData = `${entry.timestamp}|${entry.eventType}|${entry.details}|${entry.prevHash}`;
      const expectedHash = this.computeHmac(entryData);
      if (entry.entryHash !== expectedHash) {
        return false;
      }
      prevHash = entry.entryHash;
    }
    return true;
  }

  private computeHmac(data: string): string {
    return createHmac('sha256', this.hmacKey).update(data).digest('hex');
  }

  getLastHash(): string {
    return this.prevHash;
  }
}
