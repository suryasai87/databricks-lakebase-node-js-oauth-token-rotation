import { readFileSync } from 'node:fs';
import type { TlsConfig } from '../types/config.types.js';
import { SecurityError } from '../types/security.types.js';

export interface TlsOptions {
  rejectUnauthorized: boolean;
  minVersion: string;
  ca?: Buffer;
}

export class TlsEnforcer {
  private config: TlsConfig;

  constructor(config: TlsConfig) {
    this.config = config;
  }

  /**
   * Validates that a URL uses HTTPS when TLS is enforced.
   */
  validateUrl(url: string): void {
    if (this.config.enforce && !url.startsWith('https://')) {
      throw new SecurityError(
        'TLS enforcement requires HTTPS URLs',
        'TLS_VIOLATION',
      );
    }
  }

  /**
   * Returns TLS options for PostgreSQL pg.Pool connections.
   */
  getPgSslConfig(): TlsOptions | false {
    if (!this.config.enforce) {
      return false;
    }

    const options: TlsOptions = {
      rejectUnauthorized: this.config.rejectUnauthorized,
      minVersion: 'TLSv1.2',
    };

    if (this.config.caCertPath) {
      options.ca = readFileSync(this.config.caCertPath);
    }

    return options;
  }

  /**
   * Validates a server certificate fingerprint against pinned fingerprints.
   */
  validateCertFingerprint(fingerprint: string): boolean {
    if (!this.config.certPinning.enabled) {
      return true;
    }

    const pinned = this.config.certPinning.fingerprints;
    if (!pinned || pinned.length === 0) {
      return true;
    }

    const normalizedFingerprint = fingerprint.toLowerCase().replace(/:/g, '');
    return pinned.some(
      (pin) => pin.toLowerCase().replace(/:/g, '') === normalizedFingerprint,
    );
  }

  isEnforced(): boolean {
    return this.config.enforce;
  }
}
