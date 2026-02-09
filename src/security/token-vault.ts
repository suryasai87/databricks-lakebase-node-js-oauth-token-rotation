import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

export class TokenVault {
  private encryptionKey: Buffer;
  private encryptedData: Buffer | null = null;
  private iv: Buffer | null = null;
  private authTag: Buffer | null = null;
  private enabled: boolean;

  constructor(enabled = true) {
    this.enabled = enabled;
    this.encryptionKey = randomBytes(32);
  }

  store(token: string): void {
    if (!this.enabled) {
      // Store as plain buffer (still not a string reference)
      this.encryptedData = Buffer.from(token, 'utf-8');
      this.iv = null;
      this.authTag = null;
      return;
    }

    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.encryptionKey, iv);

    const encrypted = Buffer.concat([
      cipher.update(token, 'utf-8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    this.encryptedData = encrypted;
    this.iv = iv;
    this.authTag = authTag;
  }

  retrieve(): string | null {
    if (!this.encryptedData) {
      return null;
    }

    if (!this.enabled) {
      return this.encryptedData.toString('utf-8');
    }

    if (!this.iv || !this.authTag) {
      return null;
    }

    const decipher = createDecipheriv(
      ALGORITHM,
      this.encryptionKey,
      this.iv,
    );
    decipher.setAuthTag(this.authTag);

    const decrypted = Buffer.concat([
      decipher.update(this.encryptedData),
      decipher.final(),
    ]);

    const result = decrypted.toString('utf-8');

    // Zero out the decrypted buffer to minimize plaintext exposure
    decrypted.fill(0);

    return result;
  }

  clear(): void {
    if (this.encryptedData) {
      this.encryptedData.fill(0);
      this.encryptedData = null;
    }
    if (this.iv) {
      this.iv.fill(0);
      this.iv = null;
    }
    if (this.authTag) {
      this.authTag.fill(0);
      this.authTag = null;
    }
  }

  hasToken(): boolean {
    return this.encryptedData !== null;
  }
}
