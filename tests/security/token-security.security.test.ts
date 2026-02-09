import { TokenVault } from '../../src/security/token-vault';
import { createMockJwt } from '../helpers/mock-server';

describe('TokenVault Security', () => {
  describe('encryption roundtrip', () => {
    it('should encrypt and decrypt a token correctly', () => {
      const vault = new TokenVault(true);
      const token = createMockJwt(3600);

      vault.store(token);
      const retrieved = vault.retrieve();

      expect(retrieved).toBe(token);
    });

    it('should encrypt and decrypt a simple string', () => {
      const vault = new TokenVault(true);
      const secret = 'my-super-secret-value-12345';

      vault.store(secret);
      expect(vault.retrieve()).toBe(secret);
    });

    it('should handle empty string', () => {
      const vault = new TokenVault(true);

      vault.store('');
      expect(vault.retrieve()).toBe('');
    });

    it('should handle very long tokens', () => {
      const vault = new TokenVault(true);
      const longToken = 'A'.repeat(10000);

      vault.store(longToken);
      expect(vault.retrieve()).toBe(longToken);
    });

    it('should handle unicode content', () => {
      const vault = new TokenVault(true);
      const unicodeToken = 'token-with-unicode-\u00e9\u00e8\u00ea-\u4e16\u754c';

      vault.store(unicodeToken);
      expect(vault.retrieve()).toBe(unicodeToken);
    });
  });

  describe('encryption verification', () => {
    it('should store data in encrypted form (not plaintext)', () => {
      const vault = new TokenVault(true);
      const token = 'plaintext-secret-token-value';

      vault.store(token);

      // Access internal state to verify encryption
      // The encryptedData buffer should NOT contain the plaintext
      const internalData = (vault as any).encryptedData as Buffer;
      expect(internalData).not.toBeNull();

      const storedString = internalData.toString('utf-8');
      expect(storedString).not.toBe(token);
    });

    it('should have an IV when encryption is enabled', () => {
      const vault = new TokenVault(true);
      vault.store('test-token');

      expect((vault as any).iv).not.toBeNull();
      expect((vault as any).authTag).not.toBeNull();
    });

    it('should produce different ciphertext for same plaintext (random IV)', () => {
      const vault1 = new TokenVault(true);
      const vault2 = new TokenVault(true);
      const token = 'identical-token';

      vault1.store(token);
      vault2.store(token);

      const data1 = (vault1 as any).encryptedData as Buffer;
      const data2 = (vault2 as any).encryptedData as Buffer;

      // Different keys and IVs should produce different ciphertext
      expect(data1.equals(data2)).toBe(false);
    });
  });

  describe('clear()', () => {
    it('should remove all stored data', () => {
      const vault = new TokenVault(true);
      vault.store('secret-token');

      expect(vault.hasToken()).toBe(true);
      vault.clear();
      expect(vault.hasToken()).toBe(false);
      expect(vault.retrieve()).toBeNull();
    });

    it('should zero out internal buffers on clear', () => {
      const vault = new TokenVault(true);
      vault.store('secret-token');

      vault.clear();

      expect((vault as any).encryptedData).toBeNull();
      expect((vault as any).iv).toBeNull();
      expect((vault as any).authTag).toBeNull();
    });
  });

  describe('different instances', () => {
    it('should have different encryption keys', () => {
      const vault1 = new TokenVault(true);
      const vault2 = new TokenVault(true);

      const key1 = (vault1 as any).encryptionKey as Buffer;
      const key2 = (vault2 as any).encryptionKey as Buffer;

      expect(key1.equals(key2)).toBe(false);
    });

    it('should not be able to decrypt each other\'s data', () => {
      const vault1 = new TokenVault(true);
      vault1.store('vault1-secret');

      const vault2 = new TokenVault(true);
      vault2.store('vault2-secret');

      // Verify each retrieves its own data
      expect(vault1.retrieve()).toBe('vault1-secret');
      expect(vault2.retrieve()).toBe('vault2-secret');

      // Cross-contamination: swap encrypted data into vault2 but keep vault2's key
      const encData1 = (vault1 as any).encryptedData;
      const iv1 = (vault1 as any).iv;
      const tag1 = (vault1 as any).authTag;

      (vault2 as any).encryptedData = encData1;
      (vault2 as any).iv = iv1;
      (vault2 as any).authTag = tag1;

      // Should fail to decrypt because key is different
      expect(() => vault2.retrieve()).toThrow();
    });
  });

  describe('disabled vault', () => {
    it('should store as plaintext buffer when disabled', () => {
      const vault = new TokenVault(false);
      const token = 'plaintext-token';

      vault.store(token);

      // When disabled, data is stored as a plain buffer
      const internalData = (vault as any).encryptedData as Buffer;
      expect(internalData.toString('utf-8')).toBe(token);
    });

    it('should still retrieve correctly when disabled', () => {
      const vault = new TokenVault(false);
      const token = createMockJwt(1800);

      vault.store(token);
      expect(vault.retrieve()).toBe(token);
    });

    it('should not set IV or authTag when disabled', () => {
      const vault = new TokenVault(false);
      vault.store('test');

      expect((vault as any).iv).toBeNull();
      expect((vault as any).authTag).toBeNull();
    });
  });

  describe('hasToken()', () => {
    it('should return false when no token is stored', () => {
      const vault = new TokenVault(true);
      expect(vault.hasToken()).toBe(false);
    });

    it('should return true after storing a token', () => {
      const vault = new TokenVault(true);
      vault.store('some-token');
      expect(vault.hasToken()).toBe(true);
    });

    it('should return false after clearing', () => {
      const vault = new TokenVault(true);
      vault.store('some-token');
      vault.clear();
      expect(vault.hasToken()).toBe(false);
    });

    it('should return true for disabled vault with token', () => {
      const vault = new TokenVault(false);
      vault.store('token');
      expect(vault.hasToken()).toBe(true);
    });
  });

  describe('retrieve() without store', () => {
    it('should return null when nothing was stored (enabled)', () => {
      const vault = new TokenVault(true);
      expect(vault.retrieve()).toBeNull();
    });

    it('should return null when nothing was stored (disabled)', () => {
      const vault = new TokenVault(false);
      expect(vault.retrieve()).toBeNull();
    });
  });
});
