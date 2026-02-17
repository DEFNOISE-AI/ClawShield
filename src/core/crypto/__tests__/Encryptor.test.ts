import { describe, it, expect } from 'vitest';
import { Encryptor } from '../Encryptor.js';

describe('Encryptor', () => {
  const key = Encryptor.generateKey();
  const encryptor = new Encryptor(key);

  describe('constructor', () => {
    it('should reject keys that are not 32 bytes', () => {
      expect(() => new Encryptor(Buffer.alloc(16))).toThrow('must be exactly 32 bytes');
      expect(() => new Encryptor(Buffer.alloc(64))).toThrow('must be exactly 32 bytes');
    });

    it('should accept a 32-byte key', () => {
      expect(() => new Encryptor(Buffer.alloc(32))).not.toThrow();
    });
  });

  describe('encrypt/decrypt', () => {
    it('should encrypt and decrypt a simple string', () => {
      const plaintext = 'Hello, ClawShield!';
      const ciphertext = encryptor.encrypt(plaintext);
      const decrypted = encryptor.decrypt(ciphertext);
      expect(decrypted).toBe(plaintext);
    });

    it('should produce different ciphertexts for the same plaintext (random IV)', () => {
      const plaintext = 'same input';
      const ct1 = encryptor.encrypt(plaintext);
      const ct2 = encryptor.encrypt(plaintext);
      expect(ct1).not.toBe(ct2);
    });

    it('should handle empty strings', () => {
      const ciphertext = encryptor.encrypt('');
      const decrypted = encryptor.decrypt(ciphertext);
      expect(decrypted).toBe('');
    });

    it('should handle unicode characters', () => {
      const plaintext = '日本語テスト 🔐 Ñoño';
      const ciphertext = encryptor.encrypt(plaintext);
      const decrypted = encryptor.decrypt(ciphertext);
      expect(decrypted).toBe(plaintext);
    });

    it('should handle large payloads', () => {
      const plaintext = 'A'.repeat(100000);
      const ciphertext = encryptor.encrypt(plaintext);
      const decrypted = encryptor.decrypt(ciphertext);
      expect(decrypted).toBe(plaintext);
    });

    it('should fail to decrypt with a different key', () => {
      const otherKey = Encryptor.generateKey();
      const otherEncryptor = new Encryptor(otherKey);
      const ciphertext = encryptor.encrypt('secret');
      expect(() => otherEncryptor.decrypt(ciphertext)).toThrow();
    });

    it('should fail on tampered ciphertext', () => {
      const ciphertext = encryptor.encrypt('secret');
      const bytes = Buffer.from(ciphertext, 'base64');
      bytes[bytes.length - 1] ^= 0xff;
      const tampered = bytes.toString('base64');
      expect(() => encryptor.decrypt(tampered)).toThrow();
    });

    it('should reject invalid ciphertext (too short)', () => {
      expect(() => encryptor.decrypt(Buffer.alloc(10).toString('base64'))).toThrow('too short');
    });
  });

  describe('static methods', () => {
    it('should generate a 32-byte key', () => {
      const key = Encryptor.generateKey();
      expect(key).toBeInstanceOf(Buffer);
      expect(key.length).toBe(32);
    });

    it('should generate a 64-char hex key', () => {
      const hex = Encryptor.generateKeyHex();
      expect(hex).toMatch(/^[0-9a-f]{64}$/);
    });
  });
});
