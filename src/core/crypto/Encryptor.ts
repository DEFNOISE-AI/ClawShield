import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

export class Encryptor {
  private readonly key: Buffer;

  constructor(key: Buffer) {
    if (key.length !== 32) {
      throw new Error('Encryption key must be exactly 32 bytes');
    }
    this.key = key;
  }

  encrypt(plaintext: string): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);

    const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Format: IV (16) + AuthTag (16) + Ciphertext
    return Buffer.concat([iv, authTag, encrypted]).toString('base64');
  }

  decrypt(ciphertext: string): string {
    const data = Buffer.from(ciphertext, 'base64');

    if (data.length < IV_LENGTH + AUTH_TAG_LENGTH) {
      throw new Error('Invalid ciphertext: too short');
    }

    const iv = data.subarray(0, IV_LENGTH);
    const authTag = data.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const encrypted = data.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
    return decrypted.toString('utf8');
  }

  static generateKey(): Buffer {
    return randomBytes(32);
  }

  static generateKeyHex(): string {
    return randomBytes(32).toString('hex');
  }
}
