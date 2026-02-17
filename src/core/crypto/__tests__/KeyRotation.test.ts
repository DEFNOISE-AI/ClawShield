import { describe, it, expect, afterEach } from 'vitest';
import { rmSync, existsSync, readFileSync } from 'node:fs';
import { KeyRotation } from '../KeyRotation.js';
import { createLogger } from '../../../utils/logger.js';

const TEST_DIR = '/tmp/clawshield-keyrotation-test';
const logger = createLogger('silent');

afterEach(() => {
  rmSync(TEST_DIR, { recursive: true, force: true });
});

describe('KeyRotation', () => {
  describe('generateInitialKeys', () => {
    it('should generate RSA key pair and encryption key', () => {
      const result = KeyRotation.generateInitialKeys(TEST_DIR);

      expect(existsSync(result.privateKeyPath)).toBe(true);
      expect(existsSync(result.publicKeyPath)).toBe(true);
      expect(result.encryptionKeyHex).toMatch(/^[0-9a-f]{64}$/);

      const privKey = readFileSync(result.privateKeyPath, 'utf8');
      expect(privKey).toContain('BEGIN PRIVATE KEY');

      const pubKey = readFileSync(result.publicKeyPath, 'utf8');
      expect(pubKey).toContain('BEGIN PUBLIC KEY');
    });

    it('should create directory if it does not exist', () => {
      const nested = `${TEST_DIR}/a/b/c`;
      KeyRotation.generateInitialKeys(nested);
      expect(existsSync(`${nested}/jwt_private.pem`)).toBe(true);
    });
  });

  describe('rotateKeys', () => {
    it('should create versioned key files', async () => {
      const rotation = new KeyRotation(
        { rotationIntervalMs: 99999999, keyDirectory: TEST_DIR },
        logger,
      );

      await rotation.rotateKeys();
      expect(rotation.getCurrentVersion()).toBe(1);
      expect(existsSync(`${TEST_DIR}/jwt_private_v1.pem`)).toBe(true);
      expect(existsSync(`${TEST_DIR}/jwt_public_v1.pem`)).toBe(true);
      expect(existsSync(`${TEST_DIR}/encryption_v1.key`)).toBe(true);

      await rotation.rotateKeys();
      expect(rotation.getCurrentVersion()).toBe(2);
      expect(existsSync(`${TEST_DIR}/jwt_private_v2.pem`)).toBe(true);
    });
  });

  describe('start / stop', () => {
    it('should start and stop without error', () => {
      const rotation = new KeyRotation(
        { rotationIntervalMs: 60000, keyDirectory: TEST_DIR },
        logger,
      );

      rotation.start();
      rotation.stop();
    });
  });
});
