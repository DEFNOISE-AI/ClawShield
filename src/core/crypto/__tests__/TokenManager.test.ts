import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { TokenManager } from '../TokenManager.js';
import type { TokenManagerConfig } from '../TokenManager.js';

const TEST_KEYS_DIR = '/tmp/clawshield-test-keys';

const mockRedis = {
  get: vi.fn().mockResolvedValue(null),
  setex: vi.fn().mockResolvedValue('OK'),
};

let tokenManager: TokenManager;
let config: TokenManagerConfig;

beforeAll(() => {
  mkdirSync(TEST_KEYS_DIR, { recursive: true });

  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  writeFileSync(`${TEST_KEYS_DIR}/private.pem`, privateKey);
  writeFileSync(`${TEST_KEYS_DIR}/public.pem`, publicKey);

  config = {
    privateKeyPath: `${TEST_KEYS_DIR}/private.pem`,
    publicKeyPath: `${TEST_KEYS_DIR}/public.pem`,
    expiresIn: '15m',
    refreshExpiresIn: '7d',
    issuer: 'clawshield-test',
    audience: 'clawshield-api-test',
  };

  tokenManager = new TokenManager(config, mockRedis as never);
});

afterAll(() => {
  rmSync(TEST_KEYS_DIR, { recursive: true, force: true });
});

describe('TokenManager', () => {
  const testPayload = { userId: '123e4567-e89b-12d3-a456-426614174000', role: 'admin' };

  describe('signAccessToken / verifyToken', () => {
    it('should sign and verify an access token', () => {
      const token = tokenManager.signAccessToken(testPayload);
      const decoded = tokenManager.verifyToken(token);
      expect(decoded.userId).toBe(testPayload.userId);
      expect(decoded.role).toBe(testPayload.role);
      expect(decoded.iss).toBe(config.issuer);
      expect(decoded.aud).toBe(config.audience);
    });

    it('should reject a tampered token', () => {
      const token = tokenManager.signAccessToken(testPayload);
      const tampered = token.slice(0, -5) + 'XXXXX';
      expect(() => tokenManager.verifyToken(tampered)).toThrow();
    });

    it('should reject an expired token', () => {
      const expiredManager = new TokenManager(
        { ...config, expiresIn: '0s' },
        mockRedis as never,
      );
      const token = expiredManager.signAccessToken(testPayload);
      expect(() => expiredManager.verifyToken(token)).toThrow('expired');
    });
  });

  describe('signRefreshToken', () => {
    it('should sign a refresh token with type field', () => {
      const token = tokenManager.signRefreshToken(testPayload);
      const decoded = tokenManager.verifyToken(token);
      expect(decoded.userId).toBe(testPayload.userId);
      expect((decoded as Record<string, unknown>).type).toBe('refresh');
    });
  });

  describe('generateTokenPair', () => {
    it('should return both access and refresh tokens', () => {
      const pair = tokenManager.generateTokenPair(testPayload);
      expect(pair.accessToken).toBeDefined();
      expect(pair.refreshToken).toBeDefined();
      expect(pair.accessToken).not.toBe(pair.refreshToken);
    });
  });

  describe('blacklist', () => {
    it('should report non-blacklisted tokens correctly', async () => {
      mockRedis.get.mockResolvedValueOnce(null);
      const token = tokenManager.signAccessToken(testPayload);
      const result = await tokenManager.isBlacklisted(token);
      expect(result).toBe(false);
    });

    it('should blacklist a token and detect it', async () => {
      const token = tokenManager.signAccessToken(testPayload);

      await tokenManager.blacklistToken(token);
      expect(mockRedis.setex).toHaveBeenCalled();

      mockRedis.get.mockResolvedValueOnce('1');
      const result = await tokenManager.isBlacklisted(token);
      expect(result).toBe(true);
    });

    it('should reject blacklisted token in verifyAndCheckBlacklist', async () => {
      const token = tokenManager.signAccessToken(testPayload);
      mockRedis.get.mockResolvedValueOnce('1');
      await expect(tokenManager.verifyAndCheckBlacklist(token)).rejects.toThrow('revoked');
    });
  });

  describe('getPublicKey', () => {
    it('should return the PEM public key', () => {
      const pk = tokenManager.getPublicKey();
      expect(pk).toContain('BEGIN PUBLIC KEY');
    });
  });
});
