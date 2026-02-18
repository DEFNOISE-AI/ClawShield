import { describe, it, expect, beforeEach, vi } from 'vitest';
import { MetricsCollector } from '../MetricsCollector.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('silent');

function createMockRedis() {
  return {
    incr: vi.fn().mockResolvedValue(1),
    keys: vi.fn().mockResolvedValue([]),
    del: vi.fn().mockResolvedValue(1),
    pipeline: vi.fn().mockReturnValue({
      incr: vi.fn().mockReturnThis(),
      get: vi.fn().mockReturnThis(),
      keys: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([
        [null, '42'],
        [null, '5'],
        [null, '3'],
        [null, []],
      ]),
    }),
  };
}

describe('MetricsCollector', () => {
  let metrics: MetricsCollector;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockRedis = createMockRedis();
    metrics = new MetricsCollector(mockRedis as never, logger);
  });

  describe('recordRequest', () => {
    it('should increment total_requests counter', async () => {
      await metrics.recordRequest(false, 50);
      const pipeline = mockRedis.pipeline();
      expect(mockRedis.pipeline).toHaveBeenCalled();
    });

    it('should increment blocked_requests for blocked request', async () => {
      await metrics.recordRequest(true, 100);
      expect(mockRedis.pipeline).toHaveBeenCalled();
    });
  });

  describe('recordThreat', () => {
    it('should increment total_threats counter', async () => {
      await metrics.recordThreat();
      expect(mockRedis.incr).toHaveBeenCalledWith('metrics:total_threats');
    });
  });

  describe('getMetrics', () => {
    it('should return system metrics from Redis', async () => {
      const result = await metrics.getMetrics();
      expect(result).toHaveProperty('totalRequests');
      expect(result).toHaveProperty('blockedRequests');
      expect(result).toHaveProperty('totalThreats');
      expect(result).toHaveProperty('activeAgents');
      expect(result).toHaveProperty('avgResponseTimeMs');
      expect(result).toHaveProperty('uptime');
      expect(result.uptime).toBeGreaterThan(0);
    });

    it('should calculate average response time from recorded requests', async () => {
      await metrics.recordRequest(false, 100);
      await metrics.recordRequest(false, 200);
      const result = await metrics.getMetrics();
      expect(result.avgResponseTimeMs).toBe(150);
    });
  });

  describe('reset', () => {
    it('should delete all metrics keys and clear response times', async () => {
      mockRedis.keys.mockResolvedValueOnce(['metrics:total_requests', 'metrics:total_threats']);
      await metrics.reset();
      expect(mockRedis.del).toHaveBeenCalledWith('metrics:total_requests', 'metrics:total_threats');
    });

    it('should handle empty keys gracefully', async () => {
      mockRedis.keys.mockResolvedValueOnce([]);
      await expect(metrics.reset()).resolves.not.toThrow();
      expect(mockRedis.del).not.toHaveBeenCalled();
    });
  });
});
