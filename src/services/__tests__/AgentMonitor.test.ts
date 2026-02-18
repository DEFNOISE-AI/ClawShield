import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { AgentMonitor } from '../AgentMonitor.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('silent');

function createMockRedis() {
  return {
    hgetall: vi.fn().mockResolvedValue({}),
    hincrby: vi.fn().mockResolvedValue(1),
    hset: vi.fn().mockResolvedValue(1),
    expire: vi.fn().mockResolvedValue(1),
    keys: vi.fn().mockResolvedValue([]),
    pipeline: vi.fn().mockReturnValue({
      hincrby: vi.fn().mockReturnThis(),
      hset: vi.fn().mockReturnThis(),
      expire: vi.fn().mockReturnThis(),
      exec: vi.fn().mockResolvedValue([]),
    }),
  };
}

describe('AgentMonitor', () => {
  let monitor: AgentMonitor;
  let mockRedis: ReturnType<typeof createMockRedis>;

  beforeEach(() => {
    mockRedis = createMockRedis();
    monitor = new AgentMonitor(mockRedis as never, logger);
  });

  afterEach(() => {
    monitor.stop();
  });

  describe('start/stop', () => {
    it('should start and stop without errors', () => {
      monitor.start(60000);
      monitor.stop();
    });

    it('should handle multiple stops gracefully', () => {
      monitor.start(60000);
      monitor.stop();
      monitor.stop();
    });
  });

  describe('recordRequest', () => {
    it('should record a successful request', async () => {
      await monitor.recordRequest('agent-1', 50, true);
      expect(mockRedis.pipeline).toHaveBeenCalled();
    });

    it('should record a failed request with error increment', async () => {
      await monitor.recordRequest('agent-1', 100, false);
      expect(mockRedis.pipeline).toHaveBeenCalled();
    });
  });

  describe('getAgentHealth', () => {
    it('should return default health for unknown agent', async () => {
      const health = await monitor.getAgentHealth('unknown');
      expect(health.agentId).toBe('unknown');
      expect(health.connected).toBe(false);
      expect(health.requestCount).toBe(0);
      expect(health.errorCount).toBe(0);
    });

    it('should return connected=true for recently seen agent', async () => {
      mockRedis.hgetall.mockResolvedValueOnce({
        lastSeen: String(Date.now()),
        requestCount: '10',
        errorCount: '1',
        lastResponseTime: '42',
      });

      const health = await monitor.getAgentHealth('active-agent');
      expect(health.connected).toBe(true);
      expect(health.requestCount).toBe(10);
      expect(health.errorCount).toBe(1);
    });

    it('should return connected=false for stale agent', async () => {
      mockRedis.hgetall.mockResolvedValueOnce({
        lastSeen: String(Date.now() - 120_000),
        requestCount: '5',
        errorCount: '0',
        lastResponseTime: '100',
      });

      const health = await monitor.getAgentHealth('stale-agent');
      expect(health.connected).toBe(false);
    });
  });

  describe('getAllAgentHealth', () => {
    it('should return empty array when no agents', async () => {
      const result = await monitor.getAllAgentHealth();
      expect(result).toEqual([]);
    });

    it('should return health for all registered agents', async () => {
      mockRedis.keys.mockResolvedValueOnce(['agent:metrics:a1', 'agent:metrics:a2']);
      mockRedis.hgetall
        .mockResolvedValueOnce({ lastSeen: String(Date.now()), requestCount: '5', errorCount: '0', lastResponseTime: '30' })
        .mockResolvedValueOnce({ lastSeen: String(Date.now()), requestCount: '3', errorCount: '1', lastResponseTime: '50' });

      const result = await monitor.getAllAgentHealth();
      expect(result).toHaveLength(2);
      expect(result[0].agentId).toBe('a1');
      expect(result[1].agentId).toBe('a2');
    });
  });
});
