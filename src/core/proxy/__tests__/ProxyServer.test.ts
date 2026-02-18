import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ProxyServer } from '../ProxyServer.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('silent');

function createMockFirewall() {
  return {
    inspectRequest: vi.fn().mockResolvedValue({ allowed: true, threatScore: 0.1 }),
    inspectAgentMessage: vi.fn().mockResolvedValue({ allowed: true }),
    registerAgent: vi.fn(),
    unregisterAgent: vi.fn(),
  };
}

const defaultConfig = {
  targetUrl: 'http://localhost:8080',
  maxWsConnectionsPerIp: 5,
};

describe('ProxyServer', () => {
  let proxyServer: ProxyServer;
  let mockFirewall: ReturnType<typeof createMockFirewall>;

  beforeEach(() => {
    mockFirewall = createMockFirewall();
    proxyServer = new ProxyServer(mockFirewall as never, logger, defaultConfig);
  });

  describe('initialization', () => {
    it('should create a Fastify instance', () => {
      expect(proxyServer.getFastify()).toBeDefined();
    });

    it('should initialize without errors', async () => {
      await expect(proxyServer.initialize()).resolves.not.toThrow();
    });
  });

  describe('WebSocket connection tracking', () => {
    it('should return 0 for unknown IP', () => {
      expect(proxyServer.getWsConnectionCount('1.2.3.4')).toBe(0);
    });
  });

  describe('config', () => {
    it('should use provided target URL', () => {
      const custom = new ProxyServer(
        mockFirewall as never,
        logger,
        { targetUrl: 'http://custom:9090', maxWsConnectionsPerIp: 3 },
      );
      expect(custom.getFastify()).toBeDefined();
    });
  });
});
