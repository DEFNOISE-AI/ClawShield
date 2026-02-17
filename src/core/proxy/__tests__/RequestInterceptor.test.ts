import { describe, it, expect, vi } from 'vitest';
import { RequestInterceptor } from '../RequestInterceptor.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('silent');

describe('RequestInterceptor', () => {
  const mockFirewall = {
    inspectRequest: vi.fn().mockResolvedValue({ allowed: true, threatScore: 0.1 }),
  };

  const interceptor = new RequestInterceptor(mockFirewall as never, logger);

  describe('extractRequest', () => {
    it('should extract agent ID from x-agent-id header', () => {
      const mockRequest = {
        headers: { 'x-agent-id': 'agent-123', 'content-type': 'application/json' },
        method: 'POST',
        url: '/api/test',
        body: '{"data": "test"}',
        ip: '127.0.0.1',
      };
      const result = interceptor.extractRequest(mockRequest as never);
      expect(result.agentId).toBe('agent-123');
      expect(result.method).toBe('POST');
      expect(result.path).toBe('/api/test');
    });

    it('should extract agent ID from x-clawshield-agent-id header', () => {
      const mockRequest = {
        headers: { 'x-clawshield-agent-id': 'agent-456' },
        method: 'GET',
        url: '/api/data',
        ip: '10.0.0.1',
      };
      const result = interceptor.extractRequest(mockRequest as never);
      expect(result.agentId).toBe('agent-456');
    });

    it('should stringify object body', () => {
      const mockRequest = {
        headers: {},
        method: 'POST',
        url: '/api/test',
        body: { key: 'value' },
        ip: '127.0.0.1',
      };
      const result = interceptor.extractRequest(mockRequest as never);
      expect(result.body).toBe('{"key":"value"}');
    });
  });

  describe('buildProxyHeaders', () => {
    it('should inject ClawShield headers', () => {
      const result = interceptor.buildProxyHeaders(
        { 'content-type': 'application/json' },
        'req-123',
        0.2,
      );
      expect(result['x-clawshield-request-id']).toBe('req-123');
      expect(result['x-clawshield-threat-score']).toBe('0.2');
      expect(result['x-clawshield-inspected']).toBe('true');
    });

    it('should remove hop-by-hop headers', () => {
      const result = interceptor.buildProxyHeaders(
        {
          'content-type': 'application/json',
          connection: 'keep-alive',
          'keep-alive': 'timeout=5',
          'transfer-encoding': 'chunked',
        },
        'req-456',
      );
      expect(result.connection).toBeUndefined();
      expect(result['keep-alive']).toBeUndefined();
      expect(result['transfer-encoding']).toBeUndefined();
      expect(result['content-type']).toBe('application/json');
    });
  });

  describe('inspect', () => {
    it('should delegate to firewall inspectRequest', async () => {
      const mockRequest = {
        headers: { 'x-agent-id': 'agent-1' },
        method: 'GET',
        url: '/api/test',
        ip: '127.0.0.1',
      };
      const result = await interceptor.inspect(mockRequest as never);
      expect(result.allowed).toBe(true);
      expect(mockFirewall.inspectRequest).toHaveBeenCalled();
    });
  });
});
