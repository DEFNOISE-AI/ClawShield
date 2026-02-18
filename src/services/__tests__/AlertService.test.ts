import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AlertService } from '../AlertService.js';
import { createLogger } from '../../utils/logger.js';

const logger = createLogger('silent');

describe('AlertService', () => {
  const basePayload = {
    type: 'critical_threat' as const,
    agentId: 'agent-1',
    threatType: 'prompt_injection',
    details: { content: 'malicious' },
  };

  describe('without webhook', () => {
    it('should log alert without sending webhook', async () => {
      const service = new AlertService({}, logger);
      await expect(service.sendAlert(basePayload)).resolves.not.toThrow();
    });
  });

  describe('with webhook', () => {
    let service: AlertService;

    beforeEach(() => {
      service = new AlertService({ webhookUrl: 'https://hooks.example.com/alert' }, logger);
    });

    it('should POST to webhook URL', async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal('fetch', mockFetch);

      await service.sendAlert(basePayload);

      expect(mockFetch).toHaveBeenCalledOnce();
      const [url, opts] = mockFetch.mock.calls[0];
      expect(url).toBe('https://hooks.example.com/alert');
      expect(opts.method).toBe('POST');
      expect(opts.headers['Content-Type']).toBe('application/json');

      const body = JSON.parse(opts.body);
      expect(body.text).toContain('ClawShield Alert');
      expect(body.text).toContain('agent-1');

      vi.unstubAllGlobals();
    });

    it('should handle webhook failure gracefully', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));

      await expect(service.sendAlert(basePayload)).resolves.not.toThrow();

      vi.unstubAllGlobals();
    });

    it('should handle network error gracefully', async () => {
      vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network down')));

      await expect(service.sendAlert(basePayload)).resolves.not.toThrow();

      vi.unstubAllGlobals();
    });
  });

  describe('payload enrichment', () => {
    it('should add timestamp and source to payload', async () => {
      const mockFetch = vi.fn().mockResolvedValue({ ok: true });
      vi.stubGlobal('fetch', mockFetch);

      const service = new AlertService({ webhookUrl: 'https://hooks.example.com/alert' }, logger);
      await service.sendAlert(basePayload);

      const body = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(body.attachments[0].fields).toBeDefined();

      vi.unstubAllGlobals();
    });
  });
});
