import { describe, it, expect } from 'vitest';
import { ThreatDetector } from '../ThreatDetector.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('silent');
const detector = new ThreatDetector(logger);

describe('ThreatDetector', () => {
  it('should return 0 score for benign request', () => {
    const result = detector.analyze({
      method: 'GET',
      path: '/api/health',
      body: '{"status":"ok"}',
    });
    expect(result.score).toBe(0);
  });

  it('should detect path traversal', () => {
    const result = detector.analyze({
      path: '/api/files/../../../etc/passwd',
      body: '',
    });
    expect(result.score).toBeGreaterThan(0);
    expect(result.factors.some((f) => f.name === 'path_path_traversal' && f.triggered)).toBe(true);
  });

  it('should detect XSS attempts in body', () => {
    const result = detector.analyze({
      body: '<script>alert("xss")</script>',
    });
    expect(result.score).toBeGreaterThan(0);
    expect(result.factors.some((f) => f.name === 'xss_attempt' && f.triggered)).toBe(true);
  });

  it('should detect SQL injection', () => {
    const result = detector.analyze({
      body: "1' UNION SELECT * FROM users --",
    });
    expect(result.score).toBeGreaterThan(0);
    expect(result.factors.some((f) => f.name === 'sql_injection' && f.triggered)).toBe(true);
  });

  it('should detect SQL DROP TABLE', () => {
    const result = detector.analyze({
      body: '; DROP TABLE users;',
    });
    expect(result.score).toBeGreaterThan(0.5);
  });

  it('should flag suspicious headers', () => {
    const result = detector.analyze({
      headers: { 'x-forwarded-host': 'evil.com' },
    });
    expect(result.factors.some((f) => f.name === 'suspicious_header' && f.triggered)).toBe(true);
  });

  it('should flag rate anomaly', () => {
    const result = detector.analyze({
      requestCount: 100,
      timeSinceLastRequest: 50,
    });
    expect(result.factors.some((f) => f.name === 'rate_anomaly' && f.triggered)).toBe(true);
  });

  it('should flag large payloads', () => {
    const result = detector.analyze({
      body: 'A'.repeat(600_000),
    });
    expect(result.factors.some((f) => f.name === 'large_payload' && f.triggered)).toBe(true);
  });

  it('should detect child_process require', () => {
    const result = detector.analyze({
      body: "const cp = require('child_process');",
    });
    expect(result.score).toBeGreaterThan(0);
  });

  it('should cap score at 1', () => {
    const result = detector.analyze({
      path: '/../../etc/passwd',
      body: '<script>alert(1)</script> UNION SELECT; DROP TABLE users; require("child_process").exec("rm -rf /")',
    });
    expect(result.score).toBeLessThanOrEqual(1);
  });
});
