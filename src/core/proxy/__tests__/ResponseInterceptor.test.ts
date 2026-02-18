import { describe, it, expect } from 'vitest';
import { ResponseInterceptor } from '../ResponseInterceptor.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('silent');
const interceptor = new ResponseInterceptor(logger);

describe('ResponseInterceptor', () => {
  it('should pass a clean response', () => {
    const result = interceptor.inspectResponse(
      200,
      {
        'x-content-type-options': 'nosniff',
        'content-security-policy': "default-src 'self'",
      },
      '{"data": "safe content"}',
    );
    expect(result.safe).toBe(true);
    expect(result.issues).toHaveLength(0);
  });

  it('should detect API key leaks in body', () => {
    const result = interceptor.inspectResponse(
      200,
      { 'x-content-type-options': 'nosniff' },
      'Error: api_key=sk-abc123def456ghi789jkl012mno345pqr',
    );
    expect(result.safe).toBe(false);
    expect(result.issues.some((i) => i.includes('credential leak'))).toBe(true);
  });

  it('should detect GitHub token in response', () => {
    const result = interceptor.inspectResponse(
      200,
      { 'x-content-type-options': 'nosniff' },
      'token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789',
    );
    expect(result.safe).toBe(false);
  });

  it('should detect private key in response', () => {
    const result = interceptor.inspectResponse(
      200,
      { 'x-content-type-options': 'nosniff' },
      '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...',
    );
    expect(result.safe).toBe(false);
    expect(result.issues.some((i) => i.includes('credential leak'))).toBe(true);
  });

  it('should flag wildcard CORS', () => {
    const result = interceptor.inspectResponse(200, {
      'access-control-allow-origin': '*',
      'x-content-type-options': 'nosniff',
    });
    expect(result.safe).toBe(false);
    expect(result.issues.some((i) => i.includes('CORS'))).toBe(true);
  });

  it('should flag missing X-Content-Type-Options', () => {
    const result = interceptor.inspectResponse(200, {});
    expect(result.issues.some((i) => i.includes('X-Content-Type-Options'))).toBe(true);
  });

  it('should flag server version disclosure', () => {
    const result = interceptor.inspectResponse(200, {
      server: 'Apache/2.4.41',
      'x-content-type-options': 'nosniff',
    });
    expect(result.issues.some((i) => i.includes('Server version'))).toBe(true);
  });

  it('should flag stack traces in error responses', () => {
    const result = interceptor.inspectResponse(
      500,
      { 'x-content-type-options': 'nosniff' },
      'Error: something failed\n    at Object.<anonymous> (/app/server.js:10:3)\n    at Module._compile',
    );
    expect(result.issues.some((i) => i.includes('Stack trace'))).toBe(true);
  });

  it('should flag infrastructure details in errors', () => {
    const result = interceptor.inspectResponse(
      502,
      { 'x-content-type-options': 'nosniff' },
      'Error: connect ECONNREFUSED 10.0.0.5:5432',
    );
    expect(result.issues.some((i) => i.includes('infrastructure'))).toBe(true);
  });
});
