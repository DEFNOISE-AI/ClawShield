// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { Logger } from '../../utils/logger.js';

export interface ResponseInspectionResult {
  safe: boolean;
  issues: string[];
}

export class ResponseInterceptor {
  private readonly credentialPatterns = [
    /(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})/gi,
    /(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"]{8,})/gi,
    /(?:secret|token)\s*[:=]\s*['"]?([a-zA-Z0-9_-]{20,})/gi,
    /(?:aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?([A-Z0-9]{16,})/gi,
    /(?:sk-|pk_live_|pk_test_|rk_live_|rk_test_)[a-zA-Z0-9]{20,}/g,
    /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{30,}/g,
    /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
  ];

  constructor(private readonly logger: Logger) {}

  inspectResponse(
    statusCode: number,
    headers: Record<string, string | string[] | undefined>,
    body?: string,
  ): ResponseInspectionResult {
    const issues: string[] = [];

    // Check for credential leaks in response body
    if (body) {
      for (const pattern of this.credentialPatterns) {
        pattern.lastIndex = 0;
        if (pattern.test(body)) {
          issues.push(`Potential credential leak detected (pattern: ${pattern.source.slice(0, 30)}...)`);
          pattern.lastIndex = 0;
        }
      }
    }

    // Check for overly permissive CORS in response
    const accessControlOrigin = headers['access-control-allow-origin'];
    if (accessControlOrigin === '*') {
      issues.push('Response has wildcard CORS origin (access-control-allow-origin: *)');
    }

    // Check for missing security headers
    if (!headers['x-content-type-options']) {
      issues.push('Missing X-Content-Type-Options header');
    }
    if (!headers['x-frame-options'] && !headers['content-security-policy']) {
      issues.push('Missing X-Frame-Options or CSP header');
    }

    // Check for server info disclosure
    const server = headers['server'];
    if (typeof server === 'string' && /nginx|apache|iis|express/i.test(server)) {
      issues.push(`Server version disclosure: ${server}`);
    }

    // Check for sensitive error details in response
    if (body && statusCode >= 500) {
      if (/\bat\s+\S+\s+\(.*:\d+:\d+\)/.test(body) || (body.includes('stack') && body.includes('at '))) {
        issues.push('Stack trace exposed in error response');
      }
      if (/ECONNREFUSED|ENOTFOUND|ETIMEDOUT/.test(body)) {
        issues.push('Internal infrastructure details exposed in error');
      }
    }

    if (issues.length > 0) {
      this.logger.warn({ statusCode, issueCount: issues.length }, 'Response inspection found issues');
    }

    return {
      safe: issues.length === 0,
      issues,
    };
  }
}
