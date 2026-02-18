// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { Logger } from '../../utils/logger.js';

export interface ThreatAnalysisContext {
  agentId?: string;
  method?: string;
  path?: string;
  body?: string;
  headers?: Record<string, string>;
  ip?: string;
  requestCount?: number;
  timeSinceLastRequest?: number;
}

export interface ThreatAnalysisResult {
  score: number;
  factors: ThreatFactor[];
}

export interface ThreatFactor {
  name: string;
  weight: number;
  triggered: boolean;
  detail?: string;
}

export class ThreatDetector {
  private readonly suspiciousPatterns = [
    { pattern: /\.\.\//g, name: 'path_traversal', weight: 0.3 },
    { pattern: /<script[^>]*>/gi, name: 'xss_attempt', weight: 0.4 },
    { pattern: /union\s+select/gi, name: 'sql_injection', weight: 0.5 },
    { pattern: /;\s*drop\s+table/gi, name: 'sql_drop', weight: 0.9 },
    { pattern: /\$\{.*\}/g, name: 'template_injection', weight: 0.3 },
    { pattern: /process\.env/gi, name: 'env_access', weight: 0.4 },
    { pattern: /child_process/gi, name: 'command_exec', weight: 0.6 },
    { pattern: /require\s*\(\s*['"]child_process['"]\s*\)/gi, name: 'require_child_process', weight: 0.8 },
    { pattern: /exec\s*\(/gi, name: 'exec_call', weight: 0.5 },
  ];

  private readonly suspiciousHeaders = new Set([
    'x-forwarded-host',
    'x-original-url',
    'x-rewrite-url',
  ]);

  constructor(private readonly logger: Logger) {}

  analyze(context: ThreatAnalysisContext): ThreatAnalysisResult {
    const factors: ThreatFactor[] = [];

    // Pattern matching on body
    if (context.body) {
      for (const { pattern, name, weight } of this.suspiciousPatterns) {
        const triggered = pattern.test(context.body);
        pattern.lastIndex = 0; // Reset regex state
        factors.push({ name, weight, triggered, detail: triggered ? 'Found in request body' : undefined });
      }
    }

    // Pattern matching on path
    if (context.path) {
      for (const { pattern, name, weight } of this.suspiciousPatterns) {
        const triggered = pattern.test(context.path);
        pattern.lastIndex = 0;
        if (triggered) {
          factors.push({ name: `path_${name}`, weight, triggered, detail: 'Found in URL path' });
        }
      }
    }

    // Suspicious headers
    if (context.headers) {
      for (const header of Object.keys(context.headers)) {
        if (this.suspiciousHeaders.has(header.toLowerCase())) {
          factors.push({
            name: 'suspicious_header',
            weight: 0.2,
            triggered: true,
            detail: `Suspicious header: ${header}`,
          });
        }
      }
    }

    // Rate anomaly detection
    if (context.requestCount !== undefined && context.timeSinceLastRequest !== undefined) {
      if (context.requestCount > 50 && context.timeSinceLastRequest < 1000) {
        factors.push({
          name: 'rate_anomaly',
          weight: 0.3,
          triggered: true,
          detail: `${context.requestCount} requests, ${context.timeSinceLastRequest}ms interval`,
        });
      }
    }

    // Large payload detection
    if (context.body && context.body.length > 500_000) {
      factors.push({
        name: 'large_payload',
        weight: 0.2,
        triggered: true,
        detail: `Payload size: ${context.body.length}`,
      });
    }

    // Calculate composite score
    const triggeredFactors = factors.filter((f) => f.triggered);
    let score = 0;
    for (const factor of triggeredFactors) {
      score = Math.min(1, score + factor.weight * (1 - score));
    }

    if (score > 0.5) {
      this.logger.warn(
        { agentId: context.agentId, score, factors: triggeredFactors.map((f) => f.name) },
        'Elevated threat score detected',
      );
    }

    return { score, factors };
  }
}
