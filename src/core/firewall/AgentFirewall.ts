// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { and, eq } from 'drizzle-orm';
import type { Redis } from 'ioredis';
import { createHash } from 'node:crypto';
import { RuleEngine } from './RuleEngine.js';
import { ThreatDetector } from './ThreatDetector.js';
import { agents as agentsTable, agentCommunicationRules } from '../../db/schema/agents.js';
import { threats } from '../../db/schema/threats.js';
import type { Database } from '../../db/client.js';
import type { Logger } from '../../utils/logger.js';
import type { AgentContext, AgentMessage } from '../../types/agent.types.js';
import { AgentMessageSchema } from '../../types/agent.types.js';
import type { InspectionResult, AlertPayload } from '../../types/threat.types.js';
import type { ThreatLevel } from '../../types/threat.types.js';

export interface FirewallConfig {
  threatThreshold: number;
  blockDuration: number;
  maxWsConnectionsPerIp: number;
}

export class AgentFirewall {
  private readonly ruleEngine: RuleEngine;
  private readonly threatDetector: ThreatDetector;
  private readonly agentRegistry: Map<string, AgentContext> = new Map();
  private alertHandler: ((payload: AlertPayload) => Promise<void>) | null = null;

  constructor(
    private readonly db: Database,
    private readonly redis: Redis,
    private readonly logger: Logger,
    private readonly config: FirewallConfig,
  ) {
    this.ruleEngine = new RuleEngine(db, logger);
    this.threatDetector = new ThreatDetector(logger);
  }

  setAlertHandler(handler: (payload: AlertPayload) => Promise<void>): void {
    this.alertHandler = handler;
  }

  async initialize(): Promise<void> {
    await this.ruleEngine.loadRules();
    this.logger.info('Agent firewall initialized');
  }

  async inspectRequest(params: {
    agentId?: string;
    method: string;
    path: string;
    body?: string;
    headers?: Record<string, string>;
    ip?: string;
  }): Promise<InspectionResult> {
    const startTime = Date.now();
    const { agentId, method, path, body, headers, ip } = params;

    try {
      // 1. Rate limiting check
      if (agentId) {
        const rateLimitOk = await this.checkRateLimit(agentId);
        if (!rateLimitOk) {
          return { allowed: false, reason: 'Rate limit exceeded', threatLevel: 'medium' };
        }
      }

      // 2. Check blacklist
      if (agentId && (await this.isBlacklisted(agentId))) {
        return { allowed: false, reason: 'Agent is blacklisted', threatLevel: 'critical' };
      }

      // 3. Apply firewall rules
      const ruleContext: Record<string, unknown> = {
        method,
        path,
        body: body ?? '',
        ip: ip ?? '',
        agentId: agentId ?? '',
        content: body ?? '',
      };
      if (headers) {
        ruleContext.headers = headers;
      }

      const ruleResult = await this.ruleEngine.evaluate(ruleContext);
      if (!ruleResult.allowed) {
        if (agentId) {
          await this.logThreat(agentId, 'rule_violation', ruleResult.reason ?? 'Rule violation', {
            method,
            path,
          });
        }
        return ruleResult;
      }

      // 4. Threat detection
      const agentCtx = agentId ? this.agentRegistry.get(agentId) : undefined;
      const threatResult = this.threatDetector.analyze({
        agentId,
        method,
        path,
        body,
        headers,
        ip,
        requestCount: agentCtx?.requestCount,
      });

      if (threatResult.score > this.config.threatThreshold) {
        if (agentId) {
          await this.logThreat(agentId, 'high_threat_score', 'Suspicious activity detected', {
            threatScore: threatResult.score,
          });
        }
        return {
          allowed: false,
          reason: 'Suspicious activity detected',
          threatLevel: 'high',
          threatScore: threatResult.score,
        };
      }

      // 5. Update context
      if (agentId) {
        this.updateAgentContext(agentId);
      }

      const duration = Date.now() - startTime;
      this.logger.debug({ agentId, duration }, 'Request inspection completed');

      return { allowed: true, threatScore: threatResult.score };
    } catch (error) {
      this.logger.error({ err: error }, 'Request inspection error');
      // FAIL CLOSED
      return { allowed: false, reason: 'Inspection error', threatLevel: 'unknown' };
    }
  }

  async inspectAgentMessage(agentId: string, message: unknown): Promise<InspectionResult> {
    // 1. Validate message structure
    const validated = AgentMessageSchema.safeParse(message);
    if (!validated.success) {
      return { allowed: false, reason: 'Invalid message format', threatLevel: 'low' };
    }
    const msg = validated.data;

    // 2. Agent-to-agent communication check
    if ((msg.type === 'sessions_send' || msg.type === 'sessions_spawn') && msg.targetAgentId) {
      const allowed = await this.checkAgentToAgentCommunication(agentId, msg.targetAgentId);
      if (!allowed) {
        await this.logThreat(
          agentId,
          'unauthorized_agent_communication',
          'Unauthorized agent-to-agent communication',
          {
            targetAgentId: msg.targetAgentId,
          },
        );
        return {
          allowed: false,
          reason: 'Unauthorized agent-to-agent communication',
          threatLevel: 'high',
        };
      }
    }

    // 3. Infinite loop detection
    if (await this.detectLoop(agentId, msg)) {
      return { allowed: false, reason: 'Infinite loop detected', threatLevel: 'medium' };
    }

    // 4. Prompt injection detection
    if (msg.content) {
      const injected = this.detectPromptInjection(msg.content);
      if (injected) {
        await this.logThreat(agentId, 'prompt_injection', 'Prompt injection detected', {
          contentSnippet: msg.content.slice(0, 200),
        });
        return { allowed: false, reason: 'Prompt injection detected', threatLevel: 'critical' };
      }
    }

    // 5. Data exfiltration detection
    if (await this.detectExfiltration(agentId, msg)) {
      return {
        allowed: false,
        reason: 'Data exfiltration attempt detected',
        threatLevel: 'critical',
      };
    }

    return { allowed: true };
  }

  async checkAgentToAgentCommunication(
    sourceAgentId: string,
    targetAgentId: string,
  ): Promise<boolean> {
    const allowed = await this.db
      .select()
      .from(agentCommunicationRules)
      .where(
        and(
          eq(agentCommunicationRules.sourceAgentId, sourceAgentId),
          eq(agentCommunicationRules.targetAgentId, targetAgentId),
          eq(agentCommunicationRules.enabled, true),
        ),
      )
      .limit(1);

    return allowed.length > 0;
  }

  async detectLoop(agentId: string, message: AgentMessage): Promise<boolean> {
    const cacheKey = `agent:${agentId}:messages`;
    const messageHash = this.hashMessage(message);

    const recentMessages = await this.redis.lrange(cacheKey, 0, 9);
    const duplicates = recentMessages.filter((m) => m === messageHash);

    if (duplicates.length >= 3) {
      return true;
    }

    await this.redis.lpush(cacheKey, messageHash);
    await this.redis.ltrim(cacheKey, 0, 9);
    await this.redis.expire(cacheKey, 300);

    return false;
  }

  detectPromptInjection(content: string): boolean {
    const injectionPatterns = [
      /ignore\s+(all\s+)?previous\s+instructions?/i,
      /system\s*:\s*you\s+are/i,
      /\[INST\]/i,
      /<\|im_start\|>/i,
      /\{\{system\}\}/i,
      /disregard\s+your\s+programming/i,
      /override\s+your\s+rules/i,
      /pretend\s+you\s+are/i,
      /new\s+instructions?\s*:/i,
      /forget\s+(all\s+)?(your\s+)?instructions?/i,
    ];

    for (const pattern of injectionPatterns) {
      if (pattern.test(content)) {
        return true;
      }
    }

    // Check for base64-encoded payloads
    try {
      const decoded = Buffer.from(content, 'base64').toString('utf8');
      if (decoded !== content && decoded.length > 10) {
        const looksLikeBase64 = /^[A-Za-z0-9+/]+=*$/.test(content.trim());
        if (looksLikeBase64) {
          return this.detectPromptInjection(decoded);
        }
      }
    } catch {
      // Not valid base64
    }

    return false;
  }

  async detectExfiltration(agentId: string, message: AgentMessage): Promise<boolean> {
    if (message.type !== 'api_call' || !message.url) return false;

    try {
      const parsed = new URL(message.url);
      const domain = parsed.hostname;

      // Check for large data uploads to external domains
      if (message.body && message.body.length > 100_000) {
        const trusted = await this.isTrustedDomain(agentId, domain);
        if (!trusted) {
          await this.logThreat(
            agentId,
            'data_exfiltration',
            'Large data upload to untrusted domain',
            {
              domain,
              bodySize: message.body.length,
            },
          );
          return true;
        }
      }

      // Check for sensitive data patterns in outgoing body
      if (message.body) {
        const sensitivePatterns = [
          /api[_-]?key\s*[:=]\s*\S+/i,
          /password\s*[:=]\s*\S+/i,
          /secret\s*[:=]\s*\S+/i,
          /token\s*[:=]\s*\S+/i,
          /private[_-]?key/i,
        ];

        for (const pattern of sensitivePatterns) {
          if (pattern.test(message.body)) {
            const trusted = await this.isTrustedDomain(agentId, domain);
            if (!trusted) {
              return true;
            }
          }
        }
      }
    } catch {
      // Invalid URL
    }

    return false;
  }

  async isBlacklisted(agentId: string): Promise<boolean> {
    const result = await this.redis.get(`agent:blacklist:${agentId}`);
    return result !== null;
  }

  async blacklistAgent(agentId: string, durationSeconds?: number): Promise<void> {
    const ttl = durationSeconds ?? this.config.blockDuration;
    await this.redis.setex(`agent:blacklist:${agentId}`, ttl, '1');
    this.logger.warn({ agentId, ttl }, 'Agent blacklisted');
  }

  registerAgent(agentId: string, context: Partial<AgentContext>): void {
    const existing = this.agentRegistry.get(agentId);
    this.agentRegistry.set(agentId, {
      id: agentId,
      name: context.name ?? agentId,
      status: context.status ?? 'active',
      permissions: context.permissions ?? [],
      trustedDomains: context.trustedDomains ?? existing?.trustedDomains ?? [],
      maxRequestsPerMinute: context.maxRequestsPerMinute ?? existing?.maxRequestsPerMinute ?? 100,
      requestCount: existing?.requestCount ?? 0,
      lastSeen: Date.now(),
      createdAt: existing?.createdAt ?? Date.now(),
      threatScore: existing?.threatScore ?? 0,
      recentMessages: existing?.recentMessages ?? [],
      connectedAt: context.connectedAt ?? Date.now(),
      ipAddress: context.ipAddress,
    });
  }

  async loadAgentFromDb(agentId: string): Promise<AgentContext | null> {
    const [row] = await this.db
      .select({
        id: agentsTable.id,
        name: agentsTable.name,
        status: agentsTable.status,
        permissions: agentsTable.permissions,
        trustedDomains: agentsTable.trustedDomains,
        maxRequestsPerMinute: agentsTable.maxRequestsPerMinute,
      })
      .from(agentsTable)
      .where(eq(agentsTable.id, agentId))
      .limit(1);

    if (!row) return null;

    const ctx: AgentContext = {
      id: row.id,
      name: row.name,
      status: (row.status as AgentContext['status']) ?? 'active',
      permissions: (row.permissions as AgentContext['permissions']) ?? [],
      trustedDomains: row.trustedDomains ?? [],
      maxRequestsPerMinute: row.maxRequestsPerMinute,
      requestCount: 0,
      lastSeen: Date.now(),
      createdAt: Date.now(),
      threatScore: 0,
      recentMessages: [],
    };

    this.agentRegistry.set(agentId, ctx);
    return ctx;
  }

  unregisterAgent(agentId: string): void {
    this.agentRegistry.delete(agentId);
  }

  getAgentContext(agentId: string): AgentContext | undefined {
    return this.agentRegistry.get(agentId);
  }

  private async checkRateLimit(agentId: string): Promise<boolean> {
    let ctx = this.agentRegistry.get(agentId);
    if (!ctx) {
      ctx = (await this.loadAgentFromDb(agentId)) ?? undefined;
    }
    const limit = ctx?.maxRequestsPerMinute ?? 100;

    const key = `agent:ratelimit:${agentId}`;
    const count = await this.redis.incr(key);
    if (count === 1) {
      await this.redis.expire(key, 60);
    }
    return count <= limit;
  }

  private async isTrustedDomain(agentId: string, domain: string): Promise<boolean> {
    let ctx = this.agentRegistry.get(agentId);
    if (!ctx) {
      ctx = (await this.loadAgentFromDb(agentId)) ?? undefined;
    }
    if (!ctx || ctx.trustedDomains.length === 0) return false;

    const normalizedDomain = domain.toLowerCase();
    return ctx.trustedDomains.some((trusted) => {
      const normalizedTrusted = trusted.toLowerCase();
      return (
        normalizedDomain === normalizedTrusted || normalizedDomain.endsWith(`.${normalizedTrusted}`)
      );
    });
  }

  private updateAgentContext(agentId: string): void {
    const ctx = this.agentRegistry.get(agentId);
    if (ctx) {
      ctx.requestCount++;
      ctx.lastSeen = Date.now();
    }
  }

  private hashMessage(message: AgentMessage): string {
    const content = JSON.stringify({
      type: message.type,
      content: message.content,
      targetAgentId: message.targetAgentId,
    });
    return createHash('sha256').update(content).digest('hex').slice(0, 16);
  }

  private async logThreat(
    agentId: string,
    threatType: string,
    description: string,
    details: Record<string, unknown>,
  ): Promise<void> {
    const severity = this.calculateSeverity(threatType);

    try {
      await this.db.insert(threats).values({
        agentId,
        threatType,
        severity,
        details: { ...details, description },
      });
    } catch (error) {
      this.logger.error({ err: error }, 'Failed to log threat to database');
    }

    if (severity === 'critical' && this.alertHandler) {
      await this.alertHandler({
        type: 'critical_threat',
        agentId,
        threatType,
        details,
      }).catch((err) => {
        this.logger.error({ err }, 'Failed to send alert');
      });
    }
  }

  private calculateSeverity(threatType: string): ThreatLevel {
    const severityMap: Record<string, ThreatLevel> = {
      rule_violation: 'medium',
      high_threat_score: 'high',
      prompt_injection: 'critical',
      data_exfiltration: 'critical',
      unauthorized_agent_communication: 'high',
      infinite_loop: 'medium',
      rate_limit_exceeded: 'low',
      malware_detected: 'critical',
      credential_leak: 'critical',
      websocket_abuse: 'medium',
    };
    return severityMap[threatType] ?? 'unknown';
  }
}
