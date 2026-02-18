// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { Redis } from 'ioredis';
import type { Logger } from '../utils/logger.js';

export interface AgentHealthStatus {
  agentId: string;
  connected: boolean;
  lastSeen: number;
  requestCount: number;
  errorCount: number;
  avgResponseTime: number;
}

export class AgentMonitor {
  private monitorInterval: ReturnType<typeof setInterval> | null = null;
  private readonly HEALTH_KEY_PREFIX = 'agent:health:';
  private readonly METRICS_KEY_PREFIX = 'agent:metrics:';

  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger,
  ) {}

  start(intervalMs = 30000): void {
    this.monitorInterval = setInterval(() => {
      this.checkAgentHealth().catch((err) => {
        this.logger.error({ err }, 'Agent health check failed');
      });
    }, intervalMs);
    this.logger.info({ intervalMs }, 'Agent monitor started');
  }

  stop(): void {
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
      this.logger.info('Agent monitor stopped');
    }
  }

  async recordRequest(agentId: string, responseTimeMs: number, success: boolean): Promise<void> {
    const key = `${this.METRICS_KEY_PREFIX}${agentId}`;
    const pipeline = this.redis.pipeline();
    pipeline.hincrby(key, 'requestCount', 1);
    if (!success) {
      pipeline.hincrby(key, 'errorCount', 1);
    }
    pipeline.hset(key, 'lastSeen', Date.now().toString());
    pipeline.hset(key, 'lastResponseTime', responseTimeMs.toString());
    pipeline.expire(key, 3600);
    await pipeline.exec();
  }

  async getAgentHealth(agentId: string): Promise<AgentHealthStatus> {
    const key = `${this.METRICS_KEY_PREFIX}${agentId}`;
    const data = await this.redis.hgetall(key);

    return {
      agentId,
      connected: Boolean(data.lastSeen && Date.now() - Number(data.lastSeen) < 60000),
      lastSeen: Number(data.lastSeen ?? 0),
      requestCount: Number(data.requestCount ?? 0),
      errorCount: Number(data.errorCount ?? 0),
      avgResponseTime: Number(data.lastResponseTime ?? 0),
    };
  }

  async getAllAgentHealth(): Promise<AgentHealthStatus[]> {
    const keys = await this.redis.keys(`${this.METRICS_KEY_PREFIX}*`);
    const results: AgentHealthStatus[] = [];

    for (const key of keys) {
      const agentId = key.replace(this.METRICS_KEY_PREFIX, '');
      const health = await this.getAgentHealth(agentId);
      results.push(health);
    }

    return results;
  }

  private async checkAgentHealth(): Promise<void> {
    const agents = await this.getAllAgentHealth();
    const staleThreshold = Date.now() - 120_000; // 2 minutes

    for (const agent of agents) {
      if (agent.lastSeen > 0 && agent.lastSeen < staleThreshold) {
        this.logger.warn(
          { agentId: agent.agentId, lastSeen: agent.lastSeen },
          'Agent appears stale',
        );
      }

      if (agent.requestCount > 0) {
        const errorRate = agent.errorCount / agent.requestCount;
        if (errorRate > 0.5) {
          this.logger.warn(
            { agentId: agent.agentId, errorRate },
            'Agent has high error rate',
          );
        }
      }
    }
  }
}
