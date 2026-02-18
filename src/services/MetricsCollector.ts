// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { Redis } from 'ioredis';
import type { Logger } from '../utils/logger.js';

export interface SystemMetrics {
  totalRequests: number;
  blockedRequests: number;
  totalThreats: number;
  activeAgents: number;
  avgResponseTimeMs: number;
  uptime: number;
}

export class MetricsCollector {
  private readonly METRICS_PREFIX = 'metrics:';
  private requestTimes: number[] = [];
  private readonly MAX_REQUEST_TIMES = 1000;

  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger,
  ) {}

  async recordRequest(blocked: boolean, responseTimeMs: number): Promise<void> {
    const pipeline = this.redis.pipeline();
    pipeline.incr(`${this.METRICS_PREFIX}total_requests`);
    if (blocked) {
      pipeline.incr(`${this.METRICS_PREFIX}blocked_requests`);
    }
    await pipeline.exec();

    this.requestTimes.push(responseTimeMs);
    if (this.requestTimes.length > this.MAX_REQUEST_TIMES) {
      this.requestTimes = this.requestTimes.slice(-this.MAX_REQUEST_TIMES);
    }
  }

  async recordThreat(): Promise<void> {
    await this.redis.incr(`${this.METRICS_PREFIX}total_threats`);
  }

  async getMetrics(): Promise<SystemMetrics> {
    const pipeline = this.redis.pipeline();
    pipeline.get(`${this.METRICS_PREFIX}total_requests`);
    pipeline.get(`${this.METRICS_PREFIX}blocked_requests`);
    pipeline.get(`${this.METRICS_PREFIX}total_threats`);
    pipeline.keys('agent:metrics:*');

    const results = await pipeline.exec();
    if (!results) {
      return {
        totalRequests: 0,
        blockedRequests: 0,
        totalThreats: 0,
        activeAgents: 0,
        avgResponseTimeMs: 0,
        uptime: process.uptime(),
      };
    }

    const totalRequests = Number(results[0]?.[1] ?? 0);
    const blockedRequests = Number(results[1]?.[1] ?? 0);
    const totalThreats = Number(results[2]?.[1] ?? 0);
    const agentKeys = (results[3]?.[1] as string[] | null) ?? [];

    const avgResponseTimeMs =
      this.requestTimes.length > 0
        ? this.requestTimes.reduce((a, b) => a + b, 0) / this.requestTimes.length
        : 0;

    return {
      totalRequests,
      blockedRequests,
      totalThreats,
      activeAgents: agentKeys.length,
      avgResponseTimeMs: Math.round(avgResponseTimeMs * 100) / 100,
      uptime: process.uptime(),
    };
  }

  async reset(): Promise<void> {
    const keys = await this.redis.keys(`${this.METRICS_PREFIX}*`);
    if (keys.length > 0) {
      await this.redis.del(...keys);
    }
    this.requestTimes = [];
    this.logger.info('Metrics reset');
  }
}
