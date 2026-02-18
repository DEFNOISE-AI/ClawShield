// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import type { Redis } from 'ioredis';
import type { Database } from '../../db/client.js';

export async function healthRoutes(
  fastify: FastifyInstance,
  opts: { db: Database; redis: Redis },
): Promise<void> {
  fastify.get('/health', async (_request, reply) => {
    return reply.send({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
    });
  });

  fastify.get('/health/ready', async (_request, reply) => {
    const checks: Record<string, string> = {};

    // Check database
    try {
      await opts.db.execute({ sql: 'SELECT 1' } as never);
      checks.database = 'ok';
    } catch {
      checks.database = 'error';
    }

    // Check Redis
    try {
      await opts.redis.ping();
      checks.redis = 'ok';
    } catch {
      checks.redis = 'error';
    }

    const allOk = Object.values(checks).every((v) => v === 'ok');
    const statusCode = allOk ? 200 : 503;

    return reply.status(statusCode).send({
      status: allOk ? 'ready' : 'degraded',
      checks,
      timestamp: new Date().toISOString(),
    });
  });
}
