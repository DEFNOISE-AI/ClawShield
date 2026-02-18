// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import type { Redis } from 'ioredis';

export async function registerGlobalRateLimit(
  fastify: FastifyInstance,
  redis: Redis,
  max = 100,
  timeWindow = 60000,
): Promise<void> {
  await fastify.register(rateLimit, {
    max,
    timeWindow,
    cache: 10000,
    redis,
    keyGenerator: (request) => {
      return (request.headers['x-forwarded-for'] as string) ?? request.ip;
    },
    errorResponseBuilder: (_request, context) => ({
      error: {
        message: 'Rate limit exceeded',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: context.after,
      },
    }),
  });
}

export function sensitiveRouteRateLimit(redis: Redis) {
  return {
    config: {
      rateLimit: {
        max: 5,
        timeWindow: 60000,
        redis,
        keyGenerator: (request: { headers: Record<string, string | undefined>; ip: string }) => {
          return request.headers['x-forwarded-for'] ?? request.ip;
        },
      },
    },
  };
}
