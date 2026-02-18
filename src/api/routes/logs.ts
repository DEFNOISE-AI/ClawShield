// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import { desc, eq, and, gte, lte } from 'drizzle-orm';
import { z } from 'zod';
import { requestLogs } from '../../db/schema/logs.js';
import { threats } from '../../db/schema/threats.js';
import { validateQuery } from '../middlewares/validation.middleware.js';
import { createAuthMiddleware } from '../middlewares/auth.middleware.js';
import type { TokenManager } from '../../core/crypto/TokenManager.js';
import type { Database } from '../../db/client.js';

const LogQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  agentId: z.string().uuid().optional(),
  blocked: z.enum(['true', 'false']).optional(),
  from: z.string().datetime().optional(),
  to: z.string().datetime().optional(),
});

const ThreatQuerySchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  severity: z.enum(['low', 'medium', 'high', 'critical']).optional(),
  resolved: z.enum(['true', 'false']).optional(),
});

export async function logRoutes(
  fastify: FastifyInstance,
  opts: { db: Database; tokenManager: TokenManager },
): Promise<void> {
  const { db, tokenManager } = opts;
  const auth = createAuthMiddleware(tokenManager);

  // GET /logs/requests
  fastify.get(
    '/logs/requests',
    { preHandler: [auth, validateQuery(LogQuerySchema)] },
    async (request, reply) => {
      const query = request.query as z.infer<typeof LogQuerySchema>;
      const offset = (query.page - 1) * query.limit;

      const conditions = [];
      if (query.agentId) conditions.push(eq(requestLogs.agentId, query.agentId));
      if (query.blocked) conditions.push(eq(requestLogs.blocked, query.blocked));
      if (query.from) conditions.push(gte(requestLogs.createdAt, new Date(query.from)));
      if (query.to) conditions.push(lte(requestLogs.createdAt, new Date(query.to)));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const logs = await db
        .select()
        .from(requestLogs)
        .where(where)
        .orderBy(desc(requestLogs.createdAt))
        .limit(query.limit)
        .offset(offset);

      return reply.send({
        logs,
        pagination: { page: query.page, limit: query.limit },
      });
    },
  );

  // GET /logs/threats
  fastify.get(
    '/logs/threats',
    { preHandler: [auth, validateQuery(ThreatQuerySchema)] },
    async (request, reply) => {
      const query = request.query as z.infer<typeof ThreatQuerySchema>;
      const offset = (query.page - 1) * query.limit;

      const conditions = [];
      if (query.severity) conditions.push(eq(threats.severity, query.severity));
      if (query.resolved !== undefined) {
        conditions.push(eq(threats.resolved, query.resolved === 'true'));
      }

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const results = await db
        .select()
        .from(threats)
        .where(where)
        .orderBy(desc(threats.createdAt))
        .limit(query.limit)
        .offset(offset);

      return reply.send({
        threats: results,
        pagination: { page: query.page, limit: query.limit },
      });
    },
  );
}
