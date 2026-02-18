// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { hash } from 'argon2';
import { randomBytes } from 'node:crypto';
import { agents, agentCommunicationRules } from '../../db/schema/agents.js';
import {
  CreateAgentSchema,
  UpdateAgentSchema,
  CommunicationRuleSchema,
} from '../schemas/agent.schema.js';
import { validateBody } from '../middlewares/validation.middleware.js';
import { createAuthMiddleware } from '../middlewares/auth.middleware.js';
import type { TokenManager } from '../../core/crypto/TokenManager.js';
import type { Database } from '../../db/client.js';
import { NotFoundError } from '../../utils/errors.js';

export async function agentRoutes(
  fastify: FastifyInstance,
  opts: { db: Database; tokenManager: TokenManager },
): Promise<void> {
  const { db, tokenManager } = opts;
  const auth = createAuthMiddleware(tokenManager);

  // GET /agents - list all agents
  fastify.get('/agents', { preHandler: [auth] }, async (_request, reply) => {
    const allAgents = await db
      .select({
        id: agents.id,
        name: agents.name,
        endpoint: agents.endpoint,
        permissions: agents.permissions,
        status: agents.status,
        maxRequestsPerMinute: agents.maxRequestsPerMinute,
        createdAt: agents.createdAt,
      })
      .from(agents);

    return reply.send({ agents: allAgents });
  });

  // GET /agents/:id
  fastify.get('/agents/:id', { preHandler: [auth] }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const [agent] = await db
      .select({
        id: agents.id,
        name: agents.name,
        endpoint: agents.endpoint,
        permissions: agents.permissions,
        status: agents.status,
        maxRequestsPerMinute: agents.maxRequestsPerMinute,
        trustedDomains: agents.trustedDomains,
        metadata: agents.metadata,
        createdAt: agents.createdAt,
        updatedAt: agents.updatedAt,
      })
      .from(agents)
      .where(eq(agents.id, id))
      .limit(1);

    if (!agent) throw new NotFoundError('Agent');
    return reply.send(agent);
  });

  // POST /agents - create agent
  fastify.post(
    '/agents',
    { preHandler: [auth, validateBody(CreateAgentSchema)] },
    async (request, reply) => {
      const body = request.body as {
        name: string;
        endpoint: string;
        permissions: string[];
        maxRequestsPerMinute: number;
        trustedDomains: string[];
      };

      // Generate API key and hash it
      const apiKey = randomBytes(32).toString('hex');
      const apiKeyHash = await hash(apiKey, {
        type: 2,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
      });

      const [agent] = await db
        .insert(agents)
        .values({
          name: body.name,
          endpoint: body.endpoint,
          apiKeyHash,
          permissions: body.permissions,
          maxRequestsPerMinute: body.maxRequestsPerMinute,
          trustedDomains: body.trustedDomains,
        })
        .returning();

      if (!agent) throw new Error('Failed to create agent');

      return reply.status(201).send({
        agent: {
          id: agent.id,
          name: agent.name,
          endpoint: agent.endpoint,
          permissions: agent.permissions,
          status: agent.status,
        },
        apiKey, // Only returned once at creation
      });
    },
  );

  // PUT /agents/:id
  fastify.put(
    '/agents/:id',
    { preHandler: [auth, validateBody(UpdateAgentSchema)] },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const body = request.body as Record<string, unknown>;

      const [updated] = await db
        .update(agents)
        .set({ ...body, updatedAt: new Date() })
        .where(eq(agents.id, id))
        .returning();

      if (!updated) throw new NotFoundError('Agent');

      return reply.send({
        id: updated.id,
        name: updated.name,
        endpoint: updated.endpoint,
        permissions: updated.permissions,
        status: updated.status,
      });
    },
  );

  // DELETE /agents/:id
  fastify.delete('/agents/:id', { preHandler: [auth] }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const [deleted] = await db.delete(agents).where(eq(agents.id, id)).returning({ id: agents.id });

    if (!deleted) throw new NotFoundError('Agent');
    return reply.status(204).send();
  });

  // POST /agents/communication-rules
  fastify.post(
    '/agents/communication-rules',
    { preHandler: [auth, validateBody(CommunicationRuleSchema)] },
    async (request, reply) => {
      const body = request.body as {
        sourceAgentId: string;
        targetAgentId: string;
        enabled: boolean;
        maxMessagesPerMinute: number;
      };

      const [rule] = await db.insert(agentCommunicationRules).values(body).returning();

      if (!rule) throw new Error('Failed to create communication rule');
      return reply.status(201).send(rule);
    },
  );
}
