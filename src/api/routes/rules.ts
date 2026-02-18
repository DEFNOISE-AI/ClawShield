// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { firewallRules } from '../../db/schema/rules.js';
import { CreateRuleSchema, UpdateRuleSchema } from '../schemas/rule.schema.js';
import { validateBody } from '../middlewares/validation.middleware.js';
import { createAuthMiddleware } from '../middlewares/auth.middleware.js';
import type { TokenManager } from '../../core/crypto/TokenManager.js';
import type { Database } from '../../db/client.js';
import { NotFoundError } from '../../utils/errors.js';

export async function ruleRoutes(
  fastify: FastifyInstance,
  opts: { db: Database; tokenManager: TokenManager },
): Promise<void> {
  const { db, tokenManager } = opts;
  const auth = createAuthMiddleware(tokenManager);

  // GET /rules
  fastify.get('/rules', { preHandler: [auth] }, async (_request, reply) => {
    const rules = await db.select().from(firewallRules);
    return reply.send({ rules });
  });

  // GET /rules/:id
  fastify.get('/rules/:id', { preHandler: [auth] }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const [rule] = await db.select().from(firewallRules).where(eq(firewallRules.id, id)).limit(1);
    if (!rule) throw new NotFoundError('Rule');
    return reply.send(rule);
  });

  // POST /rules
  fastify.post(
    '/rules',
    { preHandler: [auth, validateBody(CreateRuleSchema)] },
    async (request, reply) => {
      const body = request.body as {
        name: string;
        description: string;
        type: string;
        priority: number;
        enabled: boolean;
        conditions: unknown[];
        action: Record<string, unknown>;
      };

      const [rule] = await db
        .insert(firewallRules)
        .values({
          name: body.name,
          description: body.description,
          type: body.type,
          priority: body.priority,
          enabled: body.enabled,
          conditions: body.conditions as typeof firewallRules.$inferInsert.conditions,
          action: body.action as typeof firewallRules.$inferInsert.action,
        })
        .returning();

      if (!rule) throw new Error('Failed to create rule');
      return reply.status(201).send(rule);
    },
  );

  // PUT /rules/:id
  fastify.put(
    '/rules/:id',
    { preHandler: [auth, validateBody(UpdateRuleSchema)] },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      const body = request.body as Record<string, unknown>;

      const [updated] = await db
        .update(firewallRules)
        .set({ ...body, updatedAt: new Date() })
        .where(eq(firewallRules.id, id))
        .returning();

      if (!updated) throw new NotFoundError('Rule');
      return reply.send(updated);
    },
  );

  // DELETE /rules/:id
  fastify.delete('/rules/:id', { preHandler: [auth] }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const [deleted] = await db
      .delete(firewallRules)
      .where(eq(firewallRules.id, id))
      .returning({ id: firewallRules.id });

    if (!deleted) throw new NotFoundError('Rule');
    return reply.status(204).send();
  });
}
