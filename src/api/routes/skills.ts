// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import { eq } from 'drizzle-orm';
import { analyzedSkills } from '../../db/schema/skills.js';
import { AnalyzeSkillRequestSchema } from '../schemas/skill.schema.js';
import { validateBody } from '../middlewares/validation.middleware.js';
import { createAuthMiddleware } from '../middlewares/auth.middleware.js';
import type { TokenManager } from '../../core/crypto/TokenManager.js';
import type { Database } from '../../db/client.js';
import type { SkillAnalyzer } from '../../core/analyzer/SkillAnalyzer.js';

export async function skillRoutes(
  fastify: FastifyInstance,
  opts: { db: Database; tokenManager: TokenManager; skillAnalyzer: SkillAnalyzer },
): Promise<void> {
  const { db, tokenManager, skillAnalyzer } = opts;
  const auth = createAuthMiddleware(tokenManager);

  // POST /skills/analyze
  fastify.post(
    '/skills/analyze',
    { preHandler: [auth, validateBody(AnalyzeSkillRequestSchema)] },
    async (request, reply) => {
      const { code, timeout } = request.body as {
        code: string;
        language: string;
        timeout?: number;
      };

      // Check cache by code hash
      const codeHash = skillAnalyzer.getCodeHash(code);
      const [cached] = await db
        .select()
        .from(analyzedSkills)
        .where(eq(analyzedSkills.codeHash, codeHash))
        .limit(1);

      if (cached) {
        return reply.send({
          cached: true,
          result: {
            safe: cached.safe,
            riskScore: cached.riskScore,
            reason: cached.reason,
            vulnerabilities: cached.vulnerabilities,
            patterns: cached.patterns,
          },
        });
      }

      // Run analysis
      const result = await skillAnalyzer.analyzeSkill(code, {
        timeout: timeout ?? 5000,
      });

      // Cache result
      await db.insert(analyzedSkills).values({
        codeHash,
        safe: result.safe,
        riskScore: result.riskScore,
        reason: result.reason ?? null,
        vulnerabilities: result.vulnerabilities ?? [],
        patterns: result.patterns ?? [],
        analysisTimeMs: result.analysisTimeMs,
      });

      return reply.send({ cached: false, result });
    },
  );

  // GET /skills/analysis/:hash
  fastify.get('/skills/analysis/:hash', { preHandler: [auth] }, async (request, reply) => {
    const { hash } = request.params as { hash: string };
    const [result] = await db
      .select()
      .from(analyzedSkills)
      .where(eq(analyzedSkills.codeHash, hash))
      .limit(1);

    if (!result) {
      return reply.status(404).send({ error: 'Analysis not found' });
    }

    return reply.send(result);
  });
}
