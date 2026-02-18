// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import Fastify, { type FastifyInstance } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import type { Redis } from 'ioredis';
import { createErrorHandler } from './middlewares/errorHandler.middleware.js';
import { registerGlobalRateLimit } from './middlewares/rateLimit.middleware.js';
import { healthRoutes } from './routes/health.js';
import { authRoutes } from './routes/auth.js';
import { agentRoutes } from './routes/agents.js';
import { ruleRoutes } from './routes/rules.js';
import { skillRoutes } from './routes/skills.js';
import { logRoutes } from './routes/logs.js';
import type { TokenManager } from '../core/crypto/TokenManager.js';
import type { SkillAnalyzer } from '../core/analyzer/SkillAnalyzer.js';
import type { Database } from '../db/client.js';
import type { Logger } from '../utils/logger.js';

export interface ServerDependencies {
  db: Database;
  redis: Redis;
  tokenManager: TokenManager;
  skillAnalyzer: SkillAnalyzer;
  logger: Logger;
}

export interface ServerConfig {
  port: number;
  host: string;
  isDev: boolean;
  corsOrigins: string[];
  rateLimitMax: number;
  rateLimitWindow: number;
}

export async function createServer(
  config: ServerConfig,
  deps: ServerDependencies,
): Promise<FastifyInstance> {
  const fastify = Fastify({
    logger: false,
    requestIdLogLabel: 'requestId',
    bodyLimit: 1048576,
    trustProxy: true,
  });

  // Security headers
  await fastify.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:', 'https:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        mediaSrc: ["'self'"],
        frameSrc: ["'none'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  });

  // CORS
  await fastify.register(cors, {
    origin: (origin, cb) => {
      const allowed = [
        ...config.corsOrigins,
        ...(config.isDev ? ['http://localhost:3000'] : []),
      ];
      if (!origin || allowed.includes(origin)) {
        cb(null, true);
      } else {
        cb(new Error('Not allowed by CORS'), false);
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    maxAge: 86400,
  });

  // Rate limiting
  await registerGlobalRateLimit(deps.redis, deps.redis, config.rateLimitMax, config.rateLimitWindow);

  // Request timing hook
  fastify.addHook('onRequest', async (request) => {
    (request as Record<string, unknown>).startTime = Date.now();
  });

  fastify.addHook('onResponse', async (request, reply) => {
    const startTime = (request as Record<string, unknown>).startTime as number;
    const duration = Date.now() - startTime;
    deps.logger.info(
      {
        method: request.method,
        url: request.url,
        statusCode: reply.statusCode,
        duration,
        requestId: request.id,
      },
      'Request completed',
    );
  });

  // Error handler
  fastify.setErrorHandler(createErrorHandler(deps.logger, config.isDev));

  // Routes
  await fastify.register(healthRoutes, { prefix: '', db: deps.db, redis: deps.redis });
  await fastify.register(authRoutes, { prefix: '', db: deps.db, tokenManager: deps.tokenManager });
  await fastify.register(agentRoutes, { prefix: '', db: deps.db, tokenManager: deps.tokenManager });
  await fastify.register(ruleRoutes, { prefix: '', db: deps.db, tokenManager: deps.tokenManager });
  await fastify.register(skillRoutes, {
    prefix: '',
    db: deps.db,
    tokenManager: deps.tokenManager,
    skillAnalyzer: deps.skillAnalyzer,
  });
  await fastify.register(logRoutes, { prefix: '', db: deps.db, tokenManager: deps.tokenManager });

  return fastify;
}
