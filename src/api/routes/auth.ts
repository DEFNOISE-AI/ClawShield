// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyInstance } from 'fastify';
import { hash, verify } from 'argon2';
import { eq } from 'drizzle-orm';
import { users } from '../../db/schema/users.js';
import { LoginSchema, RegisterSchema, RefreshTokenSchema } from '../schemas/auth.schema.js';
import { validateBody } from '../middlewares/validation.middleware.js';
import { createAuthMiddleware } from '../middlewares/auth.middleware.js';
import type { TokenManager } from '../../core/crypto/TokenManager.js';
import type { Database } from '../../db/client.js';
import { AuthError, ValidationError } from '../../utils/errors.js';

export async function authRoutes(
  fastify: FastifyInstance,
  opts: { db: Database; tokenManager: TokenManager },
): Promise<void> {
  const { db, tokenManager } = opts;

  // POST /auth/register
  fastify.post(
    '/auth/register',
    { preHandler: [validateBody(RegisterSchema)] },
    async (request, reply) => {
      const { username, password, role } = request.body as {
        username: string;
        password: string;
        role: string;
      };

      // Check if user exists
      const existing = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);

      if (existing.length > 0) {
        throw new ValidationError('Username already taken');
      }

      const passwordHash = await hash(password, {
        type: 2, // Argon2id
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
      });

      const [user] = await db
        .insert(users)
        .values({ username, passwordHash, role })
        .returning({ id: users.id, username: users.username, role: users.role });

      if (!user) {
        throw new Error('Failed to create user');
      }

      const tokens = tokenManager.generateTokenPair({
        userId: user.id,
        role: user.role,
      });

      return reply.status(201).send({
        user: { id: user.id, username: user.username, role: user.role },
        ...tokens,
      });
    },
  );

  // POST /auth/login
  fastify.post(
    '/auth/login',
    { preHandler: [validateBody(LoginSchema)] },
    async (request, reply) => {
      const { username, password } = request.body as {
        username: string;
        password: string;
      };

      const [user] = await db
        .select()
        .from(users)
        .where(eq(users.username, username))
        .limit(1);

      if (!user) {
        throw new AuthError('Invalid credentials');
      }

      const validPassword = await verify(user.passwordHash, password);
      if (!validPassword) {
        throw new AuthError('Invalid credentials');
      }

      const tokens = tokenManager.generateTokenPair({
        userId: user.id,
        role: user.role,
      });

      return reply.send({
        user: { id: user.id, username: user.username, role: user.role },
        ...tokens,
      });
    },
  );

  // POST /auth/refresh
  fastify.post(
    '/auth/refresh',
    { preHandler: [validateBody(RefreshTokenSchema)] },
    async (request, reply) => {
      const { refreshToken } = request.body as { refreshToken: string };

      try {
        const payload = await tokenManager.verifyAndCheckBlacklist(refreshToken);

        // Blacklist old refresh token
        await tokenManager.blacklistToken(refreshToken);

        const tokens = tokenManager.generateTokenPair({
          userId: payload.userId,
          role: payload.role,
        });

        return reply.send(tokens);
      } catch {
        throw new AuthError('Invalid refresh token');
      }
    },
  );

  // POST /auth/logout
  fastify.post(
    '/auth/logout',
    { preHandler: [createAuthMiddleware(tokenManager)] },
    async (request, reply) => {
      const authHeader = request.headers.authorization;
      if (authHeader) {
        const token = authHeader.slice(7);
        await tokenManager.blacklistToken(token);
      }
      return reply.send({ message: 'Logged out successfully' });
    },
  );
}
