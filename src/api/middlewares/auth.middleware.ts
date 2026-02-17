import type { FastifyReply, FastifyRequest } from 'fastify';
import type { TokenManager } from '../../core/crypto/TokenManager.js';
import { AuthError } from '../../utils/errors.js';

declare module 'fastify' {
  interface FastifyRequest {
    user?: {
      userId: string;
      role: string;
    };
  }
}

export function createAuthMiddleware(tokenManager: TokenManager) {
  return async function authMiddleware(
    request: FastifyRequest,
    _reply: FastifyReply,
  ): Promise<void> {
    const authHeader = request.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      throw new AuthError('Missing or invalid Authorization header');
    }

    const token = authHeader.slice(7);

    if (!token) {
      throw new AuthError('Empty token');
    }

    try {
      const payload = await tokenManager.verifyAndCheckBlacklist(token);
      request.user = {
        userId: payload.userId,
        role: payload.role,
      };
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Token verification failed';
      throw new AuthError(message);
    }
  };
}

export function requireRole(...roles: string[]) {
  return async function roleMiddleware(
    request: FastifyRequest,
    _reply: FastifyReply,
  ): Promise<void> {
    if (!request.user) {
      throw new AuthError('Not authenticated');
    }
    if (!roles.includes(request.user.role)) {
      throw new AuthError('Insufficient permissions', 'FORBIDDEN');
    }
  };
}
