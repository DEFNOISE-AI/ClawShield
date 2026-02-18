// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { FastifyError, FastifyReply, FastifyRequest } from 'fastify';
import { AppError } from '../../utils/errors.js';
import type { Logger } from '../../utils/logger.js';

export function createErrorHandler(logger: Logger, isDev: boolean) {
  return function errorHandler(
    error: FastifyError,
    request: FastifyRequest,
    reply: FastifyReply,
  ): void {
    logger.error(
      {
        err: error,
        requestId: request.id,
        method: request.method,
        url: request.url,
      },
      'Request error',
    );

    if (error instanceof AppError) {
      reply.status(error.statusCode).send({
        error: {
          message: error.message,
          code: error.code,
          ...(isDev && { stack: error.stack }),
        },
        requestId: request.id,
      });
      return;
    }

    // Fastify validation errors
    if (error.validation) {
      reply.status(400).send({
        error: {
          message: 'Validation failed',
          code: 'VALIDATION_ERROR',
          details: isDev ? error.validation : undefined,
        },
        requestId: request.id,
      });
      return;
    }

    // Rate limit error
    if (error.statusCode === 429) {
      reply.status(429).send({
        error: {
          message: 'Rate limit exceeded',
          code: 'RATE_LIMIT_EXCEEDED',
        },
        requestId: request.id,
      });
      return;
    }

    // Generic error -- never leak details in production
    const statusCode = error.statusCode ?? 500;
    reply.status(statusCode).send({
      error: {
        message: isDev ? error.message : 'Internal Server Error',
        code: 'INTERNAL_ERROR',
        ...(isDev && { stack: error.stack }),
      },
      requestId: request.id,
    });
  };
}
