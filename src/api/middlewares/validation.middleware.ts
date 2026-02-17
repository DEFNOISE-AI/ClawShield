import type { FastifyReply, FastifyRequest } from 'fastify';
import { type ZodSchema, ZodError } from 'zod';
import { ValidationError } from '../../utils/errors.js';

export function validateBody(schema: ZodSchema) {
  return async function bodyValidation(
    request: FastifyRequest,
    _reply: FastifyReply,
  ): Promise<void> {
    try {
      request.body = schema.parse(request.body);
    } catch (error) {
      if (error instanceof ZodError) {
        throw new ValidationError('Request body validation failed', error.errors);
      }
      throw error;
    }
  };
}

export function validateQuery(schema: ZodSchema) {
  return async function queryValidation(
    request: FastifyRequest,
    _reply: FastifyReply,
  ): Promise<void> {
    try {
      request.query = schema.parse(request.query) as typeof request.query;
    } catch (error) {
      if (error instanceof ZodError) {
        throw new ValidationError('Query parameter validation failed', error.errors);
      }
      throw error;
    }
  };
}

export function validateParams(schema: ZodSchema) {
  return async function paramsValidation(
    request: FastifyRequest,
    _reply: FastifyReply,
  ): Promise<void> {
    try {
      request.params = schema.parse(request.params) as typeof request.params;
    } catch (error) {
      if (error instanceof ZodError) {
        throw new ValidationError('Path parameter validation failed', error.errors);
      }
      throw error;
    }
  };
}
