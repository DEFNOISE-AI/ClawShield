// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { z } from 'zod';

const ConfigSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('production'),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().min(1).default('0.0.0.0'),

  DATABASE_URL: z.string().url().startsWith('postgresql://'),
  DATABASE_POOL_MIN: z.coerce.number().int().min(1).default(2),
  DATABASE_POOL_MAX: z.coerce.number().int().min(1).default(10),

  REDIS_URL: z.string().min(1).default('redis://localhost:6379'),
  REDIS_CACHE_TTL: z.coerce.number().int().min(1).default(3600),

  JWT_PRIVATE_KEY_PATH: z.string().min(1),
  JWT_PUBLIC_KEY_PATH: z.string().min(1),
  JWT_EXPIRES_IN: z.string().default('15m'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),
  JWT_ISSUER: z.string().default('clawshield'),
  JWT_AUDIENCE: z.string().default('clawshield-api'),

  ENCRYPTION_KEY: z
    .string()
    .regex(/^[0-9a-fA-F]{64}$/, 'Must be a 64-char hex string (32 bytes)')
    .transform((v) => Buffer.from(v, 'hex')),

  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),
  RATE_LIMIT_WINDOW: z.coerce.number().int().min(1000).default(60000),

  FIREWALL_THREAT_THRESHOLD: z.coerce.number().min(0).max(1).default(0.8),
  FIREWALL_BLOCK_DURATION: z.coerce.number().int().min(1).default(3600),
  FIREWALL_MAX_WS_CONNECTIONS_PER_IP: z.coerce.number().int().min(1).default(5),

  SKILL_ANALYSIS_TIMEOUT: z.coerce.number().int().min(1000).default(5000),
  SKILL_ANALYSIS_MEMORY_LIMIT: z.coerce.number().int().min(1048576).default(52428800),

  OPENCLAW_TARGET_URL: z.string().url().default('http://localhost:8080'),

  SENTRY_DSN: z.string().optional(),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  ALERT_WEBHOOK_URL: z.string().url().optional().or(z.literal('')),

  CORS_ALLOWED_ORIGINS: z
    .string()
    .default('https://dashboard.clawshield.io')
    .transform((v) => v.split(',')),
});

export type Config = z.infer<typeof ConfigSchema>;

let _config: Config | null = null;

export function loadConfig(env: Record<string, string | undefined> = process.env): Config {
  const result = ConfigSchema.safeParse(env);

  if (!result.success) {
    const formatted = result.error.format();
    const messages = Object.entries(formatted)
      .filter(([key]) => key !== '_errors')
      .map(([key, value]) => {
        const errors = (value as { _errors?: string[] })?._errors ?? [];
        return `  ${key}: ${errors.join(', ')}`;
      })
      .join('\n');

    throw new Error(`Invalid environment configuration:\n${messages}`);
  }

  _config = result.data;
  return _config;
}

export function getConfig(): Config {
  if (!_config) {
    throw new Error('Config not loaded. Call loadConfig() first.');
  }
  return _config;
}
