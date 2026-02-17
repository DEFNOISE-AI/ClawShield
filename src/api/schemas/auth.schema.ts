import { z } from 'zod';

export const LoginSchema = z
  .object({
    username: z.string().min(1).max(100),
    password: z.string().min(8).max(256),
  })
  .strict();

export type LoginInput = z.infer<typeof LoginSchema>;

export const RegisterSchema = z
  .object({
    username: z
      .string()
      .min(3)
      .max(100)
      .regex(/^[a-zA-Z0-9_-]+$/, 'Username must be alphanumeric with underscores/hyphens'),
    password: z
      .string()
      .min(12)
      .max(256)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/,
        'Password must contain lowercase, uppercase, digit, and special character',
      ),
    role: z.enum(['admin', 'operator', 'viewer']).default('operator'),
  })
  .strict();

export type RegisterInput = z.infer<typeof RegisterSchema>;

export const RefreshTokenSchema = z
  .object({
    refreshToken: z.string().min(1),
  })
  .strict();

export type RefreshTokenInput = z.infer<typeof RefreshTokenSchema>;
