import { z } from 'zod';

export const AgentPermission = z.enum(['read', 'write', 'execute', 'admin']);
export type AgentPermission = z.infer<typeof AgentPermission>;

export const AgentStatus = z.enum(['active', 'inactive', 'blocked', 'quarantined']);
export type AgentStatus = z.infer<typeof AgentStatus>;

export const AgentConfigSchema = z
  .object({
    id: z.string().uuid(),
    name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9_-]+$/),
    endpoint: z.string().url(),
    apiKey: z.string().min(32).max(256),
    permissions: z.array(AgentPermission).max(10),
    status: AgentStatus.default('active'),
    maxRequestsPerMinute: z.number().int().min(1).max(10000).default(100),
    trustedDomains: z.array(z.string().min(1)).default([]),
    metadata: z.record(z.string()).optional(),
  })
  .strict();

export type AgentConfig = z.infer<typeof AgentConfigSchema>;

export const AgentMessageSchema = z
  .object({
    type: z.enum([
      'sessions_send',
      'sessions_spawn',
      'sessions_reply',
      'api_call',
      'skill_execute',
      'ping',
    ]),
    content: z.string().max(100000).optional(),
    targetAgentId: z.string().uuid().optional(),
    url: z.string().url().optional(),
    headers: z.record(z.string()).optional(),
    body: z.string().max(1048576).optional(),
    metadata: z.record(z.unknown()).optional(),
  })
  .strict();

export type AgentMessage = z.infer<typeof AgentMessageSchema>;

export interface AgentContext {
  id: string;
  name: string;
  status: AgentStatus;
  permissions: AgentPermission[];
  trustedDomains: string[];
  maxRequestsPerMinute: number;
  requestCount: number;
  lastSeen: number;
  createdAt: number;
  threatScore: number;
  recentMessages: string[];
  connectedAt?: number;
  ipAddress?: string;
}

export const CreateAgentSchema = z
  .object({
    name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9_-]+$/),
    endpoint: z.string().url(),
    permissions: z.array(AgentPermission).min(1).max(10),
    maxRequestsPerMinute: z.number().int().min(1).max(10000).default(100),
    trustedDomains: z.array(z.string().min(1)).default([]),
  })
  .strict();

export type CreateAgent = z.infer<typeof CreateAgentSchema>;

export const UpdateAgentSchema = z
  .object({
    name: z.string().min(1).max(100).regex(/^[a-zA-Z0-9_-]+$/).optional(),
    endpoint: z.string().url().optional(),
    permissions: z.array(AgentPermission).min(1).max(10).optional(),
    status: AgentStatus.optional(),
    maxRequestsPerMinute: z.number().int().min(1).max(10000).optional(),
    trustedDomains: z.array(z.string().min(1)).optional(),
  })
  .strict();

export type UpdateAgent = z.infer<typeof UpdateAgentSchema>;

export const CommunicationRuleSchema = z
  .object({
    sourceAgentId: z.string().uuid(),
    targetAgentId: z.string().uuid(),
    enabled: z.boolean().default(true),
    maxMessagesPerMinute: z.number().int().min(1).max(1000).default(50),
  })
  .strict();

export type CommunicationRule = z.infer<typeof CommunicationRuleSchema>;
