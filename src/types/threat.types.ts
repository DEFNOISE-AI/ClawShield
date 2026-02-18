// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { z } from 'zod';

export const ThreatLevel = z.enum(['low', 'medium', 'high', 'critical', 'unknown']);
export type ThreatLevel = z.infer<typeof ThreatLevel>;

export const ThreatType = z.enum([
  'rule_violation',
  'high_threat_score',
  'prompt_injection',
  'data_exfiltration',
  'unauthorized_agent_communication',
  'infinite_loop',
  'rate_limit_exceeded',
  'malware_detected',
  'credential_leak',
  'websocket_abuse',
  'unknown',
]);
export type ThreatType = z.infer<typeof ThreatType>;

export interface InspectionResult {
  allowed: boolean;
  reason?: string;
  threatLevel?: ThreatLevel;
  threatScore?: number;
  targetUrl?: string;
}

export interface ThreatEvent {
  id: string;
  agentId: string;
  threatType: ThreatType;
  threatLevel: ThreatLevel;
  details: Record<string, unknown>;
  timestamp: Date;
  resolved: boolean;
}

export interface FirewallRule {
  id: string;
  name: string;
  description: string;
  type: 'allow' | 'deny' | 'conditional';
  priority: number;
  enabled: boolean;
  conditions: RuleCondition[];
  action: RuleAction;
}

export interface RuleCondition {
  field: string;
  operator: 'eq' | 'neq' | 'contains' | 'regex' | 'gt' | 'lt' | 'in';
  value: string | number | string[];
}

export interface RuleAction {
  type: 'allow' | 'deny' | 'log' | 'alert' | 'quarantine';
  message?: string;
  duration?: number;
}

export const CreateRuleSchema = z
  .object({
    name: z.string().min(1).max(200),
    description: z.string().max(1000).default(''),
    type: z.enum(['allow', 'deny', 'conditional']),
    priority: z.number().int().min(0).max(1000).default(100),
    enabled: z.boolean().default(true),
    conditions: z
      .array(
        z.object({
          field: z.string().min(1),
          operator: z.enum(['eq', 'neq', 'contains', 'regex', 'gt', 'lt', 'in']),
          value: z.union([z.string(), z.number(), z.array(z.string())]),
        }),
      )
      .min(1),
    action: z.object({
      type: z.enum(['allow', 'deny', 'log', 'alert', 'quarantine']),
      message: z.string().max(500).optional(),
      duration: z.number().int().min(0).optional(),
    }),
  })
  .strict();

export type CreateRule = z.infer<typeof CreateRuleSchema>;

export const UpdateRuleSchema = CreateRuleSchema.partial().strict();
export type UpdateRule = z.infer<typeof UpdateRuleSchema>;

export interface AlertPayload {
  type: string;
  agentId: string;
  threatType: string;
  details: Record<string, unknown>;
  timestamp?: Date;
}
