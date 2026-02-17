import { z } from 'zod';

export const SkillSeverity = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export type SkillSeverity = z.infer<typeof SkillSeverity>;

export interface SkillVulnerability {
  type: string;
  severity: SkillSeverity;
  description: string;
  line?: number;
  column?: number;
}

export interface SkillAnalysisResult {
  safe: boolean;
  riskScore: number;
  reason?: string;
  vulnerabilities?: SkillVulnerability[];
  patterns?: string[];
  behavior?: string[];
  signature?: string;
  analysisTimeMs: number;
}

export interface StaticAnalysisResult {
  severity: SkillSeverity;
  vulnerabilities: SkillVulnerability[];
  suspiciousPatterns: string[];
}

export interface ASTAnalysisResult {
  safe: boolean;
  suspiciousPatterns: string[];
}

export interface DynamicAnalysisResult {
  safe: boolean;
  suspiciousBehavior: string[];
  executionTimeMs: number;
  memoryUsed: number;
  networkAttempts: string[];
  fsAttempts: string[];
}

export interface MalwareSignature {
  id: string;
  name: string;
  hash: string;
  pattern: string;
  severity: SkillSeverity;
  description: string;
}

export const AnalyzeSkillRequestSchema = z
  .object({
    code: z.string().min(1).max(500000),
    language: z.enum(['javascript', 'typescript']).default('javascript'),
    timeout: z.number().int().min(1000).max(30000).optional(),
  })
  .strict();

export type AnalyzeSkillRequest = z.infer<typeof AnalyzeSkillRequestSchema>;

export interface SandboxConfig {
  timeout: number;
  memoryLimit: number;
  networkAccess: boolean;
  fileSystemAccess: boolean;
}
