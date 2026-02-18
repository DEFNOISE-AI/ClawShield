// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { createHash } from 'node:crypto';
import { StaticAnalyzer } from './StaticAnalyzer.js';
import { DynamicAnalyzer } from './DynamicAnalyzer.js';
import { PromptInjectionDetector } from './PromptInjectionDetector.js';
import type {
  SkillAnalysisResult,
  SandboxConfig,
  MalwareSignature,
} from '../../types/skill.types.js';
import type { Logger } from '../../utils/logger.js';

export class SkillAnalyzer {
  private readonly staticAnalyzer: StaticAnalyzer;
  private readonly dynamicAnalyzer: DynamicAnalyzer;
  private readonly promptDetector: PromptInjectionDetector;
  private malwareSignatures: MalwareSignature[] = [];

  constructor(private readonly logger: Logger) {
    this.staticAnalyzer = new StaticAnalyzer();
    this.dynamicAnalyzer = new DynamicAnalyzer();
    this.promptDetector = new PromptInjectionDetector();
  }

  setMalwareSignatures(signatures: MalwareSignature[]): void {
    this.malwareSignatures = signatures;
  }

  async analyzeSkill(
    skillCode: string,
    sandboxConfig?: Partial<SandboxConfig>,
  ): Promise<SkillAnalysisResult> {
    const startTime = Date.now();

    const config: SandboxConfig = {
      timeout: sandboxConfig?.timeout ?? 5000,
      memoryLimit: sandboxConfig?.memoryLimit ?? 50 * 1024 * 1024,
      networkAccess: false,
      fileSystemAccess: false,
    };

    // 1. Static analysis
    this.logger.debug('Starting static analysis');
    const staticResult = this.staticAnalyzer.analyze(skillCode);

    if (staticResult.severity === 'critical') {
      return {
        safe: false,
        riskScore: 1.0,
        reason: 'Critical vulnerabilities found in static analysis',
        vulnerabilities: staticResult.vulnerabilities,
        patterns: staticResult.suspiciousPatterns,
        analysisTimeMs: Date.now() - startTime,
      };
    }

    // 2. Prompt injection check in string literals
    this.logger.debug('Checking for prompt injection patterns');
    const injectionResult = this.promptDetector.detect(skillCode);
    if (injectionResult.detected && injectionResult.confidence > 0.7) {
      return {
        safe: false,
        riskScore: 0.9,
        reason: 'Prompt injection patterns found in skill code',
        patterns: injectionResult.patterns,
        analysisTimeMs: Date.now() - startTime,
      };
    }

    // 3. Dynamic analysis (sandbox)
    this.logger.debug('Starting dynamic analysis');
    const dynamicResult = await this.dynamicAnalyzer.execute(skillCode, config);

    if (!dynamicResult.safe) {
      return {
        safe: false,
        riskScore: 0.8,
        reason: 'Unsafe behavior detected during sandboxed execution',
        behavior: dynamicResult.suspiciousBehavior,
        patterns: [
          ...dynamicResult.networkAttempts.map((n) => `Network: ${n}`),
          ...dynamicResult.fsAttempts.map((f) => `FS: ${f}`),
        ],
        analysisTimeMs: Date.now() - startTime,
      };
    }

    // 4. Malware signature check
    this.logger.debug('Checking malware signatures');
    const signatureMatch = this.checkMalwareSignatures(skillCode);
    if (signatureMatch) {
      return {
        safe: false,
        riskScore: 1.0,
        reason: 'Matches known malware signature',
        signature: signatureMatch.name,
        analysisTimeMs: Date.now() - startTime,
      };
    }

    // Calculate composite risk score
    const riskScore = this.calculateRiskScore(staticResult, dynamicResult, injectionResult);

    return {
      safe: riskScore < 0.5,
      riskScore,
      vulnerabilities: staticResult.vulnerabilities,
      patterns: staticResult.suspiciousPatterns,
      analysisTimeMs: Date.now() - startTime,
    };
  }

  private checkMalwareSignatures(code: string): MalwareSignature | null {
    const codeHash = createHash('sha256').update(code).digest('hex');

    for (const sig of this.malwareSignatures) {
      if (sig.hash === codeHash) return sig;
      try {
        if (new RegExp(sig.pattern).test(code)) return sig;
      } catch {
        // Invalid pattern
      }
    }

    return null;
  }

  private calculateRiskScore(
    staticResult: { severity: string; vulnerabilities: { severity: string }[] },
    dynamicResult: {
      suspiciousBehavior: string[];
      networkAttempts: string[];
      fsAttempts: string[];
    },
    injectionResult: { confidence: number },
  ): number {
    let score = 0;

    // Static analysis weight
    const severityWeights: Record<string, number> = {
      critical: 0.5,
      high: 0.3,
      medium: 0.15,
      low: 0.05,
      info: 0,
    };
    for (const v of staticResult.vulnerabilities) {
      score += severityWeights[v.severity] ?? 0;
    }

    // Dynamic analysis weight
    score += dynamicResult.networkAttempts.length * 0.1;
    score += dynamicResult.fsAttempts.length * 0.1;
    score += dynamicResult.suspiciousBehavior.length * 0.15;

    // Injection weight
    score += injectionResult.confidence * 0.3;

    return Math.min(1, score);
  }

  getCodeHash(code: string): string {
    return createHash('sha256').update(code).digest('hex');
  }
}
