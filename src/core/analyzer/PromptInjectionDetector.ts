export interface InjectionDetectionResult {
  detected: boolean;
  patterns: string[];
  confidence: number;
}

export class PromptInjectionDetector {
  private static readonly INJECTION_PATTERNS: Array<{ pattern: RegExp; name: string; weight: number }> = [
    { pattern: /ignore\s+(all\s+)?previous\s+instructions?/i, name: 'ignore_previous', weight: 0.9 },
    { pattern: /system\s*:\s*you\s+are/i, name: 'system_override', weight: 0.8 },
    { pattern: /\[INST\]/i, name: 'inst_token', weight: 0.7 },
    { pattern: /<\|im_start\|>/i, name: 'im_start_token', weight: 0.8 },
    { pattern: /\{\{system\}\}/i, name: 'template_system', weight: 0.7 },
    { pattern: /disregard\s+your\s+programming/i, name: 'disregard_programming', weight: 0.9 },
    { pattern: /override\s+your\s+rules/i, name: 'override_rules', weight: 0.9 },
    { pattern: /pretend\s+you\s+are/i, name: 'role_override', weight: 0.6 },
    { pattern: /new\s+instructions?\s*:/i, name: 'new_instructions', weight: 0.7 },
    { pattern: /forget\s+(all\s+)?(your\s+)?instructions?/i, name: 'forget_instructions', weight: 0.9 },
    { pattern: /you\s+are\s+now\s+a/i, name: 'identity_override', weight: 0.7 },
    { pattern: /act\s+as\s+(if|though)\s+you/i, name: 'act_as', weight: 0.5 },
    { pattern: /do\s+not\s+follow\s+(any|your)/i, name: 'no_follow', weight: 0.8 },
    { pattern: /bypass\s+(all\s+)?(safety|security|filter)/i, name: 'bypass_safety', weight: 0.9 },
    { pattern: /jailbreak/i, name: 'jailbreak_keyword', weight: 0.8 },
    { pattern: /DAN\s+mode/i, name: 'dan_mode', weight: 0.8 },
  ];

  detect(content: string): InjectionDetectionResult {
    if (!content || content.length === 0) {
      return { detected: false, patterns: [], confidence: 0 };
    }

    const matchedPatterns: string[] = [];
    let maxWeight = 0;

    for (const { pattern, name, weight } of PromptInjectionDetector.INJECTION_PATTERNS) {
      if (pattern.test(content)) {
        matchedPatterns.push(name);
        maxWeight = Math.max(maxWeight, weight);
      }
    }

    // Check for base64-encoded payloads
    const base64Result = this.detectBase64Encoded(content);
    if (base64Result.detected) {
      matchedPatterns.push(...base64Result.patterns.map((p) => `base64_${p}`));
      maxWeight = Math.max(maxWeight, base64Result.confidence);
    }

    // Check for unicode escape obfuscation
    const unicodeResult = this.detectUnicodeEscaped(content);
    if (unicodeResult.detected) {
      matchedPatterns.push('unicode_obfuscation');
      maxWeight = Math.max(maxWeight, unicodeResult.confidence);
    }

    // Calculate composite confidence
    const confidence =
      matchedPatterns.length === 0
        ? 0
        : Math.min(1, maxWeight + (matchedPatterns.length - 1) * 0.05);

    return {
      detected: matchedPatterns.length > 0,
      patterns: matchedPatterns,
      confidence,
    };
  }

  private detectBase64Encoded(content: string, depth = 0): InjectionDetectionResult {
    if (depth > 3) {
      return { detected: false, patterns: [], confidence: 0 };
    }

    const base64Regex = /[A-Za-z0-9+/]{40,}={0,2}/g;
    let match: RegExpExecArray | null;
    const allPatterns: string[] = [];
    let maxConf = 0;

    while ((match = base64Regex.exec(content)) !== null) {
      try {
        const decoded = Buffer.from(match[0], 'base64').toString('utf8');
        // Verify it's actually valid text
        if (/[\x00-\x08\x0e-\x1f]/.test(decoded)) continue;

        const innerResult = this.detect(decoded);
        if (innerResult.detected) {
          allPatterns.push(...innerResult.patterns);
          maxConf = Math.max(maxConf, innerResult.confidence);
        }
      } catch {
        // Not valid base64
      }
    }

    return { detected: allPatterns.length > 0, patterns: allPatterns, confidence: maxConf };
  }

  private detectUnicodeEscaped(content: string): InjectionDetectionResult {
    const unicodeEscapes = content.match(/\\u[0-9a-fA-F]{4}/g);
    if (!unicodeEscapes || unicodeEscapes.length < 5) {
      return { detected: false, patterns: [], confidence: 0 };
    }

    // Decode and re-check
    try {
      const decoded = content.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) =>
        String.fromCharCode(parseInt(hex, 16)),
      );
      const result = this.detect(decoded);
      return result;
    } catch {
      return { detected: false, patterns: [], confidence: 0 };
    }
  }
}
