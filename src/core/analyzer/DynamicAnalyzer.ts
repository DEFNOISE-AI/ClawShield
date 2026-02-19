// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { createContext, runInContext, type Context } from 'node:vm';
import type { DynamicAnalysisResult, SandboxConfig } from '../../types/skill.types.js';

const MAX_BUFFER_ALLOC = 1024 * 1024; // 1MB per allocation

function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') return obj;
  if (Object.isFrozen(obj)) return obj;
  Object.freeze(obj);
  for (const key of Object.getOwnPropertyNames(obj)) {
    const desc = Object.getOwnPropertyDescriptor(obj, key);
    if (desc?.value && typeof desc.value === 'object') deepFreeze(desc.value);
  }
  return obj;
}

export class DynamicAnalyzer {
  async execute(code: string, config: SandboxConfig): Promise<DynamicAnalysisResult> {
    const startTime = Date.now();
    const networkAttempts: string[] = [];
    const fsAttempts: string[] = [];
    const suspiciousBehavior: string[] = [];

    // Build a restricted sandbox context
    const sandbox = this.createSandbox(networkAttempts, fsAttempts, suspiciousBehavior);
    // Freeze sandbox and our own objects so prototype chain cannot be mutated
    Object.freeze(sandbox);
    for (const key of Object.keys(sandbox)) {
      const v = (sandbox as Record<string, unknown>)[key];
      if (v !== null && typeof v === 'object') {
        try {
          deepFreeze(v);
        } catch {
          // Some built-ins may throw when frozen; ignore
        }
      }
    }
    const context: Context = createContext(sandbox, {
      name: 'skill-sandbox',
    });

    // Strict mode IIFE prevents `this` from referencing the sandbox global (blocks constructor-chain escape)
    const wrappedCode = `"use strict";\nvoid function() {\n${code}\n}();`;

    try {
      runInContext(wrappedCode, context, {
        timeout: config.timeout,
        displayErrors: false,
        breakOnSigint: true,
      });
      // Let microtasks flush; async escape would have been scheduled here
      await new Promise((resolve) => setTimeout(resolve, 100));
    } catch (err: unknown) {
      const msg =
        err instanceof Error
          ? err.message
          : typeof err === 'object' && err !== null && 'message' in err
            ? String((err as { message: unknown }).message)
            : String(err);
      const code =
        typeof err === 'object' && err !== null && 'code' in err
          ? String((err as { code: unknown }).code)
          : '';
      const lower = msg.toLowerCase();
      if (
        lower.includes('timed out') ||
        lower.includes('timeout') ||
        lower.includes('script execution') ||
        code === 'ERR_SCRIPT_EXECUTION_TIMEOUT'
      ) {
        suspiciousBehavior.push('Execution timed out - possible infinite loop');
      }
      // Other errors are expected in sandboxed execution
    }

    const executionTimeMs = Date.now() - startTime;
    const safe =
      suspiciousBehavior.length === 0 && networkAttempts.length === 0 && fsAttempts.length === 0;

    return {
      safe,
      suspiciousBehavior,
      executionTimeMs,
      memoryUsed: 0,
      networkAttempts,
      fsAttempts,
    };
  }

  private createSandbox(
    networkAttempts: string[],
    fsAttempts: string[],
    suspiciousBehavior: string[],
  ): Record<string, unknown> {
    // Trapped fetch
    const fakeFetch = (url: unknown) => {
      networkAttempts.push(String(url));
      return Promise.resolve({
        ok: false,
        status: 403,
        json: () => Promise.resolve({ error: 'Network access denied in sandbox' }),
        text: () => Promise.resolve('Network access denied in sandbox'),
      });
    };

    // Trapped require
    const fakeRequire = (module: unknown) => {
      const mod = String(module);
      if (['fs', 'node:fs', 'fs/promises', 'node:fs/promises'].includes(mod)) {
        fsAttempts.push(mod);
        return new Proxy(
          {},
          {
            get: (_target, prop) => {
              fsAttempts.push(`fs.${String(prop)}`);
              return () => {
                throw new Error('File system access denied in sandbox');
              };
            },
          },
        );
      }
      if (
        ['child_process', 'node:child_process', 'net', 'node:net', 'dgram', 'dns'].includes(mod)
      ) {
        suspiciousBehavior.push(`Attempted to require dangerous module: ${mod}`);
        throw new Error(`Module '${mod}' is not available in sandbox`);
      }
      return {};
    };

    // Trapped process
    const fakeProcess = {
      env: new Proxy(
        {},
        {
          get: (_target, prop) => {
            suspiciousBehavior.push(`Attempted to access process.env.${String(prop)}`);
            return undefined;
          },
        },
      ),
      exit: () => {
        suspiciousBehavior.push('Attempted to call process.exit()');
      },
    };

    return {
      console: {
        log: () => {},
        error: () => {},
        warn: () => {},
        info: () => {},
      },
      setTimeout: (_fn: () => void, ms: number) => {
        if (ms > 1000) {
          suspiciousBehavior.push(`setTimeout with long delay: ${ms}ms`);
        }
        return 0;
      },
      setInterval: () => {
        suspiciousBehavior.push('setInterval usage detected');
        return 0;
      },
      clearTimeout: () => {},
      clearInterval: () => {},
      fetch: fakeFetch,
      require: fakeRequire,
      process: fakeProcess,
      Buffer: (() => {
        const limit = (size: number, label: string) => {
          if (size > MAX_BUFFER_ALLOC) {
            suspiciousBehavior.push(`Buffer allocation exceeds ${MAX_BUFFER_ALLOC} bytes: ${label}`);
            return MAX_BUFFER_ALLOC;
          }
          return size;
        };
        return {
          from: (input: unknown, ...args: unknown[]) => {
            const buf = Buffer.from(input as never, ...(args as never[]));
            if (buf.length > MAX_BUFFER_ALLOC) {
              suspiciousBehavior.push(
                `Buffer.from result exceeds ${MAX_BUFFER_ALLOC} bytes (${buf.length})`,
              );
              return buf.subarray(0, MAX_BUFFER_ALLOC);
            }
            return buf;
          },
          alloc: (size: number, ...args: unknown[]) =>
            Buffer.alloc(limit(size, 'alloc'), ...(args as [never])),
        };
      })(),
      JSON,
      Math,
      Date,
      Array,
      Object,
      String,
      Number,
      Boolean,
      RegExp,
      Map,
      Set,
      Error,
      TypeError,
      RangeError,
      parseInt,
      parseFloat,
      isNaN,
      isFinite,
      encodeURIComponent,
      decodeURIComponent,
      encodeURI,
      decodeURI,
    };
  }
}
