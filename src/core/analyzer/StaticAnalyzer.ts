// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import * as acorn from 'acorn';
import { walk } from 'estree-walker';
import type { Node } from 'estree';
import type {
  StaticAnalysisResult,
  SkillVulnerability,
  SkillSeverity,
} from '../../types/skill.types.js';

const DANGEROUS_FUNCTIONS = new Set(['eval', 'Function', 'setTimeout', 'setInterval']);

const DANGEROUS_MODULES = new Set(['child_process', 'cluster', 'dgram', 'dns', 'net', 'tls']);

/** Property access that can be used to escape vm sandbox via prototype chain */
const DANGEROUS_PROPERTIES = new Set(['constructor', '__proto__', 'prototype']);

/** Globals that enable escape or reflection attacks */
const DANGEROUS_GLOBALS = new Set(['Proxy', 'Reflect']);

function isObfuscated(text: string): boolean {
  if (text.length < 30) return false;
  if (/^[0-9a-fA-F]{30,}$/.test(text)) return true;
  if (/^[A-Za-z0-9+/]{50,}={0,2}$/.test(text)) return true;
  const unicodeMatches = text.match(/\\u[0-9a-fA-F]{4}/g);
  if (unicodeMatches && unicodeMatches.length > 5) return true;
  return false;
}

export class StaticAnalyzer {
  analyze(code: string): StaticAnalysisResult {
    const vulnerabilities: SkillVulnerability[] = [];
    const suspiciousPatterns: string[] = [];

    let ast: acorn.Node;
    try {
      ast = acorn.parse(code, {
        ecmaVersion: 'latest',
        sourceType: 'module',
        locations: true,
      });
    } catch (err) {
      return {
        severity: 'info',
        vulnerabilities: [
          {
            type: 'parse_error',
            severity: 'info',
            description: `Failed to parse code: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        suspiciousPatterns: ['Parse error - code may be obfuscated'],
      };
    }

    walk(ast as unknown as Node, {
      enter(node: Node) {
        // Detect eval(), Function(), etc.
        if (node.type === 'CallExpression') {
          const callee = node.callee;
          if (callee.type === 'Identifier' && DANGEROUS_FUNCTIONS.has(callee.name)) {
            vulnerabilities.push({
              type: 'dangerous_function',
              severity: callee.name === 'eval' ? 'critical' : 'high',
              description: `Uses dangerous function: ${callee.name}()`,
              line: node.loc?.start.line,
              column: node.loc?.start.column,
            });
            suspiciousPatterns.push(`${callee.name}() call detected`);
          }

          // Detect require('child_process'), require('fs'), etc.
          if (callee.type === 'Identifier' && callee.name === 'require') {
            const arg = node.arguments[0];
            if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
              const modName = arg.value.replace(/^node:/, '');
              if (DANGEROUS_MODULES.has(modName)) {
                vulnerabilities.push({
                  type: 'dangerous_module',
                  severity: 'critical',
                  description: `Imports dangerous module: ${arg.value}`,
                  line: node.loc?.start.line,
                  column: node.loc?.start.column,
                });
                suspiciousPatterns.push(`require('${arg.value}') detected`);
              }
              if (modName === 'fs' || modName === 'fs/promises') {
                vulnerabilities.push({
                  type: 'filesystem_access',
                  severity: 'high',
                  description: 'File system access detected',
                  line: node.loc?.start.line,
                });
                suspiciousPatterns.push('File system access detected');
              }
            }
          }

          // Detect fetch() calls
          if (callee.type === 'Identifier' && callee.name === 'fetch') {
            const arg = node.arguments[0];
            if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
              suspiciousPatterns.push(`Network request to: ${arg.value}`);
              vulnerabilities.push({
                type: 'network_request',
                severity: 'medium',
                description: `Network request to: ${arg.value}`,
                line: node.loc?.start.line,
              });
            } else {
              suspiciousPatterns.push('Dynamic network request (non-literal URL)');
              vulnerabilities.push({
                type: 'network_request',
                severity: 'high',
                description: 'Dynamic network request with non-literal URL',
                line: node.loc?.start.line,
              });
            }
          }
        }

        // Detect new Function() — vm escape vector (NewExpression, not CallExpression)
        if (node.type === 'NewExpression') {
          const callee = node.callee;
          if (callee.type === 'Identifier' && callee.name === 'Function') {
            vulnerabilities.push({
              type: 'dangerous_function',
              severity: 'critical',
              description: 'Uses new Function() — sandbox escape vector',
              line: node.loc?.start.line,
              column: node.loc?.start.column,
            });
            suspiciousPatterns.push('new Function() detected');
          }
          if (callee.type === 'Identifier' && DANGEROUS_GLOBALS.has(callee.name)) {
            vulnerabilities.push({
              type: 'sandbox_escape',
              severity: 'critical',
              description: `Uses ${callee.name} — enables sandbox escape`,
              line: node.loc?.start.line,
              column: node.loc?.start.column,
            });
            suspiciousPatterns.push(`${callee.name} usage detected`);
          }
        }

        // Detect constructor / __proto__ / prototype access — vm escape chain
        if (node.type === 'MemberExpression') {
          const prop =
            node.property.type === 'Identifier'
              ? node.property.name
              : node.property.type === 'Literal' && typeof node.property.value === 'string'
                ? node.property.value
                : null;
          if (prop && DANGEROUS_PROPERTIES.has(prop)) {
            vulnerabilities.push({
              type: 'sandbox_escape',
              severity: 'critical',
              description: `Access to ${prop} — sandbox escape vector`,
              line: node.loc?.start.line,
              column: node.loc?.start.column,
            });
            suspiciousPatterns.push(`${prop} access detected`);
          }
          // arguments.callee — escape vector in non-strict mode
          if (
            node.object.type === 'Identifier' &&
            node.object.name === 'arguments' &&
            node.property.type === 'Identifier' &&
            node.property.name === 'callee'
          ) {
            vulnerabilities.push({
              type: 'sandbox_escape',
              severity: 'critical',
              description: 'arguments.callee — sandbox escape vector',
              line: node.loc?.start.line,
            });
            suspiciousPatterns.push('arguments.callee detected');
          }
          // Proxy / Reflect usage (e.g. Reflect.get, Proxy.revocable)
          if (
            node.object.type === 'Identifier' &&
            DANGEROUS_GLOBALS.has(node.object.name)
          ) {
            vulnerabilities.push({
              type: 'sandbox_escape',
              severity: 'critical',
              description: `${node.object.name} usage — enables sandbox escape`,
              line: node.loc?.start.line,
              column: node.loc?.start.column,
            });
            suspiciousPatterns.push(`${node.object.name} usage detected`);
          }
        }

        // Detect dynamic import() — ImportExpression
        if (node.type === 'ImportExpression') {
          vulnerabilities.push({
            type: 'dynamic_import',
            severity: 'critical',
            description: 'Dynamic import() — bypasses static module checks',
            line: node.loc?.start.line,
            column: node.loc?.start.column,
          });
          suspiciousPatterns.push('Dynamic import() detected');
        }

        // Detect with statement — scope manipulation
        if (node.type === 'WithStatement') {
          vulnerabilities.push({
            type: 'sandbox_escape',
            severity: 'critical',
            description: 'with statement — scope manipulation',
            line: node.loc?.start.line,
          });
          suspiciousPatterns.push('with statement detected');
        }

        // Detect import declarations for dangerous modules
        if (node.type === 'ImportDeclaration') {
          const source = node.source.value;
          if (typeof source === 'string') {
            const moduleName = source.replace(/^node:/, '');
            if (DANGEROUS_MODULES.has(moduleName)) {
              vulnerabilities.push({
                type: 'dangerous_module',
                severity: 'critical',
                description: `Imports dangerous module: ${source}`,
                line: node.loc?.start.line,
              });
              suspiciousPatterns.push(`import '${source}' detected`);
            }
            if (moduleName === 'fs' || moduleName === 'fs/promises') {
              vulnerabilities.push({
                type: 'filesystem_access',
                severity: 'high',
                description: 'File system access detected',
                line: node.loc?.start.line,
              });
              suspiciousPatterns.push('File system access via import detected');
            }
          }
        }

        // Detect process.env access
        if (
          node.type === 'MemberExpression' &&
          node.object.type === 'MemberExpression' &&
          node.object.object.type === 'Identifier' &&
          node.object.object.name === 'process' &&
          node.object.property.type === 'Identifier' &&
          node.object.property.name === 'env'
        ) {
          vulnerabilities.push({
            type: 'env_access',
            severity: 'high',
            description: 'Accesses process.env variables',
            line: node.loc?.start.line,
          });
          suspiciousPatterns.push('process.env access detected');
        }

        // Check for obfuscated strings
        if (node.type === 'Literal' && typeof node.value === 'string') {
          if (isObfuscated(node.value)) {
            vulnerabilities.push({
              type: 'obfuscation',
              severity: 'medium',
              description: 'Obfuscated string detected',
              line: node.loc?.start.line,
            });
            suspiciousPatterns.push('Obfuscated string detected');
          }
        }
      },
    });

    // Determine overall severity
    let severity: SkillSeverity = 'info';
    for (const v of vulnerabilities) {
      if (v.severity === 'critical') {
        severity = 'critical';
        break;
      }
      if (v.severity === 'high') severity = 'high';
      else if (v.severity === 'medium' && severity === 'info') severity = 'medium';
    }

    return { severity, vulnerabilities, suspiciousPatterns };
  }
}
