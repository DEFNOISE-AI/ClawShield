// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { eq } from 'drizzle-orm';
import { firewallRules } from '../../db/schema/rules.js';
import type { Database } from '../../db/client.js';
import type { InspectionResult, FirewallRule, RuleCondition } from '../../types/threat.types.js';
import type { Logger } from '../../utils/logger.js';

export class RuleEngine {
  private rulesCache: FirewallRule[] = [];
  private lastCacheRefresh = 0;
  private readonly CACHE_TTL = 30_000;

  constructor(
    private readonly db: Database,
    private readonly logger: Logger,
  ) {}

  async loadRules(): Promise<void> {
    const rows = await this.db.select().from(firewallRules).where(eq(firewallRules.enabled, true));

    this.rulesCache = rows
      .map((r) => ({
        id: r.id,
        name: r.name,
        description: r.description ?? '',
        type: r.type as 'allow' | 'deny' | 'conditional',
        priority: r.priority,
        enabled: r.enabled,
        conditions: r.conditions as RuleCondition[],
        action: r.action as FirewallRule['action'],
      }))
      .sort((a, b) => a.priority - b.priority);

    this.lastCacheRefresh = Date.now();
    this.logger.debug({ ruleCount: this.rulesCache.length }, 'Firewall rules loaded');
  }

  async evaluate(context: Record<string, unknown>): Promise<InspectionResult> {
    if (Date.now() - this.lastCacheRefresh > this.CACHE_TTL) {
      await this.loadRules();
    }

    for (const rule of this.rulesCache) {
      const matches = this.matchesAllConditions(rule.conditions, context);

      if (matches) {
        if (rule.type === 'deny') {
          this.logger.info({ ruleId: rule.id, ruleName: rule.name }, 'Rule denied request');
          return {
            allowed: false,
            reason: rule.action.message ?? `Blocked by rule: ${rule.name}`,
            threatLevel: 'medium',
          };
        }
        if (rule.type === 'allow') {
          return { allowed: true };
        }
        // conditional: log but allow
        this.logger.info({ ruleId: rule.id, ruleName: rule.name }, 'Conditional rule matched');
      }
    }

    // Default: allow if no deny rules matched
    return { allowed: true };
  }

  private matchesAllConditions(
    conditions: RuleCondition[],
    context: Record<string, unknown>,
  ): boolean {
    return conditions.every((cond) => this.matchCondition(cond, context));
  }

  private matchCondition(condition: RuleCondition, context: Record<string, unknown>): boolean {
    const fieldValue = this.getNestedValue(context, condition.field);
    if (fieldValue === undefined) return false;

    const strValue = String(fieldValue);

    switch (condition.operator) {
      case 'eq':
        return strValue === String(condition.value);
      case 'neq':
        return strValue !== String(condition.value);
      case 'contains':
        return strValue.includes(String(condition.value));
      case 'regex':
        try {
          return new RegExp(String(condition.value), 'i').test(strValue);
        } catch {
          this.logger.warn({ pattern: condition.value }, 'Invalid regex in rule condition');
          return false;
        }
      case 'gt':
        return Number(fieldValue) > Number(condition.value);
      case 'lt':
        return Number(fieldValue) < Number(condition.value);
      case 'in':
        if (Array.isArray(condition.value)) {
          return condition.value.includes(strValue);
        }
        return false;
      default:
        return false;
    }
  }

  private getNestedValue(obj: Record<string, unknown>, path: string): unknown {
    const keys = path.split('.');
    let current: unknown = obj;
    for (const key of keys) {
      if (current === null || current === undefined || typeof current !== 'object') {
        return undefined;
      }
      current = (current as Record<string, unknown>)[key];
    }
    return current;
  }

  getRulesCount(): number {
    return this.rulesCache.length;
  }
}
