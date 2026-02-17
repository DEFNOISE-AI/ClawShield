import { pgTable, uuid, varchar, text, timestamp, boolean, real, jsonb } from 'drizzle-orm/pg-core';

export const analyzedSkills = pgTable('analyzed_skills', {
  id: uuid('id').primaryKey().defaultRandom(),
  codeHash: varchar('code_hash', { length: 128 }).notNull().unique(),
  language: varchar('language', { length: 20 }).notNull().default('javascript'),
  safe: boolean('safe').notNull(),
  riskScore: real('risk_score').notNull(),
  reason: text('reason'),
  vulnerabilities: jsonb('vulnerabilities')
    .$type<
      Array<{
        type: string;
        severity: string;
        description: string;
        line?: number;
        column?: number;
      }>
    >()
    .default([]),
  patterns: jsonb('patterns').$type<string[]>().default([]),
  analysisTimeMs: real('analysis_time_ms'),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
