import { pgTable, uuid, varchar, text, timestamp, boolean, jsonb } from 'drizzle-orm/pg-core';

export const threats = pgTable('threats', {
  id: uuid('id').primaryKey().defaultRandom(),
  agentId: uuid('agent_id'),
  threatType: varchar('threat_type', { length: 50 }).notNull(),
  severity: varchar('severity', { length: 20 }).notNull(),
  details: jsonb('details').$type<Record<string, unknown>>().notNull(),
  resolved: boolean('resolved').notNull().default(false),
  resolvedAt: timestamp('resolved_at', { withTimezone: true }),
  resolvedBy: varchar('resolved_by', { length: 100 }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
