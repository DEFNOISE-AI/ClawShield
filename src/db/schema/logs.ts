import { pgTable, uuid, varchar, text, timestamp, integer, jsonb } from 'drizzle-orm/pg-core';

export const requestLogs = pgTable('request_logs', {
  id: uuid('id').primaryKey().defaultRandom(),
  agentId: uuid('agent_id'),
  method: varchar('method', { length: 10 }),
  path: text('path'),
  statusCode: integer('status_code'),
  duration: integer('duration'),
  blocked: varchar('blocked', { length: 5 }).notNull().default('false'),
  blockReason: text('block_reason'),
  threatScore: integer('threat_score'),
  requestId: varchar('request_id', { length: 64 }),
  ipAddress: varchar('ip_address', { length: 45 }),
  metadata: jsonb('metadata').$type<Record<string, unknown>>(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});
