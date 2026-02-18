// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { pgTable, uuid, varchar, text, timestamp, boolean, integer, jsonb } from 'drizzle-orm/pg-core';

export const agents = pgTable('agents', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  endpoint: text('endpoint').notNull(),
  apiKeyHash: text('api_key_hash').notNull(),
  permissions: jsonb('permissions').$type<string[]>().notNull().default([]),
  status: varchar('status', { length: 20 }).notNull().default('active'),
  maxRequestsPerMinute: integer('max_requests_per_minute').notNull().default(100),
  trustedDomains: jsonb('trusted_domains').$type<string[]>().notNull().default([]),
  metadata: jsonb('metadata').$type<Record<string, string>>(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

export const agentCommunicationRules = pgTable('agent_communication_rules', {
  id: uuid('id').primaryKey().defaultRandom(),
  sourceAgentId: uuid('source_agent_id')
    .notNull()
    .references(() => agents.id, { onDelete: 'cascade' }),
  targetAgentId: uuid('target_agent_id')
    .notNull()
    .references(() => agents.id, { onDelete: 'cascade' }),
  enabled: boolean('enabled').notNull().default(true),
  maxMessagesPerMinute: integer('max_messages_per_minute').notNull().default(50),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});
