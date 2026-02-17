import { pgTable, uuid, varchar, text, timestamp, boolean, integer, jsonb } from 'drizzle-orm/pg-core';

export const firewallRules = pgTable('firewall_rules', {
  id: uuid('id').primaryKey().defaultRandom(),
  name: varchar('name', { length: 200 }).notNull(),
  description: text('description').default(''),
  type: varchar('type', { length: 20 }).notNull(),
  priority: integer('priority').notNull().default(100),
  enabled: boolean('enabled').notNull().default(true),
  conditions: jsonb('conditions')
    .$type<
      Array<{
        field: string;
        operator: string;
        value: string | number | string[];
      }>
    >()
    .notNull(),
  action: jsonb('action')
    .$type<{
      type: string;
      message?: string;
      duration?: number;
    }>()
    .notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});
