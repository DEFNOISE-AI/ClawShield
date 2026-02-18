// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as agentSchema from './schema/agents.js';
import * as ruleSchema from './schema/rules.js';
import * as logSchema from './schema/logs.js';
import * as threatSchema from './schema/threats.js';
import * as skillSchema from './schema/skills.js';
import * as userSchema from './schema/users.js';

const schema = {
  ...agentSchema,
  ...ruleSchema,
  ...logSchema,
  ...threatSchema,
  ...skillSchema,
  ...userSchema,
};

let _client: ReturnType<typeof postgres> | null = null;
let _db: ReturnType<typeof drizzle<typeof schema>> | null = null;

export function createDatabaseClient(url: string, poolMin = 2, poolMax = 10) {
  _client = postgres(url, {
    max: poolMax,
    min: poolMin,
    idle_timeout: 20,
    max_lifetime: 60 * 30,
    connect_timeout: 10,
    prepare: true,
  });

  _db = drizzle(_client, { schema });
  return _db;
}

export function getDb() {
  if (!_db) {
    throw new Error('Database not initialized. Call createDatabaseClient() first.');
  }
  return _db;
}

export async function closeDatabaseClient(): Promise<void> {
  if (_client) {
    await _client.end();
    _client = null;
    _db = null;
  }
}

export type Database = ReturnType<typeof drizzle<typeof schema>>;
