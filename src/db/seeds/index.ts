import { createDatabaseClient, closeDatabaseClient, getDb } from '../client.js';
import { firewallRules } from '../schema/rules.js';

async function seed() {
  const dbUrl = process.env.DATABASE_URL ?? 'postgresql://postgres:password@localhost:5432/clawshield';
  createDatabaseClient(dbUrl);
  const db = getDb();

  // Default firewall rules
  await db.insert(firewallRules).values([
    {
      name: 'Block prompt injection',
      description: 'Detects and blocks prompt injection attempts in agent messages',
      type: 'deny',
      priority: 10,
      enabled: true,
      conditions: [
        {
          field: 'content',
          operator: 'regex',
          value: 'ignore\\s+(all\\s+)?previous\\s+instructions?',
        },
      ],
      action: {
        type: 'deny',
        message: 'Prompt injection detected',
      },
    },
    {
      name: 'Block eval usage',
      description: 'Blocks skills that use eval() or similar dangerous functions',
      type: 'deny',
      priority: 10,
      enabled: true,
      conditions: [
        {
          field: 'code',
          operator: 'contains',
          value: 'eval(',
        },
      ],
      action: {
        type: 'deny',
        message: 'Dangerous function usage detected',
      },
    },
    {
      name: 'Rate limit external API calls',
      description: 'Limit the rate of outgoing API calls per agent',
      type: 'conditional',
      priority: 50,
      enabled: true,
      conditions: [
        {
          field: 'type',
          operator: 'eq',
          value: 'api_call',
        },
      ],
      action: {
        type: 'log',
        message: 'External API call detected',
      },
    },
  ]);

  await closeDatabaseClient();
}

seed().catch((err) => {
  process.stderr.write(`Seed failed: ${String(err)}\n`);
  process.exit(1);
});
