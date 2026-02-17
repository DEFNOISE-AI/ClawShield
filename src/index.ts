import IORedis from 'ioredis';
import { loadConfig } from './utils/config.js';
import { createLogger } from './utils/logger.js';
import { createDatabaseClient, closeDatabaseClient } from './db/client.js';
import { TokenManager } from './core/crypto/TokenManager.js';
import { AgentFirewall } from './core/firewall/AgentFirewall.js';
import { SkillAnalyzer } from './core/analyzer/SkillAnalyzer.js';
import { ProxyServer } from './core/proxy/ProxyServer.js';
import { AgentMonitor } from './services/AgentMonitor.js';
import { ThreatIntelligence } from './services/ThreatIntelligence.js';
import { AlertService } from './services/AlertService.js';
import { MetricsCollector } from './services/MetricsCollector.js';
import { createServer } from './api/server.js';

async function main(): Promise<void> {
  // Load configuration
  const config = loadConfig();
  const isDev = config.NODE_ENV === 'development';
  const logger = createLogger(config.LOG_LEVEL, isDev);

  logger.info({ env: config.NODE_ENV }, 'Starting ClawShield...');

  // Connect to PostgreSQL
  const db = createDatabaseClient(
    config.DATABASE_URL,
    config.DATABASE_POOL_MIN,
    config.DATABASE_POOL_MAX,
  );
  logger.info('Database connected');

  // Connect to Redis
  const redis = new IORedis(config.REDIS_URL, {
    maxRetriesPerRequest: 3,
    retryStrategy: (times) => Math.min(times * 50, 2000),
  });
  redis.on('error', (err) => logger.error({ err }, 'Redis error'));
  redis.on('connect', () => logger.info('Redis connected'));

  // Initialize TokenManager
  const tokenManager = new TokenManager(
    {
      privateKeyPath: config.JWT_PRIVATE_KEY_PATH,
      publicKeyPath: config.JWT_PUBLIC_KEY_PATH,
      expiresIn: config.JWT_EXPIRES_IN,
      refreshExpiresIn: config.JWT_REFRESH_EXPIRES_IN,
      issuer: config.JWT_ISSUER,
      audience: config.JWT_AUDIENCE,
    },
    redis,
  );

  // Initialize services
  const alertService = new AlertService(
    {
      webhookUrl: config.ALERT_WEBHOOK_URL || undefined,
      email: config.ALERT_EMAIL || undefined,
    },
    logger,
  );

  const threatIntel = new ThreatIntelligence(redis, logger);
  await threatIntel.initialize();

  const skillAnalyzer = new SkillAnalyzer(logger);
  skillAnalyzer.setMalwareSignatures(threatIntel.getSignatures());

  const agentMonitor = new AgentMonitor(redis, logger);
  const metricsCollector = new MetricsCollector(redis, logger);

  // Initialize firewall
  const firewall = new AgentFirewall(db, redis, logger, {
    threatThreshold: config.FIREWALL_THREAT_THRESHOLD,
    blockDuration: config.FIREWALL_BLOCK_DURATION,
    maxWsConnectionsPerIp: config.FIREWALL_MAX_WS_CONNECTIONS_PER_IP,
  });
  firewall.setAlertHandler((payload) => alertService.sendAlert(payload));
  await firewall.initialize();

  // Initialize proxy server
  const proxyServer = new ProxyServer(firewall, logger, {
    targetUrl: config.OPENCLAW_TARGET_URL,
    maxWsConnectionsPerIp: config.FIREWALL_MAX_WS_CONNECTIONS_PER_IP,
  });
  await proxyServer.initialize();

  // Create API server
  const apiServer = await createServer(
    {
      port: config.PORT,
      host: config.HOST,
      isDev,
      corsOrigins: config.CORS_ALLOWED_ORIGINS,
      rateLimitMax: config.RATE_LIMIT_MAX,
      rateLimitWindow: config.RATE_LIMIT_WINDOW,
    },
    { db, redis, tokenManager, skillAnalyzer, logger },
  );

  // Start background services
  agentMonitor.start();

  // Start the server
  await apiServer.listen({ port: config.PORT, host: config.HOST });
  logger.info({ port: config.PORT, host: config.HOST }, 'ClawShield API server started');

  // Graceful shutdown
  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'Shutting down gracefully...');

    agentMonitor.stop();

    try {
      await apiServer.close();
      logger.info('API server closed');
    } catch (err) {
      logger.error({ err }, 'Error closing API server');
    }

    try {
      redis.disconnect();
      logger.info('Redis disconnected');
    } catch (err) {
      logger.error({ err }, 'Error disconnecting Redis');
    }

    try {
      await closeDatabaseClient();
      logger.info('Database disconnected');
    } catch (err) {
      logger.error({ err }, 'Error disconnecting database');
    }

    logger.info('ClawShield shut down successfully');
    process.exit(0);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  process.on('unhandledRejection', (reason) => {
    logger.fatal({ err: reason }, 'Unhandled rejection');
    process.exit(1);
  });

  process.on('uncaughtException', (error) => {
    logger.fatal({ err: error }, 'Uncaught exception');
    process.exit(1);
  });
}

main().catch((err) => {
  process.stderr.write(`Fatal startup error: ${String(err)}\n`);
  process.exit(1);
});
