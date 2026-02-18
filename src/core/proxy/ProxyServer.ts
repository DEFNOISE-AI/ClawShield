// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import Fastify, { type FastifyInstance } from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import fastifyReplyFrom from '@fastify/reply-from';
import WebSocket from 'ws';
import { RequestInterceptor } from './RequestInterceptor.js';
import { ResponseInterceptor } from './ResponseInterceptor.js';
import type { AgentFirewall } from '../firewall/AgentFirewall.js';
import type { Logger } from '../../utils/logger.js';

export interface ProxyServerConfig {
  targetUrl: string;
  maxWsConnectionsPerIp: number;
}

interface UpstreamConnection {
  ws: WebSocket;
  alive: boolean;
}

export class ProxyServer {
  private readonly fastify: FastifyInstance;
  private readonly requestInterceptor: RequestInterceptor;
  private readonly responseInterceptor: ResponseInterceptor;
  private readonly wsConnections = new Map<string, number>();
  private readonly upstreamConnections = new Map<WebSocket, UpstreamConnection>();

  constructor(
    private readonly firewall: AgentFirewall,
    private readonly logger: Logger,
    private readonly config: ProxyServerConfig,
  ) {
    this.fastify = Fastify({
      logger: false,
      requestIdLogLabel: 'requestId',
      bodyLimit: 1048576,
      trustProxy: true,
    });

    this.requestInterceptor = new RequestInterceptor(firewall, logger);
    this.responseInterceptor = new ResponseInterceptor(logger);
  }

  async initialize(): Promise<void> {
    // Register reply-from for proxying
    await this.fastify.register(fastifyReplyFrom, {
      undici: {
        connections: 100,
        pipelining: 10,
      },
    });

    // Register websocket support
    await this.fastify.register(fastifyWebsocket);

    this.setupProxyRoutes();
    this.setupWebSocketRoute();
  }

  private setupProxyRoutes(): void {
    // Proxy all requests under /proxy/*
    this.fastify.all('/proxy/*', async (request, reply) => {
      const result = await this.requestInterceptor.inspect(request);

      if (!result.allowed) {
        return reply.code(403).send({
          error: 'Request blocked by firewall',
          reason: result.reason,
          threatLevel: result.threatLevel,
        });
      }

      const intercepted = this.requestInterceptor.extractRequest(request);
      const proxyHeaders = this.requestInterceptor.buildProxyHeaders(
        intercepted.headers,
        request.id,
        result.threatScore,
      );

      const targetPath = request.url.replace(/^\/proxy/, '');
      const targetUrl = `${this.config.targetUrl}${targetPath}`;

      return reply.from(targetUrl, {
        rewriteRequestHeaders: (_orig, headers) => ({
          ...headers,
          ...proxyHeaders,
        }),
        onResponse: (_request, reply, res) => {
          const responseHeaders: Record<string, string | string[] | undefined> = {};
          if (res && 'headers' in res) {
            const rawHeaders = (res as { headers: Record<string, string | string[] | undefined> })
              .headers;
            Object.assign(responseHeaders, rawHeaders);
          }

          const inspection = this.responseInterceptor.inspectResponse(
            reply.statusCode,
            responseHeaders,
          );

          if (!inspection.safe) {
            this.logger.warn(
              { issues: inspection.issues, path: request.url },
              'Response inspection issues',
            );
          }

          reply.send(res);
        },
      });
    });
  }

  private setupWebSocketRoute(): void {
    this.fastify.get('/ws', { websocket: true }, (socket, request) => {
      const ip = (request.headers['x-forwarded-for'] as string) ?? request.ip;
      const agentId = request.headers['x-agent-id'] as string;

      const currentCount = this.wsConnections.get(ip) ?? 0;
      if (currentCount >= this.config.maxWsConnectionsPerIp) {
        this.logger.warn({ ip, currentCount }, 'WebSocket connection limit reached');
        socket.close(1008, 'Too many connections');
        return;
      }
      this.wsConnections.set(ip, currentCount + 1);

      if (agentId) {
        this.firewall.registerAgent(agentId, { ipAddress: ip, connectedAt: Date.now() });
      }

      const targetWsUrl = this.config.targetUrl.replace(/^http/, 'ws') + '/ws';
      const upstream = new WebSocket(targetWsUrl, {
        headers: {
          'x-agent-id': agentId ?? '',
          'x-forwarded-for': ip,
          'x-clawshield-proxy': 'true',
        },
        handshakeTimeout: 10_000,
      });

      const conn: UpstreamConnection = { ws: upstream, alive: false };
      this.upstreamConnections.set(socket, conn);

      upstream.on('open', () => {
        conn.alive = true;
        this.logger.info({ ip, agentId, target: targetWsUrl }, 'Upstream WebSocket connected');
      });

      upstream.on('message', (data: WebSocket.RawData) => {
        if (socket.readyState === WebSocket.OPEN) {
          socket.send(data);
        }
      });

      upstream.on('close', (code, reason) => {
        this.logger.info({ ip, agentId, code }, 'Upstream WebSocket closed');
        if (socket.readyState === WebSocket.OPEN) {
          socket.close(code, reason);
        }
      });

      upstream.on('error', (err) => {
        this.logger.error({ err, ip, agentId }, 'Upstream WebSocket error');
        if (socket.readyState === WebSocket.OPEN) {
          socket.close(1011, 'Upstream connection failed');
        }
      });

      this.logger.info({ ip, agentId }, 'WebSocket connected');

      socket.on('message', async (data: WebSocket.RawData) => {
        try {
          const message = JSON.parse(data.toString());

          if (!agentId) {
            socket.send(JSON.stringify({ type: 'error', error: 'Missing agent ID' }));
            return;
          }

          const result = await this.firewall.inspectAgentMessage(agentId, message);

          if (!result.allowed) {
            socket.send(
              JSON.stringify({
                type: 'error',
                error: 'Message blocked by firewall',
                reason: result.reason,
              }),
            );
            return;
          }

          if (upstream.readyState === WebSocket.OPEN) {
            upstream.send(data);
            this.logger.debug(
              { agentId, messageType: message.type },
              'WebSocket message forwarded',
            );
          } else {
            const queued = !conn.alive;
            this.logger.warn(
              { agentId, upstreamState: upstream.readyState, queued },
              'Upstream not ready, message dropped',
            );
            socket.send(JSON.stringify({ type: 'error', error: 'Upstream connection not ready' }));
          }
        } catch (error) {
          this.logger.error({ err: error }, 'WebSocket message processing error');
          socket.send(JSON.stringify({ type: 'error', error: 'Message processing failed' }));
        }
      });

      socket.on('close', () => {
        const count = this.wsConnections.get(ip) ?? 1;
        this.wsConnections.set(ip, Math.max(0, count - 1));
        if (agentId) {
          this.firewall.unregisterAgent(agentId);
        }
        this.upstreamConnections.delete(socket);
        if (
          upstream.readyState === WebSocket.OPEN ||
          upstream.readyState === WebSocket.CONNECTING
        ) {
          upstream.close(1000, 'Client disconnected');
        }
        this.logger.info({ ip, agentId }, 'WebSocket disconnected');
      });

      socket.on('error', (error) => {
        this.logger.error({ err: error, ip, agentId }, 'WebSocket error');
      });
    });
  }

  getFastify(): FastifyInstance {
    return this.fastify;
  }

  getWsConnectionCount(ip: string): number {
    return this.wsConnections.get(ip) ?? 0;
  }
}
