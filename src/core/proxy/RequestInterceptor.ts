import type { FastifyRequest } from 'fastify';
import type { AgentFirewall } from '../firewall/AgentFirewall.js';
import type { InspectionResult } from '../../types/threat.types.js';
import type { Logger } from '../../utils/logger.js';

export interface InterceptedRequest {
  agentId?: string;
  method: string;
  path: string;
  body?: string;
  headers: Record<string, string>;
  ip: string;
}

export class RequestInterceptor {
  constructor(
    private readonly firewall: AgentFirewall,
    private readonly logger: Logger,
  ) {}

  extractRequest(request: FastifyRequest): InterceptedRequest {
    const agentId =
      (request.headers['x-agent-id'] as string) ??
      (request.headers['x-clawshield-agent-id'] as string);

    const rawHeaders: Record<string, string> = {};
    for (const [key, value] of Object.entries(request.headers)) {
      if (typeof value === 'string') {
        rawHeaders[key] = value;
      }
    }

    let body: string | undefined;
    if (request.body) {
      body = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
    }

    return {
      agentId,
      method: request.method,
      path: request.url,
      body,
      headers: rawHeaders,
      ip: request.headers['x-forwarded-for'] as string ?? request.ip,
    };
  }

  async inspect(request: FastifyRequest): Promise<InspectionResult> {
    const intercepted = this.extractRequest(request);

    this.logger.debug(
      {
        agentId: intercepted.agentId,
        method: intercepted.method,
        path: intercepted.path,
        ip: intercepted.ip,
      },
      'Intercepting request',
    );

    return this.firewall.inspectRequest({
      agentId: intercepted.agentId,
      method: intercepted.method,
      path: intercepted.path,
      body: intercepted.body,
      headers: intercepted.headers,
      ip: intercepted.ip,
    });
  }

  buildProxyHeaders(
    originalHeaders: Record<string, string>,
    requestId: string,
    threatScore?: number,
  ): Record<string, string> {
    const headers = { ...originalHeaders };

    // Inject ClawShield metadata
    headers['x-clawshield-request-id'] = requestId;
    if (threatScore !== undefined) {
      headers['x-clawshield-threat-score'] = String(threatScore);
    }
    headers['x-clawshield-inspected'] = 'true';

    // Remove hop-by-hop headers
    const hopByHop = [
      'connection',
      'keep-alive',
      'proxy-authenticate',
      'proxy-authorization',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade',
    ];
    for (const h of hopByHop) {
      delete headers[h];
    }

    return headers;
  }
}
