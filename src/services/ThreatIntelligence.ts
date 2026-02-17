import { createHash } from 'node:crypto';
import type { Redis } from 'ioredis';
import type { Logger } from '../utils/logger.js';
import type { MalwareSignature } from '../types/skill.types.js';

export class ThreatIntelligence {
  private signatures: MalwareSignature[] = [];
  private readonly KNOWN_BAD_IPS_KEY = 'threat:bad_ips';
  private readonly KNOWN_BAD_DOMAINS_KEY = 'threat:bad_domains';

  constructor(
    private readonly redis: Redis,
    private readonly logger: Logger,
  ) {}

  async initialize(): Promise<void> {
    // Load built-in signatures
    this.signatures = this.getDefaultSignatures();
    this.logger.info({ signatureCount: this.signatures.length }, 'Threat intelligence initialized');
  }

  getSignatures(): MalwareSignature[] {
    return [...this.signatures];
  }

  addSignature(signature: MalwareSignature): void {
    this.signatures.push(signature);
    this.logger.info({ signatureId: signature.id }, 'New malware signature added');
  }

  async isKnownBadIp(ip: string): Promise<boolean> {
    return (await this.redis.sismember(this.KNOWN_BAD_IPS_KEY, ip)) === 1;
  }

  async addBadIp(ip: string): Promise<void> {
    await this.redis.sadd(this.KNOWN_BAD_IPS_KEY, ip);
  }

  async isKnownBadDomain(domain: string): Promise<boolean> {
    return (await this.redis.sismember(this.KNOWN_BAD_DOMAINS_KEY, domain)) === 1;
  }

  async addBadDomain(domain: string): Promise<void> {
    await this.redis.sadd(this.KNOWN_BAD_DOMAINS_KEY, domain);
  }

  checkCode(code: string): MalwareSignature | null {
    const codeHash = createHash('sha256').update(code).digest('hex');

    for (const sig of this.signatures) {
      if (sig.hash && sig.hash === codeHash) return sig;
      try {
        if (sig.pattern && new RegExp(sig.pattern).test(code)) return sig;
      } catch {
        // Invalid pattern
      }
    }

    return null;
  }

  private getDefaultSignatures(): MalwareSignature[] {
    return [
      {
        id: 'sig-001',
        name: 'CryptoMiner-JS',
        hash: '',
        pattern: 'coinhive\\.min\\.js|CoinHive\\.Anonymous',
        severity: 'critical',
        description: 'JavaScript cryptocurrency miner',
      },
      {
        id: 'sig-002',
        name: 'WebShell-Generic',
        hash: '',
        pattern: 'eval\\(base64_decode|eval\\(gzuncompress',
        severity: 'critical',
        description: 'Generic web shell pattern',
      },
      {
        id: 'sig-003',
        name: 'EnvExfiltrator',
        hash: '',
        pattern: 'process\\.env.*fetch\\(|fetch\\(.*process\\.env',
        severity: 'critical',
        description: 'Environment variable exfiltration',
      },
    ];
  }
}
