// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import jwt from 'jsonwebtoken';
import { readFileSync } from 'node:fs';
import type { Redis } from 'ioredis';

export interface TokenPayload {
  userId: string;
  role: string;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface TokenManagerConfig {
  privateKeyPath: string;
  publicKeyPath: string;
  expiresIn: string;
  refreshExpiresIn: string;
  issuer: string;
  audience: string;
}

export class TokenManager {
  private readonly privateKey: string;
  private readonly publicKey: string;
  private readonly config: TokenManagerConfig;
  private readonly redis: Redis;
  private readonly TOKEN_BLACKLIST_PREFIX = 'token:blacklist:';

  constructor(config: TokenManagerConfig, redis: Redis) {
    this.config = config;
    this.redis = redis;
    this.privateKey = readFileSync(config.privateKeyPath, 'utf8');
    this.publicKey = readFileSync(config.publicKeyPath, 'utf8');
  }

  signAccessToken(payload: TokenPayload): string {
    return jwt.sign(payload, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: this.config.expiresIn,
      issuer: this.config.issuer,
      audience: this.config.audience,
      jwtid: crypto.randomUUID(),
    });
  }

  signRefreshToken(payload: TokenPayload): string {
    return jwt.sign({ userId: payload.userId, type: 'refresh' }, this.privateKey, {
      algorithm: 'RS256',
      expiresIn: this.config.refreshExpiresIn,
      issuer: this.config.issuer,
      audience: this.config.audience,
      jwtid: crypto.randomUUID(),
    });
  }

  generateTokenPair(payload: TokenPayload): TokenPair {
    return {
      accessToken: this.signAccessToken(payload),
      refreshToken: this.signRefreshToken(payload),
    };
  }

  verifyToken(token: string): TokenPayload & jwt.JwtPayload {
    const decoded = jwt.verify(token, this.publicKey, {
      algorithms: ['RS256'],
      issuer: this.config.issuer,
      audience: this.config.audience,
    });

    if (typeof decoded === 'string') {
      throw new Error('Invalid token format');
    }

    return decoded as TokenPayload & jwt.JwtPayload;
  }

  async isBlacklisted(token: string): Promise<boolean> {
    try {
      const decoded = jwt.decode(token) as jwt.JwtPayload | null;
      if (!decoded?.jti) return false;

      const result = await this.redis.get(`${this.TOKEN_BLACKLIST_PREFIX}${decoded.jti}`);
      return result !== null;
    } catch {
      return false;
    }
  }

  async blacklistToken(token: string): Promise<void> {
    try {
      const decoded = jwt.decode(token) as jwt.JwtPayload | null;
      if (!decoded?.jti || !decoded.exp) return;

      const ttl = decoded.exp - Math.floor(Date.now() / 1000);
      if (ttl > 0) {
        await this.redis.setex(`${this.TOKEN_BLACKLIST_PREFIX}${decoded.jti}`, ttl, '1');
      }
    } catch {
      // Token decode failures are silently ignored for blacklisting
    }
  }

  async verifyAndCheckBlacklist(token: string): Promise<TokenPayload & jwt.JwtPayload> {
    const isBlacklisted = await this.isBlacklisted(token);
    if (isBlacklisted) {
      throw new Error('Token has been revoked');
    }
    return this.verifyToken(token);
  }

  getPublicKey(): string {
    return this.publicKey;
  }
}
