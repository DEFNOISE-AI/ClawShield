// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import { randomBytes, generateKeyPairSync } from 'node:crypto';
import { writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Logger } from '../../utils/logger.js';

export interface KeyRotationConfig {
  rotationIntervalMs: number;
  keyDirectory: string;
}

export class KeyRotation {
  private rotationTimer: ReturnType<typeof setInterval> | null = null;
  private currentKeyVersion = 0;

  constructor(
    private readonly config: KeyRotationConfig,
    private readonly logger: Logger,
  ) {}

  start(): void {
    this.rotationTimer = setInterval(() => {
      this.rotateKeys().catch((err) => {
        this.logger.error({ err }, 'Key rotation failed');
      });
    }, this.config.rotationIntervalMs);

    this.logger.info(
      { intervalMs: this.config.rotationIntervalMs },
      'Key rotation scheduler started',
    );
  }

  stop(): void {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
      this.logger.info('Key rotation scheduler stopped');
    }
  }

  async rotateKeys(): Promise<void> {
    this.currentKeyVersion++;
    const version = this.currentKeyVersion;

    this.logger.info({ version }, 'Starting key rotation');

    const dir = this.config.keyDirectory;
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true, mode: 0o700 });
    }

    // Generate new RSA key pair for JWT
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const privatePath = `${dir}/jwt_private_v${version}.pem`;
    const publicPath = `${dir}/jwt_public_v${version}.pem`;

    writeFileSync(privatePath, privateKey, { mode: 0o600 });
    writeFileSync(publicPath, publicKey, { mode: 0o644 });

    // Generate new AES-256 encryption key
    const encryptionKey = randomBytes(32).toString('hex');
    writeFileSync(`${dir}/encryption_v${version}.key`, encryptionKey, { mode: 0o600 });

    this.logger.info({ version, privatePath, publicPath }, 'Key rotation completed');
  }

  static generateInitialKeys(directory: string): {
    privateKeyPath: string;
    publicKeyPath: string;
    encryptionKeyHex: string;
  } {
    if (!existsSync(directory)) {
      mkdirSync(directory, { recursive: true, mode: 0o700 });
    }

    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 4096,
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });

    const privateKeyPath = `${directory}/jwt_private.pem`;
    const publicKeyPath = `${directory}/jwt_public.pem`;

    const parentDir = dirname(privateKeyPath);
    if (!existsSync(parentDir)) {
      mkdirSync(parentDir, { recursive: true, mode: 0o700 });
    }

    writeFileSync(privateKeyPath, privateKey, { mode: 0o600 });
    writeFileSync(publicKeyPath, publicKey, { mode: 0o644 });

    const encryptionKeyHex = randomBytes(32).toString('hex');
    writeFileSync(`${directory}/encryption.key`, encryptionKeyHex, { mode: 0o600 });

    return { privateKeyPath, publicKeyPath, encryptionKeyHex };
  }

  getCurrentVersion(): number {
    return this.currentKeyVersion;
  }
}
