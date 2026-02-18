// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import type { Logger } from '../utils/logger.js';
import type { AlertPayload } from '../types/threat.types.js';

export interface AlertConfig {
  webhookUrl?: string;
}

export class AlertService {
  constructor(
    private readonly config: AlertConfig,
    private readonly logger: Logger,
  ) {}

  async sendAlert(payload: AlertPayload): Promise<void> {
    const enrichedPayload = {
      ...payload,
      timestamp: payload.timestamp ?? new Date(),
      source: 'clawshield',
    };

    // Send webhook notification
    if (this.config.webhookUrl) {
      await this.sendWebhook(enrichedPayload);
    }

    // Log the alert (email would be sent via external service)
    this.logger.warn(
      {
        alertType: payload.type,
        agentId: payload.agentId,
        threatType: payload.threatType,
      },
      'Security alert triggered',
    );
  }

  private async sendWebhook(payload: AlertPayload & { source: string }): Promise<void> {
    if (!this.config.webhookUrl) return;

    try {
      const response = await fetch(this.config.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `[ClawShield Alert] ${payload.type}: Agent ${payload.agentId} - ${payload.threatType}`,
          attachments: [
            {
              color: 'danger',
              fields: [
                { title: 'Agent', value: payload.agentId, short: true },
                { title: 'Threat Type', value: payload.threatType, short: true },
                { title: 'Details', value: JSON.stringify(payload.details).slice(0, 500) },
              ],
            },
          ],
        }),
        signal: AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        this.logger.error({ status: response.status }, 'Webhook alert failed');
      }
    } catch (error) {
      this.logger.error({ err: error }, 'Failed to send webhook alert');
    }
  }
}
