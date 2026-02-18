// Copyright (c) 2026 DEFNOISE AI — Licensed under AGPL-3.0. See LICENSE.

import pino from 'pino';

export function createLogger(level = 'info', isDev = false): pino.Logger {
  return pino({
    level,
    redact: {
      paths: [
        'password',
        'apiKey',
        'token',
        'authorization',
        'cookie',
        'secret',
        'encryptionKey',
        '*.password',
        '*.apiKey',
        '*.token',
        '*.secret',
        '*.authorization',
        'headers.authorization',
        'headers.cookie',
        'body.password',
        'body.apiKey',
        'body.token',
      ],
      censor: '[REDACTED]',
    },
    serializers: {
      req: (req) => ({
        method: req.method,
        url: req.url,
        remoteAddress: req.remoteAddress,
        requestId: req.id,
      }),
      res: (res) => ({
        statusCode: res.statusCode,
      }),
      err: pino.stdSerializers.err,
    },
    ...(isDev && {
      transport: {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'HH:MM:ss',
          ignore: 'pid,hostname',
        },
      },
    }),
  });
}

export type Logger = pino.Logger;
