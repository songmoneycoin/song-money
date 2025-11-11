import pino, { Logger, LoggerOptions, Bindings } from 'pino';
import { config } from './config';

const isDev = config.env !== 'production';

const options: LoggerOptions = {
  level: config.logLevel,
  base: {
    app: 'song.money-api',
    env: config.env,
  },
  timestamp: pino.stdTimeFunctions.isoTime,
  redact: {
    paths: [
      // Generic secrets
      'req.headers.authorization',
      'headers.authorization',
      'payload.client_secret',
      'clientSecret',
      'secret',
      '*.password',
      '*.pass',
      // RPC creds
      'rpc.user',
      'rpc.pass',
      'config.rpc.user',
      'config.rpc.pass',
      // PayPal
      'paypal.clientSecret',
      'paypal.webhookId',
      'config.paypal.clientSecret',
      'config.paypal.webhookId'
    ],
    censor: '[REDACTED]'
  }
};

const transport = isDev
  ? pino.transport({
      target: 'pino-pretty',
      options: {
        colorize: true,
        translateTime: 'SYS:standard',
        ignore: 'pid,hostname'
      }
    })
  : undefined;

export const logger: Logger = transport ? pino(options, transport) : pino(options);

/** Create a child logger with bound fields (e.g., { module: 'wallet' }). */
export function child(bindings: Bindings): Logger {
  return logger.child(bindings);
}
