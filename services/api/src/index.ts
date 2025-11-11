import 'dotenv/config';
import http from 'http';
import { AddressInfo } from 'net';
import { createServer } from './server';
import { logger } from './logger';

const PORT = parseInt(process.env.PORT || '4000', 10);
const HOST = process.env.HOST || '0.0.0.0';

async function bootstrap() {
  try {
    const app = await createServer();
    const server = http.createServer(app);

    server.listen(PORT, HOST, () => {
      const addr = server.address() as AddressInfo | null;
      const host = addr?.address ?? HOST;
      const port = addr?.port ?? PORT;
      logger.info(
        {
          env: process.env.NODE_ENV,
          host,
          port,
          siteUrl: process.env.SITE_URL,
          apiPublicUrl: process.env.API_PUBLIC_URL || `http://${host}:${port}`,
        },
        'SONG.money API up'
      );
    });

    const shutdown = async (signal: NodeJS.Signals | 'manual', code = 0) => {
      try {
        logger.info({ signal }, 'Shutting down API...');
        await new Promise<void>((resolve) => server.close(() => resolve()));
      } catch (e) {
        logger.error({ err: e }, 'Error while closing HTTP server');
      } finally {
        // Lazy import to avoid hard dependency here if db is unused in some tasks
        try {
          const mod = await import('./db/prisma');
          await mod.prisma.$disconnect();
        } catch {
          /* ignore */
        }
        logger.info('Goodbye.');
        process.exit(code);
      }
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('uncaughtException', (err) => {
      logger.error({ err }, 'Uncaught exception');
      // give it a moment for logs to flush
      setTimeout(() => shutdown('manual', 1), 50);
    });
    process.on('unhandledRejection', (reason) => {
      logger.error({ reason }, 'Unhandled rejection');
      setTimeout(() => shutdown('manual', 1), 50);
    });
  } catch (err) {
    logger.fatal({ err }, 'Failed to start API');
    process.exit(1);
  }
}

bootstrap();
