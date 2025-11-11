import express, { Application, Request, Response, NextFunction } from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { logger } from './logger';
import { corsMiddleware } from './middleware/cors';
import { errorHandler, notFoundHandler } from './middleware/error';

// Routers (will be created in subsequent steps)
import { authRouter } from './routes/auth.router';
import { usersRouter } from './routes/users.router';
import { walletRouter } from './routes/wallet.router';
import { mediaRouter } from './routes/media.router';
import { curationRouter } from './routes/curation.router';
import { promoRouter } from './routes/promo.router';
import { saleRouter } from './routes/sale.router';
// PayPal webhook uses a raw body parser inside its own router to preserve signature
import { paypalWebhookRouter } from './routes/paypal.webhook.router';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const UPLOAD_DIR = process.env.UPLOAD_DIR || '/data/uploads';
const API_PUBLIC_URL = process.env.API_PUBLIC_URL || '';
const SITE_URL = process.env.SITE_URL || '';
const CDN_URL = process.env.CDN_URL || '';

export async function createServer(): Promise<Application> {
  const app = express();

  // Trust proxy so we can read X-Forwarded-* behind reverse proxies
  app.set('trust proxy', true);

  // Security headers
  app.use(
    helmet({
      crossOriginResourcePolicy: { policy: 'cross-origin' },
    })
  );

  // CORS
  app.use(corsMiddleware());

  // Parsers (NOTE: PayPal webhook mounts its own raw parser to preserve signature)
  app.use(express.json({ limit: '25mb' }));
  app.use(express.urlencoded({ extended: true, limit: '25mb' }));

  // Local file serving (when STORAGE_DRIVER=local)
  if ((process.env.STORAGE_DRIVER || 'local') === 'local') {
    app.use(
      '/uploads',
      express.static(UPLOAD_DIR, {
        fallthrough: true,
        setHeaders(res) {
          // Cache aggressively for immutable assets; adjust as needed
          res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
        },
      })
    );
  }

  // Health & meta
  app.get('/health', (_req: Request, res: Response) => {
    res.json({ ok: true, ts: new Date().toISOString() });
  });

  app.get('/version', (_req: Request, res: Response) => {
    res.json({
      name: 'song.money-api',
      env: process.env.NODE_ENV || 'development',
      siteUrl: SITE_URL,
      apiPublicUrl: API_PUBLIC_URL,
      cdnUrl: CDN_URL || (API_PUBLIC_URL ? `${API_PUBLIC_URL}/uploads` : undefined),
    });
  });

  // Mount routers
  app.use('/auth', authRouter);
  app.use('/users', usersRouter);
  app.use('/wallet', walletRouter);
  app.use('/media', mediaRouter);
  app.use('/curation', curationRouter);
  app.use('/promo', promoRouter);
  app.use('/sale', saleRouter);

  // Webhooks (must be mounted after general parsers but uses its own raw parser)
  app.use('/webhooks/paypal', paypalWebhookRouter);

  // 404 handler
  app.use(notFoundHandler);

  // Centralized error handler
  app.use(errorHandler);

  // Basic request logging (minimal)
  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.debug({ method: req.method, url: req.url }, 'request');
    next();
  });

  return app;
}
