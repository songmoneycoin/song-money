import z from 'zod';

/**
 * Centralized, typed configuration parsed from environment variables.
 * Keep all defaults in sync with .env.example and README.
 */

const str = (v: string | undefined, d: string) => (v && v.length ? v : d);
const int = (v: string | undefined, d: number) => {
  const n = Number.parseInt(v ?? '', 10);
  return Number.isFinite(n) ? n : d;
};
const num = (v: string | undefined, d: number) => {
  const n = Number(v);
  return Number.isFinite(n) ? n : d;
};
const bool = (v: string | undefined, d: boolean) => {
  if (v == null) return d;
  const s = v.toLowerCase?.() ?? '';
  if (['1', 'true', 'yes', 'y', 'on'].includes(s)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(s)) return false;
  return d;
};
const csv = (v: string | undefined): string[] =>
  (v ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

const schema = z.object({
  env: z.enum(['development', 'test', 'production']).default('development'),
  logLevel: z.string().default('info'),

  host: z.string().default('0.0.0.0'),
  port: z.number().int().default(4000),

  siteUrl: z.string().url().default('https://song.money'),
  apiPublicUrl: z.string().url().or(z.literal('')).default(''),
  cdnUrl: z.string().url().or(z.literal('')).default(''),

  corsOrigins: z.array(z.string()).default(['http://localhost:3000', 'https://song.money']),

  // Storage
  storageDriver: z.enum(['local', 'minio', 's3']).default('local'),
  uploadDir: z.string().default('/data/uploads'),
  s3: z.object({
    endpoint: z.string().default('http://minio:9000'),
    region: z.string().default('us-east-1'),
    bucket: z.string().default('song-uploads'),
    accessKeyId: z.string().default('change_me'),
    secretAccessKey: z.string().default('change_me'),
    forcePathStyle: z.boolean().default(true),
  }),

  // SONG RPC
  rpc: z.object({
    url: z.string().default('http://127.0.0.1:6332'),
    user: z.string().default('change_me'),
    pass: z.string().default('change_me'),
    confirmations: z.number().int().nonnegative().default(6),
  }),

  // Sale parameters (numbers; precise math handled with Prisma.Decimal in services/seed)
  sale: z.object({
    totalSong: z.number().positive().default(500_000),
    targetUsd: z.number().positive().default(2_300_000),
    kLn2: z.number().positive().default(0.69314718056),
    quoteLockSeconds: z.number().int().positive().default(120),
    perOrderMaxSong: z.number().nonnegative().default(5_000),
    hotWalletDailyLimitSong: z.number().nonnegative().default(25_000),
  }),

  // PayPal
  paypal: z.object({
    env: z.enum(['sandbox', 'live']).default('sandbox'),
    clientId: z.string().default('change_me'),
    clientSecret: z.string().default('change_me'),
    webhookId: z.string().default('change_me'),
  }),

  // Feature flags / policies
  requireProfileForSale: z.boolean().default(false),
  requireDepositBeforeWithdraw: z.boolean().default(true),
});

export type AppConfig = z.infer<typeof schema>;

export const config: AppConfig = schema.parse({
  env: str(process.env.NODE_ENV, 'development'),
  logLevel: str(process.env.LOG_LEVEL, 'info'),

  host: str(process.env.HOST, '0.0.0.0'),
  port: int(process.env.PORT, 4000),

  siteUrl: str(process.env.SITE_URL, 'https://song.money'),
  apiPublicUrl: str(process.env.API_PUBLIC_URL, ''),
  cdnUrl: str(process.env.CDN_URL, ''),

  corsOrigins: csv(process.env.CORS_ORIGINS).length
    ? csv(process.env.CORS_ORIGINS)
    : ['http://localhost:3000', 'https://song.money'],

  storageDriver: str(process.env.STORAGE_DRIVER, 'local') as 'local' | 'minio' | 's3',
  uploadDir: str(process.env.UPLOAD_DIR, '/data/uploads'),
  s3: {
    endpoint: str(process.env.S3_ENDPOINT, 'http://minio:9000'),
    region: str(process.env.S3_REGION, 'us-east-1'),
    bucket: str(process.env.S3_BUCKET, 'song-uploads'),
    accessKeyId: str(process.env.S3_ACCESS_KEY_ID, 'change_me'),
    secretAccessKey: str(process.env.S3_SECRET_ACCESS_KEY, 'change_me'),
    forcePathStyle: bool(process.env.S3_FORCE_PATH_STYLE, true),
  },

  rpc: {
    url: str(process.env.SONG_RPC_URL, 'http://127.0.0.1:6332'),
    user: str(process.env.SONG_RPC_USER, 'change_me'),
    pass: str(process.env.SONG_RPC_PASS, 'change_me'),
    confirmations: int(process.env.CONFIRMATIONS, 6),
  },

  sale: {
    totalSong: num(process.env.PREMINE_TOTAL, 500_000),
    targetUsd: num(process.env.PREMINE_TARGET_USD, 2_300_000),
    kLn2: num(process.env.PREMINE_K_LN2, 0.69314718056),
    quoteLockSeconds: int(process.env.QUOTE_LOCK_SECONDS, 120),
    perOrderMaxSong: num(process.env.ORDER_MAX_SONG, 5_000),
    hotWalletDailyLimitSong: num(process.env.HOTWALLET_DAILY_LIMIT_SONG, 25_000),
  },

  paypal: {
    env: (str(process.env.PAYPAL_ENV, 'sandbox') as 'sandbox' | 'live'),
    clientId: str(process.env.PAYPAL_CLIENT_ID, 'change_me'),
    clientSecret: str(process.env.PAYPAL_CLIENT_SECRET, 'change_me'),
    webhookId: str(process.env.PAYPAL_WEBHOOK_ID, 'change_me'),
  },

  requireProfileForSale: bool(process.env.REQUIRE_PROFILE_FOR_SALE, false),
  requireDepositBeforeWithdraw: bool(process.env.REQUIRE_DEPOSIT_BEFORE_WITHDRAW, true),
});

// Derived helpers

/** Returns the absolute URL for public uploads when using local storage. */
export function uploadsBaseUrl(): string | undefined {
  if (config.cdnUrl) return config.cdnUrl;
  if (config.apiPublicUrl) return `${config.apiPublicUrl.replace(/\/+$/, '')}/uploads`;
  return undefined;
}

/** Validates that a requested SONG amount respects policy limits. */
export function clampOrderQuantitySong(q: number): number {
  const max = config.sale.perOrderMaxSong;
  if (!max || max <= 0) return q;
  return Math.min(q, max);
}
