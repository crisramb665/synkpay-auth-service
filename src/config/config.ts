export default () => ({
  PORT: parseInt(process.env.PORT ?? '5000', 10),
  NODE_ENV: process.env.NODE_ENV ?? 'development',
  API_KEY: process.env.API_KEY,
  RATE_LIMIT_GLOBAL: parseInt(process.env.RATE_LIMIT_GLOBAL ?? '10', 10),
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS ?? '60000', 10),
  SDK_FINANCE_BASE_URL: process.env.SDK_FINANCE_BASE_URL,
  JWT_PUBLIC_KEY_DEV: process.env.JWT_PUBLIC_KEY_DEV ?? '',
  JWT_PUBLIC_KEY_PROD: process.env.JWT_PUBLIC_KEY_PROD ?? '',
  JWT_PRIVATE_KEY_DEV: process.env.JWT_PRIVATE_KEY_DEV ?? '',
  JWT_PRIVATE_KEY_PROD: process.env.JWT_PRIVATE_KEY_PROD ?? '',
  JWT_EXPIRE_TIME: process.env.JWT_EXPIRE_TIME ?? '5h',
  JWT_REFRESH_EXPIRE_TIME: process.env.JWT_REFRESH_EXPIRE_TIME ?? '7d',
  REDIS_HOST: process.env.REDIS_HOST ?? 'localhost',
  REDIS_PORT: parseInt(process.env.REDIS_PORT ?? '6379', 10),
  ENABLE_HTTPS: process.env.ENABLE_HTTPS === 'true',
  CORS_ORIGIN: process.env.CORS_ORIGIN ?? '*',

  // Logging Configuration
  LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  LOG_TO_CONSOLE: process.env.LOG_TO_CONSOLE !== 'false',
  LOG_TO_FILE: process.env.LOG_TO_FILE === 'true',
  LOG_FILE_PATH: process.env.LOG_FILE_PATH || 'logs/app.log',
})
