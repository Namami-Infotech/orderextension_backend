require('dotenv').config();

function int(name, def) {
  const v = process.env[name];
  const n = v === undefined || v === '' ? def : parseInt(v, 10);
  if (Number.isNaN(n)) throw new Error(`Env ${name} must be a number`);
  return n;
}

const config = {
  port: int('PORT', 3000),
  // Bind to localhost by default (safe behind nginx). Use HOST=0.0.0.0 inside Docker/containers.
  host: process.env.HOST || '127.0.0.1',
  trustProxy: process.env.TRUST_PROXY === undefined ? 1 : (isNaN(+process.env.TRUST_PROXY) ? process.env.TRUST_PROXY : +process.env.TRUST_PROXY),
  db: {
    host: process.env.DB_HOST || 'localhost',
    port: int('DB_PORT', 3306),
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    ssl: process.env.DB_SSL === 'true',
  },
  jwtSecret: process.env.JWT_SECRET,
  tokenTtl: int('TOKEN_TTL_SECONDS', 300),
  challengeTtl: int('CHALLENGE_TTL_SECONDS', 60),
  sessionTimeout: int('SESSION_TIMEOUT_SECONDS', 180),
  pingEvery: int('PING_EVERY_SECONDS', 60),
  resetCodeMinutes: int('RESET_CODE_MINUTES', 60),
  resetMaxAttempts: int('RESET_MAX_ATTEMPTS', 5),
  globalRateLimit: int('RATE_LIMIT_PER_MIN', 120),
  strictRateLimit: int('STRICT_RATE_LIMIT_PER_MIN', 20),
  minExtensionVersion: process.env.MIN_EXTENSION_VERSION || '1.0.0',
};

if (!config.db.user || !config.db.database) throw new Error('DB_USER and DB_NAME must be set');
if (!config.jwtSecret || config.jwtSecret.length < 16 || config.jwtSecret.startsWith('CHANGE_ME')) {
  throw new Error('JWT_SECRET must be set (at least 16 characters)');
}

module.exports = config;
