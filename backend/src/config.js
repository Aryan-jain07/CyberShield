const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

for (const name of ['MONGODB_URI', 'JWT_SECRET']) {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
}

const postgres = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL
    }
  : (() => {
      const required = [
        'POSTGRES_HOST',
        'POSTGRES_PORT',
        'POSTGRES_DB',
        'POSTGRES_USER',
        'POSTGRES_PASSWORD'
      ];

      for (const name of required) {
        if (!process.env[name]) {
          throw new Error(
            `Missing required environment variable: ${name} (or provide DATABASE_URL)`
          );
        }
      }

      return {
        host: process.env.POSTGRES_HOST,
        port: Number(process.env.POSTGRES_PORT),
        database: process.env.POSTGRES_DB,
        user: process.env.POSTGRES_USER,
        password: process.env.POSTGRES_PASSWORD
      };
    })();

const localOrigins = ['http://localhost:5173', 'http://127.0.0.1:5173'];
const configuredOrigins = (process.env.FRONTEND_URL || '').split(',').map((value) => {
  const origin = value.trim();
  if (!origin) return null;
  if (origin === '*') throw new Error('FRONTEND_URL must not contain a wildcard origin.');

  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    throw new Error(`Invalid FRONTEND_URL origin: ${origin}`);
  }

  if (!['http:', 'https:'].includes(parsed.protocol)
    || parsed.pathname !== '/'
    || parsed.search
    || parsed.hash
    || parsed.username
    || parsed.password) {
    throw new Error(`Invalid FRONTEND_URL origin: ${origin}`);
  }

  return parsed.origin;
}).filter(Boolean);
const frontendOrigins = [...new Set([...localOrigins, ...configuredOrigins])];

module.exports = {
  frontendOrigins,
  port: Number(process.env.PORT || 4000),
  jwtSecret: process.env.JWT_SECRET,
  postgres,
  mongoUri: process.env.MONGODB_URI
};
