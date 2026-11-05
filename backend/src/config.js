const path = require('path');
require('dotenv').config({ path: path.resolve(__dirname, '../../.env') });

for (const name of ['POSTGRES_HOST', 'POSTGRES_PORT', 'POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD', 'MONGODB_URI', 'JWT_SECRET']) {
  if (!process.env[name]) throw new Error(`Missing required environment variable: ${name}`);
}

module.exports = {
  port: Number(process.env.PORT || 4000),
  jwtSecret: process.env.JWT_SECRET,
  postgres: {
    host: process.env.POSTGRES_HOST,
    port: Number(process.env.POSTGRES_PORT),
    database: process.env.POSTGRES_DB,
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD
  },
  mongoUri: process.env.MONGODB_URI
};
