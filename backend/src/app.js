const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const api = require('./routes/api');
const { apiError } = require('./lib/http');
const cors = require('cors');
const { frontendOrigins } = require('./config');
const { query } = require('./db/postgres');
const { getMongoDb } = require('./db/mongo');

const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: (origin, callback) => {
    if (!origin || frontendOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(apiError(403, 'Origin is not allowed.'));
  },
  credentials: true
}));
app.use(express.json({ limit: '100kb' }));
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.get('/ready', async (_req, res) => {
  const [postgres, mongodb] = await Promise.allSettled([
    query('SELECT 1'),
    getMongoDb().then((database) => database.command({ ping: 1 }))
  ]);
  const dependencies = {
    postgres: postgres.status === 'fulfilled' ? 'ok' : 'unavailable',
    mongodb: mongodb.status === 'fulfilled' ? 'ok' : 'unavailable'
  };
  if (Object.values(dependencies).every((status) => status === 'ok')) {
    return res.json({ status: 'ready', dependencies });
  }
  return res.status(503).json({ status: 'not_ready', dependencies });
});
app.use('/api', api);
app.use((_req, _res, next) => next(apiError(404, 'Route not found.')));
app.use((error, _req, res, _next) => {
  const status = error.status || (error.code === '23505' ? 409 : error.code === '23503' ? 400 : 500);
  if (status === 500) console.error(error);
  res.status(status).json({ error: error.message || 'Internal server error.' });
});
module.exports = app;
