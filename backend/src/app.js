const express = require('express');
const api = require('./routes/api');
const { apiError } = require('./lib/http');

const app = express();
app.use(express.json({ limit: '100kb' }));
app.get('/health', (_req, res) => res.json({ status: 'ok' }));
app.use('/api', api);
app.use((_req, _res, next) => next(apiError(404, 'Route not found.')));
app.use((error, _req, res, _next) => {
  const status = error.status || (error.code === '23505' ? 409 : error.code === '23503' ? 400 : 500);
  if (status === 500) console.error(error);
  res.status(status).json({ error: error.message || 'Internal server error.' });
});
module.exports = app;
