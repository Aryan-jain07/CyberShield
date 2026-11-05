const app = require('./app');
const { port } = require('./config');
const { query, pool } = require('./db/postgres');
const { getMongoDb, closeMongo } = require('./db/mongo');

async function start() {
  await query('SELECT 1');
  await (await getMongoDb()).command({ ping: 1 });
  const server = app.listen(port, () => console.log(`CyberShield API listening on http://localhost:${port}`));
  const shutdown = async () => { server.close(); await pool.end(); await closeMongo(); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

start().catch((error) => { console.error('Startup failed:', error); process.exit(1); });
