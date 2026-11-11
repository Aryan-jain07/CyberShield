const { Pool } = require('pg');
const { postgres } = require('../config');

const pool = new Pool({ ...postgres, max: 10, idleTimeoutMillis: 10_000 });
pool.on('error', (error) => console.error('Unexpected PostgreSQL pool error:', error));

async function withTransaction(callback) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await callback(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

module.exports = { pool, query: (text, params) => pool.query(text, params), withTransaction };
