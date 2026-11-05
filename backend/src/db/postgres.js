const { Pool } = require('pg');
const { postgres } = require('../config');

const pool = new Pool({ ...postgres, max: 10, idleTimeoutMillis: 10_000 });
pool.on('error', (error) => console.error('Unexpected PostgreSQL pool error:', error));

module.exports = { pool, query: (text, params) => pool.query(text, params) };
