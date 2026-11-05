const bcrypt = require('bcrypt');
const { query, pool } = require('../src/db/postgres');

async function resetDemoPasswords() {
  const passwordHash = await bcrypt.hash('password', 12);
  const result = await query('UPDATE user_account SET password_hash = $1', [passwordHash]);
  console.log(`Updated ${result.rowCount} synthetic demo account password hashes.`);
  await pool.end();
}

resetDemoPasswords().catch((error) => { console.error(error); process.exitCode = 1; });
