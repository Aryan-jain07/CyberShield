const app = require('../src/app');
const { query, pool } = require('../src/db/postgres');
const { getMongoDb, closeMongo } = require('../src/db/mongo');

async function request(baseUrl, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const body = await response.json();
  return { response, body };
}

function headers(token) {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

async function main() {
  await query('SELECT 1');
  await (await getMongoDb()).command({ ping: 1 });
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  let incidentId;
  const indicatorValue = '198.51.100.250';

  try {
    const unauthenticated = await request(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'Unauthenticated report', description: 'Should be rejected.', severity: 'LOW', detected_at: new Date().toISOString() })
    });
    if (unauthenticated.response.status !== 401) throw new Error('Unauthenticated incident reporting was not rejected.');

    const login = await request(baseUrl, '/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'dev.patel@cybershield.test', password: 'password' })
    });
    if (login.response.status !== 200) throw new Error('Viewer login failed.');
    const auth = headers(login.body.token);

    const invalidCategory = await request(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({ title: 'Invalid category', category: 'Exploit', description: 'This category is not supported.', severity: 'LOW', detected_at: new Date(Date.now() - 60000).toISOString() })
    });
    if (invalidCategory.response.status !== 400) throw new Error('Invalid category was accepted.');

    const invalidAsset = await request(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({ title: 'Invalid asset', category: 'Other', description: 'This asset does not exist.', severity: 'LOW', detected_at: new Date(Date.now() - 60000).toISOString(), asset_id: 999999 })
    });
    if (invalidAsset.response.status !== 400) throw new Error('Invalid asset was accepted.');

    const protectedFields = await request(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({ title: 'Protected fields', category: 'Other', description: 'A reporter cannot assign or set status.', severity: 'LOW', status: 'CLOSED', assigned_to: 1, detected_at: new Date(Date.now() - 60000).toISOString() })
    });
    if (protectedFields.response.status !== 403) throw new Error(`Protected incident fields returned ${protectedFields.response.status}.`);

    const created = await request(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({
        title: 'Incident reporting verification',
        category: 'Phishing',
        description: 'A temporary incident used to verify the reporting workflow.',
        severity: 'HIGH',
        detected_at: new Date(Date.now() - 60000).toISOString(),
        asset_id: 1,
        source: 'Verification script',
        indicators: [indicatorValue],
        additional_notes: 'Temporary verification record.'
      })
    });
    if (created.response.status !== 201) throw new Error(`Incident reporting creation returned ${created.response.status}: ${created.body.error || ''}`);
    incidentId = created.body.incident_id;
    if (created.body.status !== 'OPEN' || created.body.category !== 'Phishing' || created.body.created_by !== login.body.user.user_id) {
      throw new Error('Created incident did not preserve reporting attribution or initial state.');
    }

    const detail = await request(baseUrl, `/api/incidents/${incidentId}`, { headers: auth });
    if (detail.response.status !== 200 || !detail.body.indicators.some((indicator) => indicator.value === indicatorValue)) {
      throw new Error('Created incident could not be retrieved with its indicator.');
    }

    const audit = await query(
      `SELECT user_id FROM audit_log
       WHERE entity_name = 'incident' AND entity_id = $1 AND action IN ('INCIDENT_CREATED', 'INCIDENT_CREATED_API')
       ORDER BY timestamp DESC LIMIT 1`,
      [String(incidentId)]
    );
    if (!audit.rowCount || audit.rows[0].user_id !== login.body.user.user_id) throw new Error('Incident creation audit attribution was not recorded.');

    console.log('Incident reporting verification passed: validation, RBAC, transaction creation, retrieval, indicator linking, and audit attribution confirmed.');
  } finally {
    if (incidentId) {
      await query('DELETE FROM audit_log WHERE entity_name = $1 AND entity_id = $2', ['incident', String(incidentId)]);
      await query('DELETE FROM incident WHERE incident_id = $1', [incidentId]);
      await query('DELETE FROM indicator WHERE type = $1 AND value = $2', ['IP', indicatorValue]);
    }
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
    await closeMongo();
  }
}

main().catch((error) => { console.error(error); process.exitCode = 1; });
