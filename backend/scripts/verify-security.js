const app = require('../src/app');
const { query, pool, withTransaction } = require('../src/db/postgres');
const { getMongoDb, closeMongo } = require('../src/db/mongo');

async function jsonRequest(baseUrl, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const body = await response.json();
  return { response, body };
}

async function verifyTriggerAttribution(actorContext, expectedUserId, label) {
  await withTransaction(async (client) => {
    await client.query("SELECT set_config('app.actor_user_id', $1, true)", [actorContext]);
    const inserted = await client.query(
      `INSERT INTO incident (title, description, severity, status, detected_at, created_by)
       VALUES ($1, $2, 'LOW', 'OPEN', CURRENT_TIMESTAMP, 1)
       RETURNING incident_id`,
      [`Security trigger test: ${label}`, `Temporary trigger attribution test for ${label}.`]
    );
    const audit = await client.query(
      `SELECT user_id FROM audit_log
       WHERE entity_name = 'incident' AND entity_id = $1 AND action = 'INCIDENT_CREATED'`,
      [String(inserted.rows[0].incident_id)]
    );
    if (!audit.rowCount || audit.rows[0].user_id !== expectedUserId) {
      throw new Error(`Trigger attribution failed for ${label}.`);
    }
    await client.query('DELETE FROM audit_log WHERE entity_name = $1 AND entity_id = $2', ['incident', String(inserted.rows[0].incident_id)]);
    await client.query('DELETE FROM incident WHERE incident_id = $1', [inserted.rows[0].incident_id]);
  });
}

function headers(ip, extra = {}) {
  return { 'Content-Type': 'application/json', 'X-Forwarded-For': ip, ...extra };
}

async function main() {
  await query('SELECT 1');
  await (await getMongoDb()).command({ ping: 1 });
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  let validationIncidentId;

  try {
    const health = await jsonRequest(baseUrl, '/health');
    if (health.response.status !== 200 || health.body.status !== 'ok') throw new Error('Liveness check failed.');

    const ready = await jsonRequest(baseUrl, '/ready');
    if (ready.response.status !== 200 || ready.body.status !== 'ready') throw new Error('Readiness check failed.');

    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const login = await jsonRequest(baseUrl, '/api/auth/login', {
        method: 'POST',
        headers: headers('198.51.100.10'),
        body: JSON.stringify({ email: 'invalid@example.test', password: 'invalid' })
      });
      if (login.response.status !== 401) throw new Error(`Unexpected login status on attempt ${attempt}: ${login.response.status}`);
    }
    const limited = await jsonRequest(baseUrl, '/api/auth/login', {
      method: 'POST',
      headers: headers('198.51.100.10'),
      body: JSON.stringify({ email: 'invalid@example.test', password: 'invalid' })
    });
    if (limited.response.status !== 429) throw new Error(`Expected login rate limit, got ${limited.response.status}.`);

    const adminLogin = await jsonRequest(baseUrl, '/api/auth/login', {
      method: 'POST',
      headers: headers('198.51.100.11'),
      body: JSON.stringify({ email: 'avery.shah@cybershield.test', password: 'password' })
    });
    if (adminLogin.response.status !== 200) throw new Error('Admin login failed.');
    const auth = headers('198.51.100.11', { Authorization: `Bearer ${adminLogin.body.token}` });

    const roleAccounts = [
      ['avery.shah@cybershield.test', 'Admin', true, true],
      ['riya.mehta@cybershield.test', 'Security Analyst', true, false],
      ['karan.iyer@cybershield.test', 'Incident Responder', true, false],
      ['nina.roy@cybershield.test', 'Threat Researcher', false, true],
      ['dev.patel@cybershield.test', 'Viewer', false, false]
    ];
    for (const [index, [email, role, canWrite, canReadAudit]] of roleAccounts.entries()) {
      const session = await jsonRequest(baseUrl, '/api/auth/login', {
        method: 'POST',
        headers: headers(`198.51.100.${20 + index}`),
        body: JSON.stringify({ email, password: 'password' })
      });
      if (session.response.status !== 200 || session.body.user.role_name !== role) throw new Error(`RBAC login failed for ${role}.`);
      const roleAuth = headers('198.51.100.50', { Authorization: `Bearer ${session.body.token}` });
      const read = await jsonRequest(baseUrl, '/api/incidents', { headers: roleAuth });
      if (read.response.status !== 200) throw new Error(`${role} could not read incidents.`);
      const write = await jsonRequest(baseUrl, '/api/incidents', {
        method: 'POST',
        headers: roleAuth,
        body: JSON.stringify({})
      });
      if (write.response.status !== (canWrite ? 400 : 403)) throw new Error(`${role} write authorization returned ${write.response.status}.`);
      const audit = await jsonRequest(baseUrl, '/api/audit-logs?limit=1', { headers: roleAuth });
      if (audit.response.status !== (canReadAudit ? 200 : 403)) throw new Error(`${role} audit authorization returned ${audit.response.status}.`);
    }

    const invalidCreate = await jsonRequest(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({ title: 42, description: 'Invalid payload', severity: 'LOW', status: 'OPEN', detected_at: new Date().toISOString() })
    });
    if (invalidCreate.response.status !== 400) throw new Error(`Invalid incident was accepted with ${invalidCreate.response.status}.`);

    const invalidUpdate = await jsonRequest(baseUrl, '/api/incidents/not-an-id', {
      method: 'PUT',
      headers: auth,
      body: JSON.stringify({ status: 'OPEN' })
    });
    if (invalidUpdate.response.status !== 400) throw new Error(`Invalid incident ID returned ${invalidUpdate.response.status}.`);

    const unknownFieldUpdate = await jsonRequest(baseUrl, '/api/incidents/1', {
      method: 'PUT',
      headers: auth,
      body: JSON.stringify({ status: 'OPEN', unexpected: true })
    });
    if (unknownFieldUpdate.response.status !== 400 || !unknownFieldUpdate.body.error.includes('Unknown incident field')) {
      throw new Error(`Unknown incident field returned ${unknownFieldUpdate.response.status}.`);
    }

    const invalidResponse = await jsonRequest(baseUrl, '/api/incidents/1/responses', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({ action_type: 'TEST', description: 'Invalid status', status: 'INVALID' })
    });
    if (invalidResponse.response.status !== 400) throw new Error(`Invalid response action was accepted with ${invalidResponse.response.status}.`);

    const created = await jsonRequest(baseUrl, '/api/incidents', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({
        title: 'Security Verification Incident',
        description: 'Temporary record for security verification.',
        severity: 'LOW',
        status: 'OPEN',
        detected_at: new Date(Date.now() - 60_000).toISOString()
      })
    });
    if (created.response.status !== 201) throw new Error(`Security verification incident creation failed with ${created.response.status}.`);
    validationIncidentId = created.body.incident_id;

    const updated = await jsonRequest(baseUrl, `/api/incidents/${validationIncidentId}`, {
      method: 'PUT',
      headers: auth,
      body: JSON.stringify({ status: 'INVESTIGATING' })
    });
    if (updated.response.status !== 200) throw new Error(`Security verification incident update failed with ${updated.response.status}.`);

    const audit = await query(
      `SELECT user_id FROM audit_log
       WHERE entity_name = 'incident' AND entity_id = $1 AND action = 'INCIDENT_UPDATED_API'
       ORDER BY timestamp DESC LIMIT 1`,
      [String(validationIncidentId)]
    );
    if (!audit.rowCount || audit.rows[0].user_id !== adminLogin.body.user.user_id) throw new Error('Incident update audit attribution was not assigned to the acting user.');

    await verifyTriggerAttribution('2', 2, 'valid actor');
    await verifyTriggerAttribution('not-a-user-id', 1, 'malformed actor');
    await verifyTriggerAttribution('2147483647', 1, 'nonexistent actor');

    console.log('Security verification passed: rate limiting, validation, readiness, and audit attribution confirmed.');
  } finally {
    if (validationIncidentId) {
      await query('DELETE FROM incident WHERE incident_id = $1', [validationIncidentId]);
    }
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
    await closeMongo();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
