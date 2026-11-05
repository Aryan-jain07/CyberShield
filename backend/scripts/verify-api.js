const app = require('../src/app');
const { query, pool } = require('../src/db/postgres');
const { getMongoDb, closeMongo } = require('../src/db/mongo');

async function request(baseUrl, path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, options);
  const body = await response.json();
  if (!response.ok) throw new Error(`${options.method || 'GET'} ${path}: ${response.status} ${body.error || ''}`);
  return body;
}

async function main() {
  await query('SELECT 1');
  await (await getMongoDb()).command({ ping: 1 });
  const server = app.listen(0);
  await new Promise((resolve) => server.once('listening', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  let validationIncidentId;
  try {
    await request(baseUrl, '/health');
    const admin = await request(baseUrl, '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'avery.shah@cybershield.test', password: 'password' }) });
    const viewer = await request(baseUrl, '/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'dev.patel@cybershield.test', password: 'password' }) });
    const auth = { Authorization: `Bearer ${admin.token}`, 'Content-Type': 'application/json' };
    const nlp = await request(baseUrl, '/api/nlp/analyze', { method: 'POST', headers: auth, body: JSON.stringify({ title: 'Phishing Attack', description: 'Employee received a suspicious email with a malicious login link and entered credentials.' }) });
    if (nlp.suggested_category !== 'Phishing' || !nlp.suggested_techniques.includes('T1566')) throw new Error('NLP phishing rule did not return expected suggestions.');
    for (const path of ['/api/users', '/api/assets', '/api/assets/1', '/api/software', '/api/vulnerabilities', '/api/incidents', '/api/incidents/1', '/api/incidents/1/responses', '/api/indicators', '/api/threat-intelligence/185.23.45.10', '/api/analytics/overview', '/api/audit-logs?limit=5']) {
      await request(baseUrl, path, { headers: auth });
    }
    const demoCorrelation = await request(baseUrl, '/api/incidents/1/correlation', { headers: auth });
    const demoRules = new Set(demoCorrelation.findings.map((finding) => finding.rule));
    for (const rule of ['REPEATED_INDICATOR', 'CRITICAL_VULNERABILITY', 'THREAT_INTELLIGENCE_MATCH', 'RECURRING_ASSET', 'RELATED_INCIDENT']) {
      if (!demoRules.has(rule)) throw new Error(`Demo correlation is missing ${rule}.`);
    }
    const responseGap = await request(baseUrl, '/api/incidents/5/correlation', { headers: auth });
    if (!responseGap.findings.some((finding) => finding.rule === 'RESPONSE_GAP')) throw new Error('Response-gap correlation rule did not trigger.');
    const created = await request(baseUrl, '/api/incidents', { method: 'POST', headers: auth, body: JSON.stringify({ title: 'API Validation Incident', description: 'Real database API integration validation record.', severity: 'LOW', status: 'OPEN', detected_at: new Date(Date.now() - 60000).toISOString(), assigned_to: 3 }) });
    validationIncidentId = created.incident_id;
    await request(baseUrl, `/api/incidents/${created.incident_id}`, { method: 'PUT', headers: auth, body: JSON.stringify({ status: 'INVESTIGATING' }) });
    await request(baseUrl, `/api/incidents/${created.incident_id}/responses`, { method: 'POST', headers: auth, body: JSON.stringify({ action_type: 'API_VALIDATION', description: 'Real write-path test response.', status: 'COMPLETED' }) });
    await request(baseUrl, `/api/incidents/${created.incident_id}/responses`, { headers: auth });
    const denied = await fetch(`${baseUrl}/api/audit-logs`, { headers: { Authorization: `Bearer ${viewer.token}` } });
    if (denied.status !== 403) throw new Error(`Expected Viewer RBAC denial, got ${denied.status}.`);
    console.log('API integration verification passed: all endpoints responded from live PostgreSQL/MongoDB; RBAC denial confirmed.');
  } finally {
    if (validationIncidentId) await query("DELETE FROM incident WHERE incident_id = $1 AND title = 'API Validation Incident'", [validationIncidentId]);
    await new Promise((resolve) => server.close(resolve));
    await pool.end();
    await closeMongo();
  }
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
