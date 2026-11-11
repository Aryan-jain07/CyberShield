const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { query, withTransaction } = require('../db/postgres');
const { getMongoDb } = require('../db/mongo');
const { jwtSecret } = require('../config');
const {
  asyncHandler,
  apiError,
  parseId,
  requireFields,
  requireString,
  requireEnum,
  requireOptionalId,
  requireDate
} = require('../lib/http');
const { authenticate, authorize, roles } = require('../middleware/auth');
const { writeAudit } = require('../services/audit');
const { getInvestigation, correlateIncident } = require('../services/correlation');
const { analyzeIncidentText } = require('../services/nlp');

const router = express.Router();
const readers = [roles.ADMIN, roles.ANALYST, roles.RESPONDER, roles.RESEARCHER, roles.VIEWER];
const investigators = [roles.ADMIN, roles.ANALYST, roles.RESPONDER];
const severity = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const incidentStatus = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'];
const actionStatus = ['PLANNED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'];
const loginLimiter = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' }
});

router.post('/auth/login', loginLimiter, asyncHandler(async (req, res) => {
  requireFields(req.body, ['email', 'password']);
  requireString(req.body.email, 'email', 255);
  requireString(req.body.password, 'password', 200);
  const result = await query(`SELECT u.user_id,u.name,u.email,u.password_hash,r.role_name FROM user_account u JOIN role r ON r.role_id=u.role_id WHERE lower(u.email)=lower($1)`, [req.body.email]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(req.body.password, user.password_hash))) throw apiError(401, 'Invalid email or password.');
  const token = jwt.sign({ user_id: user.user_id, name: user.name, email: user.email, role_name: user.role_name }, jwtSecret, { expiresIn: '8h' });
  await writeAudit(user.user_id, 'user_account', user.user_id, 'LOGIN', { email: user.email });
  res.json({ token, user: { user_id: user.user_id, name: user.name, email: user.email, role_name: user.role_name } });
}));

router.use(authenticate);

router.post('/nlp/analyze', authorize(...readers), asyncHandler(async (req, res) => {
  requireFields(req.body, ['title', 'description']);
  if (req.body.title.length > 200 || req.body.description.length > 10_000) throw apiError(400, 'Incident text exceeds the allowed length.');
  res.json(analyzeIncidentText(req.body.title, req.body.description));
}));

router.get('/users', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query(`SELECT u.user_id,u.name,u.email,r.role_name FROM user_account u JOIN role r ON r.role_id=u.role_id ORDER BY u.user_id`);
  res.json(result.rows);
}));

router.get('/assets', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query(`SELECT a.*,u.name AS owner_name,COUNT(DISTINCT aws.software_id) AS software_count,COUNT(DISTINCT sv.vuln_id) AS vulnerability_count FROM asset a LEFT JOIN user_account u ON u.user_id=a.owner_user_id LEFT JOIN asset_software aws ON aws.asset_id=a.asset_id LEFT JOIN software_vuln sv ON sv.software_id=aws.software_id GROUP BY a.asset_id,u.name ORDER BY a.hostname`);
  res.json(result.rows);
}));
router.get('/assets/:id', authorize(...readers), asyncHandler(async (req, res) => {
  const id = parseId(req.params.id, 'asset id');
  const asset = await query('SELECT a.*,u.name AS owner_name FROM asset a LEFT JOIN user_account u ON u.user_id=a.owner_user_id WHERE a.asset_id=$1', [id]);
  if (!asset.rowCount) throw apiError(404, 'Asset not found.');
  const software = await query(`SELECT s.*,aws.installed_version,aws.installed_at,COALESCE(json_agg(jsonb_build_object('cve_id',v.cve_id,'cvss_score',v.cvss_score,'status',v.status)) FILTER (WHERE v.vuln_id IS NOT NULL),'[]') AS vulnerabilities FROM asset_software aws JOIN software s ON s.software_id=aws.software_id LEFT JOIN software_vuln sv ON sv.software_id=s.software_id LEFT JOIN vulnerability v ON v.vuln_id=sv.vuln_id WHERE aws.asset_id=$1 GROUP BY s.software_id,aws.installed_version,aws.installed_at`, [id]);
  res.json({ ...asset.rows[0], software: software.rows });
}));

router.get('/software', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query(`SELECT s.*,COUNT(DISTINCT aws.asset_id) AS asset_count,COUNT(DISTINCT sv.vuln_id) AS vulnerability_count FROM software s LEFT JOIN asset_software aws ON aws.software_id=s.software_id LEFT JOIN software_vuln sv ON sv.software_id=s.software_id GROUP BY s.software_id ORDER BY s.name,s.version`);
  res.json(result.rows);
}));
router.get('/vulnerabilities', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query(`SELECT v.*,COUNT(DISTINCT sv.software_id) AS software_count FROM vulnerability v LEFT JOIN software_vuln sv ON sv.vuln_id=v.vuln_id GROUP BY v.vuln_id ORDER BY v.cvss_score DESC,v.cve_id`);
  res.json(result.rows);
}));

router.get('/incidents', authorize(...readers), asyncHandler(async (req, res) => {
  const values = []; const filters = [];
  if (req.query.severity) { if (!severity.includes(req.query.severity)) throw apiError(400, 'Invalid severity filter.'); values.push(req.query.severity); filters.push(`i.severity=$${values.length}`); }
  if (req.query.status) { if (!incidentStatus.includes(req.query.status)) throw apiError(400, 'Invalid status filter.'); values.push(req.query.status); filters.push(`i.status=$${values.length}`); }
  if (req.query.search) { values.push(`%${req.query.search}%`); filters.push(`(i.title ILIKE $${values.length} OR i.description ILIKE $${values.length})`); }
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const result = await query(`SELECT * FROM vw_incident_summary i ${where} ORDER BY i.detected_at DESC`, values);
  res.json(result.rows);
}));
router.get('/incidents/:id', authorize(...readers), asyncHandler(async (req, res) => res.json(await getInvestigation(parseId(req.params.id, 'incident id')))));
router.get('/incidents/:id/correlation', authorize(...readers), asyncHandler(async (req, res) => res.json(await correlateIncident(parseId(req.params.id, 'incident id')))));
router.post('/incidents', authorize(...investigators), asyncHandler(async (req, res) => {
  requireFields(req.body, ['title', 'description', 'severity', 'status', 'detected_at']);
  requireString(req.body.title, 'title', 200);
  requireString(req.body.description, 'description', 10_000);
  requireEnum(req.body.severity, 'severity', severity);
  requireEnum(req.body.status, 'status', incidentStatus);
  requireDate(req.body.detected_at, 'detected_at');
  requireOptionalId(req.body.assigned_to, 'assigned_to');
  const result = await withTransaction(async (client) => {
    await client.query("SELECT set_config('app.actor_user_id', $1, true)", [String(req.user.user_id)]);
    const inserted = await client.query(`INSERT INTO incident (title,description,severity,status,detected_at,created_by,assigned_to) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`, [req.body.title, req.body.description, req.body.severity, req.body.status, req.body.detected_at, req.user.user_id, req.body.assigned_to ?? null]);
    await writeAudit(req.user.user_id, 'incident', inserted.rows[0].incident_id, 'INCIDENT_CREATED_API', {}, client.query.bind(client));
    return inserted;
  });
  res.status(201).json(result.rows[0]);
}));
router.put('/incidents/:id', authorize(...investigators), asyncHandler(async (req, res) => {
  const id = parseId(req.params.id, 'incident id'); requireFields(req.body, []);
  const allowed = ['title', 'description', 'severity', 'status', 'assigned_to'];
  const unknownFields = Object.keys(req.body).filter((key) => !allowed.includes(key));
  if (unknownFields.length) throw apiError(400, `Unknown incident field(s): ${unknownFields.join(', ')}.`);
  const entries = Object.entries(req.body).filter(([key]) => allowed.includes(key));
  if (!entries.length) throw apiError(400, 'No editable incident fields supplied.');
  if (Object.prototype.hasOwnProperty.call(req.body, 'title')) requireString(req.body.title, 'title', 200);
  if (Object.prototype.hasOwnProperty.call(req.body, 'description')) requireString(req.body.description, 'description', 10_000);
  if (Object.prototype.hasOwnProperty.call(req.body, 'severity')) requireEnum(req.body.severity, 'severity', severity);
  if (Object.prototype.hasOwnProperty.call(req.body, 'status')) requireEnum(req.body.status, 'status', incidentStatus);
  if (Object.prototype.hasOwnProperty.call(req.body, 'assigned_to')) requireOptionalId(req.body.assigned_to, 'assigned_to');
  const set = entries.map(([key], index) => `${key}=$${index + 2}`).join(', ');
  const result = await withTransaction(async (client) => {
    await client.query("SELECT set_config('app.actor_user_id', $1, true)", [String(req.user.user_id)]);
    const updated = await client.query(`UPDATE incident SET ${set} WHERE incident_id=$1 RETURNING *`, [id, ...entries.map(([, value]) => value)]);
    if (updated.rowCount) await writeAudit(req.user.user_id, 'incident', id, 'INCIDENT_UPDATED_API', Object.fromEntries(entries), client.query.bind(client));
    return updated;
  });
  if (!result.rowCount) throw apiError(404, 'Incident not found.');
  res.json(result.rows[0]);
}));
router.get('/incidents/:id/responses', authorize(...readers), asyncHandler(async (req, res) => {
  const id = parseId(req.params.id, 'incident id');
  const result = await query('SELECT ra.*,u.name AS responder_name FROM response_action ra LEFT JOIN user_account u ON u.user_id=ra.responder_id WHERE ra.incident_id=$1 ORDER BY ra.performed_at DESC', [id]);
  res.json(result.rows);
}));
router.post('/incidents/:id/responses', authorize(...investigators), asyncHandler(async (req, res) => {
  const id = parseId(req.params.id, 'incident id'); requireFields(req.body, ['action_type', 'description', 'status']);
  requireString(req.body.action_type, 'action_type', 100);
  requireString(req.body.description, 'description', 10_000);
  requireEnum(req.body.status, 'status', actionStatus);
  if (req.body.performed_at !== undefined && req.body.performed_at !== null) requireDate(req.body.performed_at, 'performed_at');
  const result = await query(`INSERT INTO response_action (incident_id,responder_id,action_type,description,status,performed_at) VALUES ($1,$2,$3,$4,$5,COALESCE($6,CURRENT_TIMESTAMP)) RETURNING *`, [id, req.user.user_id, req.body.action_type, req.body.description, req.body.status, req.body.performed_at || null]);
  await writeAudit(req.user.user_id, 'response_action', result.rows[0].action_id, 'RESPONSE_ACTION_CREATED');
  res.status(201).json(result.rows[0]);
}));

router.get('/indicators', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query(`SELECT ind.*,COUNT(DISTINCT ii.incident_id) AS incident_count FROM indicator ind LEFT JOIN incident_indicator ii ON ii.indicator_id=ind.indicator_id GROUP BY ind.indicator_id ORDER BY ind.last_seen DESC`); res.json(result.rows);
}));
router.get('/threat-intelligence/:indicator', authorize(...readers), asyncHandler(async (req, res) => {
  const db = await getMongoDb(); const documents = await db.collection('threat_indicators').find({ indicator: req.params.indicator }).project({ _id: 0 }).toArray();
  console.info('[threat-intelligence lookup]', {
    database: db.databaseName,
    collection: 'threat_indicators',
    indicatorLength: req.params.indicator.length,
    matchCount: documents.length
  });
  if (!documents.length) throw apiError(404, 'Threat intelligence not found for indicator.'); res.json(documents);
}));

router.get('/analytics/overview', authorize(...readers), asyncHandler(async (_req, res) => {
  const [totals, severityData, statusData, assets, techniques] = await Promise.all([
    query(`SELECT COUNT(*) AS total_incidents,COUNT(*) FILTER (WHERE status IN ('OPEN','INVESTIGATING')) AS open_incidents,COUNT(*) FILTER (WHERE severity='CRITICAL') AS critical_incidents,(SELECT COUNT(*) FROM asset) AS total_assets,(SELECT COUNT(*) FROM vulnerability WHERE status='OPEN' AND cvss_score>=7) AS critical_vulnerabilities FROM incident`),
    query('SELECT severity,COUNT(*) AS count FROM incident GROUP BY severity ORDER BY severity'), query('SELECT status,COUNT(*) AS count FROM incident GROUP BY status ORDER BY status'),
    query('SELECT a.hostname,COUNT(*) AS count FROM asset a JOIN incident_asset ia ON ia.asset_id=a.asset_id GROUP BY a.asset_id,a.hostname ORDER BY count DESC,a.hostname LIMIT 10'),
    query('SELECT t.attack_id,t.name,COUNT(*) AS count FROM technique t JOIN incident_technique it ON it.technique_id=t.technique_id GROUP BY t.technique_id,t.attack_id,t.name ORDER BY count DESC,t.attack_id LIMIT 10')
  ]);
  res.json({ ...totals.rows[0], incidents_by_severity: severityData.rows, incidents_by_status: statusData.rows, most_affected_assets: assets.rows, common_techniques: techniques.rows });
}));
router.get('/audit-logs', authorize(roles.ADMIN, roles.RESEARCHER), asyncHandler(async (req, res) => {
  const limit = Math.min(Number(req.query.limit || 100), 500); if (!Number.isInteger(limit) || limit < 1) throw apiError(400, 'limit must be a positive integer.');
  const result = await query('SELECT al.*,u.name AS user_name FROM audit_log al LEFT JOIN user_account u ON u.user_id=al.user_id ORDER BY al.timestamp DESC LIMIT $1', [limit]); res.json(result.rows);
}));

module.exports = router;
