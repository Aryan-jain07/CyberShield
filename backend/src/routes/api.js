const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const net = require('node:net');
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
const { syncNvd, syncKev, syncAll, getSyncStatus } = require('../services/vulnerabilitySync');

const router = express.Router();
const readers = [roles.ADMIN, roles.ANALYST, roles.RESPONDER, roles.RESEARCHER, roles.VIEWER];
const investigators = [roles.ADMIN, roles.ANALYST, roles.RESPONDER];
const severity = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
const incidentStatus = ['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'];
const incidentFilterStatus = ['PENDING_REVIEW', ...incidentStatus];
const incidentSorts = {
  newest: 'i.detected_at DESC, i.incident_id DESC',
  oldest: 'i.detected_at ASC, i.incident_id ASC',
  severity_desc: `CASE i.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 END DESC, i.detected_at DESC, i.incident_id DESC`,
  severity_asc: `CASE i.severity WHEN 'LOW' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'HIGH' THEN 3 WHEN 'CRITICAL' THEN 4 END ASC, i.detected_at DESC, i.incident_id DESC`,
  title_asc: 'i.title ASC, i.incident_id ASC',
  title_desc: 'i.title DESC, i.incident_id DESC'
};
const assetSorts = {
  newest: 'a.asset_id DESC',
  oldest: 'a.asset_id ASC',
  name_asc: 'a.hostname ASC, a.asset_id ASC',
  name_desc: 'a.hostname DESC, a.asset_id DESC',
  criticality_desc: `CASE a.criticality WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 END DESC, a.asset_id DESC`,
  criticality_asc: `CASE a.criticality WHEN 'LOW' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'HIGH' THEN 3 WHEN 'CRITICAL' THEN 4 END ASC, a.asset_id DESC`,
  vulnerabilities_desc: 'COUNT(DISTINCT sv.vuln_id) DESC, a.asset_id DESC',
  vulnerabilities_asc: 'COUNT(DISTINCT sv.vuln_id) ASC, a.asset_id DESC'
};
const vulnerabilitySorts = {
  newest: 'v.vuln_id DESC',
  oldest: 'v.vuln_id ASC',
  cvss_desc: 'v.cvss_score DESC, v.vuln_id DESC',
  cvss_asc: 'v.cvss_score ASC, v.vuln_id DESC',
  severity_desc: 'v.cvss_score DESC, v.vuln_id DESC',
  severity_asc: 'v.cvss_score ASC, v.vuln_id DESC',
  cve_asc: 'v.cve_id ASC, v.vuln_id ASC',
  cve_desc: 'v.cve_id DESC, v.vuln_id DESC'
};
const auditSorts = {
  newest: 'al.timestamp DESC, al.audit_id DESC',
  oldest: 'al.timestamp ASC, al.audit_id ASC',
  user_asc: "COALESCE(u.name, 'System') ASC, al.audit_id ASC",
  user_desc: "COALESCE(u.name, 'System') DESC, al.audit_id DESC",
  action_asc: 'al.action ASC, al.audit_id ASC',
  action_desc: 'al.action DESC, al.audit_id DESC',
  entity_asc: 'al.entity_name ASC, al.audit_id ASC',
  entity_desc: 'al.entity_name DESC, al.audit_id DESC'
};
const cvssSeverity = { LOW: [0, 3.9], MEDIUM: [4, 6.9], HIGH: [7, 8.9], CRITICAL: [9, 10] };
const actionStatus = ['PLANNED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED'];
const incidentCategories = ['Malware', 'Phishing', 'Ransomware', 'Unauthorized Access', 'Data Breach', 'Denial of Service', 'Suspicious Network Activity', 'Insider Threat', 'Other'];
const loginLimiter = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Try again later.' }
});
const incidentReportLimiter = require('express-rate-limit')({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'Too many incident reports. Try again later.' }
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

router.get('/assets', authorize(...readers), asyncHandler(async (req, res) => {
  const values = []; const filters = [];
  if (req.query.asset_type) { requireString(req.query.asset_type, 'asset_type', 50); values.push(req.query.asset_type); filters.push(`a.asset_type=$${values.length}`); }
  if (req.query.criticality) { if (!severity.includes(req.query.criticality)) throw apiError(400, 'Invalid criticality filter.'); values.push(req.query.criticality); filters.push(`a.criticality=$${values.length}`); }
  if (req.query.status) { if (!['ACTIVE', 'INACTIVE', 'RETIRED', 'QUARANTINED'].includes(req.query.status)) throw apiError(400, 'Invalid asset status filter.'); values.push(req.query.status); filters.push(`a.status=$${values.length}`); }
  if (req.query.owner_user_id) {
    if (req.query.owner_user_id === 'unassigned') filters.push('a.owner_user_id IS NULL');
    else { const ownerId = parseId(req.query.owner_user_id, 'owner_user_id'); values.push(ownerId); filters.push(`a.owner_user_id=$${values.length}`); }
  }
  if (req.query.search) { values.push(`%${req.query.search}%`); filters.push(`(a.hostname ILIKE $${values.length} OR a.ip_address::TEXT ILIKE $${values.length} OR a.asset_type ILIKE $${values.length})`); }
  const sort = req.query.sort || 'newest';
  if (!Object.prototype.hasOwnProperty.call(assetSorts, sort)) throw apiError(400, 'Invalid asset sort.');
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const result = await query(`SELECT a.*,u.name AS owner_name,COUNT(DISTINCT aws.software_id) AS software_count,COUNT(DISTINCT sv.vuln_id) AS vulnerability_count FROM asset a LEFT JOIN user_account u ON u.user_id=a.owner_user_id LEFT JOIN asset_software aws ON aws.asset_id=a.asset_id LEFT JOIN software_vuln sv ON sv.software_id=aws.software_id ${where} GROUP BY a.asset_id,u.name ORDER BY ${assetSorts[sort]}`, values);
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
router.get('/vulnerabilities', authorize(...readers), asyncHandler(async (req, res) => {
  const values = []; const filters = [];
  if (req.query.severity) {
    if (!Object.prototype.hasOwnProperty.call(cvssSeverity, req.query.severity)) throw apiError(400, 'Invalid vulnerability severity filter.');
    const [min, max] = cvssSeverity[req.query.severity]; values.push(min, max); filters.push(`v.cvss_score BETWEEN $${values.length - 1} AND $${values.length}`);
  }
  if (req.query.status) { if (!['OPEN', 'PATCHED', 'ACCEPTED_RISK', 'MITIGATED'].includes(req.query.status)) throw apiError(400, 'Invalid vulnerability status filter.'); values.push(req.query.status); filters.push(`v.status=$${values.length}`); }
  if (req.query.software_id) { const softwareId = parseId(req.query.software_id, 'software_id'); values.push(softwareId); filters.push(`EXISTS (SELECT 1 FROM software_vuln filter_sv WHERE filter_sv.vuln_id=v.vuln_id AND filter_sv.software_id=$${values.length})`); }
  if (req.query.asset_id) { const assetId = parseId(req.query.asset_id, 'asset_id'); values.push(assetId); filters.push(`EXISTS (SELECT 1 FROM software_vuln filter_sv JOIN asset_software filter_as ON filter_as.software_id=filter_sv.software_id WHERE filter_sv.vuln_id=v.vuln_id AND filter_as.asset_id=$${values.length})`); }
  if (req.query.kev) { if (req.query.kev !== 'true') throw apiError(400, 'kev must be true when supplied.'); filters.push('vi.is_kev=TRUE'); }
  if (req.query.search) { values.push(`%${req.query.search}%`); filters.push(`(v.cve_id ILIKE $${values.length} OR v.description ILIKE $${values.length} OR EXISTS (SELECT 1 FROM software_vuln search_sv JOIN software search_s ON search_s.software_id=search_sv.software_id WHERE search_sv.vuln_id=v.vuln_id AND search_s.name ILIKE $${values.length}))`); }
  const sort = req.query.sort || 'newest';
  if (!Object.prototype.hasOwnProperty.call(vulnerabilitySorts, sort)) throw apiError(400, 'Invalid vulnerability sort.');
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const result = await query(`SELECT v.*,vi.intelligence_id,vi.source_name,vi.source_published_at,vi.source_last_modified_at,vi.last_synced_at,vi.external_status,vi.severity AS source_severity,vi.is_kev,vi.kev_date_added,vi.kev_required_action,vi.kev_due_date,vi.kev_known_ransomware,COALESCE(software_summary.software_count,0) AS software_count FROM vulnerability v LEFT JOIN vulnerability_intelligence vi ON vi.vuln_id=v.vuln_id LEFT JOIN (SELECT vuln_id,COUNT(DISTINCT software_id) AS software_count FROM software_vuln GROUP BY vuln_id) software_summary ON software_summary.vuln_id=v.vuln_id ${where} ORDER BY ${vulnerabilitySorts[sort]}`, values);
  res.json(result.rows);
}));
router.get('/vulnerabilities/:id', authorize(...readers), asyncHandler(async (req, res) => {
  const id = parseId(req.params.id, 'vulnerability id');
  const vulnerability = await query(`SELECT v.*,vi.* FROM vulnerability v LEFT JOIN vulnerability_intelligence vi ON vi.vuln_id=v.vuln_id WHERE v.vuln_id=$1`, [id]);
  if (!vulnerability.rowCount) throw apiError(404, 'Vulnerability not found.');
  const [software, assets] = await Promise.all([
    query(`SELECT s.software_id,s.name,s.vendor,s.version,vm.match_type,vm.evidence,vm.analyst_verified FROM vulnerability_software_match vm JOIN software s ON s.software_id=vm.software_id WHERE vm.intelligence_id=$1 ORDER BY s.name,s.version`, [vulnerability.rows[0].intelligence_id || 0]),
    query(`SELECT DISTINCT a.asset_id,a.hostname,a.ip_address,a.status FROM vulnerability_software_match vm JOIN asset_software aws ON aws.software_id=vm.software_id JOIN asset a ON a.asset_id=aws.asset_id WHERE vm.intelligence_id=$1 AND vm.match_type IN ('EXACT','PROBABLE') ORDER BY a.hostname`, [vulnerability.rows[0].intelligence_id || 0])
  ]);
  res.json({ ...vulnerability.rows[0], affected_software: software.rows, related_assets: assets.rows });
}));
router.get('/vulnerability-intelligence/kev', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query(`SELECT v.*,vi.* FROM vulnerability v JOIN vulnerability_intelligence vi ON vi.vuln_id=v.vuln_id WHERE vi.is_kev=TRUE ORDER BY vi.kev_date_added DESC NULLS LAST,v.cve_id`);
  res.json(result.rows);
}));
router.get('/vulnerability-intelligence/status', authorize(...readers), asyncHandler(async (_req, res) => res.json(await getSyncStatus())));
router.get('/vulnerability-intelligence/runs', authorize(...readers), asyncHandler(async (_req, res) => {
  const result = await query('SELECT * FROM vulnerability_sync_run ORDER BY started_at DESC LIMIT 20');
  res.json(result.rows);
}));
router.post('/vulnerability-intelligence/sync', authorize(roles.ADMIN), asyncHandler(async (req, res) => {
  const source = req.body?.source || 'ALL';
  if (!['NVD', 'CISA_KEV', 'ALL'].includes(source)) throw apiError(400, 'source must be NVD, CISA_KEV, or ALL.');
  const result = source === 'NVD' ? await syncNvd(req.user.user_id) : source === 'CISA_KEV' ? await syncKev(req.user.user_id) : await syncAll(req.user.user_id);
  res.status(202).json(result);
}));

router.get('/incidents', authorize(...readers), asyncHandler(async (req, res) => {
  const values = []; const filters = [];
  if (req.query.severity) { if (!severity.includes(req.query.severity)) throw apiError(400, 'Invalid severity filter.'); values.push(req.query.severity); filters.push(`i.severity=$${values.length}`); }
  if (req.query.status) { if (!incidentFilterStatus.includes(req.query.status)) throw apiError(400, 'Invalid status filter.'); values.push(req.query.status); filters.push(`i.status=$${values.length}`); }
  if (req.query.assigned_to) {
    if (req.query.assigned_to === 'unassigned') filters.push('i.assigned_to_name IS NULL');
    else {
      const assignedTo = parseId(req.query.assigned_to, 'assigned_to');
      values.push(assignedTo); filters.push(`i.assigned_to_name = (SELECT u.name FROM user_account u WHERE u.user_id=$${values.length})`);
    }
  }
  if (req.query.start_date) { requireDate(req.query.start_date, 'start_date'); values.push(req.query.start_date); filters.push(`i.detected_at >= $${values.length}::date`); }
  if (req.query.end_date) { requireDate(req.query.end_date, 'end_date'); values.push(req.query.end_date); filters.push(`i.detected_at < ($${values.length}::date + INTERVAL '1 day')`); }
  if (req.query.start_date && req.query.end_date && new Date(req.query.start_date) > new Date(req.query.end_date)) throw apiError(400, 'start_date must be before or equal to end_date.');
  if (req.query.search) { values.push(`%${req.query.search}%`); filters.push(`(i.title ILIKE $${values.length} OR i.description ILIKE $${values.length} OR CAST(i.incident_id AS TEXT) ILIKE $${values.length} OR EXISTS (SELECT 1 FROM incident_asset search_ia JOIN asset search_a ON search_a.asset_id=search_ia.asset_id WHERE search_ia.incident_id=i.incident_id AND (search_a.hostname ILIKE $${values.length} OR search_a.ip_address::TEXT ILIKE $${values.length})))`); }
  const sort = req.query.sort || 'newest';
  if (!Object.prototype.hasOwnProperty.call(incidentSorts, sort)) throw apiError(400, 'Invalid incident sort.');
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const result = await query(`SELECT * FROM vw_incident_summary i ${where} ORDER BY ${incidentSorts[sort]}`, values);
  res.json(result.rows);
}));
router.get('/incidents/:id', authorize(...readers), asyncHandler(async (req, res) => res.json(await getInvestigation(parseId(req.params.id, 'incident id')))));
router.get('/incidents/:id/correlation', authorize(...readers), asyncHandler(async (req, res) => res.json(await correlateIncident(parseId(req.params.id, 'incident id')))));
router.post('/incidents', incidentReportLimiter, authorize(...readers), asyncHandler(async (req, res) => {
  requireFields(req.body, ['title', 'description', 'severity', 'detected_at']);
  const reportingOnly = !investigators.includes(req.user.role_name);
  const allowed = ['title', 'category', 'description', 'severity', 'detected_at', 'source', 'additional_notes', 'asset_id', 'indicators', 'status', 'assigned_to'];
  const unknownFields = Object.keys(req.body).filter((key) => !allowed.includes(key));
  if (unknownFields.length) throw apiError(400, `Unknown incident field(s): ${unknownFields.join(', ')}.`);
  if (reportingOnly && (Object.prototype.hasOwnProperty.call(req.body, 'status') || Object.prototype.hasOwnProperty.call(req.body, 'assigned_to'))) {
    throw apiError(403, 'Reporting users cannot set incident status or assignment.');
  }
  requireString(req.body.title, 'title', 200);
  requireString(req.body.description, 'description', 10_000);
  requireEnum(req.body.category || 'Other', 'category', incidentCategories);
  requireEnum(req.body.severity, 'severity', severity);
  if (req.body.source !== undefined && req.body.source !== null) requireString(req.body.source, 'source', 120);
  if (req.body.additional_notes !== undefined && req.body.additional_notes !== null) requireString(req.body.additional_notes, 'additional_notes', 10_000, 0);
  requireDate(req.body.detected_at, 'detected_at');
  requireOptionalId(req.body.asset_id, 'asset_id');
  if (req.body.indicators !== undefined && (!Array.isArray(req.body.indicators) || req.body.indicators.length > 50)) {
    throw apiError(400, 'indicators must be an array containing no more than 50 values.');
  }
  const indicators = (req.body.indicators || []).map((value) => {
    requireString(value, 'indicator', 500);
    if (net.isIP(value) || /^https?:\/\/\S+$/i.test(value)) return { value, type: net.isIP(value) ? 'IP' : 'URL' };
    if (/^[a-f0-9]{32,128}$/i.test(value)) return { value, type: 'HASH' };
    if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(value)) return { value, type: 'DOMAIN' };
    throw apiError(400, `Invalid indicator: ${value}.`);
  });
  if (!reportingOnly) {
    requireEnum(req.body.status || 'OPEN', 'status', incidentStatus);
    requireOptionalId(req.body.assigned_to, 'assigned_to');
  }
  const result = await withTransaction(async (client) => {
    await client.query("SELECT set_config('app.actor_user_id', $1, true)", [String(req.user.user_id)]);
    if (req.body.asset_id !== undefined && req.body.asset_id !== null) {
      const asset = await client.query('SELECT asset_id FROM asset WHERE asset_id = $1', [req.body.asset_id]);
      if (!asset.rowCount) throw apiError(400, 'Affected asset not found.');
    }
    if (!reportingOnly && req.body.assigned_to !== undefined && req.body.assigned_to !== null) {
      const assignee = await client.query('SELECT user_id FROM user_account WHERE user_id = $1', [req.body.assigned_to]);
      if (!assignee.rowCount) throw apiError(400, 'Assigned user not found.');
    }
    const inserted = await client.query(
      `INSERT INTO incident (title,category,description,severity,status,detected_at,created_by,assigned_to,source,additional_notes)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *`,
      [req.body.title, req.body.category || 'Other', req.body.description, req.body.severity, reportingOnly ? 'OPEN' : (req.body.status || 'OPEN'), req.body.detected_at, req.user.user_id, reportingOnly ? null : (req.body.assigned_to ?? null), req.body.source ?? null, req.body.additional_notes ?? null]
    );
    if (req.body.asset_id !== undefined && req.body.asset_id !== null) {
      await client.query(
        'INSERT INTO incident_asset (incident_id, asset_id, impact_type, affected_at) VALUES ($1, $2, $3, $4)',
        [inserted.rows[0].incident_id, req.body.asset_id, 'REPORTED_AFFECTED_ASSET', req.body.detected_at]
      );
    }
    for (const indicator of indicators) {
      const saved = await client.query(
        `INSERT INTO indicator (type, value, confidence, first_seen, last_seen)
         VALUES ($1, $2, 50, $3, $3)
         ON CONFLICT (type, value) DO UPDATE SET last_seen = GREATEST(indicator.last_seen, EXCLUDED.last_seen)
         RETURNING indicator_id`,
        [indicator.type, indicator.value, req.body.detected_at]
      );
      await client.query(
        `INSERT INTO incident_indicator (incident_id, indicator_id, observed_at, observation_context)
         VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
        [inserted.rows[0].incident_id, saved.rows[0].indicator_id, req.body.detected_at, 'Reported during incident submission.']
      );
    }
    await writeAudit(req.user.user_id, 'incident', inserted.rows[0].incident_id, 'INCIDENT_CREATED_API', {}, client.query.bind(client));
    return inserted;
  });
  res.status(201).json(result.rows[0]);
}));
router.put('/incidents/:id', authorize(...investigators), asyncHandler(async (req, res) => {
  const id = parseId(req.params.id, 'incident id'); requireFields(req.body, []);
  const allowed = ['title', 'category', 'description', 'severity', 'status', 'assigned_to'];
  const unknownFields = Object.keys(req.body).filter((key) => !allowed.includes(key));
  if (unknownFields.length) throw apiError(400, `Unknown incident field(s): ${unknownFields.join(', ')}.`);
  const entries = Object.entries(req.body).filter(([key]) => allowed.includes(key));
  if (!entries.length) throw apiError(400, 'No editable incident fields supplied.');
  if (Object.prototype.hasOwnProperty.call(req.body, 'title')) requireString(req.body.title, 'title', 200);
  if (Object.prototype.hasOwnProperty.call(req.body, 'category')) requireEnum(req.body.category, 'category', incidentCategories);
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
  const values = []; const filters = [];
  if (req.query.user_id) { const userId = parseId(req.query.user_id, 'user_id'); values.push(userId); filters.push(`al.user_id=$${values.length}`); }
  if (req.query.action) { requireString(req.query.action, 'action', 80); values.push(req.query.action); filters.push(`al.action=$${values.length}`); }
  if (req.query.entity_name) { requireString(req.query.entity_name, 'entity_name', 80); values.push(req.query.entity_name); filters.push(`al.entity_name=$${values.length}`); }
  if (req.query.start_date) { requireDate(req.query.start_date, 'start_date'); values.push(req.query.start_date); filters.push(`al.timestamp >= $${values.length}::date`); }
  if (req.query.end_date) { requireDate(req.query.end_date, 'end_date'); values.push(req.query.end_date); filters.push(`al.timestamp < ($${values.length}::date + INTERVAL '1 day')`); }
  if (req.query.start_date && req.query.end_date && new Date(req.query.start_date) > new Date(req.query.end_date)) throw apiError(400, 'start_date must be before or equal to end_date.');
  if (req.query.search) { values.push(`%${req.query.search}%`); filters.push(`(COALESCE(u.name, 'System') ILIKE $${values.length} OR al.action ILIKE $${values.length} OR al.entity_name ILIKE $${values.length} OR al.details::TEXT ILIKE $${values.length})`); }
  const sort = req.query.sort || 'newest';
  if (!Object.prototype.hasOwnProperty.call(auditSorts, sort)) throw apiError(400, 'Invalid audit log sort.');
  const limit = Math.min(Number(req.query.limit || 500), 500); if (!Number.isInteger(limit) || limit < 1) throw apiError(400, 'limit must be a positive integer.');
  const where = filters.length ? `WHERE ${filters.join(' AND ')}` : '';
  const result = await query(`SELECT al.*,u.name AS user_name FROM audit_log al LEFT JOIN user_account u ON u.user_id=al.user_id ${where} ORDER BY ${auditSorts[sort]} LIMIT $${values.length + 1}`, [...values, limit]); res.json(result.rows);
}));

module.exports = router;
