const { query } = require('../db/postgres');
const { getMongoDb } = require('../db/mongo');
const { apiError } = require('../lib/http');

async function getInvestigation(incidentId) {
  const incident = await query(`SELECT i.*, creator.name AS created_by_name, assignee.name AS assigned_to_name
    FROM incident i JOIN user_account creator ON creator.user_id = i.created_by
    LEFT JOIN user_account assignee ON assignee.user_id = i.assigned_to WHERE i.incident_id = $1`, [incidentId]);
  if (!incident.rowCount) throw apiError(404, 'Incident not found.');
  const [assets, indicators, actors, techniques, responses, related] = await Promise.all([
    query(`SELECT a.*, ia.impact_type, ia.affected_at,
      COALESCE(json_agg(DISTINCT jsonb_build_object('software_id',s.software_id,'name',s.name,'vendor',s.vendor,'version',aws.installed_version)) FILTER (WHERE s.software_id IS NOT NULL),'[]') AS software,
      COALESCE(json_agg(DISTINCT jsonb_build_object('cve_id',v.cve_id,'cvss_score',v.cvss_score,'status',v.status)) FILTER (WHERE v.vuln_id IS NOT NULL),'[]') AS vulnerabilities
      FROM incident_asset ia JOIN asset a ON a.asset_id=ia.asset_id LEFT JOIN asset_software aws ON aws.asset_id=a.asset_id LEFT JOIN software s ON s.software_id=aws.software_id LEFT JOIN software_vuln sv ON sv.software_id=s.software_id LEFT JOIN vulnerability v ON v.vuln_id=sv.vuln_id WHERE ia.incident_id=$1 GROUP BY a.asset_id,ia.impact_type,ia.affected_at`, [incidentId]),
    query('SELECT ind.*, ii.observed_at, ii.observation_context FROM incident_indicator ii JOIN indicator ind ON ind.indicator_id=ii.indicator_id WHERE ii.incident_id=$1', [incidentId]),
    query('SELECT DISTINCT ta.*, ai.relationship_type, ai.confidence AS relationship_confidence FROM incident_indicator ii JOIN actor_indicator ai ON ai.indicator_id=ii.indicator_id JOIN threat_actor ta ON ta.actor_id=ai.actor_id WHERE ii.incident_id=$1', [incidentId]),
    query('SELECT t.*, it.confidence, it.source FROM incident_technique it JOIN technique t ON t.technique_id=it.technique_id WHERE it.incident_id=$1', [incidentId]),
    query('SELECT ra.*, u.name AS responder_name FROM response_action ra LEFT JOIN user_account u ON u.user_id=ra.responder_id WHERE ra.incident_id=$1 ORDER BY ra.performed_at DESC', [incidentId]),
    query(`SELECT DISTINCT i.incident_id,i.title,i.severity,i.status,i.detected_at,'SHARED_INDICATOR_OR_ASSET' AS relationship FROM incident i WHERE i.incident_id<>$1 AND
      (EXISTS (SELECT 1 FROM incident_indicator c JOIN incident_indicator o ON o.indicator_id=c.indicator_id WHERE c.incident_id=$1 AND o.incident_id=i.incident_id)
      OR EXISTS (SELECT 1 FROM incident_asset c JOIN incident_asset o ON o.asset_id=c.asset_id WHERE c.incident_id=$1 AND o.incident_id=i.incident_id)) ORDER BY i.detected_at DESC`, [incidentId])
  ]);
  const values = indicators.rows.map((row) => row.value);
  const db = await getMongoDb();
  const intelligence = values.length ? await db.collection('threat_indicators').find({ indicator: { $in: values } }).project({ _id: 0 }).toArray() : [];
  return { incident: incident.rows[0], assets: assets.rows, indicators: indicators.rows, threat_actors: actors.rows, techniques: techniques.rows, response_actions: responses.rows, related_incidents: related.rows, threat_intelligence: intelligence };
}

async function correlateIncident(incidentId) {
  const investigation = await getInvestigation(incidentId);
  const findings = [];
  const repeated = await query(`SELECT ind.type,ind.value,COUNT(DISTINCT ii.incident_id) AS incident_count FROM incident_indicator ii JOIN indicator ind ON ind.indicator_id=ii.indicator_id WHERE ind.indicator_id IN (SELECT indicator_id FROM incident_indicator WHERE incident_id=$1) GROUP BY ind.indicator_id,ind.type,ind.value HAVING COUNT(DISTINCT ii.incident_id)>1`, [incidentId]);
  if (repeated.rowCount) findings.push({ rule: 'REPEATED_INDICATOR', message: 'Indicator appears in multiple incidents.', evidence: repeated.rows });
  const critical = await query(`SELECT DISTINCT a.hostname,v.cve_id,v.cvss_score FROM incident_asset ia JOIN asset a ON a.asset_id=ia.asset_id JOIN asset_software aws ON aws.asset_id=a.asset_id JOIN software_vuln sv ON sv.software_id=aws.software_id JOIN vulnerability v ON v.vuln_id=sv.vuln_id WHERE ia.incident_id=$1 AND v.status='OPEN' AND v.cvss_score>=7`, [incidentId]);
  if (critical.rowCount) findings.push({ rule: 'CRITICAL_VULNERABILITY', message: 'Incident affects an asset with a critical vulnerability.', evidence: critical.rows });
  if (investigation.threat_intelligence.length) findings.push({ rule: 'THREAT_INTELLIGENCE_MATCH', message: 'Indicator matches known threat intelligence.', evidence: investigation.threat_intelligence });
  const recurring = await query(`SELECT a.asset_id,a.hostname,COUNT(DISTINCT other.incident_id) AS incident_count FROM incident_asset current JOIN asset a ON a.asset_id=current.asset_id JOIN incident_asset other ON other.asset_id=a.asset_id WHERE current.incident_id=$1 GROUP BY a.asset_id,a.hostname HAVING COUNT(DISTINCT other.incident_id)>1`, [incidentId]);
  if (recurring.rowCount) findings.push({ rule: 'RECURRING_ASSET', message: 'Asset has appeared in multiple incidents.', evidence: recurring.rows });
  if (['OPEN', 'INVESTIGATING'].includes(investigation.incident.status) && !investigation.response_actions.length) findings.push({ rule: 'RESPONSE_GAP', message: 'Incident has no recorded response action.', evidence: [] });
  if (investigation.related_incidents.length) findings.push({ rule: 'RELATED_INCIDENT', message: 'Related incident detected.', evidence: investigation.related_incidents });
  return { incident_id: incidentId, findings, investigation };
}

module.exports = { getInvestigation, correlateIncident };
