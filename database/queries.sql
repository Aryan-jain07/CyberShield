-- Run with: psql "$env:DATABASE_URL" -f database/queries.sql
BEGIN READ ONLY;

-- Critical vulnerabilities affecting assets linked to an incident.
SELECT DISTINCT i.incident_id, i.title, a.hostname, s.name AS software_name, v.cve_id, v.cvss_score
FROM incident i
JOIN incident_asset ia ON ia.incident_id = i.incident_id
JOIN asset a ON a.asset_id = ia.asset_id
JOIN asset_software aws ON aws.asset_id = a.asset_id
JOIN software s ON s.software_id = aws.software_id
JOIN software_vuln sv ON sv.software_id = s.software_id
JOIN vulnerability v ON v.vuln_id = sv.vuln_id
WHERE v.status = 'OPEN' AND v.cvss_score >= 7.0
ORDER BY v.cvss_score DESC, i.incident_id;

-- Indicators observed in multiple incidents (GROUP BY and HAVING).
SELECT ind.type, ind.value, COUNT(*) AS incident_count, ARRAY_AGG(ii.incident_id ORDER BY ii.incident_id) AS incidents
FROM incident_indicator ii
JOIN indicator ind ON ind.indicator_id = ii.indicator_id
GROUP BY ind.indicator_id, ind.type, ind.value
HAVING COUNT(*) > 1
ORDER BY incident_count DESC, ind.value;

-- Related incident pairs sharing an indicator or asset (self-join).
SELECT DISTINCT LEAST(i1.incident_id, i2.incident_id) AS incident_a,
       GREATEST(i1.incident_id, i2.incident_id) AS incident_b,
       'SHARED_INDICATOR' AS relationship
FROM incident_indicator i1
JOIN incident_indicator i2 ON i1.indicator_id = i2.indicator_id AND i1.incident_id < i2.incident_id
UNION
SELECT DISTINCT LEAST(a1.incident_id, a2.incident_id),
       GREATEST(a1.incident_id, a2.incident_id),
       'SHARED_ASSET'
FROM incident_asset a1
JOIN incident_asset a2 ON a1.asset_id = a2.asset_id AND a1.incident_id < a2.incident_id
ORDER BY incident_a, incident_b;

-- Open or investigating incidents with no response action (NOT EXISTS).
SELECT i.incident_id, i.title, i.status
FROM incident i
WHERE i.status IN ('OPEN', 'INVESTIGATING')
  AND NOT EXISTS (SELECT 1 FROM response_action ra WHERE ra.incident_id = i.incident_id)
ORDER BY i.detected_at DESC;

-- Most affected assets.
SELECT a.asset_id, a.hostname, COUNT(*) AS incident_count
FROM asset a
JOIN incident_asset ia ON ia.asset_id = a.asset_id
GROUP BY a.asset_id, a.hostname
ORDER BY incident_count DESC, a.hostname
LIMIT 10;

-- Most common MITRE ATT&CK techniques.
SELECT t.attack_id, t.name, COUNT(*) AS incident_count
FROM technique t
JOIN incident_technique it ON it.technique_id = t.technique_id
GROUP BY t.technique_id, t.attack_id, t.name
ORDER BY incident_count DESC, t.attack_id
LIMIT 10;

-- Function and view demonstration.
SELECT * FROM get_incident_overview(1);
SELECT * FROM vw_open_critical_vulnerabilities ORDER BY cvss_score DESC, hostname LIMIT 10;

COMMIT;
