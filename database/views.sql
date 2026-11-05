CREATE OR REPLACE VIEW vw_incident_summary AS
SELECT
    i.incident_id,
    i.title,
    i.severity,
    i.status,
    i.detected_at,
    creator.name AS created_by_name,
    assignee.name AS assigned_to_name,
    COUNT(DISTINCT ia.asset_id) AS affected_asset_count,
    COUNT(DISTINCT ii.indicator_id) AS indicator_count,
    COUNT(DISTINCT ra.action_id) AS response_action_count
FROM incident i
JOIN user_account creator ON creator.user_id = i.created_by
LEFT JOIN user_account assignee ON assignee.user_id = i.assigned_to
LEFT JOIN incident_asset ia ON ia.incident_id = i.incident_id
LEFT JOIN incident_indicator ii ON ii.incident_id = i.incident_id
LEFT JOIN response_action ra ON ra.incident_id = i.incident_id
GROUP BY i.incident_id, creator.name, assignee.name;

CREATE OR REPLACE VIEW vw_open_critical_vulnerabilities AS
SELECT
    a.asset_id, a.hostname, a.criticality AS asset_criticality,
    s.software_id, s.name AS software_name, s.vendor, s.version,
    v.vuln_id, v.cve_id, v.cvss_score, v.status AS vulnerability_status
FROM asset a
JOIN asset_software aws ON aws.asset_id = a.asset_id
JOIN software s ON s.software_id = aws.software_id
JOIN software_vuln sv ON sv.software_id = s.software_id
JOIN vulnerability v ON v.vuln_id = sv.vuln_id
WHERE v.status = 'OPEN' AND v.cvss_score >= 7.0;
