BEGIN READ ONLY;
SELECT 'role' AS table_name, COUNT(*) AS row_count FROM role
UNION ALL SELECT 'user_account', COUNT(*) FROM user_account
UNION ALL SELECT 'asset', COUNT(*) FROM asset
UNION ALL SELECT 'software', COUNT(*) FROM software
UNION ALL SELECT 'vulnerability', COUNT(*) FROM vulnerability
UNION ALL SELECT 'incident', COUNT(*) FROM incident
UNION ALL SELECT 'indicator', COUNT(*) FROM indicator
UNION ALL SELECT 'threat_actor', COUNT(*) FROM threat_actor
UNION ALL SELECT 'technique', COUNT(*) FROM technique
UNION ALL SELECT 'response_action', COUNT(*) FROM response_action
UNION ALL SELECT 'audit_log', COUNT(*) FROM audit_log
ORDER BY table_name;

SELECT COUNT(*) AS table_count
FROM information_schema.tables
WHERE table_schema = 'public' AND table_type = 'BASE TABLE';

SELECT incident_id, title, severity, status FROM incident WHERE incident_id = 1;
COMMIT;
