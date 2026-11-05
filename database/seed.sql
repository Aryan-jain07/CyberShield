BEGIN;

INSERT INTO role (role_name, description) VALUES
('Admin', 'Manages the platform and security configuration.'),
('Security Analyst', 'Investigates alerts and creates incidents.'),
('Incident Responder', 'Executes containment and remediation actions.'),
('Threat Researcher', 'Maintains threat intelligence and adversary context.'),
('Viewer', 'Has read-only access to investigation data.');

INSERT INTO user_account (name, email, password_hash, role_id) VALUES
('Avery Shah', 'avery.shah@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 1),
('Riya Mehta', 'riya.mehta@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 2),
('Karan Iyer', 'karan.iyer@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 3),
('Nina Roy', 'nina.roy@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 4),
('Dev Patel', 'dev.patel@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 5),
('Maya Sen', 'maya.sen@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 2),
('Ishaan Bose', 'ishaan.bose@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 3),
('Zoya Khan', 'zoya.khan@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 4),
('Arjun Das', 'arjun.das@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 2),
('Tara Nair', 'tara.nair@cybershield.test', '$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 5);

-- All synthetic demo accounts use the bcrypt-hashed password "password".
UPDATE user_account
SET password_hash = '$2b$12$icxwgViT.DiC92f3HE4W7.KsGK95NdKtlw/dlPrNZzSeunRT7p6zu';

INSERT INTO asset (hostname, asset_type, ip_address, criticality, status, owner_user_id)
SELECT
    CASE WHEN n = 7 THEN 'LAPTOP-007' ELSE CASE WHEN n <= 15 THEN 'LAPTOP-' ELSE 'SERVER-' END || LPAD(n::TEXT, 3, '0') END,
    CASE WHEN n <= 15 THEN 'WORKSTATION' WHEN n <= 24 THEN 'SERVER' ELSE 'NETWORK_DEVICE' END,
    ('10.20.1.' || n)::INET,
    (ARRAY['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])[1 + ((n - 1) % 4)],
    CASE WHEN n IN (12, 24) THEN 'QUARANTINED' ELSE 'ACTIVE' END,
    1 + ((n - 1) % 10)
FROM generate_series(1, 30) AS n;

INSERT INTO software (name, vendor, version)
SELECT
    (ARRAY['SecureBrowse', 'OfficeSuite', 'EndpointGuard', 'DataSync', 'MailClient', 'RemoteAssist', 'WebServer', 'DatabaseEngine', 'FileTransfer', 'LogAgent', 'VPNClient', 'PDFReader', 'JavaRuntime', 'PythonRuntime', 'ContainerHost']) [1 + ((n - 1) % 15)],
    (ARRAY['Northstar Labs', 'Proton Systems', 'Aegis Corp'])[1 + ((n - 1) % 3)],
    (1 + ((n - 1) % 5))::TEXT || '.' || ((n * 3) % 10)::TEXT || '.' || n::TEXT
FROM generate_series(1, 45) AS n;

INSERT INTO asset_software (asset_id, software_id, installed_version, installed_at)
SELECT a.asset_id, s.software_id, s.version, NOW() - (a.asset_id || ' days')::INTERVAL
FROM asset a
JOIN software s ON s.software_id IN (
    ((a.asset_id - 1) % 45) + 1,
    ((a.asset_id + 6) % 45) + 1,
    ((a.asset_id + 18) % 45) + 1
);

INSERT INTO vulnerability (cve_id, description, cvss_score, status)
SELECT
    'CVE-2025-' || LPAD((1000 + n)::TEXT, 4, '0'),
    'Synthetic vulnerability ' || n || ' retained exclusively for the CyberShield demonstration dataset.',
    CASE WHEN n % 10 = 0 THEN 9.8 WHEN n % 5 = 0 THEN 8.2 ELSE 4.0 + ((n % 35) / 10.0) END,
    CASE WHEN n % 9 = 0 THEN 'PATCHED' WHEN n % 7 = 0 THEN 'MITIGATED' ELSE 'OPEN' END
FROM generate_series(1, 40) AS n;

INSERT INTO software_vuln (software_id, vuln_id)
SELECT ((n - 1) % 45) + 1, n FROM generate_series(1, 40) AS n;
INSERT INTO software_vuln (software_id, vuln_id) VALUES (7, 10), (7, 20), (7, 30), (7, 40), (1, 10), (2, 20)
ON CONFLICT DO NOTHING;

INSERT INTO incident (title, description, severity, status, created_at, detected_at, created_by, assigned_to) VALUES
('Phishing Attack Targeting Employee', 'Employee received a suspicious email containing a malicious login URL and entered credentials.', 'HIGH', 'INVESTIGATING', NOW() - INTERVAL '2 days', NOW() - INTERVAL '2 days 2 hours', 2, 3),
('Credential Stuffing Against VPN', 'Repeated authentication attempts targeted remote access accounts.', 'CRITICAL', 'OPEN', NOW() - INTERVAL '3 days', NOW() - INTERVAL '3 days 1 hour', 2, 3),
('Suspicious PowerShell Activity', 'Endpoint telemetry detected encoded PowerShell execution.', 'HIGH', 'RESOLVED', NOW() - INTERVAL '4 days', NOW() - INTERVAL '4 days 3 hours', 6, 7),
('Malware Beaconing Detected', 'A server established periodic connections to an unfamiliar IP address.', 'CRITICAL', 'INVESTIGATING', NOW() - INTERVAL '5 days', NOW() - INTERVAL '5 days 2 hours', 9, 3),
('Untriaged DNS Anomaly', 'An unusual domain was requested by a workstation.', 'MEDIUM', 'OPEN', NOW() - INTERVAL '6 days', NOW() - INTERVAL '6 days 1 hour', 2, 6);

INSERT INTO incident (title, description, severity, status, created_at, detected_at, created_by, assigned_to)
SELECT 'Synthetic Security Event ' || n, 'Synthetic incident narrative ' || n || ' for correlation and reporting tests.',
    (ARRAY['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])[1 + ((n - 1) % 4)],
    (ARRAY['OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED'])[1 + ((n - 1) % 4)],
    NOW() - (n + 6 || ' days')::INTERVAL, NOW() - (n + 6 || ' days')::INTERVAL - INTERVAL '1 hour',
    1 + ((n - 1) % 10), 1 + (n % 10)
FROM generate_series(6, 25) AS n;

INSERT INTO indicator (type, value, confidence, first_seen, last_seen) VALUES
('URL', 'https://secure-login-check.example.test/verify', 96, NOW() - INTERVAL '20 days', NOW() - INTERVAL '2 days'),
('IP', '185.23.45.10', 92, NOW() - INTERVAL '30 days', NOW() - INTERVAL '1 day'),
('DOMAIN', 'credential-portal.example.test', 89, NOW() - INTERVAL '21 days', NOW() - INTERVAL '2 days'),
('HASH', 'a3f5c9d1e7b2f4a6c8d0e2f3a5b7c9d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b', 98, NOW() - INTERVAL '40 days', NOW() - INTERVAL '4 days'),
('EMAIL', 'alerts@credential-check.example.test', 84, NOW() - INTERVAL '25 days', NOW() - INTERVAL '3 days');

INSERT INTO indicator (type, value, confidence, first_seen, last_seen)
SELECT
    (ARRAY['IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL'])[1 + ((n - 1) % 5)],
    CASE (1 + ((n - 1) % 5))
        WHEN 1 THEN '198.51.100.' || n
        WHEN 2 THEN 'threat-' || n || '.example.test'
        WHEN 3 THEN 'https://malicious-' || n || '.example.test/payload'
        WHEN 4 THEN LPAD(n::TEXT, 64, 'a')
        ELSE 'alert-' || n || '@example.test'
    END,
    40 + (n % 60), NOW() - (n || ' days')::INTERVAL, NOW() - ((n % 5) || ' days')::INTERVAL
FROM generate_series(6, 80) AS n;

INSERT INTO incident_asset (incident_id, asset_id, impact_type, affected_at) VALUES
(1, 7, 'CREDENTIAL_EXPOSURE', NOW() - INTERVAL '2 days'), (1, 1, 'PHISHING_TARGET', NOW() - INTERVAL '2 days'),
(2, 7, 'ACCOUNT_TARGETING', NOW() - INTERVAL '3 days'), (2, 18, 'VPN_SERVICE', NOW() - INTERVAL '3 days'),
(3, 3, 'EXECUTION', NOW() - INTERVAL '4 days'), (4, 20, 'COMMAND_AND_CONTROL', NOW() - INTERVAL '5 days'),
(5, 9, 'DNS_ANOMALY', NOW() - INTERVAL '6 days');
INSERT INTO incident_asset (incident_id, asset_id, impact_type, affected_at)
SELECT n, ((n * 3) % 30) + 1, 'SYNTHETIC_IMPACT', NOW() - (n || ' days')::INTERVAL FROM generate_series(6, 25) AS n
ON CONFLICT DO NOTHING;

INSERT INTO incident_indicator (incident_id, indicator_id, observed_at, observation_context) VALUES
(1, 1, NOW() - INTERVAL '2 days', 'Malicious login URL delivered by email.'),
(1, 3, NOW() - INTERVAL '2 days', 'Credential harvesting domain.'),
(2, 2, NOW() - INTERVAL '3 days', 'Originating IP on VPN logs.'),
(3, 4, NOW() - INTERVAL '4 days', 'Malware hash in endpoint telemetry.'),
(4, 2, NOW() - INTERVAL '5 days', 'Beacon destination IP.'),
(5, 3, NOW() - INTERVAL '6 days', 'DNS request for suspicious domain.');
INSERT INTO incident_indicator (incident_id, indicator_id, observed_at, observation_context)
SELECT n, ((n * 3) % 80) + 1, NOW() - (n || ' days')::INTERVAL, 'Synthetic indicator observation.' FROM generate_series(6, 25) AS n
ON CONFLICT DO NOTHING;

INSERT INTO threat_actor (name, description, confidence)
SELECT 'Synthetic Group ' || n, 'Synthetic threat actor used only to demonstrate relationships.', 55 + (n * 4)
FROM generate_series(1, 10) AS n;
UPDATE threat_actor SET name = 'Example Group', description = 'Synthetic phishing-focused actor used by the demo incident.' WHERE actor_id = 1;
INSERT INTO actor_indicator (actor_id, indicator_id, relationship_type, confidence) VALUES
(1, 1, 'USES', 95), (1, 3, 'USES', 88), (2, 2, 'USES', 90), (3, 4, 'USES', 93), (4, 5, 'USES', 80);
INSERT INTO actor_indicator (actor_id, indicator_id, relationship_type, confidence)
SELECT ((n - 1) % 10) + 1, n, 'ASSOCIATED_WITH', 50 + (n % 45) FROM generate_series(6, 80) AS n
ON CONFLICT DO NOTHING;

INSERT INTO technique (attack_id, name, tactic, description) VALUES
('T1566', 'Phishing', 'Initial Access', 'Adversaries send phishing messages to gain access.'),
('T1204', 'User Execution', 'Execution', 'Adversaries rely on a user to execute malicious content.'),
('T1059.001', 'PowerShell', 'Execution', 'Adversaries may abuse PowerShell for execution.'),
('T1071.001', 'Web Protocols', 'Command and Control', 'Adversaries communicate through web protocols.'),
('T1110', 'Brute Force', 'Credential Access', 'Adversaries attempt password guessing.'),
('T1078', 'Valid Accounts', 'Defense Evasion', 'Adversaries use legitimate credentials.'),
('T1046', 'Network Service Discovery', 'Discovery', 'Adversaries scan network services.'),
('T1486', 'Data Encrypted for Impact', 'Impact', 'Adversaries encrypt data.'),
('T1003', 'OS Credential Dumping', 'Credential Access', 'Adversaries obtain credential material.'),
('T1021', 'Remote Services', 'Lateral Movement', 'Adversaries use remote services.'),
('T1105', 'Ingress Tool Transfer', 'Command and Control', 'Adversaries transfer tools.'),
('T1053', 'Scheduled Task', 'Execution', 'Adversaries schedule execution.'),
('T1547.001', 'Registry Run Keys', 'Persistence', 'Adversaries establish run-key persistence.'),
('T1082', 'System Information Discovery', 'Discovery', 'Adversaries discover system information.'),
('T1083', 'File and Directory Discovery', 'Discovery', 'Adversaries enumerate files.'),
('T1027', 'Obfuscated Files or Information', 'Defense Evasion', 'Adversaries obfuscate content.'),
('T1562.001', 'Impair Defenses', 'Defense Evasion', 'Adversaries disable defensive tools.'),
('T1190', 'Exploit Public-Facing Application', 'Initial Access', 'Adversaries exploit an exposed service.'),
('T1218', 'System Binary Proxy Execution', 'Defense Evasion', 'Adversaries abuse signed binaries.'),
('T1098', 'Account Manipulation', 'Persistence', 'Adversaries modify accounts.');

INSERT INTO incident_technique (incident_id, technique_id, confidence, source) VALUES
(1, 1, 98, 'Analyst confirmation'), (1, 2, 94, 'NLP suggestion accepted'), (2, 5, 91, 'Authentication logs'),
(3, 3, 96, 'Endpoint telemetry'), (4, 4, 88, 'Network telemetry'), (5, 4, 65, 'DNS telemetry');
INSERT INTO incident_technique (incident_id, technique_id, confidence, source)
SELECT n, ((n - 1) % 20) + 1, 55 + (n % 40), 'Synthetic mapping' FROM generate_series(6, 25) AS n
ON CONFLICT DO NOTHING;

INSERT INTO response_action (incident_id, responder_id, action_type, description, status, performed_at) VALUES
(1, 3, 'ACCOUNT_DISABLED', 'Disabled the affected employee account.', 'COMPLETED', NOW() - INTERVAL '1 day 20 hours'),
(1, 3, 'URL_BLOCKED', 'Blocked the malicious login URL at the secure web gateway.', 'COMPLETED', NOW() - INTERVAL '1 day 18 hours'),
(2, 7, 'RATE_LIMITING', 'Applied temporary VPN rate limiting.', 'IN_PROGRESS', NOW() - INTERVAL '2 days'),
(3, 7, 'HOST_ISOLATION', 'Isolated the endpoint and collected evidence.', 'COMPLETED', NOW() - INTERVAL '3 days');
INSERT INTO response_action (incident_id, responder_id, action_type, description, status, performed_at)
SELECT ((n - 1) % 20) + 6, 1 + (n % 10), 'SYNTHETIC_RESPONSE', 'Synthetic response action for reporting tests.',
    (ARRAY['PLANNED', 'IN_PROGRESS', 'COMPLETED'])[1 + (n % 3)], NOW() - (n || ' hours')::INTERVAL
FROM generate_series(1, 40) AS n;

INSERT INTO audit_log (user_id, entity_name, entity_id, action, timestamp, details)
SELECT 1 + ((n - 1) % 10),
    (ARRAY['incident', 'asset', 'indicator', 'response_action'])[1 + ((n - 1) % 4)],
    ((n - 1) % 30 + 1)::TEXT,
    (ARRAY['VIEWED', 'CREATED', 'UPDATED', 'EXPORTED'])[1 + ((n - 1) % 4)],
    NOW() - (n || ' hours')::INTERVAL,
    jsonb_build_object('source', 'synthetic seed', 'sequence', n)
FROM generate_series(1, 120) AS n;

COMMIT;
