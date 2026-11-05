BEGIN;

CREATE TABLE role (
    role_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    role_name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE user_account (
    user_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(120) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role_id INTEGER NOT NULL REFERENCES role(role_id) ON DELETE RESTRICT
);

CREATE TABLE asset (
    asset_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname VARCHAR(120) NOT NULL UNIQUE,
    asset_type VARCHAR(50) NOT NULL,
    ip_address INET NOT NULL UNIQUE,
    criticality VARCHAR(12) NOT NULL CHECK (criticality IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'INACTIVE', 'RETIRED', 'QUARANTINED')),
    owner_user_id INTEGER REFERENCES user_account(user_id) ON DELETE SET NULL
);

CREATE TABLE software (
    software_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    vendor VARCHAR(120) NOT NULL,
    version VARCHAR(80) NOT NULL,
    UNIQUE (name, vendor, version)
);

CREATE TABLE asset_software (
    asset_id INTEGER NOT NULL REFERENCES asset(asset_id) ON DELETE CASCADE,
    software_id INTEGER NOT NULL REFERENCES software(software_id) ON DELETE RESTRICT,
    installed_version VARCHAR(80) NOT NULL,
    installed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (asset_id, software_id)
);

CREATE TABLE vulnerability (
    vuln_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id VARCHAR(20) NOT NULL UNIQUE CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    description TEXT NOT NULL,
    cvss_score NUMERIC(3,1) NOT NULL CHECK (cvss_score >= 0 AND cvss_score <= 10),
    status VARCHAR(20) NOT NULL CHECK (status IN ('OPEN', 'PATCHED', 'ACCEPTED_RISK', 'MITIGATED'))
);

CREATE TABLE software_vuln (
    software_id INTEGER NOT NULL REFERENCES software(software_id) ON DELETE CASCADE,
    vuln_id INTEGER NOT NULL REFERENCES vulnerability(vuln_id) ON DELETE CASCADE,
    PRIMARY KEY (software_id, vuln_id)
);

CREATE TABLE incident (
    incident_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(10) NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    status VARCHAR(20) NOT NULL CHECK (status IN ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    detected_at TIMESTAMPTZ NOT NULL,
    created_by INTEGER NOT NULL REFERENCES user_account(user_id) ON DELETE RESTRICT,
    assigned_to INTEGER REFERENCES user_account(user_id) ON DELETE SET NULL,
    CHECK (detected_at <= created_at)
);

CREATE TABLE incident_asset (
    incident_id INTEGER NOT NULL REFERENCES incident(incident_id) ON DELETE CASCADE,
    asset_id INTEGER NOT NULL REFERENCES asset(asset_id) ON DELETE RESTRICT,
    impact_type VARCHAR(80) NOT NULL,
    affected_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (incident_id, asset_id)
);

CREATE TABLE indicator (
    indicator_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    type VARCHAR(10) NOT NULL CHECK (type IN ('IP', 'DOMAIN', 'URL', 'HASH', 'EMAIL')),
    value TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    UNIQUE (type, value),
    CHECK (last_seen >= first_seen)
);

CREATE TABLE incident_indicator (
    incident_id INTEGER NOT NULL REFERENCES incident(incident_id) ON DELETE CASCADE,
    indicator_id INTEGER NOT NULL REFERENCES indicator(indicator_id) ON DELETE RESTRICT,
    observed_at TIMESTAMPTZ NOT NULL,
    observation_context TEXT NOT NULL,
    PRIMARY KEY (incident_id, indicator_id)
);

CREATE TABLE threat_actor (
    actor_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,
    description TEXT NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100)
);

CREATE TABLE actor_indicator (
    actor_id INTEGER NOT NULL REFERENCES threat_actor(actor_id) ON DELETE CASCADE,
    indicator_id INTEGER NOT NULL REFERENCES indicator(indicator_id) ON DELETE CASCADE,
    relationship_type VARCHAR(80) NOT NULL,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    PRIMARY KEY (actor_id, indicator_id)
);

CREATE TABLE technique (
    technique_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    attack_id VARCHAR(12) NOT NULL UNIQUE CHECK (attack_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    name VARCHAR(150) NOT NULL,
    tactic VARCHAR(100) NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE incident_technique (
    incident_id INTEGER NOT NULL REFERENCES incident(incident_id) ON DELETE CASCADE,
    technique_id INTEGER NOT NULL REFERENCES technique(technique_id) ON DELETE RESTRICT,
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    source VARCHAR(120) NOT NULL,
    PRIMARY KEY (incident_id, technique_id)
);

CREATE TABLE response_action (
    action_id INTEGER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id INTEGER NOT NULL REFERENCES incident(incident_id) ON DELETE CASCADE,
    responder_id INTEGER REFERENCES user_account(user_id) ON DELETE SET NULL,
    action_type VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('PLANNED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED')),
    performed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE audit_log (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id INTEGER REFERENCES user_account(user_id) ON DELETE SET NULL,
    entity_name VARCHAR(80) NOT NULL,
    entity_id VARCHAR(80) NOT NULL,
    action VARCHAR(80) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

COMMIT;
