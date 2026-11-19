BEGIN;

ALTER TABLE incident
    ADD COLUMN IF NOT EXISTS category VARCHAR(40) NOT NULL DEFAULT 'Other',
    ADD COLUMN IF NOT EXISTS source VARCHAR(120),
    ADD COLUMN IF NOT EXISTS additional_notes TEXT;

ALTER TABLE incident
    DROP CONSTRAINT IF EXISTS incident_category_check;

ALTER TABLE incident
    ADD CONSTRAINT incident_category_check CHECK (
        category IN (
            'Malware',
            'Phishing',
            'Ransomware',
            'Unauthorized Access',
            'Data Breach',
            'Denial of Service',
            'Suspicious Network Activity',
            'Insider Threat',
            'Other'
        )
    );

COMMIT;
