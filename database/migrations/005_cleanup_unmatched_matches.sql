BEGIN;

CREATE TABLE IF NOT EXISTS vulnerability_software_match_unmatched_archive
(
    match_id BIGINT PRIMARY KEY,
    intelligence_id BIGINT NOT NULL,
    software_id INTEGER NOT NULL,
    match_type VARCHAR(20) NOT NULL,
    evidence JSONB NOT NULL,
    source VARCHAR(40) NOT NULL,
    analyst_verified BOOLEAN NOT NULL,
    matched_at TIMESTAMPTZ NOT NULL
);

INSERT INTO vulnerability_software_match_unmatched_archive
    (match_id,intelligence_id,software_id,match_type,evidence,source,analyst_verified,matched_at)
SELECT match_id,intelligence_id,software_id,match_type,evidence,source,analyst_verified,matched_at
FROM vulnerability_software_match
WHERE match_type = 'UNMATCHED'
ON CONFLICT (match_id) DO NOTHING;

DELETE FROM vulnerability_software_match
WHERE match_type = 'UNMATCHED';

COMMIT;

-- Reversal, to be run only after reviewing the archive:
-- INSERT INTO vulnerability_software_match
--     (match_id,intelligence_id,software_id,match_type,evidence,source,analyst_verified,matched_at)
-- OVERRIDING SYSTEM VALUE
-- SELECT match_id,intelligence_id,software_id,match_type,evidence,source,analyst_verified,matched_at
-- FROM vulnerability_software_match_unmatched_archive
-- ON CONFLICT (match_id) DO NOTHING;
