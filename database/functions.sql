CREATE OR REPLACE FUNCTION get_incident_overview(p_incident_id INTEGER)
RETURNS TABLE (
    incident_id INTEGER,
    title VARCHAR,
    severity VARCHAR,
    status VARCHAR,
    asset_count BIGINT,
    indicator_count BIGINT,
    response_count BIGINT
)
LANGUAGE sql
STABLE
AS $$
    SELECT
        s.incident_id, s.title, s.severity, s.status,
        s.affected_asset_count, s.indicator_count, s.response_action_count
    FROM vw_incident_summary s
    WHERE s.incident_id = p_incident_id;
$$;

CREATE OR REPLACE PROCEDURE add_response_action(
    p_incident_id INTEGER,
    p_responder_id INTEGER,
    p_action_type VARCHAR,
    p_description TEXT,
    p_status VARCHAR
)
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO response_action (incident_id, responder_id, action_type, description, status)
    VALUES (p_incident_id, p_responder_id, p_action_type, p_description, p_status);
END;
$$;
