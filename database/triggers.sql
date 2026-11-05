CREATE OR REPLACE FUNCTION audit_incident_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO audit_log (user_id, entity_name, entity_id, action, details)
    VALUES (
        NEW.created_by,
        'incident',
        NEW.incident_id::TEXT,
        CASE WHEN TG_OP = 'INSERT' THEN 'INCIDENT_CREATED' ELSE 'INCIDENT_UPDATED' END,
        jsonb_build_object('severity', NEW.severity, 'status', NEW.status, 'title', NEW.title)
    );
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_audit_incident_change
AFTER INSERT OR UPDATE OF severity, status, assigned_to ON incident
FOR EACH ROW EXECUTE FUNCTION audit_incident_change();
