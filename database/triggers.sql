CREATE OR REPLACE FUNCTION audit_incident_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    actor_context TEXT;
    actor_user_id INTEGER;
BEGIN
    actor_context := NULLIF(BTRIM(current_setting('app.actor_user_id', true)), '');

    IF actor_context ~ '^[1-9][0-9]*$' THEN
        SELECT user_id
        INTO actor_user_id
        FROM user_account
        WHERE user_id::TEXT = actor_context;
    END IF;

    INSERT INTO audit_log (user_id, entity_name, entity_id, action, details)
    VALUES (
        COALESCE(actor_user_id, NEW.created_by),
        'incident',
        NEW.incident_id::TEXT,
        CASE WHEN TG_OP = 'INSERT' THEN 'INCIDENT_CREATED' ELSE 'INCIDENT_UPDATED' END,
        jsonb_build_object('severity', NEW.severity, 'status', NEW.status, 'title', NEW.title)
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_audit_incident_change ON incident;
CREATE TRIGGER trg_audit_incident_change
AFTER INSERT OR UPDATE OF title, description, severity, status, assigned_to ON incident
FOR EACH ROW EXECUTE FUNCTION audit_incident_change();
