const { query } = require('../db/postgres');

async function writeAudit(userId, entityName, entityId, action, details = {}) {
  await query(
    'INSERT INTO audit_log (user_id, entity_name, entity_id, action, details) VALUES ($1, $2, $3, $4, $5::jsonb)',
    [userId, entityName, String(entityId), action, JSON.stringify(details)]
  );
}

module.exports = { writeAudit };
