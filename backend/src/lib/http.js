function asyncHandler(handler) {
  return (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);
}

function apiError(status, message) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function parseId(value, field = 'id') {
  const id = Number(value);
  if (!Number.isInteger(id) || id < 1) throw apiError(400, `${field} must be a positive integer.`);
  return id;
}

function requireFields(body, fields) {
  for (const field of fields) {
    if (body[field] === undefined || body[field] === null || body[field] === '') throw apiError(400, `${field} is required.`);
  }
}

module.exports = { asyncHandler, apiError, parseId, requireFields };
