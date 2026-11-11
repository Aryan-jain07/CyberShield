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
  if (!body || typeof body !== 'object' || Array.isArray(body)) throw apiError(400, 'Request body must be an object.');
  for (const field of fields) {
    if (body[field] === undefined || body[field] === null || body[field] === '') throw apiError(400, `${field} is required.`);
  }
}

function requireString(value, field, maxLength, minLength = 1) {
  if (typeof value !== 'string' || value.trim().length < minLength || value.length > maxLength) {
    throw apiError(400, `${field} must be a string between ${minLength} and ${maxLength} characters.`);
  }
}

function requireEnum(value, field, allowed) {
  if (typeof value !== 'string' || !allowed.includes(value)) {
    throw apiError(400, `Invalid ${field}.`);
  }
}

function requireOptionalId(value, field) {
  if (value !== undefined && value !== null && (!Number.isInteger(value) || value < 1)) {
    throw apiError(400, `${field} must be a positive integer or null.`);
  }
}

function requireDate(value, field) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) {
    throw apiError(400, `Invalid ${field}.`);
  }
}

module.exports = {
  asyncHandler,
  apiError,
  parseId,
  requireFields,
  requireString,
  requireEnum,
  requireOptionalId,
  requireDate
};
