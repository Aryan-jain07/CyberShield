const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config');
const { apiError } = require('../lib/http');

const roles = {
  ADMIN: 'Admin', ANALYST: 'Security Analyst', RESPONDER: 'Incident Responder',
  RESEARCHER: 'Threat Researcher', VIEWER: 'Viewer'
};

function authenticate(req, _res, next) {
  const token = req.headers.authorization?.startsWith('Bearer ') && req.headers.authorization.slice(7);
  if (!token) return next(apiError(401, 'Bearer authentication is required.'));
  try { req.user = jwt.verify(token, jwtSecret); return next(); }
  catch { return next(apiError(401, 'Invalid or expired token.')); }
}

function authorize(...allowedRoles) {
  return (req, _res, next) => allowedRoles.includes(req.user.role_name)
    ? next() : next(apiError(403, 'Your role is not authorized for this action.'));
}

module.exports = { authenticate, authorize, roles };
