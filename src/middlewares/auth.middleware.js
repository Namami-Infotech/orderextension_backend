const jwt = require('jsonwebtoken');
const config = require('../config');
const { sendError } = require('../utils/util');

function requireToken(req, res, next) {
  const h = req.get('authorization') || '';
  const m = /^Bearer (.+)$/.exec(h);
  if (!m) return sendError(res, 401, 'invalid_token', 'Missing token.');

  try {
    req.claims = jwt.verify(m[1], config.jwtSecret, { algorithms: ['HS256'] });
    return next();
  } catch (e) {
    const expired = e && e.name === 'TokenExpiredError';
    return sendError(res, 401, expired ? 'token_expired' : 'invalid_token', 'Token is not valid.');
  }
}

module.exports = {
  requireToken,
};
