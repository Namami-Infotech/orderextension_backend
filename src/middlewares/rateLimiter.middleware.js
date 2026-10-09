const rateLimit = require('express-rate-limit');
const config = require('../config');
const { sendError } = require('../utils/util');

const createLimiter = (max) =>
  rateLimit({
    windowMs: 60 * 1000,
    limit: max,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) =>
      sendError(res, 429, 'rate_limited', 'Too many requests. Try again shortly.'),
  });

const globalLimiter = createLimiter(config.globalRateLimit);
const strictLimiter = createLimiter(config.strictRateLimit);

module.exports = {
  createLimiter,
  globalLimiter,
  strictLimiter,
};
