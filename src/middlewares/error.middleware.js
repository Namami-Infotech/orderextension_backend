const { sendError } = require('../utils/util');

function notFoundHandler(req, res) {
  return sendError(res, 404, 'not_found', 'Not found.');
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  if (err && err.type === 'entity.parse.failed') {
    return sendError(res, 400, 'invalid_request', 'Invalid JSON.');
  }
  if (err && err.type === 'entity.too.large') {
    return sendError(res, 413, 'invalid_request', 'Request too large.');
  }
  console.error(err);
  return sendError(res, 500, 'server_error', 'Something went wrong.');
}

module.exports = {
  notFoundHandler,
  errorHandler,
};
