const { query } = require('../../config/db');

async function checkHealth(req, res) {
  await query('SELECT 1');
  return res.json({ ok: true });
}

module.exports = {
  checkHealth,
};
