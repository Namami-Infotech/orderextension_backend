const mysql = require('mysql2/promise');
const config = require('./index');

const pool = mysql.createPool({
  host: config.db.host,
  port: config.db.port,
  user: config.db.user,
  password: config.db.password,
  database: config.db.database,
  ssl: config.db.ssl ? { rejectUnauthorized: false } : undefined,
  connectionLimit: 10,
  waitForConnections: true,
  timezone: 'Z',          // read DATETIME values as UTC
  dateStrings: true,      // return DATE/DATETIME as plain strings, never shifted by the server timezone
  flags: ['+FOUND_ROWS'], // affectedRows = rows matched by WHERE, not only rows whose values changed
});

// Every connection works in UTC, so defaults like CURRENT_TIMESTAMP are UTC too.
pool.pool.on('connection', (conn) => conn.query("SET time_zone = '+00:00'"));

// Always parameterised (values are escaped by the driver). Returns a small, uniform result:
//   SELECT -> { rows: [...] }     UPDATE/INSERT/DELETE -> { affectedRows, insertId }
async function query(sql, params) {
  const [res] = await pool.query(sql, params);
  if (Array.isArray(res)) return { rows: res, affectedRows: 0, insertId: 0 };
  return { rows: [], affectedRows: res.affectedRows, insertId: res.insertId };
}

// Best effort: logging must never break a request.
async function logEvent(licenseId, event, deviceId, ip, detail) {
  try {
    await pool.query(
      'INSERT INTO activity_log (license_id, event, device_id, ip, detail) VALUES (?,?,?,?,?)',
      [licenseId || null, event, deviceId || null, ip || null, detail ? String(detail).slice(0, 255) : null]
    );
  } catch (e) {
    console.error('log failed:', e.message);
  }
}

module.exports = { pool, query, logEvent };
