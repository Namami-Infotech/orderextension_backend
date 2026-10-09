#!/usr/bin/env node
// Admin commands. Run on the server (never exposed over HTTP):
//   node src/scripts/admin.js create "<Client name>" <STATION> <YYYY-MM-DD>
//   node src/scripts/admin.js list
//   node src/scripts/admin.js show <id>
//   node src/scripts/admin.js revoke <id>       (stops the license; extension locks at its next ping)
//   node src/scripts/admin.js enable <id>       (undo revoke)
//   node src/scripts/admin.js extend <id> <YYYY-MM-DD>
//   node src/scripts/admin.js reset <id>        (unbind device + create a one-time reset code)
//   node src/scripts/admin.js kick <id>         (end the active session now)
//   node src/scripts/admin.js logs <id> [count]

const config = require('../config');
const { pool, query, logEvent } = require('../config/db');
const U = require('../utils/util');

const [, , cmd, ...args] = process.argv;

const isDate = (s) => /^\d{4}-\d{2}-\d{2}$/.test(s || '') && !Number.isNaN(Date.parse(s));
const toId = (s) => {
  const n = parseInt(s, 10);
  if (!Number.isInteger(n) || n < 1) throw new Error('Give a valid license id (see: list)');
  return n;
};

async function main() {
  switch (cmd) {
    case 'create': {
      const [client, station, expiry] = args;
      if (!client || !station || !isDate(expiry)) {
        throw new Error('Usage: create "<Client name>" <STATION> <YYYY-MM-DD>');
      }
      const key = U.generateLicenseKey();
      const r = await query(
        `INSERT INTO licenses (license_key, client_name, station_code, expiry_date)
         VALUES (?,?,?,?)`,
        [key, client, station.toUpperCase(), expiry]
      );
      console.log(`Created license id ${r.insertId}`);
      console.log(`Client : ${client}`);
      console.log(`Station: ${station.toUpperCase()}`);
      console.log(`Expires: ${expiry}`);
      console.log(`KEY    : ${key}`);
      break;
    }

    case 'list': {
      const r = await query(
        `SELECT id, client_name, station_code, status, DATE_FORMAT(expiry_date,'%Y-%m-%d') AS expiry,
                (bound_device_id IS NOT NULL) AS bound,
                (reset_code_hash IS NOT NULL) AS reset_pending,
                (current_session_id IS NOT NULL
                   AND session_last_ping > DATE_SUB(UTC_TIMESTAMP(), INTERVAL ? SECOND)) AS in_use,
                license_key
           FROM licenses ORDER BY id`,
        [config.sessionTimeout]
      );
      console.table(
        r.rows.map((x) => ({
          ...x,
          bound: !!x.bound,
          reset_pending: !!x.reset_pending,
          in_use: !!x.in_use,
        }))
      );
      break;
    }

    case 'show': {
      const id = toId(args[0]);
      const r = await query(
        `SELECT id, client_name, station_code, status, expiry_date, bound_device_id,
                LEFT(bound_public_key, 16) AS public_key_start, bound_at, reset_count,
                (reset_code_hash IS NOT NULL) AS reset_pending, reset_expires_at, reset_attempts,
                current_session_id, session_last_ping, session_ip, created_at, license_key
           FROM licenses WHERE id = ?`,
        [id]
      );
      if (!r.rows[0]) throw new Error('License not found');
      console.log(r.rows[0]);
      break;
    }

    case 'revoke':
    case 'enable': {
      const id = toId(args[0]);
      const status = cmd === 'revoke' ? 'revoked' : 'active';
      const r = await query('UPDATE licenses SET status = ? WHERE id = ?', [status, id]);
      if (!r.affectedRows) throw new Error('License not found');
      await logEvent(id, cmd, null, null, 'admin');
      console.log(
        `License ${id} is now ${status}.` +
          (cmd === 'revoke' ? ' The extension locks at its next ping (within about a minute).' : '')
      );
      break;
    }

    case 'extend': {
      const id = toId(args[0]);
      if (!isDate(args[1])) throw new Error('Usage: extend <id> <YYYY-MM-DD>');
      const r = await query('UPDATE licenses SET expiry_date = ? WHERE id = ?', [args[1], id]);
      if (!r.affectedRows) throw new Error('License not found');
      await logEvent(id, 'extend', null, null, `to ${args[1]}`);
      console.log(`License ${id} now expires on ${args[1]}.`);
      break;
    }

    case 'reset': {
      const id = toId(args[0]);
      const code = U.generateResetCode();
      const info = await query('SELECT client_name, station_code FROM licenses WHERE id = ?', [id]);
      if (!info.rows[0]) throw new Error('License not found');
      await query(
        `UPDATE licenses
            SET bound_device_id = NULL, bound_public_key = NULL, bound_at = NULL,
                reset_code_hash = ?,
                reset_expires_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? MINUTE),
                reset_attempts = 0,
                current_challenge = NULL, challenge_expires_at = NULL,
                current_session_id = NULL, session_last_ping = NULL, session_ip = NULL
          WHERE id = ?`,
        [U.sha256Hex(code), config.resetCodeMinutes, id]
      );
      await logEvent(id, 'reset', null, null, 'admin reset');
      console.log(`Device unbound for license ${id} (${info.rows[0].client_name}, ${info.rows[0].station_code}).`);
      console.log(`RESET CODE: ${code}   (valid ${config.resetCodeMinutes} minutes, one use)`);
      console.log("Send this code ONLY to the client's registered email. It is not stored in readable form.");
      break;
    }

    case 'kick': {
      const id = toId(args[0]);
      const r = await query(
        `UPDATE licenses SET current_session_id = NULL, session_last_ping = NULL, session_ip = NULL
          WHERE id = ?`,
        [id]
      );
      if (!r.affectedRows) throw new Error('License not found');
      await logEvent(id, 'kick', null, null, 'admin ended session');
      console.log(`Session ended for license ${id}.`);
      break;
    }

    case 'logs': {
      const id = toId(args[0]);
      const n = Math.min(Math.max(parseInt(args[1], 10) || 20, 1), 200);
      const r = await query(
        `SELECT created_at, event, device_id, ip, detail
           FROM activity_log WHERE license_id = ? ORDER BY created_at DESC, id DESC LIMIT ?`,
        [id, n]
      );
      console.table(r.rows);
      break;
    }

    default:
      console.log(require('fs').readFileSync(__filename, 'utf8').split('\n').slice(1, 13).join('\n'));
  }
}

main()
  .catch((e) => {
    console.error('Error:', e.message);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
