const jwt = require('jsonwebtoken');
const config = require('../../config');
const { query, logEvent } = require('../../config/db');
const U = require('../../utils/util');

// Expiry and reset checks are done in SQL so they use the database clock (UTC), never the client's.
const LICENSE_SELECT = `
  SELECT *,
         (expiry_date < UTC_DATE()) AS expired,
         (reset_expires_at IS NULL OR reset_expires_at <= UTC_TIMESTAMP()) AS reset_expired
  FROM licenses`;

async function getLicenseByKey(key) {
  const r = await query(`${LICENSE_SELECT} WHERE license_key = ?`, [key]);
  return r.rows[0] || null;
}

async function getLicenseById(id) {
  const r = await query(`${LICENSE_SELECT} WHERE id = ?`, [id]);
  return r.rows[0] || null;
}

// null = usable, otherwise the reason
function inactiveReason(lic) {
  if (lic.status !== 'active') return 'revoked';
  if (lic.expired) return 'expired';
  return null;
}

function issueToken(licenseId, sessionId) {
  return jwt.sign({ lid: licenseId, sid: sessionId }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: config.tokenTtl,
  });
}

async function recordFailedResetAttempt(licenseId) {
  await query(
    `UPDATE licenses
        SET reset_attempts = reset_attempts + 1,
            reset_expires_at = CASE WHEN reset_attempts >= ? THEN DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 SECOND) ELSE reset_expires_at END
      WHERE id = ?`,
    [config.resetMaxAttempts, licenseId]
  );
  const r = await query('SELECT reset_attempts FROM licenses WHERE id = ?', [licenseId]);
  return r.rows[0] ? r.rows[0].reset_attempts : config.resetMaxAttempts;
}

async function bindDevice(licenseId, deviceId, publicKey, resetHash) {
  const upd = await query(
    `UPDATE licenses
        SET bound_device_id = ?, bound_public_key = ?, bound_at = UTC_TIMESTAMP(),
            reset_count = reset_count + ?,
            current_challenge = NULL, challenge_expires_at = NULL,
            current_session_id = NULL, session_last_ping = NULL, session_ip = NULL,
            reset_code_hash = NULL, reset_expires_at = NULL, reset_attempts = 0
      WHERE id = ?
        AND bound_device_id IS NULL
        AND reset_code_hash <=> ?`,
    [deviceId, publicKey, resetHash ? 1 : 0, licenseId, resetHash]
  );
  return upd.affectedRows > 0;
}

async function setChallenge(licenseId, challenge, ttlSeconds) {
  await query(
    `UPDATE licenses
        SET current_challenge = ?,
            challenge_expires_at = DATE_ADD(UTC_TIMESTAMP(), INTERVAL ? SECOND)
      WHERE id = ?`,
    [challenge, ttlSeconds, licenseId]
  );
}

async function consumeChallenge(licenseId, challenge) {
  const used = await query(
    `UPDATE licenses
        SET current_challenge = NULL, challenge_expires_at = NULL
      WHERE id = ? AND current_challenge = ? AND challenge_expires_at > UTC_TIMESTAMP()`,
    [licenseId, challenge]
  );
  return used.affectedRows > 0;
}

async function claimSession(licenseId, sessionId, ip) {
  const claim = await query(
    `UPDATE licenses
        SET current_session_id = ?, session_last_ping = UTC_TIMESTAMP(), session_ip = ?
      WHERE id = ?`,
    [sessionId, ip || null, licenseId]
  );
  return claim.affectedRows > 0;
}

async function getRemainingSessionSeconds(licenseId) {
  const w = await query(
    `SELECT GREATEST(1, TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), DATE_ADD(session_last_ping, INTERVAL ? SECOND))) AS s
       FROM licenses WHERE id = ?`,
    [config.sessionTimeout, licenseId]
  );
  return w.rows[0] && w.rows[0].s ? Number(w.rows[0].s) : config.sessionTimeout;
}

async function refreshSession(licenseId, sessionId, ip) {
  const upd = await query(
    `UPDATE licenses SET session_last_ping = UTC_TIMESTAMP(), session_ip = ?
      WHERE id = ? AND current_session_id = ?`,
    [ip || null, licenseId, sessionId]
  );
  return upd.affectedRows > 0;
}

async function endSession(licenseId, sessionId) {
  const r = await query(
    `UPDATE licenses
        SET current_session_id = NULL, session_last_ping = NULL, session_ip = NULL
      WHERE id = ? AND current_session_id = ?`,
    [licenseId, sessionId]
  );
  return r.affectedRows > 0;
}

module.exports = {
  getLicenseByKey,
  getLicenseById,
  inactiveReason,
  issueToken,
  recordFailedResetAttempt,
  bindDevice,
  setChallenge,
  consumeChallenge,
  claimSession,
  getRemainingSessionSeconds,
  refreshSession,
  endSession,
  logEvent,
};
