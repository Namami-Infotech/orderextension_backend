const config = require('../../config');
const U = require('../../utils/util');
const licenseService = require('./license.service');
const { getScanConfig } = require('../scan/scan.service');

const { sendError } = U;

const bad = (res, msg) => sendError(res, 400, 'invalid_request', msg || 'Invalid request.');
const badCreds = (res) => sendError(res, 401, 'invalid_credentials', 'Login details are not valid.');

function rejectInactive(res, lic) {
  const reason = licenseService.inactiveReason(lic);
  if (!reason) return false;
  sendError(
    res,
    403,
    'license_inactive',
    reason === 'expired' ? 'This license has expired.' : 'This license is not active.',
    { reason }
  );
  return true;
}

function rejectBadVersion(res, version) {
  if (!U.isVersion(version)) {
    sendError(res, 400, 'invalid_request', 'Missing or invalid version.');
    return true;
  }
  if (!U.versionAtLeast(version, config.minExtensionVersion)) {
    sendError(res, 426, 'update_required', 'Please update the extension.', {
      minVersion: config.minExtensionVersion,
    });
    return true;
  }
  return false;
}

/**
 * POST /activate
 * Binds a license to the first device that activates it (or to the new device after an admin reset).
 */
async function activate(req, res) {
  const b = req.body || {};
  const licenseKey = U.normalizeLicenseKey(b.licenseKey);
  const { deviceId, publicKey, version } = b;
  const resetCode = b.resetCode ? String(b.resetCode).trim().toUpperCase() : null;

  if (!U.isLicenseKey(licenseKey) || !U.isDeviceId(deviceId)) return bad(res);
  if (!U.isBase64(publicKey, 400) || !U.parsePublicKey(publicKey)) return bad(res, 'Invalid public key.');
  if (resetCode !== null && !U.isResetCode(resetCode)) return bad(res, 'Invalid reset code format.');
  if (rejectBadVersion(res, version)) return;

  const lic = await licenseService.getLicenseByKey(licenseKey);
  if (!lic) {
    await licenseService.logEvent(null, 'activate_refused', deviceId, req.ip, 'unknown license key');
    return badCreds(res);
  }
  if (rejectInactive(res, lic)) return;

  // Already bound?
  if (lic.bound_device_id) {
    if (lic.bound_device_id === deviceId && lic.bound_public_key === publicKey) {
      return res.json({ ok: true, alreadyActivated: true });
    }
    await licenseService.logEvent(lic.id, 'activate_refused', deviceId, req.ip, 'bound to another device');
    return sendError(
      res,
      409,
      'bound_elsewhere',
      'This license is already activated on another device. Contact support to move it.'
    );
  }

  // Not bound. If an admin reset is pending, a valid one-time code is required.
  let resetHash = null;
  if (lic.reset_code_hash) {
    if (lic.reset_expired) {
      return sendError(res, 403, 'reset_code_expired', 'The reset code has expired. Contact support.');
    }
    if (!resetCode) {
      return sendError(res, 403, 'reset_code_required', 'A reset code is required to activate this license.');
    }
    const hash = U.sha256Hex(resetCode);
    if (!U.safeEqualHex(hash, lic.reset_code_hash)) {
      const attempts = await licenseService.recordFailedResetAttempt(lic.id);
      await licenseService.logEvent(lic.id, 'activate_refused', deviceId, req.ip, `wrong reset code (${attempts})`);
      return sendError(res, 403, 'reset_code_invalid', 'The reset code is not correct.', {
        attemptsLeft: Math.max(0, config.resetMaxAttempts - attempts),
      });
    }
    resetHash = lic.reset_code_hash;
  }

  // Bind atomically. The WHERE clause protects against two devices activating at the same moment.
  const bound = await licenseService.bindDevice(lic.id, deviceId, publicKey, resetHash);
  if (!bound) {
    return sendError(res, 409, 'bound_elsewhere', 'This license was just activated on another device.');
  }

  await licenseService.logEvent(lic.id, 'activate', deviceId, req.ip, resetHash ? 'after reset' : 'first activation');
  return res.json({ ok: true });
}

/**
 * POST /challenge
 * Gives the bound device a fresh one-time random text to sign.
 */
async function challenge(req, res) {
  const b = req.body || {};
  const licenseKey = U.normalizeLicenseKey(b.licenseKey);
  const { deviceId } = b;
  if (!U.isLicenseKey(licenseKey) || !U.isDeviceId(deviceId)) return bad(res);

  const lic = await licenseService.getLicenseByKey(licenseKey);
  if (!lic || !lic.bound_device_id || lic.bound_device_id !== deviceId) return badCreds(res);
  if (rejectInactive(res, lic)) return;

  const chal = U.randomHex(32); // 64 hex characters
  await licenseService.setChallenge(lic.id, chal, config.challengeTtl);
  return res.json({ challenge: chal, expiresInSeconds: config.challengeTtl });
}

/**
 * POST /login
 * Verifies the signed challenge, enforces ONE active session, and returns a short-lived token.
 */
async function login(req, res) {
  const b = req.body || {};
  const licenseKey = U.normalizeLicenseKey(b.licenseKey);
  const { deviceId, challenge: chal, signature, version } = b;

  if (!U.isLicenseKey(licenseKey) || !U.isDeviceId(deviceId)) return bad(res);
  if (typeof chal !== 'string' || !/^[a-f0-9]{64}$/.test(chal)) return bad(res);
  if (!U.isBase64(signature, 200)) return bad(res);
  if (rejectBadVersion(res, version)) return;

  const lic = await licenseService.getLicenseByKey(licenseKey);
  if (!lic || !lic.bound_device_id || lic.bound_device_id !== deviceId) {
    await licenseService.logEvent(lic && lic.id, 'login_failed', deviceId, req.ip, 'unknown license or device mismatch');
    return badCreds(res);
  }
  if (rejectInactive(res, lic)) return;

  // Consume the challenge: it can be used exactly once, and only while it is fresh.
  const challengeConsumed = await licenseService.consumeChallenge(lic.id, chal);
  if (!challengeConsumed) {
    await licenseService.logEvent(lic.id, 'login_failed', deviceId, req.ip, 'challenge invalid or expired');
    return badCreds(res);
  }

  if (!U.verifySignature(lic.bound_public_key, chal, signature)) {
    await licenseService.logEvent(lic.id, 'login_failed', deviceId, req.ip, 'bad signature');
    return badCreds(res);
  }

  // Claim the single session slot atomically.
  const sid = U.randomHex(16);
  const claimed = await licenseService.claimSession(lic.id, sid, req.ip);
  if (!claimed) {
    const retryAfterSeconds = await licenseService.getRemainingSessionSeconds(lic.id);
    await licenseService.logEvent(lic.id, 'in_use', deviceId, req.ip, 'login refused, session active');
    return sendError(
      res,
      409,
      'in_use',
      'This station is already in use. If Chrome just closed, try again shortly.',
      { retryAfterSeconds }
    );
  }

  await licenseService.logEvent(lic.id, 'login', deviceId, req.ip, null);
  return res.json({
    token: licenseService.issueToken(lic.id, sid),
    expiresInSeconds: config.tokenTtl,
    pingEverySeconds: config.pingEvery,
    scanConfig: getScanConfig(lic),
  });
}

/**
 * POST /ping
 * Keeps the session alive and returns a fresh token. Also the moment a revoked license is cut off.
 */
async function ping(req, res) {
  if (rejectBadVersion(res, (req.body || {}).version)) return;

  const { lid, sid } = req.claims;
  const lic = await licenseService.getLicenseById(lid);
  if (!lic) return sendError(res, 401, 'invalid_token', 'Token is not valid.');
  if (rejectInactive(res, lic)) return;
  if (lic.current_session_id !== sid) {
    return sendError(res, 401, 'session_ended', 'This session has ended. Please log in again.');
  }

  const updated = await licenseService.refreshSession(lid, sid, req.ip);
  if (!updated) {
    return sendError(res, 401, 'session_ended', 'This session has ended. Please log in again.');
  }

  return res.json({
    token: licenseService.issueToken(lid, sid),
    expiresInSeconds: config.tokenTtl,
    scanConfig: getScanConfig(lic),
  });
}

/**
 * POST /logout
 * Frees the station immediately. Safe to call twice.
 */
async function logout(req, res) {
  const { lid, sid } = req.claims;
  const lic = await licenseService.getLicenseById(lid);
  const ended = await licenseService.endSession(lid, sid);
  if (ended) {
    await licenseService.logEvent(lid, 'logout', lic && lic.bound_device_id, req.ip, null);
  }
  return res.json({ ok: true });
}

module.exports = {
  activate,
  challenge,
  login,
  ping,
  logout,
};
