const crypto = require('crypto');

// ---------- random values ----------
const randomHex = (bytes) => crypto.randomBytes(bytes).toString('hex');

// License key: 128 bits of randomness, shown as 8 groups of 4, e.g. A1B2-C3D4-E5F6-...
function generateLicenseKey() {
  const hex = randomHex(16).toUpperCase();
  return hex.match(/.{4}/g).join('-');
}

// Reset code: 40 bits, shown as XXXXX-XXXXX
function generateResetCode() {
  const hex = randomHex(5).toUpperCase();
  return `${hex.slice(0, 5)}-${hex.slice(5)}`;
}

const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ---------- validation ----------
const normalizeLicenseKey = (k) => String(k || '').trim().toUpperCase();

const isLicenseKey = (k) => typeof k === 'string' && /^[A-Z0-9-]{16,64}$/.test(k);
const isDeviceId = (d) => typeof d === 'string' && /^[A-Za-z0-9_-]{8,64}$/.test(d);
const isVersion = (v) => typeof v === 'string' && /^\d+(\.\d+){0,3}$/.test(v);
const isBase64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/]+={0,2}$/.test(s);
const isResetCode = (c) => typeof c === 'string' && /^[A-Za-z0-9-]{6,32}$/.test(c);

// Returns true when version a >= b  ("1.2.0" vs "1.10.0" handled numerically)
function versionAtLeast(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x > y) return true;
    if (x < y) return false;
  }
  return true;
}

// ---------- device public key / signature ----------
// The extension sends its public key as base64 SPKI (WebCrypto exportKey('spki')).
// Returns a KeyObject, or null when it is not a valid P-256 public key.
function parsePublicKey(b64) {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec') return null;
    if (key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve !== 'prime256v1') return null;
    return key;
  } catch (e) {
    return null;
  }
}

// WebCrypto ECDSA signatures are raw r||s (IEEE P1363), not DER.
function verifySignature(publicKeyB64, challengeText, signatureB64) {
  const key = parsePublicKey(publicKeyB64);
  if (!key) return false;
  try {
    return crypto.verify(
      'sha256',
      Buffer.from(challengeText, 'utf8'),
      { key, dsaEncoding: 'ieee-p1363' },
      Buffer.from(signatureB64, 'base64')
    );
  } catch (e) {
    return false;
  }
}

// ---------- misc ----------
const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function sendError(res, status, error, message, extra) {
  return res.status(status).json({ error, message, ...(extra || {}) });
}

module.exports = {
  randomHex,
  generateLicenseKey,
  generateResetCode,
  sha256Hex,
  safeEqualHex,
  normalizeLicenseKey,
  isLicenseKey,
  isDeviceId,
  isVersion,
  isBase64,
  isResetCode,
  versionAtLeast,
  parsePublicKey,
  verifySignature,
  asyncHandler,
  sendError,
};
