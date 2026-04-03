'use strict';

/**
 * Encryption Service — AES-256-GCM
 *
 * Provides:
 *   encrypt(plaintext)        → AES-256-GCM ciphertext (iv|authTag|ciphertext, base64 parts)
 *   decrypt(ciphertext)       → original plaintext
 *   hmacToken(value)          → HMAC-SHA256 hex digest — deterministic, for indexed lookups
 *   hashPassword(password)    → bcrypt hash (cost 12)
 *   verifyPassword(pw, hash)  → boolean
 *
 * Algorithm choice — AES-256-GCM:
 *   - 256-bit key satisfies "strong cryptography" requirements
 *   - GCM provides confidentiality + authenticated integrity in one pass
 *   - Random 12-byte IV per call prevents IV reuse attacks
 *
 * Stored ciphertext format (pipe-delimited, each part base64-encoded):
 *   <iv_b64>|<authTag_b64>|<ciphertext_b64>
 */

const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');

const ALGORITHM    = 'aes-256-gcm';
const IV_LEN       = 12;   // 96-bit IV — NIST recommended for GCM
const AUTH_TAG_LEN = 16;   // 128-bit auth tag — GCM default
const SEP          = '|';
const BCRYPT_COST  = 12;

// ── Key loading ───────────────────────────────────────────────────────────────

function loadKey(envVar, label) {
  const hex = process.env[envVar];
  if (!hex || hex.length !== 64) {
    throw new Error(
      `[Encryption] ${label} (${envVar}) must be a 64-character hex string (32 bytes). ` +
      `Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
    );
  }
  return Buffer.from(hex, 'hex');
}

let _encKey  = null;
let _hmacKey = null;

function getEncKey()  { return _encKey  || (_encKey  = loadKey('ENCRYPTION_KEY', 'Encryption key')); }
function getHmacKey() { return _hmacKey || (_hmacKey = loadKey('HMAC_KEY',        'HMAC key')); }

// ── AES-256-GCM encrypt / decrypt ────────────────────────────────────────────

/**
 * Encrypts a string value.
 * @param {string} plaintext
 * @returns {string}  "<iv_b64>|<authTag_b64>|<ciphertext_b64>"
 */
function encrypt(plaintext) {
  if (plaintext === null || plaintext === undefined) {
    throw new TypeError('[Encryption] encrypt() received null/undefined.');
  }
  const iv      = crypto.randomBytes(IV_LEN);
  const cipher  = crypto.createCipheriv(ALGORITHM, getEncKey(), iv, { authTagLength: AUTH_TAG_LEN });
  const enc     = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return [iv.toString('base64'), authTag.toString('base64'), enc.toString('base64')].join(SEP);
}

/**
 * Decrypts a ciphertext produced by encrypt().
 * Throws if the auth tag fails (tamper detection).
 * @param {string} ciphertext
 * @returns {string}
 */
function decrypt(ciphertext) {
  if (!ciphertext || typeof ciphertext !== 'string') {
    throw new TypeError('[Encryption] decrypt() received invalid input.');
  }
  const parts = ciphertext.split(SEP);
  if (parts.length !== 3) throw new Error('[Encryption] Malformed ciphertext.');

  const [ivB64, tagB64, encB64] = parts;
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    getEncKey(),
    Buffer.from(ivB64, 'base64'),
    { authTagLength: AUTH_TAG_LEN }
  );
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));

  const plain = Buffer.concat([
    decipher.update(Buffer.from(encB64, 'base64')),
    decipher.final(),
  ]);
  return plain.toString('utf8');
}

// ── HMAC token ────────────────────────────────────────────────────────────────

/**
 * Produces a deterministic HMAC-SHA256 token for a value.
 * Used for database lookups on encrypted columns (email, phone, BVN, etc.).
 * The token reveals nothing about the original value.
 *
 * @param {string} value  — normalised before hashing (trimmed + lowercased)
 * @returns {string}      — 64-char hex digest
 */
function hmacToken(value) {
  const normalised = String(value).trim().toLowerCase();
  return crypto.createHmac('sha256', getHmacKey()).update(normalised).digest('hex');
}

// ── Password helpers ──────────────────────────────────────────────────────────

/**
 * Returns a bcrypt hash for the given password.
 * @param {string} password
 * @returns {Promise<string>}
 */
function hashPassword(password) {
  return bcrypt.hash(password, BCRYPT_COST);
}

/**
 * Compares a plaintext password against a stored bcrypt hash.
 * @param {string} password
 * @param {string} hash
 * @returns {Promise<boolean>}
 */
function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

module.exports = { encrypt, decrypt, hmacToken, hashPassword, verifyPassword };
