'use strict';

/**
 * JWT Authentication Middleware
 *
 * Token strategy:
 *   - Access token  : HS256, 15 min TTL — short-lived to limit exposure
 *   - Refresh token : HS256, 7 day TTL  — longer-lived, stored as SHA-256
 *                     hash in DB so it can be individually revoked
 *
 * Usage:
 *   All protected routes call jwtAuth as middleware:
 *     router.get('/wallet', jwtAuth, handler)
 *
 *   The decoded payload is attached as req.user:
 *     { id, kycStatus, kycLevel }
 */

const crypto  = require('crypto');
const jwt     = require('jsonwebtoken');
const { pool }   = require('../config/database');
const { logger } = require('../utils/logger');

// ── Helpers ───────────────────────────────────────────────────────────────────

function jwtSecret() {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters. Generate with: node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
  }
  return s;
}

/** Sign a short-lived access token. */
function signAccessToken(payload) {
  return jwt.sign(payload, jwtSecret(), { algorithm: 'HS256', expiresIn: '15m' });
}

/** Sign a longer-lived refresh token. */
function signRefreshToken(payload) {
  return jwt.sign(payload, jwtSecret(), { algorithm: 'HS256', expiresIn: '7d' });
}

/** Hash a raw refresh token for storage (never store the raw token). */
function hashRefreshToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// ── Middleware ────────────────────────────────────────────────────────────────

async function jwtAuth(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: 'Authorization header missing or malformed. Expected: Bearer <token>',
    });
  }

  const token = authHeader.slice(7);
  let payload;

  try {
    payload = jwt.verify(token, jwtSecret(), { algorithms: ['HS256'] });
  } catch (err) {
    logger.warn({ message: 'JWT verification failed', error: err.message, ip: req.ip });
    const msg = err.name === 'TokenExpiredError' ? 'Access token expired.' : 'Invalid access token.';
    return res.status(401).json({ success: false, error: msg });
  }

  // Confirm user still exists and is active (catches disabled/deleted accounts)
  let user;
  try {
    const { rows } = await pool.query(
      `SELECT id, kyc_status, kyc_level, is_active FROM users WHERE id = $1`,
      [payload.sub]
    );
    user = rows[0];
  } catch (dbErr) {
    return next(dbErr);
  }

  if (!user || !user.is_active) {
    return res.status(401).json({ success: false, error: 'Account not found or has been deactivated.' });
  }

  req.user = { id: user.id, kycStatus: user.kyc_status, kycLevel: user.kyc_level };
  next();
}

module.exports = { jwtAuth, signAccessToken, signRefreshToken, hashRefreshToken };
