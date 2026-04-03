'use strict';

/**
 * Auth Routes
 *
 * POST /api/v1/auth/register  — create account + wallet
 * POST /api/v1/auth/login     — authenticate; return access + refresh tokens
 * POST /api/v1/auth/refresh   — exchange refresh token for new access token
 * POST /api/v1/auth/logout    — revoke a specific refresh token
 * GET  /api/v1/auth/me        — return current user's profile (JWT required)
 */

const express        = require('express');
const { v4: uuidv4 } = require('uuid');
const Joi            = require('joi');

const { pool }                                          = require('../config/database');
const { encrypt, decrypt, hmacToken,
        hashPassword, verifyPassword }                  = require('../services/encryption');
const { jwtAuth, signAccessToken,
        signRefreshToken, hashRefreshToken }            = require('../middleware/jwtAuth');
const { authLimiter }                                   = require('../middleware/rateLimiter');
const { logger }                                        = require('../utils/logger');

const router = express.Router();

// ── Validation schemas ────────────────────────────────────────────────────────

const registerSchema = Joi.object({
  firstName:   Joi.string().trim().min(2).max(50).required(),
  lastName:    Joi.string().trim().min(2).max(50).required(),
  email:       Joi.string().trim().email().required(),
  phone:       Joi.string().trim().pattern(/^\+?[1-9]\d{9,14}$/).required().messages({
    'string.pattern.base': 'Phone must be a valid international number (10–15 digits).',
  }),
  password:    Joi.string().min(8).max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_])/)
    .required()
    .messages({
      'string.pattern.base':
        'Password must contain uppercase, lowercase, a digit, and a special character.',
    }),
  dateOfBirth: Joi.string().isoDate().required().messages({
    'string.isoDate': 'dateOfBirth must be an ISO date (YYYY-MM-DD).',
  }),
});

const loginSchema = Joi.object({
  email:    Joi.string().trim().email().required(),
  password: Joi.string().required(),
});

const refreshSchema = Joi.object({
  refreshToken: Joi.string().required(),
});

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Generate a 10-digit wallet number (Nigerian-style account number). */
async function generateWalletNumber(client) {
  let number, exists;
  do {
    number = Math.floor(1_000_000_000 + Math.random() * 9_000_000_000).toString();
    const { rows } = await client.query(
      'SELECT 1 FROM wallets WHERE wallet_number = $1',
      [number]
    );
    exists = rows.length > 0;
  } while (exists);
  return number;
}

/** Build the safe user profile object (no encrypted fields returned raw). */
function buildProfile(user) {
  return {
    id:          user.id,
    email:       decrypt(user.encrypted_email),
    phone:       decrypt(user.encrypted_phone),
    firstName:   decrypt(user.encrypted_first_name),
    lastName:    decrypt(user.encrypted_last_name),
    dateOfBirth: user.date_of_birth,
    kycStatus:   user.kyc_status,
    kycLevel:    user.kyc_level,
    createdAt:   user.created_at,
  };
}

// ── POST /register ────────────────────────────────────────────────────────────

router.post('/register', authLimiter, async (req, res, next) => {
  const { error, value } = registerSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  const { firstName, lastName, email, phone, password, dateOfBirth } = value;
  const emailToken = hmacToken(email);
  const phoneToken = hmacToken(phone);

  // Check uniqueness
  const { rows: existing } = await pool.query(
    'SELECT id FROM users WHERE email_token = $1 OR phone_token = $2',
    [emailToken, phoneToken]
  );
  if (existing.length > 0) {
    return res.status(409).json({ success: false, error: 'Email or phone already registered.' });
  }

  const userId       = uuidv4();
  const passwordHash = await hashPassword(password);
  const walletId     = uuidv4();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Insert user (PII encrypted)
    await client.query(
      `INSERT INTO users
         (id, email_token, encrypted_email, phone_token, encrypted_phone,
          encrypted_first_name, encrypted_last_name, date_of_birth, password_hash)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        userId,
        emailToken,
        encrypt(email),
        phoneToken,
        encrypt(phone),
        encrypt(firstName),
        encrypt(lastName),
        dateOfBirth,
        passwordHash,
      ]
    );

    // Create wallet automatically
    const walletNumber = await generateWalletNumber(client);
    await client.query(
      `INSERT INTO wallets (id, user_id, wallet_number) VALUES ($1,$2,$3)`,
      [walletId, userId, walletNumber]
    );

    await client.query('COMMIT');
  } catch (dbErr) {
    await client.query('ROLLBACK');
    return next(dbErr);
  } finally {
    client.release();
  }

  logger.info({ message: 'User registered', userId, ip: req.ip });

  return res.status(201).json({
    success: true,
    message: 'Registration successful. Please complete KYC to unlock full wallet features.',
    user: {
      id:           userId,
      firstName,
      lastName,
      email,
      phone,
      kycStatus:    'PENDING',
      kycLevel:     0,
    },
  });
});

// ── POST /login ───────────────────────────────────────────────────────────────

router.post('/login', authLimiter, async (req, res, next) => {
  const { error, value } = loginSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  const { email, password } = value;
  const emailToken = hmacToken(email);

  let user;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email_token = $1', [emailToken]);
    user = rows[0];
  } catch (dbErr) {
    return next(dbErr);
  }

  // Constant-time: always run verifyPassword even on missing user (prevents timing attacks)
  const dummyHash    = '$2a$12$xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
  const passwordHash = user ? user.password_hash : dummyHash;
  const valid        = await verifyPassword(password, passwordHash);

  if (!user || !valid || !user.is_active) {
    logger.warn({ message: 'Login failed', ip: req.ip });
    return res.status(401).json({ success: false, error: 'Invalid email or password.' });
  }

  // Issue tokens
  const accessToken  = signAccessToken({ sub: user.id });
  const rawRefresh   = uuidv4() + '-' + uuidv4();   // high-entropy raw token
  const refreshHash  = hashRefreshToken(rawRefresh);
  const expiresAt    = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  try {
    await pool.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [uuidv4(), user.id, refreshHash, expiresAt]
    );
  } catch (dbErr) {
    return next(dbErr);
  }

  logger.info({ message: 'User logged in', userId: user.id, ip: req.ip });

  return res.json({
    success: true,
    accessToken,
    refreshToken: rawRefresh,
    expiresIn:    900,   // 15 minutes in seconds
    tokenType:    'Bearer',
    user: {
      id:        user.id,
      email:     decrypt(user.encrypted_email),
      firstName: decrypt(user.encrypted_first_name),
      lastName:  decrypt(user.encrypted_last_name),
      kycStatus: user.kyc_status,
      kycLevel:  user.kyc_level,
    },
  });
});

// ── POST /refresh ─────────────────────────────────────────────────────────────

router.post('/refresh', authLimiter, async (req, res, next) => {
  const { error, value } = refreshSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ success: false, error: 'refreshToken is required.' });
  }

  const tokenHash = hashRefreshToken(value.refreshToken);

  let row;
  try {
    const { rows } = await pool.query(
      `SELECT rt.id, rt.user_id, rt.expires_at, rt.revoked,
              u.is_active, u.kyc_status, u.kyc_level
       FROM refresh_tokens rt
       JOIN users u ON u.id = rt.user_id
       WHERE rt.token_hash = $1`,
      [tokenHash]
    );
    row = rows[0];
  } catch (dbErr) {
    return next(dbErr);
  }

  if (!row || row.revoked || new Date(row.expires_at) < new Date() || !row.is_active) {
    return res.status(401).json({ success: false, error: 'Invalid or expired refresh token.' });
  }

  const newAccessToken = signAccessToken({ sub: row.user_id });

  // Token rotation: revoke old refresh token and issue a new one
  const rawNewRefresh  = uuidv4() + '-' + uuidv4();
  const newRefreshHash = hashRefreshToken(rawNewRefresh);
  const expiresAt      = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('UPDATE refresh_tokens SET revoked = TRUE WHERE id = $1', [row.id]);
    await client.query(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at) VALUES ($1,$2,$3,$4)`,
      [uuidv4(), row.user_id, newRefreshHash, expiresAt]
    );
    await client.query('COMMIT');
  } catch (dbErr) {
    await client.query('ROLLBACK');
    return next(dbErr);
  } finally {
    client.release();
  }

  return res.json({
    success:      true,
    accessToken:  newAccessToken,
    refreshToken: rawNewRefresh,
    expiresIn:    900,
    tokenType:    'Bearer',
  });
});

// ── POST /logout ──────────────────────────────────────────────────────────────

router.post('/logout', jwtAuth, async (req, res, next) => {
  const { error, value } = refreshSchema.validate(req.body);
  if (error) {
    return res.status(400).json({ success: false, error: 'refreshToken is required.' });
  }

  const tokenHash = hashRefreshToken(value.refreshToken);

  try {
    await pool.query(
      `UPDATE refresh_tokens SET revoked = TRUE
       WHERE token_hash = $1 AND user_id = $2`,
      [tokenHash, req.user.id]
    );
  } catch (dbErr) {
    return next(dbErr);
  }

  logger.info({ message: 'User logged out', userId: req.user.id, ip: req.ip });
  return res.json({ success: true, message: 'Logged out successfully.' });
});

// ── GET /me ───────────────────────────────────────────────────────────────────

router.get('/me', jwtAuth, async (req, res, next) => {
  let user;
  try {
    const { rows } = await pool.query(`SELECT * FROM users WHERE id = $1`, [req.user.id]);
    user = rows[0];
  } catch (dbErr) {
    return next(dbErr);
  }

  if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

  return res.json({ success: true, user: buildProfile(user) });
});

module.exports = router;
