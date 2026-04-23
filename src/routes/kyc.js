'use strict';

/**
 * KYC Routes
 *
 * POST /api/v1/kyc/submit  — submit a KYC document for verification
 * GET  /api/v1/kyc/status  — retrieve current KYC status and level
 * GET  /api/v1/kyc/documents — list all submitted KYC documents
 *
 * All routes require a valid JWT (jwtAuth middleware).
 *
 * On successful verification the user's kyc_level is upgraded and
 * their wallet's daily/monthly debit limits are updated accordingly.
 */

const express        = require('express');
const { v4: uuidv4 } = require('uuid');
const Joi            = require('joi');

const { pool }                              = require('../config/database');
const { encrypt, hmacToken }               = require('../services/encryption');
const { verifyDocument, DOCUMENT_RULES, limitsForLevel } = require('../services/kycService');
const { jwtAuth }                          = require('../middleware/jwtAuth');
const { logger }                           = require('../utils/logger');

const router = express.Router();

// All KYC routes require authentication
router.use(jwtAuth);

// ── Validation schema ─────────────────────────────────────────────────────────

const submitSchema = Joi.object({
  documentType:   Joi.string().valid(...Object.keys(DOCUMENT_RULES)).required().messages({
    'any.only': `documentType must be one of: ${Object.keys(DOCUMENT_RULES).join(', ')}`,
  }),
  documentNumber: Joi.string().trim().min(5).max(30).required(),
});

// ── POST /submit ──────────────────────────────────────────────────────────────

router.post('/submit', async (req, res, next) => {
  const { error, value } = submitSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  const { documentType, documentNumber } = value;
  const userId    = req.user.id;
  const docToken  = hmacToken(documentType + ':' + documentNumber);

  // Check for duplicate document number across all users (prevents reuse)
  const { rows: dupRows } = await pool.query(
    'SELECT id FROM kyc_documents WHERE document_token = $1',
    [docToken]
  );
  if (dupRows.length > 0) {
    return res.status(409).json({
      success: false,
      error:   'This document number has already been used.',
    });
  }

  // Validate document format (simulated) but do NOT auto-approve —
  // admin must review and approve via the admin dashboard.
  const result = verifyDocument(documentType, documentNumber);
  if (!result.valid) {
    return res.status(422).json({
      success: false,
      error:   `Document validation failed: ${result.reason}`,
    });
  }

  const docId = uuidv4();

  try {
    // Upsert kyc_documents with PENDING status
    await pool.query(
      `INSERT INTO kyc_documents
         (id, user_id, document_type, document_token, encrypted_document_number,
          verification_status, verified_at, rejection_reason)
       VALUES ($1,$2,$3,$4,$5,'PENDING',NULL,NULL)
       ON CONFLICT (user_id, document_type)
       DO UPDATE SET
         document_token             = EXCLUDED.document_token,
         encrypted_document_number  = EXCLUDED.encrypted_document_number,
         verification_status        = 'PENDING',
         verified_at                = NULL,
         rejection_reason           = NULL`,
      [docId, userId, documentType, docToken, encrypt(documentNumber)]
    );

    // Mark user KYC status as PENDING (awaiting admin review)
    await pool.query(
      `UPDATE users SET kyc_status = 'PENDING', updated_at = NOW() WHERE id = $1`,
      [userId]
    );
  } catch (dbErr) {
    return next(dbErr);
  }

  logger.info({ message: 'KYC document submitted — awaiting admin review', userId, documentType });

  return res.json({
    success: true,
    verification: {
      documentType,
      status:    'PENDING',
      kycStatus: 'PENDING',
      message:   'Document submitted successfully. Your KYC is under review and will be processed within 24 hours.',
    },
  });
});

// ── GET /status ───────────────────────────────────────────────────────────────

router.get('/status', async (req, res, next) => {
  let user;
  try {
    const { rows } = await pool.query(
      'SELECT kyc_status, kyc_level FROM users WHERE id = $1',
      [req.user.id]
    );
    user = rows[0];
  } catch (dbErr) {
    return next(dbErr);
  }

  if (!user) return res.status(404).json({ success: false, error: 'User not found.' });

  const limits = limitsForLevel(user.kyc_level);

  return res.json({
    success: true,
    kyc: {
      status:             user.kyc_status,
      level:              user.kyc_level,
      dailyDebitLimit:    limits.dailyDebit,
      monthlyDebitLimit:  limits.monthlyDebit,
      levelDescription: {
        0: 'Unverified — wallet funded only (no debits)',
        1: 'BVN verified — NGN 50,000/day',
        2: 'NIN verified — NGN 200,000/day',
        3: 'Full KYC — NGN 1,000,000/day',
      }[user.kyc_level] || 'Unknown',
    },
  });
});

// ── GET /documents ────────────────────────────────────────────────────────────

router.get('/documents', async (req, res, next) => {
  let docs;
  try {
    const { rows } = await pool.query(
      `SELECT document_type, verification_status, verified_at, rejection_reason, created_at
       FROM kyc_documents
       WHERE user_id = $1
       ORDER BY created_at DESC`,
      [req.user.id]
    );
    docs = rows;
  } catch (dbErr) {
    return next(dbErr);
  }

  return res.json({
    success: true,
    documents: docs.map(d => ({
      documentType:       d.document_type,
      verificationStatus: d.verification_status,
      verifiedAt:         d.verified_at,
      rejectionReason:    d.rejection_reason,
      submittedAt:        d.created_at,
    })),
  });
});

module.exports = router;
