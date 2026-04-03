'use strict';

/**
 * Wallet Routes
 *
 * GET  /api/v1/wallet               — wallet details and balance
 * POST /api/v1/wallet/fund          — credit the authenticated user's wallet
 * POST /api/v1/wallet/debit         — debit the authenticated user's wallet
 * POST /api/v1/wallet/transfer      — transfer to another wallet by wallet number
 * POST /api/v1/wallet/withdraw      — external bank withdrawal
 * GET  /api/v1/wallet/transactions  — paginated transaction history
 * GET  /api/v1/wallet/transactions/:reference — single transaction lookup
 *
 * All routes require a valid JWT (jwtAuth middleware).
 * Mutating routes additionally enforce KYC level checks inside walletService.
 */

const express        = require('express');
const Joi            = require('joi');

const { pool }                                         = require('../config/database');
const { decrypt }                                      = require('../services/encryption');
const { fundWallet, debitFromWallet,
        transfer, withdraw }                           = require('../services/walletService');
const { jwtAuth }                                      = require('../middleware/jwtAuth');
const { walletLimiter }                                = require('../middleware/rateLimiter');
const { logger }                                       = require('../utils/logger');

const router = express.Router();

router.use(jwtAuth);

// ── Validation schemas ────────────────────────────────────────────────────────

const amountSchema = Joi.number().positive().precision(2).max(10_000_000).required().messages({
  'number.positive':  'Amount must be a positive number.',
  'number.max':       'Amount cannot exceed NGN 10,000,000 per transaction.',
});

const fundSchema = Joi.object({
  amount:    amountSchema,
  narration: Joi.string().trim().max(255).default('Wallet funding'),
});

const debitSchema = Joi.object({
  amount:    amountSchema,
  narration: Joi.string().trim().max(255).default('Wallet debit'),
});

const transferSchema = Joi.object({
  destinationWalletNumber: Joi.string().pattern(/^\d{10}$/).required().messages({
    'string.pattern.base': 'destinationWalletNumber must be a 10-digit wallet number.',
  }),
  amount:    amountSchema,
  narration: Joi.string().trim().max(255).default('Wallet transfer'),
});

const withdrawSchema = Joi.object({
  amount:        amountSchema,
  bankCode:      Joi.string().trim().pattern(/^\d{3}$/).required().messages({
    'string.pattern.base': 'bankCode must be exactly 3 digits.',
  }),
  accountNumber: Joi.string().trim().pattern(/^\d{10}$/).required().messages({
    'string.pattern.base': 'accountNumber must be exactly 10 digits.',
  }),
  accountName:   Joi.string().trim().min(2).max(100).required(),
  narration:     Joi.string().trim().max(255).default('Wallet withdrawal'),
});

// ── GET / — wallet details ────────────────────────────────────────────────────

router.get('/', async (req, res, next) => {
  let wallet;
  try {
    const { rows } = await pool.query(
      `SELECT w.*, u.kyc_level
       FROM wallets w
       JOIN users u ON u.id = w.user_id
       WHERE w.user_id = $1`,
      [req.user.id]
    );
    wallet = rows[0];
  } catch (dbErr) {
    return next(dbErr);
  }

  if (!wallet) {
    return res.status(404).json({ success: false, error: 'Wallet not found.' });
  }

  return res.json({
    success: true,
    wallet: {
      id:                  wallet.id,
      walletNumber:        wallet.wallet_number,
      balance:             parseFloat(wallet.balance),
      currency:            wallet.currency,
      status:              wallet.status,
      kycLevel:            wallet.kyc_level,
      limits: {
        dailyDebit:        parseFloat(wallet.daily_debit_limit),
        dailyDebitUsed:    parseFloat(wallet.daily_debit_used),
        dailyCredit:       parseFloat(wallet.daily_credit_limit),
        dailyCreditUsed:   parseFloat(wallet.daily_credit_used),
        monthlyDebit:      parseFloat(wallet.monthly_debit_limit),
        monthlyDebitUsed:  parseFloat(wallet.monthly_debit_used),
      },
      createdAt: wallet.created_at,
    },
  });
});

// ── GET helper: resolve walletId from userId ──────────────────────────────────

async function getUserWalletId(userId) {
  const { rows } = await pool.query(
    'SELECT id FROM wallets WHERE user_id = $1',
    [userId]
  );
  if (!rows[0]) throw Object.assign(new Error('Wallet not found.'), { status: 404 });
  return rows[0].id;
}

// ── POST /fund ────────────────────────────────────────────────────────────────

router.post('/fund', walletLimiter, async (req, res, next) => {
  const { error, value } = fundSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  let walletId;
  try {
    walletId = await getUserWalletId(req.user.id);
    const result = await fundWallet(pool, walletId, value.amount, value.narration);

    return res.status(201).json({
      success: true,
      message: `Wallet funded with NGN ${value.amount.toLocaleString()}.`,
      transaction: result.transaction,
      newBalance:  result.newBalance,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── POST /debit ───────────────────────────────────────────────────────────────

router.post('/debit', walletLimiter, async (req, res, next) => {
  const { error, value } = debitSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  try {
    const walletId = await getUserWalletId(req.user.id);
    const result   = await debitFromWallet(
      pool, walletId, value.amount, value.narration, {}, req.user.kycLevel
    );

    return res.status(201).json({
      success: true,
      message: `NGN ${value.amount.toLocaleString()} debited from wallet.`,
      transaction: result.transaction,
      newBalance:  result.newBalance,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── POST /transfer ────────────────────────────────────────────────────────────

router.post('/transfer', walletLimiter, async (req, res, next) => {
  const { error, value } = transferSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  try {
    // Resolve sender wallet
    const fromWalletId = await getUserWalletId(req.user.id);

    // Resolve destination wallet
    const { rows: destRows } = await pool.query(
      'SELECT id, user_id FROM wallets WHERE wallet_number = $1',
      [value.destinationWalletNumber]
    );
    if (!destRows[0]) {
      return res.status(404).json({ success: false, error: 'Destination wallet not found.' });
    }

    const toWalletId = destRows[0].id;

    if (fromWalletId === toWalletId) {
      return res.status(400).json({ success: false, error: 'Cannot transfer to your own wallet.' });
    }

    const result = await transfer(
      pool, fromWalletId, toWalletId, value.amount, value.narration, req.user.kycLevel
    );

    return res.status(201).json({
      success: true,
      message: `NGN ${value.amount.toLocaleString()} transferred to wallet ${value.destinationWalletNumber}.`,
      transferRef:     result.transferRef,
      debitTransaction:  result.debit,
      senderNewBalance:  result.senderNewBalance,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── POST /withdraw ────────────────────────────────────────────────────────────

router.post('/withdraw', walletLimiter, async (req, res, next) => {
  const { error, value } = withdrawSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  // Only KYC level 2+ can do external withdrawals
  if (req.user.kycLevel < 2) {
    return res.status(403).json({
      success: false,
      error:   'External withdrawals require KYC level 2 (NIN verified). Please complete your KYC.',
    });
  }

  try {
    const walletId = await getUserWalletId(req.user.id);
    const result   = await withdraw(
      pool, walletId, value.amount,
      value.bankCode, value.accountNumber, value.accountName,
      value.narration, req.user.kycLevel
    );

    return res.status(201).json({
      success: true,
      message: `NGN ${value.amount.toLocaleString()} withdrawal initiated to ${value.accountNumber} (${value.bankCode}).`,
      transaction: result.transaction,
      newBalance:  result.newBalance,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── GET /transactions ─────────────────────────────────────────────────────────

router.get('/transactions', async (req, res, next) => {
  const page     = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit    = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset   = (page - 1) * limit;
  const category = req.query.category;   // optional filter
  const type     = req.query.type;       // CREDIT | DEBIT

  try {
    const walletId = await getUserWalletId(req.user.id);

    const conditions = ['wallet_id = $1'];
    const params     = [walletId];
    let   pIdx       = 2;

    if (category) { conditions.push(`category = $${pIdx++}`); params.push(category.toUpperCase()); }
    if (type)     { conditions.push(`type = $${pIdx++}`);     params.push(type.toUpperCase()); }

    const where = conditions.join(' AND ');

    const [txRows, countRow] = await Promise.all([
      pool.query(
        `SELECT id, reference, type, category, amount, balance_before, balance_after,
                encrypted_narration, status, metadata, created_at, processed_at
         FROM wallet_transactions
         WHERE ${where}
         ORDER BY created_at DESC
         LIMIT $${pIdx} OFFSET $${pIdx + 1}`,
        [...params, limit, offset]
      ),
      pool.query(`SELECT COUNT(*) AS total FROM wallet_transactions WHERE ${where}`, params),
    ]);

    const total = parseInt(countRow.rows[0].total, 10);

    const transactions = txRows.rows.map(tx => ({
      id:           tx.id,
      reference:    tx.reference,
      type:         tx.type,
      category:     tx.category,
      amount:       parseFloat(tx.amount),
      balanceBefore: parseFloat(tx.balance_before),
      balanceAfter:  parseFloat(tx.balance_after),
      narration:    tx.encrypted_narration ? decrypt(tx.encrypted_narration) : null,
      status:       tx.status,
      metadata:     tx.metadata,
      createdAt:    tx.created_at,
      processedAt:  tx.processed_at,
    }));

    return res.json({
      success: true,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      transactions,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── GET /transactions/:reference ──────────────────────────────────────────────

router.get('/transactions/:reference', async (req, res, next) => {
  try {
    const walletId = await getUserWalletId(req.user.id);

    const { rows } = await pool.query(
      `SELECT * FROM wallet_transactions
       WHERE reference = $1 AND wallet_id = $2`,
      [req.params.reference, walletId]
    );

    const tx = rows[0];
    if (!tx) {
      return res.status(404).json({ success: false, error: 'Transaction not found.' });
    }

    return res.json({
      success: true,
      transaction: {
        id:            tx.id,
        reference:     tx.reference,
        type:          tx.type,
        category:      tx.category,
        amount:        parseFloat(tx.amount),
        balanceBefore: parseFloat(tx.balance_before),
        balanceAfter:  parseFloat(tx.balance_after),
        narration:     tx.encrypted_narration ? decrypt(tx.encrypted_narration) : null,
        status:        tx.status,
        metadata:      tx.metadata,
        createdAt:     tx.created_at,
        processedAt:   tx.processed_at,
      },
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

module.exports = router;
