'use strict';

/**
 * Wallet Routes
 *
 * GET  /api/v1/wallet                        — wallet details and balance
 * POST /api/v1/wallet/fund                   — initialize Paystack payment (returns checkout URL)
 * GET  /api/v1/wallet/fund/callback          — Paystack redirect after payment
 * GET  /api/v1/wallet/banks                  — list supported banks (Paystack)
 * POST /api/v1/wallet/resolve-account        — resolve account name (Paystack)
 * POST /api/v1/wallet/transfer               — transfer to another wallet by wallet number
 * POST /api/v1/wallet/withdraw               — external bank withdrawal via Paystack
 * GET  /api/v1/wallet/transactions           — paginated transaction history
 * GET  /api/v1/wallet/transactions/:reference — single transaction lookup
 *
 * Funding flow (Paystack):
 *   1. POST /fund         → initialize Paystack → return { checkoutUrl, reference }
 *   2. Customer pays on Paystack checkout page
 *   3. Paystack POSTs to /webhooks/paystack (charge.success)
 *   4. Webhook credits internal RECEIVABLE account then credits customer wallet
 *
 * Withdrawal flow (Paystack):
 *   1. POST /resolve-account  → verify account name via Paystack
 *   2. POST /withdraw         → create recipient → debit customer → credit PAYABLE → initiate transfer
 *   3. Paystack POSTs to /webhooks/paystack (transfer.success / transfer.failed)
 *   4. On failure: webhook reverses customer debit
 */

const express        = require('express');
const { v4: uuidv4 } = require('uuid');
const Joi            = require('joi');

const { pool }                                       = require('../config/database');
const { decrypt }                                    = require('../services/encryption');
const { transfer }                                   = require('../services/walletService');
const {
  initializeTransaction,
  getBanks,
  resolveAccount,
  createTransferRecipient,
  initiateTransfer,
}                                                    = require('../services/paystackService');
const { jwtAuth }                                    = require('../middleware/jwtAuth');
const { walletLimiter }                              = require('../middleware/rateLimiter');
const { logger }                                     = require('../utils/logger');

const router = express.Router();

// ── Public routes (no JWT required) ──────────────────────────────────────────
// Must be registered BEFORE router.use(jwtAuth)

router.get('/fund/callback', async (req, res) => {
  const { reference, trxref } = req.query;
  const ref = reference || trxref;

  const html = (icon, title, body, color) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>${title}</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
         display:flex;flex-direction:column;align-items:center;justify-content:center;
         min-height:100vh;background:#f9fafb;padding:24px;text-align:center}
    .card{background:#fff;border-radius:20px;padding:40px 28px;max-width:360px;
          box-shadow:0 4px 24px rgba(0,0,0,.08)}
    .icon{font-size:52px;margin-bottom:16px}
    h1{font-size:22px;font-weight:700;color:#111827;margin-bottom:10px}
    p{font-size:14px;color:#6b7280;line-height:1.6}
    .badge{display:inline-block;margin-top:16px;padding:6px 14px;border-radius:99px;
           font-size:12px;font-weight:600;background:${color}22;color:${color}}
  </style>
</head>
<body>
  <div class="card">
    <div class="icon">${icon}</div>
    <h1>${title}</h1>
    <p>${body}</p>
    ${ref ? `<div class="badge">Ref: ${ref}</div>` : ''}
    <p style="margin-top:20px;font-size:13px;color:#9ca3af">You can close this window and return to the app.</p>
  </div>
</body>
</html>`;

  if (!ref) {
    return res.status(400).send(html('⚠️', 'Missing Reference', 'No payment reference was provided.', '#d97706'));
  }

  const { rows } = await pool.query(
    `SELECT status FROM provider_transactions WHERE provider_reference = $1`,
    [ref]
  );

  const pt = rows[0];
  if (!pt) {
    return res.status(404).send(html('🔍', 'Not Found', 'This payment reference does not exist.', '#dc2626'));
  }

  if (pt.status === 'SUCCESS') {
    return res.send(html('✅', 'Payment Successful!', 'Your wallet has been funded. The balance will reflect in your app.', '#059669'));
  }

  return res.send(html('⏳', 'Payment Processing', 'Your payment is being processed by Paystack. Your wallet will be funded automatically once confirmed.', '#7c3aed'));
});

router.use(jwtAuth);

// ── Validation schemas ────────────────────────────────────────────────────────

const amountSchema = Joi.number().positive().precision(2).max(10_000_000).required().messages({
  'number.positive': 'Amount must be a positive number.',
  'number.max':      'Amount cannot exceed NGN 10,000,000 per transaction.',
});

const fundSchema = Joi.object({
  amount:    amountSchema,
  narration: Joi.string().trim().max(255).default('Wallet funding'),
});

const resolveAccountSchema = Joi.object({
  accountNumber: Joi.string().trim().pattern(/^\d{10}$/).required().messages({
    'string.pattern.base': 'accountNumber must be exactly 10 digits.',
  }),
  bankCode: Joi.string().trim().pattern(/^\d{3}$/).required().messages({
    'string.pattern.base': 'bankCode must be exactly 3 digits.',
  }),
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

// ── Helpers ───────────────────────────────────────────────────────────────────

async function getUserWallet(userId) {
  const { rows } = await pool.query(
    `SELECT w.*, u.encrypted_email, u.kyc_level
     FROM wallets w
     JOIN users u ON u.id = w.user_id
     WHERE w.user_id = $1`,
    [userId]
  );
  if (!rows[0]) throw Object.assign(new Error('Wallet not found.'), { status: 404 });
  return rows[0];
}

// ── GET / — wallet details ────────────────────────────────────────────────────

router.get('/', async (req, res, next) => {
  try {
    const wallet = await getUserWallet(req.user.id);

    return res.json({
      success: true,
      wallet: {
        id:               wallet.id,
        walletNumber:     wallet.wallet_number,
        balance:          parseFloat(wallet.balance),
        currency:         wallet.currency,
        status:           wallet.status,
        kycLevel:         wallet.kyc_level,
        limits: {
          dailyDebit:       parseFloat(wallet.daily_debit_limit),
          dailyDebitUsed:   parseFloat(wallet.daily_debit_used),
          dailyCredit:      parseFloat(wallet.daily_credit_limit),
          dailyCreditUsed:  parseFloat(wallet.daily_credit_used),
          monthlyDebit:     parseFloat(wallet.monthly_debit_limit),
          monthlyDebitUsed: parseFloat(wallet.monthly_debit_used),
        },
        createdAt: wallet.created_at,
      },
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── POST /fund — initialize Paystack payment ──────────────────────────────────

router.post('/fund', walletLimiter, async (req, res, next) => {
  const { error, value } = fundSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  try {
    const wallet    = await getUserWallet(req.user.id);
    const email     = decrypt(wallet.encrypted_email);
    const reference = `FUND-${uuidv4().replace(/-/g, '').slice(0, 16).toUpperCase()}`;

    // Record provider transaction before calling Paystack
    await pool.query(
      `INSERT INTO provider_transactions
         (id, type, user_id, wallet_id, amount, provider_reference, status, metadata)
       VALUES ($1, 'FUNDING', $2, $3, $4, $5, 'PENDING', $6)`,
      [
        uuidv4(), req.user.id, wallet.id, value.amount, reference,
        JSON.stringify({ narration: value.narration }),
      ]
    );

    // Initialize Paystack transaction
    const paystack = await initializeTransaction({
      email,
      amount:      value.amount,
      reference,
      callbackUrl: process.env.PAYSTACK_CALLBACK_URL,
      metadata:    { userId: req.user.id, walletId: wallet.id, narration: value.narration },
    });

    logger.info({ message: 'Paystack funding initialized', userId: req.user.id, reference, amount: value.amount });

    return res.json({
      success:     true,
      message:     'Redirect the user to the checkout URL to complete payment.',
      checkoutUrl: paystack.authorization_url,
      reference,
      amount:      value.amount,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── GET /banks — list supported banks ────────────────────────────────────────

router.get('/banks', async (_req, res, next) => {
  try {
    const banks = await getBanks();
    return res.json({ success: true, banks });
  } catch (err) {
    return next(err);
  }
});

// ── POST /resolve-account — verify account name ───────────────────────────────

router.post('/resolve-account', async (req, res, next) => {
  const { error, value } = resolveAccountSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  try {
    const account = await resolveAccount(value.accountNumber, value.bankCode);
    return res.json({
      success:       true,
      accountNumber: account.account_number,
      accountName:   account.account_name,
    });
  } catch (err) {
    // Paystack returns 422 for unresolvable accounts
    if (err.response?.status === 422 || err.response?.status === 404) {
      return res.status(422).json({ success: false, error: 'Could not resolve account. Check the account number and bank code.' });
    }
    return next(err);
  }
});

// ── POST /transfer — intra-wallet transfer ────────────────────────────────────

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
    const wallet = await getUserWallet(req.user.id);

    const { rows: destRows } = await pool.query(
      'SELECT id, user_id FROM wallets WHERE wallet_number = $1',
      [value.destinationWalletNumber]
    );
    if (!destRows[0]) {
      return res.status(404).json({ success: false, error: 'Destination wallet not found.' });
    }
    if (wallet.id === destRows[0].id) {
      return res.status(400).json({ success: false, error: 'Cannot transfer to your own wallet.' });
    }

    const result = await transfer(
      pool, wallet.id, destRows[0].id, value.amount, value.narration, req.user.kycLevel
    );

    return res.status(201).json({
      success:          true,
      message:          `NGN ${value.amount.toLocaleString()} transferred to wallet ${value.destinationWalletNumber}.`,
      transferRef:      result.transferRef,
      debitTransaction: result.debit,
      senderNewBalance: result.senderNewBalance,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  }
});

// ── POST /withdraw — external withdrawal via Paystack ────────────────────────

router.post('/withdraw', walletLimiter, async (req, res, next) => {
  const { error, value } = withdrawSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   'Validation failed.',
      details: error.details.map(d => d.message),
    });
  }

  if (req.user.kycLevel < 2) {
    return res.status(403).json({
      success: false,
      error:   'External withdrawals require KYC level 2 (NIN verified). Please complete your KYC.',
    });
  }

  const client = await pool.connect();
  try {
    // 1. Resolve & validate account via Paystack
    let resolved;
    try {
      resolved = await resolveAccount(value.accountNumber, value.bankCode);
    } catch (resolveErr) {
      logger.error({ message: 'Account resolution failed', error: resolveErr.response?.data || resolveErr.message });
      return res.status(422).json({
        success: false,
        error: 'Could not verify bank account. Check account number and bank code.',
        detail: resolveErr.response?.data?.message || resolveErr.message,
      });
    }

    // 2. Register transfer recipient with Paystack
    let recipient;
    try {
      recipient = await createTransferRecipient({
        name:          resolved.account_name,
        accountNumber: value.accountNumber,
        bankCode:      value.bankCode,
      });
    } catch (recipientErr) {
      logger.error({ message: 'Create transfer recipient failed', error: recipientErr.response?.data || recipientErr.message });
      return res.status(422).json({
        success: false,
        error:  'Could not register transfer recipient.',
        detail: recipientErr.response?.data?.message || recipientErr.message,
      });
    }

    await client.query('BEGIN');

    const wallet  = await getUserWallet(req.user.id);
    const balance = parseFloat(wallet.balance);

    if (balance < value.amount) {
      await client.query('ROLLBACK');
      return res.status(422).json({
        success: false,
        error:   `Insufficient balance. Available: NGN ${balance.toLocaleString()}.`,
      });
    }

    const reference = `WDR-${uuidv4().replace(/-/g, '').slice(0, 16).toUpperCase()}`;

    // 3. Debit customer wallet
    const balanceBefore = balance;
    const balanceAfter  = +(balance - value.amount).toFixed(2);
    const txId          = uuidv4();
    const txRef         = `DR-${Date.now().toString(36).toUpperCase()}-${uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase()}`;

    await client.query(
      `UPDATE wallets SET balance = $1, daily_debit_used = daily_debit_used + $2,
       monthly_debit_used = monthly_debit_used + $2, updated_at = NOW() WHERE id = $3`,
      [balanceAfter, value.amount, wallet.id]
    );

    await client.query(
      `INSERT INTO wallet_transactions
         (id, reference, wallet_id, type, category, amount,
          balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
       VALUES ($1,$2,$3,'DEBIT','WITHDRAWAL',$4,$5,$6,$7,'PENDING',$8,NOW())`,
      [
        txId, txRef, wallet.id, value.amount, balanceBefore, balanceAfter,
        null,
        JSON.stringify({ bankCode: value.bankCode, accountNumber: value.accountNumber, accountName: resolved.account_name }),
      ]
    );

    // 4. Credit internal PAYABLE account
    await client.query(
      `UPDATE internal_accounts SET balance = balance + $1, updated_at = NOW() WHERE type = 'PAYABLE'`,
      [value.amount]
    );

    // 5. Create provider transaction record
    const providerTxId = uuidv4();
    await client.query(
      `INSERT INTO provider_transactions
         (id, type, user_id, wallet_id, amount, provider_reference,
          recipient_code, bank_code, account_number, account_name, status, wallet_tx_id, metadata)
       VALUES ($1,'WITHDRAWAL',$2,$3,$4,$5,$6,$7,$8,$9,'PENDING',$10,$11)`,
      [
        providerTxId, req.user.id, wallet.id, value.amount, reference,
        recipient.recipient_code, value.bankCode, value.accountNumber, resolved.account_name,
        txId,
        JSON.stringify({ narration: value.narration, recipientCode: recipient.recipient_code }),
      ]
    );

    await client.query('COMMIT');

    // 6. Initiate Paystack transfer (outside DB transaction — network call)
    let transfer;
    try {
      transfer = await initiateTransfer({
        amount:    value.amount,
        recipient: recipient.recipient_code,
        reason:    value.narration,
        reference,
      });
    } catch (paystackErr) {
      // Transfer initiation failed — reverse the debit
      await pool.query(`
        UPDATE wallets SET balance = $1, daily_debit_used = daily_debit_used - $2,
        monthly_debit_used = monthly_debit_used - $2, updated_at = NOW() WHERE id = $3`,
        [balanceBefore, value.amount, wallet.id]
      );
      await pool.query(
        `UPDATE wallet_transactions SET status = 'FAILED' WHERE id = $1`, [txId]
      );
      await pool.query(
        `UPDATE internal_accounts SET balance = balance - $1, updated_at = NOW() WHERE type = 'PAYABLE'`,
        [value.amount]
      );
      await pool.query(
        `UPDATE provider_transactions SET status = 'FAILED', updated_at = NOW(), completed_at = NOW() WHERE id = $1`,
        [providerTxId]
      );
      logger.error({ message: 'Paystack transfer initiation failed', error: paystackErr.message, reference });
      return res.status(502).json({ success: false, error: 'Could not initiate bank transfer. Funds have not been deducted.' });
    }

    // Update provider_transaction with Paystack transfer_code
    await pool.query(
      `UPDATE provider_transactions SET metadata = metadata || $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify({ transferCode: transfer.transfer_code }), providerTxId]
    );

    logger.info({ message: 'Withdrawal initiated', userId: req.user.id, reference, amount: value.amount });

    return res.status(201).json({
      success:       true,
      message:       `NGN ${value.amount.toLocaleString()} withdrawal initiated to ${resolved.account_name} (${value.accountNumber}).`,
      reference,
      transferCode:  transfer.transfer_code,
      accountName:   resolved.account_name,
      accountNumber: value.accountNumber,
      newBalance:    balanceAfter,
    });
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    if (err.status) return res.status(err.status).json({ success: false, error: err.message });
    return next(err);
  } finally {
    client.release();
  }
});

// ── GET /transactions ─────────────────────────────────────────────────────────

router.get('/transactions', async (req, res, next) => {
  const page     = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit    = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset   = (page - 1) * limit;
  const category = req.query.category;
  const type     = req.query.type;

  try {
    const wallet = await getUserWallet(req.user.id);

    const conditions = ['wallet_id = $1'];
    const params     = [wallet.id];
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

    const total        = parseInt(countRow.rows[0].total, 10);
    const transactions = txRows.rows.map(tx => ({
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
    const wallet = await getUserWallet(req.user.id);

    const { rows } = await pool.query(
      `SELECT * FROM wallet_transactions WHERE reference = $1 AND wallet_id = $2`,
      [req.params.reference, wallet.id]
    );

    const tx = rows[0];
    if (!tx) return res.status(404).json({ success: false, error: 'Transaction not found.' });

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
