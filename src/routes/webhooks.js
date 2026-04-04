'use strict';

/**
 * Paystack Webhook Handler
 *
 * POST /api/v1/webhooks/paystack
 *
 * This route MUST be registered before express.json() in app.js so that
 * express.raw() can capture the raw body for HMAC signature verification.
 *
 * Events handled:
 *   charge.success      — customer payment confirmed → credit RECEIVABLE + credit customer wallet
 *   transfer.success    — bank transfer confirmed    → mark provider_transaction SUCCESS
 *   transfer.failed     — bank transfer failed       → reverse customer debit, debit PAYABLE
 *   transfer.reversed   — bank transfer reversed     → reverse customer debit, debit PAYABLE
 */

const express = require('express');
const crypto  = require('crypto');

const { pool }    = require('../config/database');
const { encrypt } = require('../services/encryption');
const { v4: uuidv4 } = require('uuid');
const { logger }  = require('../utils/logger');

const router = express.Router();

// ── Signature verification middleware ─────────────────────────────────────────

function verifyPaystackSignature(req, res, next) {
  const secret    = process.env.PAYSTACK_SECRET_KEY;
  const signature = req.headers['x-paystack-signature'];

  if (!signature) {
    logger.warn({ message: 'Webhook received without signature' });
    return res.status(401).json({ error: 'Missing signature.' });
  }

  const hash = crypto
    .createHmac('sha512', secret)
    .update(req.body)   // req.body is a Buffer from express.raw()
    .digest('hex');

  if (hash !== signature) {
    logger.warn({ message: 'Webhook signature mismatch' });
    return res.status(401).json({ error: 'Invalid signature.' });
  }

  // Parse body now that signature is verified
  req.webhookPayload = JSON.parse(req.body.toString());
  next();
}

// ── POST /paystack ─────────────────────────────────────────────────────────────

router.post(
  '/paystack',
  express.raw({ type: 'application/json' }),
  verifyPaystackSignature,
  async (req, res) => {
    // Acknowledge immediately — Paystack retries if it doesn't get 200 quickly
    res.sendStatus(200);

    const { event, data } = req.webhookPayload;
    logger.debug({ message: 'Paystack webhook received', event, reference: data?.reference });

    try {
      if (event === 'charge.success') {
        await handleChargeSuccess(data);
      } else if (event === 'transfer.success') {
        await handleTransferSuccess(data);
      } else if (event === 'transfer.failed' || event === 'transfer.reversed') {
        await handleTransferFailure(data, event);
      }
    } catch (err) {
      logger.error({ message: 'Webhook handler error', event, error: err.message });
    }
  }
);

// ── charge.success — fund customer wallet ─────────────────────────────────────

async function handleChargeSuccess(data) {
  const reference = data.reference;
  const amountNgn = data.amount / 100;   // Paystack sends kobo

  // Find provider transaction
  const { rows: ptRows } = await pool.query(
    `SELECT * FROM provider_transactions WHERE provider_reference = $1 AND type = 'FUNDING'`,
    [reference]
  );
  const pt = ptRows[0];
  if (!pt) {
    logger.warn({ message: 'charge.success: provider_transaction not found', reference });
    return;
  }

  // Idempotency guard
  if (pt.status !== 'PENDING') {
    logger.info({ message: 'charge.success: already processed', reference, status: pt.status });
    return;
  }

  const metadata = pt.metadata || {};
  const narration = metadata.narration || 'Wallet funding';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Credit internal RECEIVABLE account
    await client.query(
      `UPDATE internal_accounts SET balance = balance + $1, updated_at = NOW() WHERE type = 'RECEIVABLE'`,
      [amountNgn]
    );

    // Credit customer wallet
    const { rows: walletRows } = await client.query(
      'SELECT * FROM wallets WHERE id = $1 FOR UPDATE',
      [pt.wallet_id]
    );
    const wallet = walletRows[0];
    if (!wallet || wallet.status !== 'ACTIVE') {
      throw new Error(`Wallet ${pt.wallet_id} not active.`);
    }

    const balanceBefore = parseFloat(wallet.balance);
    const balanceAfter  = +(balanceBefore + amountNgn).toFixed(2);

    await client.query(
      `UPDATE wallets SET balance = $1, daily_credit_used = daily_credit_used + $2, updated_at = NOW() WHERE id = $3`,
      [balanceAfter, amountNgn, wallet.id]
    );

    // Record wallet transaction
    const txId  = uuidv4();
    const txRef = `CR-${Date.now().toString(36).toUpperCase()}-${uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase()}`;

    await client.query(
      `INSERT INTO wallet_transactions
         (id, reference, wallet_id, type, category, amount,
          balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
       VALUES ($1,$2,$3,'CREDIT','FUNDING',$4,$5,$6,$7,'SUCCESS',$8,NOW())`,
      [
        txId, txRef, wallet.id, amountNgn, balanceBefore, balanceAfter,
        encrypt(narration),
        JSON.stringify({ paystackReference: reference, channel: data.channel }),
      ]
    );

    // Mark provider transaction SUCCESS
    await client.query(
      `UPDATE provider_transactions
       SET status = 'SUCCESS', wallet_tx_id = $1, updated_at = NOW(), completed_at = NOW()
       WHERE id = $2`,
      [txId, pt.id]
    );

    await client.query('COMMIT');

    logger.info({
      message:   'Wallet funded via Paystack',
      userId:    pt.user_id,
      walletId:  wallet.id,
      amount:    amountNgn,
      reference,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── transfer.success — confirm withdrawal ─────────────────────────────────────

async function handleTransferSuccess(data) {
  const reference = data.reference;

  const { rows: ptRows } = await pool.query(
    `SELECT * FROM provider_transactions WHERE provider_reference = $1 AND type = 'WITHDRAWAL'`,
    [reference]
  );
  const pt = ptRows[0];
  if (!pt) {
    logger.warn({ message: 'transfer.success: provider_transaction not found', reference });
    return;
  }

  if (pt.status !== 'PENDING') {
    logger.info({ message: 'transfer.success: already processed', reference, status: pt.status });
    return;
  }

  // Debit PAYABLE (funds have left our Paystack balance)
  await pool.query(
    `UPDATE internal_accounts SET balance = balance - $1, updated_at = NOW() WHERE type = 'PAYABLE'`,
    [parseFloat(pt.amount)]
  );

  // Mark wallet transaction SUCCESS
  await pool.query(
    `UPDATE wallet_transactions SET status = 'SUCCESS' WHERE id = $1`,
    [pt.wallet_tx_id]
  );

  // Mark provider transaction SUCCESS
  await pool.query(
    `UPDATE provider_transactions SET status = 'SUCCESS', updated_at = NOW(), completed_at = NOW() WHERE id = $1`,
    [pt.id]
  );

  logger.info({ message: 'Withdrawal confirmed', userId: pt.user_id, amount: pt.amount, reference });
}

// ── transfer.failed / transfer.reversed — reverse customer debit ──────────────

async function handleTransferFailure(data, event) {
  const reference = data.reference;
  const amount    = parseFloat(data.amount) / 100;

  const { rows: ptRows } = await pool.query(
    `SELECT * FROM provider_transactions WHERE provider_reference = $1 AND type = 'WITHDRAWAL'`,
    [reference]
  );
  const pt = ptRows[0];
  if (!pt) {
    logger.warn({ message: `${event}: provider_transaction not found`, reference });
    return;
  }

  if (pt.status !== 'PENDING') {
    logger.info({ message: `${event}: already processed`, reference, status: pt.status });
    return;
  }

  const newStatus = event === 'transfer.reversed' ? 'REVERSED' : 'FAILED';

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Reverse customer debit — credit back to wallet
    const { rows: walletRows } = await client.query(
      'SELECT * FROM wallets WHERE id = $1 FOR UPDATE', [pt.wallet_id]
    );
    const wallet        = walletRows[0];
    const balanceBefore = parseFloat(wallet.balance);
    const balanceAfter  = +(balanceBefore + amount).toFixed(2);

    await client.query(
      `UPDATE wallets
       SET balance = $1, daily_debit_used = GREATEST(0, daily_debit_used - $2),
           monthly_debit_used = GREATEST(0, monthly_debit_used - $2), updated_at = NOW()
       WHERE id = $3`,
      [balanceAfter, amount, wallet.id]
    );

    // Debit PAYABLE (funds did not leave — remove the earmark)
    await client.query(
      `UPDATE internal_accounts SET balance = GREATEST(0, balance - $1), updated_at = NOW() WHERE type = 'PAYABLE'`,
      [amount]
    );

    // Record reversal credit transaction
    const reversalTxId  = uuidv4();
    const reversalTxRef = `REV-${Date.now().toString(36).toUpperCase()}-${uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase()}`;

    await client.query(
      `INSERT INTO wallet_transactions
         (id, reference, wallet_id, type, category, amount,
          balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
       VALUES ($1,$2,$3,'CREDIT','WITHDRAWAL',$4,$5,$6,$7,'SUCCESS',$8,NOW())`,
      [
        reversalTxId, reversalTxRef, wallet.id, amount, balanceBefore, balanceAfter,
        encrypt('Withdrawal reversal'),
        JSON.stringify({ originalReference: reference, reason: data.reason || event }),
      ]
    );

    // Mark original debit transaction as FAILED/REVERSED
    await client.query(
      `UPDATE wallet_transactions SET status = $1 WHERE id = $2`,
      [newStatus, pt.wallet_tx_id]
    );

    // Mark provider transaction FAILED/REVERSED
    await client.query(
      `UPDATE provider_transactions SET status = $1, updated_at = NOW(), completed_at = NOW() WHERE id = $2`,
      [newStatus, pt.id]
    );

    await client.query('COMMIT');

    logger.warn({
      message:   'Withdrawal reversed — funds returned to wallet',
      event,
      userId:    pt.user_id,
      amount,
      reference,
    });
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = router;
