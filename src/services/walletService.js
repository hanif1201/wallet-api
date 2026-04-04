'use strict';

/**
 * Wallet Service — core financial operations
 *
 * All mutating operations (credit, debit, transfer, withdraw) run inside
 * an explicit PostgreSQL transaction with SELECT … FOR UPDATE on the wallet
 * row to prevent race conditions under concurrent requests.
 *
 * Limit management:
 *   Daily and monthly "used" counters are reset lazily when a wallet is
 *   touched and the calendar day or month has rolled over.  No background
 *   jobs are required.
 *
 * Operations:
 *   creditWallet(client, walletId, amount, category, narration, meta)
 *   debitWallet(client, walletId, amount, category, narration, meta)
 *   transfer(pool, fromWalletId, toWalletId, amount, narration)
 *   withdraw(pool, walletId, amount, bankCode, accountNumber, narration)
 */

const { v4: uuidv4 } = require('uuid');
const { encrypt }    = require('./encryption');
const { logger }     = require('../utils/logger');

// ── Reference generator ───────────────────────────────────────────────────────

function generateReference(prefix = 'TXN') {
  const ts  = Date.now().toString(36).toUpperCase();
  const rnd = uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase();
  return `${prefix}-${ts}-${rnd}`;
}

// ── Lazy limit reset ──────────────────────────────────────────────────────────

/**
 * Resets daily and/or monthly usage counters if the wallet's reset timestamps
 * are in a previous day/month.  Must be called while the wallet row is locked
 * with FOR UPDATE.
 *
 * @param {pg.PoolClient} client
 * @param {object}        wallet  — current wallet row
 * @returns {object}              — wallet row with possibly updated used values
 */
async function resetLimitsIfNeeded(client, wallet) {
  const now          = new Date();
  const dailyReset   = new Date(wallet.daily_reset_at);
  const monthlyReset = new Date(wallet.monthly_reset_at);

  const dayChanged   = now.toDateString() !== dailyReset.toDateString();
  const monthChanged =
    now.getFullYear() !== monthlyReset.getFullYear() ||
    now.getMonth()    !== monthlyReset.getMonth();

  if (!dayChanged && !monthChanged) return wallet;

  const updates = [];
  const params  = [];
  let   idx     = 1;

  if (dayChanged) {
    updates.push(`daily_debit_used = 0`, `daily_credit_used = 0`, `daily_reset_at = NOW()`);
    wallet = { ...wallet, daily_debit_used: 0, daily_credit_used: 0 };
  }
  if (monthChanged) {
    updates.push(`monthly_debit_used = 0`, `monthly_reset_at = NOW()`);
    wallet = { ...wallet, monthly_debit_used: 0 };
  }

  params.push(wallet.id);
  await client.query(
    `UPDATE wallets SET ${updates.join(', ')}, updated_at = NOW() WHERE id = $${idx}`,
    params
  );

  return wallet;
}

// ── Credit wallet (internal) ──────────────────────────────────────────────────

/**
 * Credits a wallet.  The caller must hold an open transaction.
 *
 * @param {pg.PoolClient} client
 * @param {string}        walletId
 * @param {number}        amount       — positive decimal
 * @param {string}        category     — FUNDING | TRANSFER_IN
 * @param {string}        narration
 * @param {object}        [metadata]
 * @returns {{ transaction: object, newBalance: number }}
 */
async function creditWallet(client, walletId, amount, category, narration, metadata = {}) {
  // Lock and fetch wallet
  const { rows } = await client.query(
    'SELECT * FROM wallets WHERE id = $1 FOR UPDATE',
    [walletId]
  );
  let wallet = rows[0];
  if (!wallet) throw Object.assign(new Error('Wallet not found.'), { status: 404 });
  if (wallet.status !== 'ACTIVE') {
    throw Object.assign(new Error(`Wallet is ${wallet.status} and cannot receive funds.`), { status: 422 });
  }

  wallet = await resetLimitsIfNeeded(client, wallet);

  // Check daily credit limit
  const creditUsed = parseFloat(wallet.daily_credit_used);
  const creditLimit = parseFloat(wallet.daily_credit_limit);
  if (creditUsed + amount > creditLimit) {
    throw Object.assign(
      new Error(`Daily credit limit of NGN ${creditLimit.toLocaleString()} reached.`),
      { status: 422 }
    );
  }

  const balanceBefore = parseFloat(wallet.balance);
  const balanceAfter  = +(balanceBefore + amount).toFixed(2);

  // Update wallet
  await client.query(
    `UPDATE wallets
     SET balance          = $1,
         daily_credit_used  = daily_credit_used + $2,
         updated_at        = NOW()
     WHERE id = $3`,
    [balanceAfter, amount, walletId]
  );

  // Insert transaction record
  const txId  = uuidv4();
  const ref   = generateReference('CR');
  const encNarration = narration ? encrypt(narration) : null;

  await client.query(
    `INSERT INTO wallet_transactions
       (id, reference, wallet_id, type, category, amount,
        balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
     VALUES ($1,$2,$3,'CREDIT',$4,$5,$6,$7,$8,'SUCCESS',$9,NOW())`,
    [txId, ref, walletId, category, amount,
     balanceBefore, balanceAfter, encNarration,
     JSON.stringify(metadata)]
  );

  logger.info({ message: 'Wallet credited', userId: wallet.user_id, walletId, amount, category, ref });

  return {
    transaction: {
      id: txId, reference: ref, type: 'CREDIT', category,
      amount, balanceBefore, balanceAfter,
    },
    newBalance: balanceAfter,
  };
}

// ── Debit wallet (internal) ───────────────────────────────────────────────────

/**
 * Debits a wallet.  The caller must hold an open transaction.
 *
 * @param {pg.PoolClient} client
 * @param {string}        walletId
 * @param {number}        amount
 * @param {string}        category     — WITHDRAWAL | TRANSFER_OUT
 * @param {string}        narration
 * @param {object}        [metadata]
 * @param {number}        kycLevel     — caller must pass the user's KYC level
 * @returns {{ transaction: object, newBalance: number }}
 */
async function debitWallet(client, walletId, amount, category, narration, metadata = {}, kycLevel = 0) {
  // Lock and fetch wallet
  const { rows } = await client.query(
    'SELECT * FROM wallets WHERE id = $1 FOR UPDATE',
    [walletId]
  );
  let wallet = rows[0];
  if (!wallet) throw Object.assign(new Error('Wallet not found.'), { status: 404 });
  if (wallet.status !== 'ACTIVE') {
    throw Object.assign(new Error(`Wallet is ${wallet.status} and cannot be debited.`), { status: 422 });
  }

  // KYC gate
  if (kycLevel < 1) {
    throw Object.assign(
      new Error('KYC verification required before debiting your wallet. Please submit a BVN.'),
      { status: 403 }
    );
  }

  wallet = await resetLimitsIfNeeded(client, wallet);

  const balance      = parseFloat(wallet.balance);
  const dailyUsed    = parseFloat(wallet.daily_debit_used);
  const monthlyUsed  = parseFloat(wallet.monthly_debit_used);
  const dailyLimit   = parseFloat(wallet.daily_debit_limit);
  const monthlyLimit = parseFloat(wallet.monthly_debit_limit);

  // Guard: sufficient balance
  if (balance < amount) {
    throw Object.assign(
      new Error(`Insufficient balance. Available: NGN ${balance.toLocaleString()}.`),
      { status: 422 }
    );
  }

  // Guard: daily debit limit
  if (dailyUsed + amount > dailyLimit) {
    const remaining = Math.max(0, dailyLimit - dailyUsed);
    throw Object.assign(
      new Error(
        `Daily debit limit exceeded. Remaining today: NGN ${remaining.toLocaleString()}.`
      ),
      { status: 422 }
    );
  }

  // Guard: monthly debit limit
  if (monthlyUsed + amount > monthlyLimit) {
    const remaining = Math.max(0, monthlyLimit - monthlyUsed);
    throw Object.assign(
      new Error(
        `Monthly debit limit exceeded. Remaining this month: NGN ${remaining.toLocaleString()}.`
      ),
      { status: 422 }
    );
  }

  const balanceBefore = balance;
  const balanceAfter  = +(balance - amount).toFixed(2);

  // Update wallet
  await client.query(
    `UPDATE wallets
     SET balance             = $1,
         daily_debit_used    = daily_debit_used  + $2,
         monthly_debit_used  = monthly_debit_used + $2,
         updated_at          = NOW()
     WHERE id = $3`,
    [balanceAfter, amount, walletId]
  );

  // Insert transaction record
  const txId         = uuidv4();
  const ref          = generateReference('DR');
  const encNarration = narration ? encrypt(narration) : null;

  await client.query(
    `INSERT INTO wallet_transactions
       (id, reference, wallet_id, type, category, amount,
        balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
     VALUES ($1,$2,$3,'DEBIT',$4,$5,$6,$7,$8,'SUCCESS',$9,NOW())`,
    [txId, ref, walletId, category, amount,
     balanceBefore, balanceAfter, encNarration,
     JSON.stringify(metadata)]
  );

  logger.info({ message: 'Wallet debited', userId: wallet.user_id, walletId, amount, category, ref });

  return {
    transaction: {
      id: txId, reference: ref, type: 'DEBIT', category,
      amount, balanceBefore, balanceAfter,
    },
    newBalance: balanceAfter,
  };
}

// ── Fund wallet ───────────────────────────────────────────────────────────────

/**
 * Fund a wallet (external deposit / top-up).
 *
 * @param {pg.Pool}  pool
 * @param {string}   walletId
 * @param {number}   amount
 * @param {string}   narration
 * @param {object}   [metadata]   — e.g. { channel: 'bank_transfer', reference: '...' }
 */
async function fundWallet(pool, walletId, amount, narration, metadata = {}) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await creditWallet(client, walletId, amount, 'FUNDING', narration, metadata);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── Debit / internal withdrawal ───────────────────────────────────────────────

/**
 * Debit a wallet (internal use — not an external bank withdrawal).
 */
async function debitFromWallet(pool, walletId, amount, narration, metadata = {}, kycLevel = 0) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await debitWallet(
      client, walletId, amount, 'WITHDRAWAL', narration, metadata, kycLevel
    );
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── Intra-wallet transfer ─────────────────────────────────────────────────────

/**
 * Transfer funds between two wallets in a single atomic transaction.
 *
 * Deadlock prevention: wallets are always locked in ascending wallet-id order.
 *
 * @param {pg.Pool}  pool
 * @param {string}   fromWalletId
 * @param {string}   toWalletId
 * @param {number}   amount
 * @param {string}   narration
 * @param {number}   kycLevel     — sender's KYC level
 */
async function transfer(pool, fromWalletId, toWalletId, amount, narration, kycLevel = 0) {
  if (fromWalletId === toWalletId) {
    throw Object.assign(new Error('Cannot transfer to the same wallet.'), { status: 400 });
  }

  // Consistent locking order to prevent deadlocks
  const [firstId, secondId] = [fromWalletId, toWalletId].sort();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Lock both wallets (consistent order)
    await client.query(
      'SELECT id FROM wallets WHERE id = ANY($1::text[]) FOR UPDATE',
      [[firstId, secondId]]
    );

    const transferRef = generateReference('TRF');

    // Debit sender
    const debitResult = await debitWallet(
      client, fromWalletId, amount, 'TRANSFER_OUT', narration,
      { transferRef, counterpartWalletId: toWalletId }, kycLevel
    );

    // Credit receiver
    const creditResult = await creditWallet(
      client, toWalletId, amount, 'TRANSFER_IN', narration,
      { transferRef, counterpartWalletId: fromWalletId }
    );

    // Link the two transaction rows with counterpart_wallet_id
    await client.query(
      `UPDATE wallet_transactions SET counterpart_wallet_id = $1 WHERE id = $2`,
      [toWalletId, debitResult.transaction.id]
    );
    await client.query(
      `UPDATE wallet_transactions SET counterpart_wallet_id = $1 WHERE id = $2`,
      [fromWalletId, creditResult.transaction.id]
    );

    await client.query('COMMIT');

    return {
      transferRef,
      debit:  debitResult.transaction,
      credit: creditResult.transaction,
      senderNewBalance: debitResult.newBalance,
    };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ── External withdrawal ───────────────────────────────────────────────────────

/**
 * Withdraw funds to an external bank account.
 *
 * In production, after debiting the wallet you would call a payment
 * provider (e.g. Paystack, Flutterwave) to initiate the bank transfer.
 * Here the bank disbursement is simulated.
 *
 * @param {pg.Pool}  pool
 * @param {string}   walletId
 * @param {number}   amount
 * @param {string}   bankCode
 * @param {string}   accountNumber
 * @param {string}   accountName
 * @param {string}   narration
 * @param {number}   kycLevel
 */
async function withdraw(
  pool, walletId, amount, bankCode, accountNumber, accountName, narration, kycLevel = 0
) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const metadata = {
      bankCode,
      accountNumber,   // NOTE: in production, encrypt this before storing
      accountName,
      channel: 'bank_transfer',
    };

    const result = await debitWallet(
      client, walletId, amount, 'WITHDRAWAL', narration, metadata, kycLevel
    );

    // ── Simulate bank disbursement ────────────────────────────────────────────
    // In production: const disbursement = await paymentProvider.transfer({ ... });
    // If the provider call fails, ROLLBACK to keep the wallet balance intact.
    logger.info({
      message:       'Bank disbursement initiated (simulated)',
      walletId,
      amount,
      bankCode,
      accountNumber: accountNumber.replace(/\d(?=\d{4})/g, '*'),   // mask for log
    });
    // ── End simulation ────────────────────────────────────────────────────────

    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { fundWallet, debitFromWallet, transfer, withdraw };
