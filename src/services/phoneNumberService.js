'use strict';

/**
 * Phone Number Service
 *
 * Orchestrates virtual phone number purchases across multiple providers
 * with automatic failover: SMS-Activate (primary) → 5SIM (fallback).
 *
 * If the primary provider is unavailable or out of stock, the service
 * transparently retries on the next provider without the caller needing
 * to know which succeeded.
 *
 * Currency flow:
 *   Provider returns price in USD → multiply by USD_TO_NGN_RATE
 *   → apply NUMBER_MARKUP_PERCENT → round up to nearest kobo
 *
 * Wallet integration:
 *   Purchase debits the wallet (category: NUMBER_PURCHASE).
 *   Cancel/expiry credits the wallet (category: NUMBER_REFUND).
 */

const { v4: uuidv4 } = require('uuid');
const { pool }       = require('../config/database');
const { encrypt }    = require('./encryption');
const { logger }     = require('../utils/logger');
const fiveSim    = require('./providers/fiveSim');
const smsMan     = require('./providers/smsMan');

// Provider chain — order determines priority.
// 5SIM is primary (reliable, well-documented REST API).
// SMS-Man is fallback (same response format as the defunct SMS-Activate).
const PROVIDERS = [fiveSim, smsMan];

// ── Catalogue ─────────────────────────────────────────────────────────────────

const SUPPORTED_COUNTRIES = [
  { code: 'NG', name: 'Nigeria',  flag: '🇳🇬' },
  { code: 'US', name: 'USA',      flag: '🇺🇸' },
  { code: 'DE', name: 'Germany',  flag: '🇩🇪' },
  { code: 'GB', name: 'UK',       flag: '🇬🇧' },
];

const SUPPORTED_SERVICES = [
  { code: 'telegram',  name: 'Telegram'  },
  { code: 'whatsapp',  name: 'WhatsApp'  },
  { code: 'facebook',  name: 'Facebook'  },
  { code: 'instagram', name: 'Instagram' },
  { code: 'google',    name: 'Google'    },
  { code: 'twitter',   name: 'Twitter/X' },
  { code: 'amazon',    name: 'Amazon'    },
  { code: 'tiktok',    name: 'TikTok'    },
  { code: 'snapchat',  name: 'Snapchat'  },
  { code: 'discord',   name: 'Discord'   },
  { code: 'fiverr',    name: 'Fiverr'    },
];

// ── Pricing helpers ───────────────────────────────────────────────────────────

async function getNumberSettings() {
  try {
    const { rows } = await pool.query(
      `SELECT key, value FROM platform_settings WHERE key IN ('usd_to_ngn_rate','number_markup_percent')`
    );
    const map = Object.fromEntries(rows.map(r => [r.key, r.value]));
    return {
      rate:   parseFloat(map.usd_to_ngn_rate       || process.env.USD_TO_NGN_RATE       || '1600'),
      markup: parseFloat(map.number_markup_percent  || process.env.NUMBER_MARKUP_PERCENT || '10'),
    };
  } catch {
    return {
      rate:   parseFloat(process.env.USD_TO_NGN_RATE       || '1600'),
      markup: parseFloat(process.env.NUMBER_MARKUP_PERCENT || '10'),
    };
  }
}

function usdToNgn(usdPrice, rate, markup) {
  const rawNgn = usdPrice * rate * (1 + markup / 100);
  // Round up to nearest 50 kobo for clean pricing
  return Math.ceil(rawNgn * 2) / 2;
}

// ── Provider failover ─────────────────────────────────────────────────────────

/**
 * Tries each provider in order. Returns { provider, result } on first success.
 * Throws if every provider fails.
 */
async function withFailover(action) {
  const errors = [];
  for (const provider of PROVIDERS) {
    try {
      const result = await action(provider);
      return { provider, result };
    } catch (err) {
      logger.warn({ message: `Provider ${provider.name} failed`, error: err.message });
      errors.push(`${provider.name}: ${err.message}`);
    }
  }
  logger.error({ message: 'All providers failed', errors });
  throw Object.assign(
    new Error('No numbers available right now. Please try again in a few minutes.'),
    { status: 503 }
  );
}

// ── debitWallet inline (avoids circular deps with walletService) ──────────────

async function debitForPurchase(client, walletId, amountNgn, orderId, kycLevel) {
  const { rows } = await client.query('SELECT * FROM wallets WHERE id = $1 FOR UPDATE', [walletId]);
  const wallet   = rows[0];
  if (!wallet)                    throw Object.assign(new Error('Wallet not found.'), { status: 404 });
  if (wallet.status !== 'ACTIVE') throw Object.assign(new Error(`Wallet is ${wallet.status}.`), { status: 422 });
  if (kycLevel < 1)               throw Object.assign(new Error('KYC verification required. Please submit a BVN.'), { status: 403 });

  // Lazy limit reset
  const now     = new Date();
  const updates = [];
  if (now.toDateString() !== new Date(wallet.daily_reset_at).toDateString()) {
    updates.push('daily_debit_used = 0', 'daily_credit_used = 0', 'daily_reset_at = NOW()');
    wallet.daily_debit_used = 0;
  }
  const mr = new Date(wallet.monthly_reset_at);
  if (now.getFullYear() !== mr.getFullYear() || now.getMonth() !== mr.getMonth()) {
    updates.push('monthly_debit_used = 0', 'monthly_reset_at = NOW()');
    wallet.monthly_debit_used = 0;
  }
  if (updates.length) {
    await client.query(`UPDATE wallets SET ${updates.join(', ')}, updated_at = NOW() WHERE id = $1`, [walletId]);
  }

  const balance      = parseFloat(wallet.balance);
  const dailyUsed    = parseFloat(wallet.daily_debit_used);
  const monthlyUsed  = parseFloat(wallet.monthly_debit_used);
  const dailyLimit   = parseFloat(wallet.daily_debit_limit);
  const monthlyLimit = parseFloat(wallet.monthly_debit_limit);

  if (balance < amountNgn) {
    throw Object.assign(
      new Error(`Insufficient balance. Available: NGN ${balance.toLocaleString()}.`),
      { status: 422 }
    );
  }
  if (dailyUsed + amountNgn > dailyLimit) {
    const rem = Math.max(0, dailyLimit - dailyUsed);
    throw Object.assign(
      new Error(`Daily debit limit exceeded. Remaining today: NGN ${rem.toLocaleString()}.`),
      { status: 422 }
    );
  }
  if (monthlyUsed + amountNgn > monthlyLimit) {
    const rem = Math.max(0, monthlyLimit - monthlyUsed);
    throw Object.assign(
      new Error(`Monthly debit limit exceeded. Remaining this month: NGN ${rem.toLocaleString()}.`),
      { status: 422 }
    );
  }

  const balanceBefore = balance;
  const balanceAfter  = +(balance - amountNgn).toFixed(2);

  await client.query(
    `UPDATE wallets
     SET balance = $1, daily_debit_used = daily_debit_used + $2,
         monthly_debit_used = monthly_debit_used + $2, updated_at = NOW()
     WHERE id = $3`,
    [balanceAfter, amountNgn, walletId]
  );

  const txId  = uuidv4();
  const ref   = `NUM-${Date.now().toString(36).toUpperCase()}-${uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase()}`;
  const narr  = encrypt(`Virtual number purchase – order ${orderId}`);

  await client.query(
    `INSERT INTO wallet_transactions
       (id, reference, wallet_id, type, category, amount,
        balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
     VALUES ($1,$2,$3,'DEBIT','NUMBER_PURCHASE',$4,$5,$6,$7,'SUCCESS',$8,NOW())`,
    [txId, ref, walletId, amountNgn, balanceBefore, balanceAfter, narr,
     JSON.stringify({ orderId })]
  );

  return { txId, ref, balanceBefore, balanceAfter };
}

async function creditForRefund(client, walletId, amountNgn, virtualNumberId) {
  const { rows } = await client.query('SELECT * FROM wallets WHERE id = $1 FOR UPDATE', [walletId]);
  const wallet   = rows[0];
  if (!wallet) throw new Error('Wallet not found for refund');

  const balanceBefore = parseFloat(wallet.balance);
  const balanceAfter  = +(balanceBefore + amountNgn).toFixed(2);

  await client.query(
    `UPDATE wallets SET balance = $1, updated_at = NOW() WHERE id = $2`,
    [balanceAfter, walletId]
  );

  const txId = uuidv4();
  const ref  = `RFD-${Date.now().toString(36).toUpperCase()}-${uuidv4().replace(/-/g, '').slice(0, 8).toUpperCase()}`;
  const narr = encrypt(`Refund for cancelled virtual number – order ${virtualNumberId}`);

  await client.query(
    `INSERT INTO wallet_transactions
       (id, reference, wallet_id, type, category, amount,
        balance_before, balance_after, encrypted_narration, status, metadata, processed_at)
     VALUES ($1,$2,$3,'CREDIT','NUMBER_REFUND',$4,$5,$6,$7,'SUCCESS',$8,NOW())`,
    [txId, ref, walletId, amountNgn, balanceBefore, balanceAfter, narr,
     JSON.stringify({ virtualNumberId })]
  );

  return { txId, ref, balanceBefore, balanceAfter };
}

// ── Public API ────────────────────────────────────────────────────────────────

function getCountries() {
  return SUPPORTED_COUNTRIES;
}

function getServices() {
  return SUPPORTED_SERVICES;
}

/**
 * Returns the quoted NGN price for a country/service combo.
 * Tries providers in order and returns the first successful price.
 */
async function getPrice(countryCode, service) {
  const [{ provider, result: priceUsd }, { rate, markup }] = await Promise.all([
    withFailover(p => p.getPrice(countryCode, service)),
    getNumberSettings(),
  ]);
  const priceNgn = usdToNgn(priceUsd, rate, markup);
  return { provider: provider.name, priceUsd, priceNgn, exchangeRate: rate, markupPercent: markup };
}

/**
 * Purchases a virtual number using wallet balance.
 *
 * Flow:
 *  1. Purchase number from providers with full failover (5SIM → SMS-Man).
 *     This is done BEFORE the DB transaction so a no-balance or no-numbers
 *     error never touches the wallet.
 *  2. Calculate NGN amount from the actual purchase price.
 *  3. BEGIN transaction → debit wallet → insert record → COMMIT.
 *  4. On any DB failure: cancel the provider purchase and ROLLBACK.
 */
async function purchaseNumber(userId, walletId, countryCode, service, kycLevel) {
  const country = SUPPORTED_COUNTRIES.find(c => c.code === countryCode);
  const svc     = SUPPORTED_SERVICES.find(s => s.code === service);
  if (!country) throw Object.assign(new Error('Unsupported country.'), { status: 400 });
  if (!svc)     throw Object.assign(new Error('Unsupported service.'), { status: 400 });

  // KYC + balance pre-check — fast fail before hitting any provider API
  if (kycLevel < 1) {
    throw Object.assign(
      new Error('KYC verification required before purchasing a number. Please submit a BVN.'),
      { status: 403 }
    );
  }
  const walletRow = await pool.query('SELECT balance FROM wallets WHERE id = $1', [walletId]);
  if (!walletRow.rows[0]) throw Object.assign(new Error('Wallet not found.'), { status: 404 });
  const currentBalance = parseFloat(walletRow.rows[0].balance);
  if (currentBalance <= 0) {
    throw Object.assign(new Error('Insufficient wallet balance. Please fund your wallet first.'), { status: 422 });
  }

  // Step 1 — purchase from provider with failover (before any DB work)
  const [{ provider, result: purchased }, { rate, markup }] = await Promise.all([
    withFailover(p => p.purchaseNumber(countryCode, service)),
    getNumberSettings(),
  ]);

  const priceNgn = usdToNgn(purchased.priceUsd, rate, markup);

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    // Step 2 — debit wallet with actual purchase price (locks wallet row)
    const debit = await debitForPurchase(dbClient, walletId, priceNgn, purchased.orderId, kycLevel);

    // Step 3 — persist virtual_number record
    const id = uuidv4();
    await dbClient.query(
      `INSERT INTO virtual_numbers
         (id, user_id, wallet_id, wallet_tx_id,
          phone_number, country_code, country_name, service_code, service_name,
          provider, provider_order_id, status,
          price_usd, price_ngn, exchange_rate, markup_percent,
          expires_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'PENDING',$12,$13,$14,$15,$16)`,
      [
        id, userId, walletId, debit.txId,
        purchased.phoneNumber, countryCode, country.name, service, svc.name,
        provider.name, purchased.orderId,
        purchased.priceUsd, priceNgn, rate, markup,
        purchased.expiresAt,
      ]
    );

    await dbClient.query('COMMIT');

    logger.info({
      message:  'Virtual number purchased',
      userId, walletId, countryCode, service,
      provider: provider.name,
      orderId:  purchased.orderId,
      priceNgn,
    });

    return {
      id,
      phoneNumber:  purchased.phoneNumber,
      countryCode,
      countryName:  country.name,
      serviceCode:  service,
      serviceName:  svc.name,
      provider:     provider.name,
      status:       'PENDING',
      priceNgn,
      walletRef:    debit.ref,
      newBalance:   debit.balanceAfter,
      expiresAt:    purchased.expiresAt,
    };
  } catch (err) {
    await dbClient.query('ROLLBACK');
    // Provider purchase succeeded but DB failed — cancel the number to avoid losing it
    provider.cancelNumber(purchased.orderId).catch(() => {});
    throw err;
  } finally {
    dbClient.release();
  }
}

/**
 * Polls the provider for SMS status and updates the DB record.
 * Also auto-expires orders that have passed their expiry time.
 */
async function checkOrder(userId, orderId) {
  const { rows } = await pool.query(
    'SELECT * FROM virtual_numbers WHERE id = $1 AND user_id = $2',
    [orderId, userId]
  );
  const order = rows[0];
  if (!order) throw Object.assign(new Error('Order not found.'), { status: 404 });

  // Already terminal — return cached state
  if (['RECEIVED', 'CANCELLED', 'EXPIRED'].includes(order.status)) {
    return formatOrder(order);
  }

  // Auto-expire
  if (new Date() > new Date(order.expires_at)) {
    await handleExpiry(order);
    return formatOrder({ ...order, status: 'EXPIRED' });
  }

  // Poll provider
  const provider = PROVIDERS.find(p => p.name === order.provider);
  if (!provider) throw new Error('Unknown provider stored on order');

  const smsResult = await provider.checkSMS(order.provider_order_id);

  if (smsResult.status === 'RECEIVED') {
    await pool.query(
      `UPDATE virtual_numbers
       SET status = 'RECEIVED', sms_code = $1, sms_text = $2, sms_sender = $3,
           updated_at = NOW(), completed_at = NOW()
       WHERE id = $4`,
      [smsResult.code, smsResult.text, smsResult.sender, order.id]
    );
    logger.info({ message: 'SMS received on virtual number', orderId: order.id, userId });
    return formatOrder({ ...order, status: 'RECEIVED', sms_code: smsResult.code, sms_text: smsResult.text });
  }

  if (smsResult.status === 'CANCELLED') {
    await handleExpiry(order);
    return formatOrder({ ...order, status: 'CANCELLED' });
  }

  return formatOrder(order);
}

/**
 * Cancels a PENDING order and refunds the wallet.
 * Refund is only issued for PENDING orders (no SMS received yet).
 */
async function cancelOrder(userId, orderId) {
  const { rows } = await pool.query(
    'SELECT * FROM virtual_numbers WHERE id = $1 AND user_id = $2',
    [orderId, userId]
  );
  const order = rows[0];
  if (!order) throw Object.assign(new Error('Order not found.'), { status: 404 });

  if (order.status !== 'PENDING') {
    throw Object.assign(
      new Error(`Cannot cancel an order with status ${order.status}.`),
      { status: 422 }
    );
  }

  // Cancel on provider (best-effort)
  const provider = PROVIDERS.find(p => p.name === order.provider);
  if (provider) {
    await provider.cancelNumber(order.provider_order_id).catch(() => {});
  }

  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');

    // Refund wallet
    const refund = await creditForRefund(dbClient, order.wallet_id, parseFloat(order.price_ngn), order.id);

    await dbClient.query(
      `UPDATE virtual_numbers
       SET status = 'CANCELLED', refund_tx_id = $1, updated_at = NOW(), completed_at = NOW()
       WHERE id = $2`,
      [refund.txId, order.id]
    );

    await dbClient.query('COMMIT');

    logger.info({ message: 'Virtual number cancelled + refunded', orderId: order.id, userId });

    return {
      ...formatOrder({ ...order, status: 'CANCELLED' }),
      refunded:    true,
      refundRef:   refund.ref,
      newBalance:  refund.balanceAfter,
    };
  } catch (err) {
    await dbClient.query('ROLLBACK');
    throw err;
  } finally {
    dbClient.release();
  }
}

/**
 * Returns paginated purchase history for a user.
 */
async function getHistory(userId, { page = 1, limit = 20 } = {}) {
  const offset = (page - 1) * limit;

  const [dataResult, countResult] = await Promise.all([
    pool.query(
      `SELECT * FROM virtual_numbers WHERE user_id = $1
       ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
      [userId, limit, offset]
    ),
    pool.query('SELECT COUNT(*) FROM virtual_numbers WHERE user_id = $1', [userId]),
  ]);

  const total = parseInt(countResult.rows[0].count, 10);

  return {
    orders: dataResult.rows.map(formatOrder),
    pagination: {
      total,
      page,
      limit,
      pages: Math.ceil(total / limit),
    },
  };
}

// ── Internal helpers ──────────────────────────────────────────────────────────

async function handleExpiry(order) {
  const dbClient = await pool.connect();
  try {
    await dbClient.query('BEGIN');
    const refund = await creditForRefund(dbClient, order.wallet_id, parseFloat(order.price_ngn), order.id);
    await dbClient.query(
      `UPDATE virtual_numbers
       SET status = 'EXPIRED', refund_tx_id = $1, updated_at = NOW(), completed_at = NOW()
       WHERE id = $2`,
      [refund.txId, order.id]
    );
    await dbClient.query('COMMIT');
    logger.info({ message: 'Virtual number expired + refunded', orderId: order.id });
  } catch (err) {
    await dbClient.query('ROLLBACK');
    logger.error({ message: 'Failed to process expiry refund', orderId: order.id, error: err.message });
  } finally {
    dbClient.release();
  }
}

function formatOrder(order) {
  return {
    id:          order.id,
    phoneNumber: order.phone_number,
    countryCode: order.country_code,
    countryName: order.country_name,
    serviceCode: order.service_code,
    serviceName: order.service_name,
    provider:    order.provider,
    status:      order.status,
    priceNgn:    parseFloat(order.price_ngn),
    smsCode:     order.sms_code     || null,
    smsText:     order.sms_text     || null,
    smsSender:   order.sms_sender   || null,
    expiresAt:   order.expires_at,
    createdAt:   order.created_at,
    completedAt: order.completed_at || null,
  };
}

module.exports = {
  getCountries,
  getServices,
  getPrice,
  purchaseNumber,
  checkOrder,
  cancelOrder,
  getHistory,
};
