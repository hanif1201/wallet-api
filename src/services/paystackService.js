'use strict';

/**
 * Paystack Service — wrapper around the Paystack REST API.
 *
 * All amounts sent to Paystack are in kobo (multiply NGN × 100).
 * All amounts received from Paystack are also in kobo (divide ÷ 100).
 *
 * Endpoints used:
 *   POST /transaction/initialize   — initiate a payment (funding)
 *   GET  /transaction/verify/:ref  — verify a completed payment
 *   GET  /bank                     — list supported banks
 *   GET  /bank/resolve             — resolve account name
 *   POST /transferrecipient        — register a withdrawal recipient
 *   POST /transfer                 — initiate a bank transfer (withdrawal)
 */

const axios = require('axios');

const PAYSTACK_BASE = 'https://api.paystack.co';

function client() {
  return axios.create({
    baseURL: PAYSTACK_BASE,
    headers: {
      Authorization:  `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      'Content-Type': 'application/json',
    },
    timeout: 30_000,
  });
}

// ── Funding ───────────────────────────────────────────────────────────────────

/**
 * Initialize a Paystack payment.
 * @returns {{ authorization_url, access_code, reference }}
 */
async function initializeTransaction({ email, amount, reference, callbackUrl, metadata = {} }) {
  const { data } = await client().post('/transaction/initialize', {
    email,
    amount:       Math.round(amount * 100),   // kobo
    reference,
    callback_url: callbackUrl,
    metadata,
  });
  return data.data;
}

/**
 * Verify a Paystack payment by reference.
 * @returns Paystack transaction object (status, amount, customer, etc.)
 */
async function verifyTransaction(reference) {
  const { data } = await client().get(`/transaction/verify/${encodeURIComponent(reference)}`);
  return data.data;
}

// ── Withdrawal ────────────────────────────────────────────────────────────────

/**
 * Fetch supported banks.
 * @returns Array of bank objects { name, code, ... }
 */
async function getBanks({ country = 'nigeria', perPage = 100 } = {}) {
  const { data } = await client().get('/bank', {
    params: { country, per_page: perPage, use_cursor: false },
  });
  return data.data;
}

/**
 * Resolve an account number to its registered name.
 * @returns {{ account_number, account_name }}
 */
async function resolveAccount(accountNumber, bankCode) {
  const { data } = await client().get('/bank/resolve', {
    params: { account_number: accountNumber, bank_code: bankCode },
  });
  return data.data;
}

/**
 * Register a transfer recipient with Paystack.
 * Must be called before initiating a transfer.
 * @returns {{ recipient_code, ... }}
 */
async function createTransferRecipient({ name, accountNumber, bankCode, currency = 'NGN' }) {
  const { data } = await client().post('/transferrecipient', {
    type:           'nuban',
    name,
    account_number: accountNumber,
    bank_code:      bankCode,
    currency,
  });
  return data.data;
}

/**
 * Initiate a transfer to a registered recipient.
 * @returns {{ transfer_code, status, ... }}
 */
async function initiateTransfer({ amount, recipient, reason, reference }) {
  const { data } = await client().post('/transfer', {
    source:    'balance',
    amount:    Math.round(amount * 100),   // kobo
    recipient,
    reason,
    reference,
  });
  return data.data;
}

module.exports = {
  initializeTransaction,
  verifyTransaction,
  getBanks,
  resolveAccount,
  createTransferRecipient,
  initiateTransfer,
};
