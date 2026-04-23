'use strict';

/**
 * 5SIM Provider
 * https://docs.5sim.net/
 *
 * Wraps the 5SIM REST API for phone number purchases.
 * All prices are returned in USD.
 *
 * Supported status flow:
 *   buy/activation → order with status PENDING
 *   check/{id}     → PENDING | RECEIVED | FINISHED | TIMEOUT | CANCELED
 *   cancel/{id}    → cancel (refund to 5SIM account balance)
 *   finish/{id}    → mark complete
 */

const axios      = require('axios');
const { logger } = require('../../utils/logger');

const BASE_URL = 'https://5sim.net/v1';

const COUNTRY_NAMES = {
  NG: 'nigeria',
  US: 'usa',
  DE: 'germany',
  GB: 'england',
};

const PRODUCT_NAMES = {
  telegram:  'telegram',
  whatsapp:  'whatsapp',
  facebook:  'facebook',
  instagram: 'instagram',
  google:    'google',
  twitter:   'twitter',
  amazon:    'amazon',
  tiktok:    'tiktok',
  snapchat:  'snapchat',
  discord:   'discord',
  fiverr:    'fiverr',
};

const NAME = 'five_sim';

// ── Helpers ───────────────────────────────────────────────────────────────────

function client() {
  return axios.create({
    baseURL: BASE_URL,
    headers: {
      Authorization: `Bearer ${process.env.FIVESIM_API_KEY}`,
      Accept:        'application/json',
    },
    timeout: 12_000,
  });
}

// ── Public interface ──────────────────────────────────────────────────────────

/**
 * Returns the USD price for the cheapest operator for a country/service combo.
 */
async function getPrice(countryCode, service) {
  const country = COUNTRY_NAMES[countryCode];
  const product = PRODUCT_NAMES[service];
  if (!country || !product) throw new Error('Unsupported country or service for 5SIM');

  const response = await client().get('/guest/prices', { params: { product, country } });
  const operators = response.data?.[country]?.[product];

  if (!operators || Object.keys(operators).length === 0) {
    throw new Error(`No numbers available on 5SIM for ${countryCode}/${service}`);
  }

  const costs = Object.values(operators)
    .map(o => parseFloat(o.cost))
    .filter(c => c > 0 && !isNaN(c));

  if (costs.length === 0) throw new Error(`No priced numbers on 5SIM for ${countryCode}/${service}`);

  return Math.min(...costs);
}

/**
 * Purchases a virtual number. Returns orderId, phoneNumber, priceUsd, expiresAt.
 */
async function purchaseNumber(countryCode, service) {
  const country = COUNTRY_NAMES[countryCode];
  const product = PRODUCT_NAMES[service];
  if (!country || !product) throw new Error('Unsupported country or service for 5SIM');

  const response = await client().get(`/user/buy/activation/${country}/any/${product}`);
  const data     = response.data;

  if (!data?.id || !data?.phone) {
    throw new Error(`5SIM purchase failed: ${JSON.stringify(data)}`);
  }

  logger.info({ message: '5SIM number purchased', orderId: data.id, countryCode, service });

  return {
    orderId:     String(data.id),
    phoneNumber: data.phone.startsWith('+') ? data.phone : `+${data.phone}`,
    priceUsd:    parseFloat(data.price),
    expiresAt:   data.expires ? new Date(data.expires) : new Date(Date.now() + 20 * 60 * 1000),
  };
}

/**
 * Polls for SMS on an active order.
 * Returns { status: 'PENDING' | 'RECEIVED' | 'CANCELLED', code, text, sender }
 */
async function checkSMS(orderId) {
  const response = await client().get(`/user/check/${orderId}`);
  const data     = response.data;

  // Terminal failure states
  if (['TIMEOUT', 'CANCELED', 'BANNED'].includes(data?.status)) {
    return { status: 'CANCELLED', code: null, text: null, sender: null };
  }

  if (['RECEIVED', 'FINISHED'].includes(data?.status)) {
    const sms    = Array.isArray(data.sms) && data.sms.length > 0 ? data.sms[0] : null;
    const code   = sms?.code   || null;
    const text   = sms?.text   || null;
    const sender = sms?.sender || null;
    return { status: 'RECEIVED', code, text, sender };
  }

  return { status: 'PENDING', code: null, text: null, sender: null };
}

/**
 * Cancels an order and requests refund to the 5SIM account balance.
 */
async function cancelNumber(orderId) {
  await client().get(`/user/cancel/${orderId}`).catch((err) => {
    logger.warn({ message: '5SIM cancel failed', orderId, error: err.message });
  });
  return { cancelled: true };
}

module.exports = { name: NAME, getPrice, purchaseNumber, checkSMS, cancelNumber };
