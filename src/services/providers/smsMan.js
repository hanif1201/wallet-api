'use strict';

/**
 * SMS-Man Provider
 * https://sms-man.com/api
 *
 * Drop-in replacement for SMS-Activate (same endpoint pattern, same response
 * format). SMS-Man was the natural migration target after SMS-Activate shut
 * down in December 2024.
 *
 * Status flow:
 *   getNumber  → ACCESS_NUMBER:{id}:{phone}
 *   getStatus  → STATUS_WAIT_CODE | STATUS_OK:{code} | STATUS_CANCEL
 *   setStatus(8) → cancel + refund to SMS-Man account balance
 */

const axios      = require('axios');
const { logger } = require('../../utils/logger');

const BASE_URL = 'https://api.sms-man.com/stubs/handler_api.php';

// SMS-Man numeric country IDs
const COUNTRY_IDS = {
  NG: 21,
  US: 12,
  DE: 6,
  GB: 16,
};

// SMS-Man two-letter service codes (same convention as SMS-Activate)
const SERVICE_CODES = {
  telegram:  'tg',
  whatsapp:  'wa',
  facebook:  'fb',
  instagram: 'ig',
  google:    'go',
  twitter:   'tw',
  amazon:    'am',
  tiktok:    'tt',
  snapchat:  'sc',
  discord:   'ds',
  fiverr:    'fv',
};

const NAME = 'sms_man';

// ── Helpers ───────────────────────────────────────────────────────────────────

async function apiCall(params) {
  const response = await axios.get(BASE_URL, {
    params: { api_key: process.env.SMSMAN_API_KEY, ...params },
    timeout: 12_000,
  });
  return response.data;
}

// ── Public interface ──────────────────────────────────────────────────────────

async function getPrice(countryCode, service) {
  const countryId   = COUNTRY_IDS[countryCode];
  const serviceCode = SERVICE_CODES[service];
  if (!countryId || !serviceCode) throw new Error('Unsupported country or service for SMS-Man');

  const data = await apiCall({ action: 'getPrices', country: countryId, service: serviceCode });

  const countryKey = countryId.toString();
  const cost = data?.[countryKey]?.[serviceCode]?.cost;
  if (!cost || parseFloat(cost) === 0) {
    throw new Error(`No numbers available on SMS-Man for ${countryCode}/${service}`);
  }

  // SMS-Man prices are in USD
  return parseFloat(cost);
}

async function purchaseNumber(countryCode, service) {
  const countryId   = COUNTRY_IDS[countryCode];
  const serviceCode = SERVICE_CODES[service];
  if (!countryId || !serviceCode) throw new Error('Unsupported country or service for SMS-Man');

  const text = await apiCall({ action: 'getNumber', service: serviceCode, country: countryId });

  if (text === 'NO_NUMBERS')  throw new Error('No numbers available on SMS-Man');
  if (text === 'NO_BALANCE')  throw new Error('SMS-Man provider balance insufficient');
  if (!String(text).startsWith('ACCESS_NUMBER:')) {
    throw new Error(`SMS-Man error: ${text}`);
  }

  const [, orderId, rawPhone] = String(text).split(':');

  await apiCall({ action: 'setStatus', id: orderId, status: 1 }).catch(() => {});

  const priceUsd  = await getPrice(countryCode, service);
  const expiresAt = new Date(Date.now() + 20 * 60 * 1000);

  logger.info({ message: 'SMS-Man number purchased', orderId, countryCode, service });

  return {
    orderId,
    phoneNumber: rawPhone.startsWith('+') ? rawPhone : `+${rawPhone}`,
    priceUsd,
    expiresAt,
  };
}

async function checkSMS(orderId) {
  const text = await apiCall({ action: 'getStatus', id: orderId });
  const str  = String(text);

  if (str === 'STATUS_WAIT_CODE') return { status: 'PENDING',   code: null, text: null, sender: null };
  if (str === 'STATUS_CANCEL')    return { status: 'CANCELLED', code: null, text: null, sender: null };

  if (str.startsWith('STATUS_OK:') || str.startsWith('STATUS_WAIT_RETRY:')) {
    const code = str.split(':')[1];
    return { status: 'RECEIVED', code, text: code, sender: null };
  }

  return { status: 'PENDING', code: null, text: null, sender: null };
}

async function cancelNumber(orderId) {
  await apiCall({ action: 'setStatus', id: orderId, status: 8 }).catch((err) => {
    logger.warn({ message: 'SMS-Man cancel failed', orderId, error: err.message });
  });
  return { cancelled: true };
}

module.exports = { name: NAME, getPrice, purchaseNumber, checkSMS, cancelNumber };
