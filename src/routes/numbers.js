'use strict';

/**
 * Virtual Number Routes
 *
 * GET  /api/v1/numbers/countries          — list supported countries
 * GET  /api/v1/numbers/services           — list supported services
 * GET  /api/v1/numbers/price              — get NGN price (?country=NG&service=telegram)
 * POST /api/v1/numbers/purchase           — buy a number (debits wallet)
 * GET  /api/v1/numbers                    — paginated order history
 * GET  /api/v1/numbers/:id               — get order + poll for SMS
 * POST /api/v1/numbers/:id/cancel        — cancel order + refund wallet
 *
 * All routes require JWT auth.
 * Purchase requires KYC level ≥ 1 (enforced inside phoneNumberService).
 *
 * Purchase flow:
 *   1. GET /price to get live NGN quote
 *   2. POST /purchase → wallet debited → provider assigns number
 *   3. Poll GET /:id every ~5s until status becomes RECEIVED or EXPIRED
 *   4. If user no longer needs the number → POST /:id/cancel → full refund
 */

const express = require('express');
const Joi     = require('joi');

const { jwtAuth }        = require('../middleware/jwtAuth');
const { walletLimiter }  = require('../middleware/rateLimiter');
const { logger }         = require('../utils/logger');
const {
  getCountries,
  getServices,
  getPrice,
  purchaseNumber,
  checkOrder,
  cancelOrder,
  getHistory,
} = require('../services/phoneNumberService');
const { pool } = require('../config/database');

const router = express.Router();

// All routes require authentication
router.use(jwtAuth);
router.use(walletLimiter);

// ── Validation helpers ────────────────────────────────────────────────────────

const VALID_COUNTRIES = ['NG', 'US', 'DE', 'GB'];
const VALID_SERVICES  = [
  'telegram', 'whatsapp', 'facebook', 'instagram',
  'google', 'twitter', 'amazon', 'tiktok', 'snapchat', 'discord', 'fiverr',
];

const priceSchema = Joi.object({
  country: Joi.string().valid(...VALID_COUNTRIES).required(),
  service: Joi.string().valid(...VALID_SERVICES).required(),
});

const purchaseSchema = Joi.object({
  country: Joi.string().valid(...VALID_COUNTRIES).required(),
  service: Joi.string().valid(...VALID_SERVICES).required(),
});

const historySchema = Joi.object({
  page:  Joi.number().integer().min(1).default(1),
  limit: Joi.number().integer().min(1).max(50).default(20),
});

// ── GET /countries ────────────────────────────────────────────────────────────

router.get('/countries', (_req, res) => {
  res.json({ success: true, countries: getCountries() });
});

// ── GET /services ─────────────────────────────────────────────────────────────

router.get('/services', (_req, res) => {
  res.json({ success: true, services: getServices() });
});

// ── GET /price ────────────────────────────────────────────────────────────────

router.get('/price', async (req, res, next) => {
  const { error, value } = priceSchema.validate(req.query, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   error.details.map(d => d.message).join(', '),
    });
  }

  try {
    const pricing = await getPrice(value.country, value.service);
    res.json({
      success: true,
      country: value.country,
      service: value.service,
      pricing: {
        priceNgn:      pricing.priceNgn,
        priceUsd:      pricing.priceUsd,
        exchangeRate:  pricing.exchangeRate,
        markupPercent: pricing.markupPercent,
        currency:      'NGN',
      },
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /purchase ────────────────────────────────────────────────────────────

router.post('/purchase', async (req, res, next) => {
  const { error, value } = purchaseSchema.validate(req.body, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   error.details.map(d => d.message).join(', '),
    });
  }

  try {
    // Fetch wallet ID for this user
    const { rows } = await pool.query(
      'SELECT id FROM wallets WHERE user_id = $1',
      [req.user.id]
    );
    if (!rows[0]) {
      return res.status(404).json({ success: false, error: 'Wallet not found.' });
    }

    const order = await purchaseNumber(
      req.user.id,
      rows[0].id,
      value.country,
      value.service,
      req.user.kycLevel,
    );

    logger.info({
      message:  'Virtual number purchase request completed',
      userId:   req.user.id,
      country:  value.country,
      service:  value.service,
      orderId:  order.id,
    });

    res.status(201).json({
      success: true,
      message: 'Number purchased successfully. Poll GET /numbers/:id to receive your SMS code.',
      order,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET / (history) ───────────────────────────────────────────────────────────

router.get('/', async (req, res, next) => {
  const { error, value } = historySchema.validate(req.query, { abortEarly: false });
  if (error) {
    return res.status(400).json({
      success: false,
      error:   error.details.map(d => d.message).join(', '),
    });
  }

  try {
    const result = await getHistory(req.user.id, value);
    res.json({ success: true, ...result });
  } catch (err) {
    next(err);
  }
});

// ── GET /:id ──────────────────────────────────────────────────────────────────

router.get('/:id', async (req, res, next) => {
  try {
    const order = await checkOrder(req.user.id, req.params.id);
    res.json({ success: true, order });
  } catch (err) {
    next(err);
  }
});

// ── POST /:id/cancel ──────────────────────────────────────────────────────────

router.post('/:id/cancel', async (req, res, next) => {
  try {
    const result = await cancelOrder(req.user.id, req.params.id);

    logger.info({
      message: 'Virtual number cancelled',
      userId:  req.user.id,
      orderId: req.params.id,
    });

    res.json({
      success: true,
      message: 'Order cancelled and wallet refunded.',
      ...result,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
