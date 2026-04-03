'use strict';

/**
 * Rate limiting middleware using express-rate-limit.
 *
 * Three tiers:
 *   globalLimiter      — all routes          (100 req / min per IP)
 *   authLimiter        — auth endpoints       (10 req / min per IP)
 *   walletLimiter      — wallet operations   (30 req / min per IP)
 */

const rateLimit = require('express-rate-limit');
const { logger }  = require('../utils/logger');

function parseEnvInt(name, fallback) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) ? v : fallback;
}

function onLimit(req, res, _next, options) {
  logger.warn({
    message: 'Rate limit exceeded',
    ip:      req.ip,
    path:    req.path,
    limit:   options.max,
  });
  res.status(429).json({
    success:    false,
    error:      'Too many requests. Please try again later.',
    retryAfter: Math.ceil(options.windowMs / 1000),
  });
}

const globalLimiter = rateLimit({
  windowMs:       parseEnvInt('RATE_LIMIT_WINDOW_MS', 60_000),
  max:            parseEnvInt('RATE_LIMIT_GLOBAL_MAX', 100),
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         onLimit,
});

const authLimiter = rateLimit({
  windowMs:       parseEnvInt('RATE_LIMIT_WINDOW_MS', 60_000),
  max:            parseEnvInt('RATE_LIMIT_AUTH_MAX', 10),
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         onLimit,
});

const walletLimiter = rateLimit({
  windowMs:       parseEnvInt('RATE_LIMIT_WINDOW_MS', 60_000),
  max:            parseEnvInt('RATE_LIMIT_WALLET_MAX', 30),
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         onLimit,
});

module.exports = { globalLimiter, authLimiter, walletLimiter };
