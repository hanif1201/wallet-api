'use strict';

/**
 * Wallet API — Application Entry Point
 *
 * Security controls:
 * ┌──────────────────────────┬──────────────────────────────────────────────┐
 * │ Control                  │ Mechanism                                    │
 * ├──────────────────────────┼──────────────────────────────────────────────┤
 * │ Secure HTTP headers      │ helmet (CSP, HSTS, X-Frame-Options …)        │
 * │ Rate limiting            │ express-rate-limit (global + per-group)      │
 * │ Authentication           │ JWT (HS256, 15-min access / 7-day refresh)   │
 * │ Password hashing         │ bcrypt (cost 12)                             │
 * │ Input validation         │ Joi schemas (every route)                    │
 * │ PII encryption at rest   │ AES-256-GCM (all sensitive columns)          │
 * │ Indexed lookups          │ HMAC-SHA256 tokens (email, phone, BVN, NIN)  │
 * │ Race condition safety    │ SELECT … FOR UPDATE in wallet operations      │
 * │ Audit logging            │ Winston (structured JSON, daily rotation)    │
 * │ Credentials in env only  │ dotenv / environment variables               │
 * └──────────────────────────┴──────────────────────────────────────────────┘
 *
 * API surface:
 *   POST   /api/v1/auth/register
 *   POST   /api/v1/auth/login
 *   POST   /api/v1/auth/refresh
 *   POST   /api/v1/auth/logout
 *   GET    /api/v1/auth/me
 *
 *   POST   /api/v1/kyc/submit
 *   GET    /api/v1/kyc/status
 *   GET    /api/v1/kyc/documents
 *
 *   GET    /api/v1/wallet
 *   POST   /api/v1/wallet/fund
 *   POST   /api/v1/wallet/debit
 *   POST   /api/v1/wallet/transfer
 *   POST   /api/v1/wallet/withdraw
 *   GET    /api/v1/wallet/transactions
 *   GET    /api/v1/wallet/transactions/:reference
 */

require('dotenv').config();

const express = require('express');
const helmet  = require('helmet');

const { logger }         = require('./utils/logger');
const { globalLimiter }  = require('./middleware/rateLimiter');
const { errorHandler }   = require('./middleware/errorHandler');
const { initSchema }     = require('./config/database');
const authRouter         = require('./routes/auth');
const kycRouter          = require('./routes/kyc');
const walletRouter       = require('./routes/wallet');
const webhookRouter      = require('./routes/webhooks');

const app = express();

// ── Security middleware ───────────────────────────────────────────────────────

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'"],
    },
  },
  hsts: {
    maxAge:            31_536_000,
    includeSubDomains: true,
    preload:           true,
  },
}));

app.disable('x-powered-by');

// Webhook route must be registered BEFORE express.json() so that
// express.raw() in the webhook handler can capture the raw body
// for Paystack HMAC-SHA512 signature verification.
app.use('/api/v1/webhooks', webhookRouter);

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));
app.set('trust proxy', 1);   // trust first proxy (for rate-limit IP detection)
app.use(globalLimiter);

// ── Request logging ───────────────────────────────────────────────────────────
// Only log errors and slow requests — not every request.
// Business events (register, login, fund, withdraw, KYC) are logged in their
// respective route handlers. Logging every request at scale generates too much
// noise and inflates observability costs.

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms     = Date.now() - start;
    const is4xx  = res.statusCode >= 400 && res.statusCode < 500;
    const is5xx  = res.statusCode >= 500;
    const isSlow = ms > 2000;

    if (is5xx) {
      logger.error({
        message: 'Server error on request',
        method:  req.method,
        path:    req.path,
        status:  res.statusCode,
        userId:  req.user?.id || null,
        ms,
        ip:      req.ip,
      });
    } else if (is4xx) {
      logger.warn({
        message: `Bad request — ${res.statusCode}`,
        method:  req.method,
        path:    req.path,
        status:  res.statusCode,
        userId:  req.user?.id || null,
        ms,
        ip:      req.ip,
      });
    } else if (isSlow) {
      logger.warn({
        message: 'Slow request',
        method:  req.method,
        path:    req.path,
        status:  res.statusCode,
        userId:  req.user?.id || null,
        ms,
        ip:      req.ip,
      });
    }
  });
  next();
});

// ── Routes ────────────────────────────────────────────────────────────────────

app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.use('/api/v1/auth',   authRouter);
app.use('/api/v1/kyc',    kycRouter);
app.use('/api/v1/wallet', walletRouter);
// Note: /api/v1/webhooks is registered above express.json() for raw body access

// 404 handler
app.use((_req, res) => {
  res.status(404).json({ success: false, error: 'Endpoint not found.' });
});

app.use(errorHandler);

// ── Startup ───────────────────────────────────────────────────────────────────

async function start() {
  try {
    await initSchema();
  } catch (err) {
    logger.error({ message: 'Failed to initialise database schema', error: err.message });
    process.exit(1);
  }

  const PORT = parseInt(process.env.PORT, 10) || 3000;
  app.listen(PORT, () => {
    logger.info({ message: `Wallet API listening on port ${PORT}`, env: process.env.NODE_ENV || 'development' });
  });
}

start();

module.exports = app;
