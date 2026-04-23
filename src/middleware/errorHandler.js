'use strict';

/**
 * Centralised Express error handler.
 *
 * Security: Stack traces and internal details are never sent to the client.
 * All errors are logged internally with full context.
 */

const { logger } = require('../utils/logger');

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
  const status = err.status || err.statusCode || 500;

  logger.error({
    message: 'Unhandled error',
    error:   err.message,
    stack:   err.stack,
    path:    req.path,
    method:  req.method,
    userId:  req.user?.id || null,
    ip:      req.ip,
  });

  // 503 (provider unavailable) is safe to surface — it carries user-facing context
  const expose = status < 500 || status === 503;
  res.status(status).json({
    success: false,
    error: expose ? err.message : 'An internal server error occurred.',
  });
}

module.exports = { errorHandler };
