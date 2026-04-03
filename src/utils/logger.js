'use strict';

/**
 * Winston logger — structured JSON output.
 *
 * Sensitive data policy:
 *   - Never log passwords, tokens, or decrypted PII.
 *   - Use masked values (e.g., email hints) in audit entries where needed.
 *   - Log files are rotated daily and kept for 30 days.
 */

const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const { Logtail } = require('@logtail/node');
const { LogtailTransport } = require('@logtail/winston');
const path = require('path');

const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '../../logs');

const { combine, timestamp, json, colorize, simple } = winston.format;

// Console transport (dev: human-readable, prod: JSON)
const consoleTransport = new winston.transports.Console({
  format: process.env.NODE_ENV === 'production'
    ? combine(timestamp(), json())
    : combine(colorize(), simple()),
});

// BetterStack telemetry transport
const logtail = new Logtail(process.env.BETTERSTACK_TOKEN);
const logtailTransport = new LogtailTransport(logtail);

// Rotating file transports
const fileTransport = new DailyRotateFile({
  dirname:      LOG_DIR,
  filename:     'wallet-api-%DATE%.log',
  datePattern:  'YYYY-MM-DD',
  maxFiles:     '30d',
  zippedArchive: true,
  format:       combine(timestamp(), json()),
  level:        'info',
});

const errorFileTransport = new DailyRotateFile({
  dirname:      LOG_DIR,
  filename:     'wallet-api-error-%DATE%.log',
  datePattern:  'YYYY-MM-DD',
  maxFiles:     '30d',
  zippedArchive: true,
  format:       combine(timestamp(), json()),
  level:        'error',
});

const logger = winston.createLogger({
  level:      process.env.LOG_LEVEL || 'info',
  transports: [consoleTransport, fileTransport, errorFileTransport, logtailTransport],
  // Never let an uncaught logger error crash the process
  exitOnError: false,
});

module.exports = { logger };
