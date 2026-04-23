'use strict';

/**
 * Database Configuration — PostgreSQL via node-postgres (pg)
 *
 * Schema overview:
 *   users               — registered customers with encrypted PII
 *   kyc_documents       — KYC submissions (BVN, NIN, passport, etc.)
 *   wallets             — one wallet per user; tracks balance and limits
 *   wallet_transactions — immutable ledger of every credit/debit event
 *   refresh_tokens      — JWT refresh tokens (hashed, revocable)
 *   internal_accounts   — system ledger accounts (RECEIVABLE, PAYABLE)
 *   provider_transactions — gateway payment records (Paystack)
 *
 * Security:
 *   - All PII columns store AES-256-GCM ciphertext
 *   - Searchable fields (email, phone, BVN) store HMAC-SHA256 tokens only
 *   - Passwords stored as bcrypt hashes (never in plaintext)
 *   - Amounts stored as NUMERIC(15,2) — no floating-point drift
 */

require('dotenv').config();
const { Pool }       = require('pg');
const { logger }     = require('../utils/logger');

// ── Connection pool ───────────────────────────────────────────────────────────

const pool = new Pool({
  connectionString:        process.env.DATABASE_URL,
  max:                     10,
  idleTimeoutMillis:       30_000,
  connectionTimeoutMillis: 2_000,
  ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  logger.error({ message: 'Unexpected PostgreSQL pool error', error: err.message });
});

// ── Schema initialisation ─────────────────────────────────────────────────────

async function initSchema() {
  await pool.query(`
    -- ── users ─────────────────────────────────────────────────────────────────
    -- PII stored encrypted; HMAC tokens used for indexed lookups.
    CREATE TABLE IF NOT EXISTS users (
      id                   TEXT         PRIMARY KEY,
      email_token          TEXT         UNIQUE NOT NULL,   -- HMAC-SHA256 of email
      encrypted_email      TEXT         NOT NULL,          -- AES-256-GCM
      phone_token          TEXT         UNIQUE NOT NULL,   -- HMAC-SHA256 of phone
      encrypted_phone      TEXT         NOT NULL,          -- AES-256-GCM
      encrypted_first_name TEXT         NOT NULL,          -- AES-256-GCM
      encrypted_last_name  TEXT         NOT NULL,          -- AES-256-GCM
      date_of_birth        DATE,
      password_hash        TEXT         NOT NULL,          -- bcrypt (cost 12)
      kyc_status           TEXT         NOT NULL DEFAULT 'PENDING',
      kyc_level            INT          NOT NULL DEFAULT 0,
      is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
      created_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_at           TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_users_email_token ON users(email_token);
    CREATE INDEX IF NOT EXISTS idx_users_phone_token ON users(phone_token);

    ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE;

    -- ── kyc_documents ──────────────────────────────────────────────────────────
    -- One row per document type per user (unique constraint).
    -- Document numbers encrypted; HMAC token used for dedup checks.
    CREATE TABLE IF NOT EXISTS kyc_documents (
      id                        TEXT         PRIMARY KEY,
      user_id                   TEXT         NOT NULL REFERENCES users(id),
      document_type             TEXT         NOT NULL,   -- BVN|NIN|PASSPORT|DRIVERS_LICENSE
      document_token            TEXT         NOT NULL,   -- HMAC-SHA256 for dedup
      encrypted_document_number TEXT         NOT NULL,   -- AES-256-GCM
      verification_status       TEXT         NOT NULL DEFAULT 'PENDING',
      verified_at               TIMESTAMPTZ,
      rejection_reason          TEXT,
      created_at                TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      UNIQUE(user_id, document_type)
    );

    CREATE INDEX IF NOT EXISTS idx_kyc_user_id    ON kyc_documents(user_id);
    CREATE INDEX IF NOT EXISTS idx_kyc_doc_token  ON kyc_documents(document_token);

    -- ── wallets ────────────────────────────────────────────────────────────────
    -- One wallet per user; balance and rolling usage limits tracked here.
    -- daily_reset_at / monthly_reset_at drive lazy limit resets inside the
    -- wallet service (no background job required).
    CREATE TABLE IF NOT EXISTS wallets (
      id                   TEXT          PRIMARY KEY,
      user_id              TEXT          UNIQUE NOT NULL REFERENCES users(id),
      wallet_number        TEXT          UNIQUE NOT NULL,
      balance              NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      currency             TEXT          NOT NULL DEFAULT 'NGN',
      daily_debit_limit    NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      daily_credit_limit   NUMERIC(15,2) NOT NULL DEFAULT 1000000.00,
      monthly_debit_limit  NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      daily_debit_used     NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      daily_credit_used    NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      monthly_debit_used   NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      daily_reset_at       TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      monthly_reset_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      status               TEXT          NOT NULL DEFAULT 'ACTIVE',
      created_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      updated_at           TIMESTAMPTZ   NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_wallets_user_id       ON wallets(user_id);
    CREATE INDEX IF NOT EXISTS idx_wallets_wallet_number ON wallets(wallet_number);

    -- ── wallet_transactions ────────────────────────────────────────────────────
    -- Append-only ledger. Rows are never deleted or updated after SUCCESS.
    -- counterpart_wallet_id is set on transfer pairs.
    CREATE TABLE IF NOT EXISTS wallet_transactions (
      id                    TEXT          PRIMARY KEY,
      reference             TEXT          UNIQUE NOT NULL,
      wallet_id             TEXT          NOT NULL REFERENCES wallets(id),
      counterpart_wallet_id TEXT          REFERENCES wallets(id),
      type                  TEXT          NOT NULL,   -- CREDIT | DEBIT
      category              TEXT          NOT NULL,   -- FUNDING | WITHDRAWAL | TRANSFER_IN | TRANSFER_OUT
      amount                NUMERIC(15,2) NOT NULL,
      balance_before        NUMERIC(15,2) NOT NULL,
      balance_after         NUMERIC(15,2) NOT NULL,
      encrypted_narration   TEXT,
      status                TEXT          NOT NULL DEFAULT 'SUCCESS',
      metadata              JSONB,
      created_at            TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      processed_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_wt_wallet_id  ON wallet_transactions(wallet_id);
    CREATE INDEX IF NOT EXISTS idx_wt_reference  ON wallet_transactions(reference);
    CREATE INDEX IF NOT EXISTS idx_wt_created_at ON wallet_transactions(created_at);

    -- ── refresh_tokens ─────────────────────────────────────────────────────────
    -- Raw tokens are never stored — only SHA-256 hashes.
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id          TEXT         PRIMARY KEY,
      user_id     TEXT         NOT NULL REFERENCES users(id),
      token_hash  TEXT         UNIQUE NOT NULL,
      expires_at  TIMESTAMPTZ  NOT NULL,
      revoked     BOOLEAN      NOT NULL DEFAULT FALSE,
      created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_rt_user_id ON refresh_tokens(user_id);

    -- ── internal_accounts ──────────────────────────────────────────────────────
    -- System ledger accounts for double-entry bookkeeping.
    --   RECEIVABLE — tracks inflows from payment gateway (funding)
    --   PAYABLE    — tracks outflows to banks via payment gateway (withdrawal)
    CREATE TABLE IF NOT EXISTS internal_accounts (
      id         TEXT          PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
      type       TEXT          UNIQUE NOT NULL,   -- RECEIVABLE | PAYABLE
      balance    NUMERIC(15,2) NOT NULL DEFAULT 0.00,
      currency   TEXT          NOT NULL DEFAULT 'NGN',
      created_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ   NOT NULL DEFAULT NOW()
    );

    -- Seed the two internal accounts (idempotent)
    INSERT INTO internal_accounts (type) VALUES ('RECEIVABLE'), ('PAYABLE')
    ON CONFLICT (type) DO NOTHING;

    -- ── provider_transactions ──────────────────────────────────────────────────
    -- One row per gateway payment request (funding or withdrawal).
    -- status lifecycle:
    --   PENDING → SUCCESS | FAILED | REVERSED
    CREATE TABLE IF NOT EXISTS provider_transactions (
      id                 TEXT          PRIMARY KEY,
      type               TEXT          NOT NULL,              -- FUNDING | WITHDRAWAL
      user_id            TEXT          NOT NULL REFERENCES users(id),
      wallet_id          TEXT          NOT NULL REFERENCES wallets(id),
      amount             NUMERIC(15,2) NOT NULL,
      currency           TEXT          NOT NULL DEFAULT 'NGN',
      provider           TEXT          NOT NULL DEFAULT 'paystack',
      provider_reference TEXT          UNIQUE,                -- Paystack reference/transfer_code
      recipient_code     TEXT,                                -- Paystack recipient code (withdrawal)
      bank_code          TEXT,
      account_number     TEXT,
      account_name       TEXT,
      status             TEXT          NOT NULL DEFAULT 'PENDING',
      wallet_tx_id       TEXT          REFERENCES wallet_transactions(id),
      metadata           JSONB         NOT NULL DEFAULT '{}',
      created_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      updated_at         TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      completed_at       TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_pt_provider_reference ON provider_transactions(provider_reference);
    CREATE INDEX IF NOT EXISTS idx_pt_user_id            ON provider_transactions(user_id);
    CREATE INDEX IF NOT EXISTS idx_pt_status             ON provider_transactions(status);

    -- ── virtual_numbers ────────────────────────────────────────────────────────
    -- Tracks phone numbers purchased by users via external SMS providers.
    -- Supports multi-provider failover (SMS-Activate primary, 5SIM fallback).
    -- status lifecycle: PENDING → RECEIVED | CANCELLED | EXPIRED
    CREATE TABLE IF NOT EXISTS virtual_numbers (
      id                  TEXT          PRIMARY KEY,
      user_id             TEXT          NOT NULL REFERENCES users(id),
      wallet_id           TEXT          NOT NULL REFERENCES wallets(id),
      wallet_tx_id        TEXT          REFERENCES wallet_transactions(id),
      refund_tx_id        TEXT          REFERENCES wallet_transactions(id),

      phone_number        TEXT          NOT NULL,
      country_code        TEXT          NOT NULL,   -- NG | US | DE | GB
      country_name        TEXT          NOT NULL,
      service_code        TEXT          NOT NULL,   -- telegram | whatsapp | etc.
      service_name        TEXT          NOT NULL,

      provider            TEXT          NOT NULL,   -- sms_activate | five_sim
      provider_order_id   TEXT          NOT NULL,

      status              TEXT          NOT NULL DEFAULT 'PENDING',

      price_usd           NUMERIC(10,4) NOT NULL,
      price_ngn           NUMERIC(15,2) NOT NULL,
      exchange_rate       NUMERIC(10,2) NOT NULL,
      markup_percent      NUMERIC(5,2)  NOT NULL DEFAULT 0,

      sms_code            TEXT,
      sms_text            TEXT,
      sms_sender          TEXT,

      expires_at          TIMESTAMPTZ   NOT NULL,
      created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      updated_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
      completed_at        TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS idx_vn_user_id           ON virtual_numbers(user_id);
    CREATE INDEX IF NOT EXISTS idx_vn_provider_order_id ON virtual_numbers(provider_order_id);
    CREATE INDEX IF NOT EXISTS idx_vn_status            ON virtual_numbers(status);

    -- ── platform_settings ──────────────────────────────────────────────────────
    -- Admin-configurable key/value store for runtime settings.
    CREATE TABLE IF NOT EXISTS platform_settings (
      key         TEXT         PRIMARY KEY,
      value       TEXT         NOT NULL,
      description TEXT,
      updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
      updated_by  TEXT         REFERENCES users(id)
    );

    INSERT INTO platform_settings (key, value, description) VALUES
      ('usd_to_ngn_rate',        '1600', 'USD → NGN exchange rate used for virtual number pricing'),
      ('number_markup_percent',  '10',   'Platform markup % added on top of provider cost (e.g. 10 = 10%)')
    ON CONFLICT (key) DO NOTHING;
  `);

  logger.info({ message: 'Database schema initialised' });
}

module.exports = { pool, initSchema };
