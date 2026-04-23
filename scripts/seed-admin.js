'use strict';

/**
 * Seeds a fresh admin user into the database.
 *
 * Usage:
 *   node scripts/seed-admin.js
 *
 * Override defaults with env vars:
 *   ADMIN_EMAIL=me@example.com ADMIN_PASSWORD=Secret99! node scripts/seed-admin.js
 */

require('dotenv').config();

const { v4: uuidv4 }         = require('uuid');
const bcryptjs               = require('bcryptjs');
const { pool, initSchema }   = require('../src/config/database');
const { encrypt, hmacToken } = require('../src/services/encryption');

const EMAIL      = process.env.ADMIN_EMAIL    || 'admin@walletapp.com';
const PASSWORD   = process.env.ADMIN_PASSWORD || 'Admin1234!';
const FIRST_NAME = process.env.ADMIN_FIRST    || 'Admin';
const LAST_NAME  = process.env.ADMIN_LAST     || 'User';
const PHONE      = process.env.ADMIN_PHONE    || '+2340000000001';

async function main() {
  await initSchema();

  // Check for duplicate
  const existing = await pool.query(
    'SELECT id FROM users WHERE email_token = $1',
    [hmacToken(EMAIL)]
  );
  if (existing.rows.length > 0) {
    console.log(`Admin already exists with email: ${EMAIL}`);
    await pool.end();
    return;
  }

  const passwordHash = await bcryptjs.hash(PASSWORD, 12);
  const userId       = uuidv4();
  const walletId     = uuidv4();

  // Generate a readable wallet number: WLT + 10 digits
  const walletNumber = 'WLT' + Date.now().toString().slice(-10);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    await client.query(
      `INSERT INTO users
         (id, email_token, encrypted_email,
          phone_token, encrypted_phone,
          encrypted_first_name, encrypted_last_name,
          password_hash, is_admin, kyc_level, kyc_status, is_active)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,TRUE,3,'VERIFIED',TRUE)`,
      [
        userId,
        hmacToken(EMAIL),
        encrypt(EMAIL),
        hmacToken(PHONE),
        encrypt(PHONE),
        encrypt(FIRST_NAME),
        encrypt(LAST_NAME),
        passwordHash,
      ]
    );

    await client.query(
      `INSERT INTO wallets
         (id, user_id, wallet_number, balance, status,
          daily_debit_limit, monthly_debit_limit)
       VALUES ($1,$2,$3,0.00,'ACTIVE',1000000,10000000)`,
      [walletId, userId, walletNumber]
    );

    await client.query('COMMIT');

    console.log('');
    console.log('✓ Admin user created successfully');
    console.log('─────────────────────────────────');
    console.log(`  Email    : ${EMAIL}`);
    console.log(`  Password : ${PASSWORD}`);
    console.log(`  Wallet   : ${walletNumber}`);
    console.log(`  User ID  : ${userId}`);
    console.log('─────────────────────────────────');
    console.log('');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  await pool.end();
}

main().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
