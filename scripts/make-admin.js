'use strict';

/**
 * Promote a user to admin by email.
 * Usage: node scripts/make-admin.js user@email.com
 */

require('dotenv').config();
const { pool }      = require('../src/config/database');
const { hmacToken } = require('../src/services/encryption');

async function main() {
  const email = process.argv[2];
  if (!email) {
    console.error('Usage: node scripts/make-admin.js user@email.com');
    process.exit(1);
  }

  const token = hmacToken(email);
  const { rowCount } = await pool.query(
    `UPDATE users SET is_admin = TRUE, updated_at = NOW() WHERE email_token = $1`,
    [token]
  );

  if (rowCount === 0) {
    console.error(`No user found with email: ${email}`);
    process.exit(1);
  }

  console.log(`✓ ${email} is now an admin.`);
  await pool.end();
}

main().catch(err => { console.error(err.message); process.exit(1); });
