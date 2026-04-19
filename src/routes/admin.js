'use strict';

/**
 * Admin Routes — internal operations dashboard
 *
 * All routes require a valid JWT from an admin user (is_admin = true).
 *
 * GET  /api/v1/admin/stats                  — dashboard overview stats
 * GET  /api/v1/admin/users                  — paginated user list with wallet balances
 * GET  /api/v1/admin/users/:id              — single user detail
 * PATCH /api/v1/admin/users/:id/status      — activate / deactivate user
 * GET  /api/v1/admin/transactions           — all wallet transactions
 * GET  /api/v1/admin/kyc                    — all KYC submissions
 * GET  /api/v1/admin/accounts               — internal RECEIVABLE/PAYABLE balances
 * GET  /api/v1/admin/provider-transactions  — all Paystack provider transactions
 */

const express = require('express');

const { pool }                              = require('../config/database');
const { decrypt }                           = require('../services/encryption');
const { computeNewLevel, limitsForLevel }   = require('../services/kycService');
const { adminAuth }                         = require('../middleware/adminAuth');
const { logger }                            = require('../utils/logger');

const router = express.Router();

router.use(adminAuth);

// ── GET /stats ────────────────────────────────────────────────────────────────

router.get('/stats', async (_req, res, next) => {
  try {
    const [
      usersRow,
      balanceRow,
      txRow,
      kycRow,
      todayFundRow,
      todayWithdrawRow,
      accountsRow,
    ] = await Promise.all([
      pool.query(`SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE is_active) AS active FROM users WHERE is_admin = FALSE`),
      pool.query(`SELECT COALESCE(SUM(balance), 0) AS total FROM wallets`),
      pool.query(`SELECT COUNT(*) AS total FROM wallet_transactions`),
      pool.query(`SELECT COUNT(*) AS pending FROM users WHERE kyc_status = 'PENDING' AND is_admin = FALSE`),
      pool.query(`SELECT COALESCE(SUM(amount), 0) AS total FROM wallet_transactions WHERE category = 'FUNDING' AND created_at >= NOW() - INTERVAL '1 day'`),
      pool.query(`SELECT COALESCE(SUM(amount), 0) AS total FROM wallet_transactions WHERE category = 'WITHDRAWAL' AND created_at >= NOW() - INTERVAL '1 day'`),
      pool.query(`SELECT type, balance FROM internal_accounts`),
    ]);

    const accounts = {};
    accountsRow.rows.forEach(r => { accounts[r.type] = parseFloat(r.balance); });

    return res.json({
      success: true,
      stats: {
        totalUsers:        parseInt(usersRow.rows[0].total),
        activeUsers:       parseInt(usersRow.rows[0].active),
        totalWalletBalance: parseFloat(balanceRow.rows[0].total),
        totalTransactions:  parseInt(txRow.rows[0].total),
        pendingKYC:         parseInt(kycRow.rows[0].pending),
        todayFunding:       parseFloat(todayFundRow.rows[0].total),
        todayWithdrawals:   parseFloat(todayWithdrawRow.rows[0].total),
        receivableBalance:  accounts.RECEIVABLE || 0,
        payableBalance:     accounts.PAYABLE    || 0,
      },
    });
  } catch (err) {
    return next(err);
  }
});

// ── GET /users ────────────────────────────────────────────────────────────────

router.get('/users', async (req, res, next) => {
  const page   = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit  = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset = (page - 1) * limit;
  const search = req.query.search?.trim();

  try {
    // Build query — search by decrypted email is not possible without scanning all rows,
    // so we search by HMAC token if search looks like an email, otherwise by name partial
    const usersQuery = `
      SELECT u.id, u.encrypted_email, u.encrypted_first_name, u.encrypted_last_name,
             u.encrypted_phone, u.kyc_status, u.kyc_level, u.is_active, u.created_at,
             w.balance, w.wallet_number, w.status AS wallet_status
      FROM users u
      LEFT JOIN wallets w ON w.user_id = u.id
      WHERE u.is_admin = FALSE
      ORDER BY u.created_at DESC
      LIMIT $1 OFFSET $2
    `;

    const countQuery = `SELECT COUNT(*) AS total FROM users WHERE is_admin = FALSE`;

    const [usersRes, countRes] = await Promise.all([
      pool.query(usersQuery, [limit, offset]),
      pool.query(countQuery),
    ]);

    const users = usersRes.rows.map(u => ({
      id:            u.id,
      email:         decrypt(u.encrypted_email),
      firstName:     decrypt(u.encrypted_first_name),
      lastName:      decrypt(u.encrypted_last_name),
      phone:         decrypt(u.encrypted_phone),
      kycStatus:     u.kyc_status,
      kycLevel:      u.kyc_level,
      isActive:      u.is_active,
      walletBalance: parseFloat(u.balance || 0),
      walletNumber:  u.wallet_number,
      walletStatus:  u.wallet_status,
      createdAt:     u.created_at,
    }));

    const total = parseInt(countRes.rows[0].total);

    return res.json({
      success: true,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      users,
    });
  } catch (err) {
    return next(err);
  }
});

// ── GET /users/:id ────────────────────────────────────────────────────────────

router.get('/users/:id', async (req, res, next) => {
  try {
    const { rows: userRows } = await pool.query(
      `SELECT u.*, w.id AS wallet_id, w.balance, w.wallet_number, w.status AS wallet_status,
              w.daily_debit_limit, w.daily_debit_used, w.daily_credit_limit,
              w.monthly_debit_limit, w.monthly_debit_used
       FROM users u
       LEFT JOIN wallets w ON w.user_id = u.id
       WHERE u.id = $1`,
      [req.params.id]
    );

    const u = userRows[0];
    if (!u) return res.status(404).json({ success: false, error: 'User not found.' });

    const { rows: kycRows } = await pool.query(
      `SELECT document_type, verification_status, verified_at, rejection_reason, created_at
       FROM kyc_documents WHERE user_id = $1 ORDER BY created_at DESC`,
      [req.params.id]
    );

    const { rows: txRows } = await pool.query(
      `SELECT id, reference, type, category, amount, balance_before, balance_after, status, created_at
       FROM wallet_transactions WHERE wallet_id = $1 ORDER BY created_at DESC LIMIT 10`,
      [u.wallet_id]
    );

    return res.json({
      success: true,
      user: {
        id:          u.id,
        email:       decrypt(u.encrypted_email),
        firstName:   decrypt(u.encrypted_first_name),
        lastName:    decrypt(u.encrypted_last_name),
        phone:       decrypt(u.encrypted_phone),
        dateOfBirth: u.date_of_birth,
        kycStatus:   u.kyc_status,
        kycLevel:    u.kyc_level,
        isActive:    u.is_active,
        createdAt:   u.created_at,
        wallet: {
          id:              u.wallet_id,
          walletNumber:    u.wallet_number,
          balance:         parseFloat(u.balance || 0),
          status:          u.wallet_status,
          dailyDebitLimit: parseFloat(u.daily_debit_limit || 0),
          dailyDebitUsed:  parseFloat(u.daily_debit_used  || 0),
        },
        kycDocuments:     kycRows,
        recentTransactions: txRows.map(t => ({
          ...t,
          amount:        parseFloat(t.amount),
          balanceBefore: parseFloat(t.balance_before),
          balanceAfter:  parseFloat(t.balance_after),
        })),
      },
    });
  } catch (err) {
    return next(err);
  }
});

// ── PATCH /users/:id/status ───────────────────────────────────────────────────

router.patch('/users/:id/status', async (req, res, next) => {
  const { status } = req.body;
  if (!['active', 'suspended'].includes(status)) {
    return res.status(400).json({ success: false, error: 'status must be "active" or "suspended".' });
  }

  try {
    const isActive = status === 'active';
    const { rowCount } = await pool.query(
      `UPDATE users SET is_active = $1, updated_at = NOW() WHERE id = $2 AND is_admin = FALSE`,
      [isActive, req.params.id]
    );

    if (rowCount === 0) return res.status(404).json({ success: false, error: 'User not found.' });

    logger.info({ message: `User ${status}`, targetUserId: req.params.id, adminId: req.user.id });

    return res.json({ success: true, message: `User ${status} successfully.` });
  } catch (err) {
    return next(err);
  }
});

// ── GET /transactions ─────────────────────────────────────────────────────────

router.get('/transactions', async (req, res, next) => {
  const page     = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit    = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset   = (page - 1) * limit;
  const category = req.query.category;
  const type     = req.query.type;
  const status   = req.query.status;

  try {
    const conditions = [];
    const params     = [];
    let   pIdx       = 1;

    if (category) { conditions.push(`wt.category = $${pIdx++}`); params.push(category.toUpperCase()); }
    if (type)     { conditions.push(`wt.type = $${pIdx++}`);     params.push(type.toUpperCase()); }
    if (status)   { conditions.push(`wt.status = $${pIdx++}`);   params.push(status.toUpperCase()); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [txRes, countRes] = await Promise.all([
      pool.query(
        `SELECT wt.id, wt.reference, wt.type, wt.category, wt.amount,
                wt.balance_before, wt.balance_after, wt.status, wt.created_at,
                w.wallet_number, w.user_id
         FROM wallet_transactions wt
         JOIN wallets w ON w.id = wt.wallet_id
         ${where}
         ORDER BY wt.created_at DESC
         LIMIT $${pIdx} OFFSET $${pIdx + 1}`,
        [...params, limit, offset]
      ),
      pool.query(`SELECT COUNT(*) AS total FROM wallet_transactions wt ${where}`, params),
    ]);

    const total = parseInt(countRes.rows[0].total);

    return res.json({
      success: true,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      transactions: txRes.rows.map(t => ({
        id:            t.id,
        reference:     t.reference,
        type:          t.type,
        category:      t.category,
        amount:        parseFloat(t.amount),
        balanceBefore: parseFloat(t.balance_before),
        balanceAfter:  parseFloat(t.balance_after),
        status:        t.status,
        walletNumber:  t.wallet_number,
        userId:        t.user_id,
        createdAt:     t.created_at,
      })),
    });
  } catch (err) {
    return next(err);
  }
});

// ── GET /kyc ──────────────────────────────────────────────────────────────────

router.get('/kyc', async (req, res, next) => {
  const page   = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit  = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset = (page - 1) * limit;
  const status = req.query.status;

  try {
    const conditions = status ? [`kd.verification_status = $1`] : [];
    const params     = status ? [status.toUpperCase()] : [];
    const where      = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const pIdx = params.length + 1;

    const [kycRes, countRes] = await Promise.all([
      pool.query(
        `SELECT kd.id, kd.user_id, kd.document_type, kd.verification_status,
                kd.encrypted_document_number, kd.verified_at, kd.rejection_reason, kd.created_at,
                u.encrypted_first_name, u.encrypted_last_name, u.encrypted_email
         FROM kyc_documents kd
         JOIN users u ON u.id = kd.user_id
         ${where}
         ORDER BY kd.created_at DESC
         LIMIT $${pIdx} OFFSET $${pIdx + 1}`,
        [...params, limit, offset]
      ),
      pool.query(`SELECT COUNT(*) AS total FROM kyc_documents kd ${where}`, params),
    ]);

    return res.json({
      success: true,
      pagination: { page, limit, total: parseInt(countRes.rows[0].total), pages: Math.ceil(parseInt(countRes.rows[0].total) / limit) },
      kyc: kycRes.rows.map(k => ({
        id:                 k.id,
        userId:             k.user_id,
        firstName:          decrypt(k.encrypted_first_name),
        lastName:           decrypt(k.encrypted_last_name),
        email:              decrypt(k.encrypted_email),
        documentType:       k.document_type,
        documentNumber:     decrypt(k.encrypted_document_number),
        verificationStatus: k.verification_status,
        verifiedAt:         k.verified_at,
        rejectionReason:    k.rejection_reason,
        submittedAt:        k.created_at,
      })),
    });
  } catch (err) {
    return next(err);
  }
});

// ── PATCH /kyc/:userId/:documentType/review ───────────────────────────────────

router.patch('/kyc/:userId/:documentType/review', async (req, res, next) => {
  const { userId, documentType } = req.params;
  const { action, reason }       = req.body;

  if (!['approve', 'reject'].includes(action)) {
    return res.status(400).json({ success: false, error: 'action must be "approve" or "reject".' });
  }
  if (action === 'reject' && !reason?.trim()) {
    return res.status(400).json({ success: false, error: 'reason is required when rejecting.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (action === 'approve') {
      // Mark document as verified
      await client.query(
        `UPDATE kyc_documents
         SET verification_status = 'VERIFIED', verified_at = NOW(), rejection_reason = NULL
         WHERE user_id = $1 AND document_type = $2`,
        [userId, documentType]
      );

      // Compute new KYC level
      const { rows: userRows } = await client.query(
        'SELECT kyc_level FROM users WHERE id = $1', [userId]
      );
      const currentLevel = userRows[0]?.kyc_level ?? 0;
      const newLevel     = computeNewLevel(currentLevel, documentType);
      const limits       = limitsForLevel(newLevel);

      await client.query(
        `UPDATE users SET kyc_level = $1, kyc_status = 'VERIFIED', updated_at = NOW() WHERE id = $2`,
        [newLevel, userId]
      );
      await client.query(
        `UPDATE wallets SET daily_debit_limit = $1, monthly_debit_limit = $2, updated_at = NOW() WHERE user_id = $3`,
        [limits.dailyDebit, limits.monthlyDebit, userId]
      );

      logger.info({ message: 'KYC approved', targetUserId: userId, documentType, newLevel, adminId: req.user.id });
    } else {
      await client.query(
        `UPDATE kyc_documents
         SET verification_status = 'REJECTED', verified_at = NULL, rejection_reason = $1
         WHERE user_id = $2 AND document_type = $3`,
        [reason.trim(), userId, documentType]
      );
      await client.query(
        `UPDATE users SET kyc_status = 'REJECTED', updated_at = NOW() WHERE id = $1`,
        [userId]
      );

      logger.info({ message: 'KYC rejected', targetUserId: userId, documentType, reason, adminId: req.user.id });
    }

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    return next(err);
  } finally {
    client.release();
  }

  return res.json({ success: true, message: `KYC ${action}d successfully.` });
});

// ── GET /accounts ─────────────────────────────────────────────────────────────

router.get('/accounts', async (_req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT type, balance, currency, updated_at FROM internal_accounts ORDER BY type`
    );

    return res.json({
      success:  true,
      accounts: rows.map(a => ({
        type:      a.type,
        balance:   parseFloat(a.balance),
        currency:  a.currency,
        updatedAt: a.updated_at,
      })),
    });
  } catch (err) {
    return next(err);
  }
});

// ── GET /provider-transactions ────────────────────────────────────────────────

router.get('/provider-transactions', async (req, res, next) => {
  const page   = Math.max(1, parseInt(req.query.page,  10) || 1);
  const limit  = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const offset = (page - 1) * limit;
  const type   = req.query.type;
  const status = req.query.status;

  try {
    const conditions = [];
    const params     = [];
    let   pIdx       = 1;

    if (type)   { conditions.push(`type = $${pIdx++}`);   params.push(type.toUpperCase()); }
    if (status) { conditions.push(`status = $${pIdx++}`); params.push(status.toUpperCase()); }

    const where = conditions.length ? `WHERE ${conditions.join(' AND ')}` : '';

    const [ptRes, countRes] = await Promise.all([
      pool.query(
        `SELECT id, type, user_id, amount, currency, provider, provider_reference,
                bank_code, account_number, account_name, status, created_at, completed_at
         FROM provider_transactions ${where}
         ORDER BY created_at DESC LIMIT $${pIdx} OFFSET $${pIdx + 1}`,
        [...params, limit, offset]
      ),
      pool.query(`SELECT COUNT(*) AS total FROM provider_transactions ${where}`, params),
    ]);

    return res.json({
      success: true,
      pagination: { page, limit, total: parseInt(countRes.rows[0].total), pages: Math.ceil(parseInt(countRes.rows[0].total) / limit) },
      providerTransactions: ptRes.rows.map(p => ({
        ...p,
        amount: parseFloat(p.amount),
      })),
    });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
