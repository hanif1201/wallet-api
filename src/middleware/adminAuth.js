'use strict';

const { pool }    = require('../config/database');
const { jwtAuth } = require('./jwtAuth');

/**
 * Admin middleware — verifies JWT then checks is_admin flag.
 * Applied to all /api/v1/admin/* routes.
 */
async function adminAuth(req, res, next) {
  // Reuse JWT verification
  jwtAuth(req, res, async (err) => {
    if (err) return next(err);

    try {
      const { rows } = await pool.query(
        'SELECT is_admin FROM users WHERE id = $1',
        [req.user.id]
      );

      if (!rows[0]?.is_admin) {
        return res.status(403).json({ success: false, error: 'Admin access required.' });
      }

      next();
    } catch (dbErr) {
      next(dbErr);
    }
  });
}

module.exports = { adminAuth };
