'use strict';

/**
 * KYC Verification Service
 *
 * In production this service would call an external identity provider
 * (e.g. NIBSS for BVN, NIMC for NIN, Smile Identity, Onfido, etc.).
 *
 * For this project the verification is simulated with rule-based checks
 * that mirror real-world format validation:
 *   BVN  — exactly 11 digits (NIBSS format)
 *   NIN  — exactly 11 digits (NIMC format)
 *   PASSPORT        — 9-char alphanumeric
 *   DRIVERS_LICENSE — 12-char alphanumeric
 *
 * KYC Levels and limits unlocked:
 * ┌───────┬─────────────────────────────┬──────────────────┬──────────────────┐
 * │ Level │ Requirements                │ Daily debit      │ Monthly debit    │
 * ├───────┼─────────────────────────────┼──────────────────┼──────────────────┤
 * │   0   │ Just registered             │ NGN 0 (no debit) │ NGN 0            │
 * │   1   │ BVN verified                │ NGN 50,000       │ NGN 200,000      │
 * │   2   │ NIN verified                │ NGN 200,000      │ NGN 1,000,000    │
 * │   3   │ Passport or Driver's Lic.   │ NGN 1,000,000    │ NGN 5,000,000    │
 * └───────┴─────────────────────────────┴──────────────────┴──────────────────┘
 */

const DOCUMENT_RULES = {
  BVN: {
    pattern:     /^\d{11}$/,
    description: 'BVN must be exactly 11 digits.',
    levelGrant:  1,
  },
  NIN: {
    pattern:     /^\d{11}$/,
    description: 'NIN must be exactly 11 digits.',
    levelGrant:  2,
  },
  PASSPORT: {
    pattern:     /^[A-Z]{1}[0-9]{8}$/i,
    description: 'Passport number must be 1 letter followed by 8 digits.',
    levelGrant:  3,
  },
  DRIVERS_LICENSE: {
    pattern:     /^[A-Z0-9]{12}$/i,
    description: "Driver's licence must be exactly 12 alphanumeric characters.",
    levelGrant:  3,
  },
};

// Wallet limits indexed by KYC level
const LIMITS_BY_LEVEL = {
  0: { dailyDebit: 0,          monthlyDebit: 0 },
  1: { dailyDebit: 50_000,     monthlyDebit: 200_000 },
  2: { dailyDebit: 200_000,    monthlyDebit: 1_000_000 },
  3: { dailyDebit: 1_000_000,  monthlyDebit: 5_000_000 },
};

/**
 * Validate document format and simulate the remote identity check.
 *
 * @param {string} documentType   — one of BVN | NIN | PASSPORT | DRIVERS_LICENSE
 * @param {string} documentNumber — raw document number (will be validated)
 * @returns {{ valid: boolean, reason?: string }}
 */
function verifyDocument(documentType, documentNumber) {
  const rule = DOCUMENT_RULES[documentType];
  if (!rule) {
    return { valid: false, reason: `Unsupported document type: ${documentType}` };
  }

  if (!rule.pattern.test(documentNumber.trim())) {
    return { valid: false, reason: rule.description };
  }

  // Simulate remote check — in production, replace with actual API call.
  // Rejection condition: documents starting with all zeros are flagged invalid.
  if (/^0+$/.test(documentNumber.trim())) {
    return { valid: false, reason: 'Document number could not be verified with the issuing authority.' };
  }

  return { valid: true };
}

/**
 * Return the new KYC level a user should receive after a document is verified.
 * The level can only go up, never down.
 *
 * @param {number} currentLevel
 * @param {string} documentType
 * @returns {number}
 */
function computeNewLevel(currentLevel, documentType) {
  const rule = DOCUMENT_RULES[documentType];
  if (!rule) return currentLevel;
  return Math.max(currentLevel, rule.levelGrant);
}

/**
 * Return the wallet limits object for a given KYC level.
 * @param {number} level
 * @returns {{ dailyDebit: number, monthlyDebit: number }}
 */
function limitsForLevel(level) {
  return LIMITS_BY_LEVEL[level] || LIMITS_BY_LEVEL[0];
}

module.exports = { verifyDocument, computeNewLevel, limitsForLevel, DOCUMENT_RULES };
