# Wallet API

A production-grade digital wallet REST API built with Node.js and PostgreSQL. It handles user onboarding with KYC compliance, encrypted PII storage, wallet funding and transfers via Paystack, and virtual phone number provisioning through third-party SMS providers.

## Features

- **Authentication** — JWT-based auth (short-lived access tokens + refresh tokens), bcrypt password hashing, role-based admin access.
- **KYC compliance** — document submission and review workflow (BVN, NIN, ID uploads) with an admin approval pipeline.
- **Wallet operations** — funding via Paystack, bank transfers, withdrawals, debits, and a full transaction ledger with idempotent, race-safe balance updates (`SELECT … FOR UPDATE`).
- **Virtual numbers** — purchase temporary phone numbers for SMS verification through 5SIM (primary) with automatic fallback to SMS-Man, including live country/service pricing.
- **Admin dashboard API** — user management, transaction oversight, KYC review, platform settings, and provider transaction visibility.
- **Security-first design** — see [Security](#security) below.
- **Structured observability** — Winston logging with daily rotation and optional BetterStack (Logtail) shipping.

## Tech Stack

| Layer          | Choice                                   |
| -------------- | ----------------------------------------- |
| Runtime        | Node.js 18+ / Express                     |
| Database       | PostgreSQL                                |
| Auth           | JWT (HS256), bcrypt                       |
| Validation     | Joi                                       |
| Payments       | Paystack                                  |
| Virtual numbers| 5SIM, SMS-Man                             |
| Logging        | Winston + winston-daily-rotate-file, BetterStack |
| Containerization| Docker / Docker Compose                  |

## API Overview

```
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh
POST   /api/v1/auth/logout
GET    /api/v1/auth/me

POST   /api/v1/kyc/submit
GET    /api/v1/kyc/status
GET    /api/v1/kyc/documents

GET    /api/v1/wallet
POST   /api/v1/wallet/fund
GET    /api/v1/wallet/fund/callback
POST   /api/v1/wallet/debit
POST   /api/v1/wallet/transfer
POST   /api/v1/wallet/withdraw
GET    /api/v1/wallet/banks
POST   /api/v1/wallet/resolve-account
GET    /api/v1/wallet/transactions
GET    /api/v1/wallet/transactions/:reference

GET    /api/v1/numbers/countries
GET    /api/v1/numbers/services
GET    /api/v1/numbers/price
POST   /api/v1/numbers/purchase
GET    /api/v1/numbers
GET    /api/v1/numbers/:id
POST   /api/v1/numbers/:id/cancel

POST   /api/v1/webhooks/paystack

GET    /api/v1/admin/stats
GET    /api/v1/admin/users
GET    /api/v1/admin/users/:id
PATCH  /api/v1/admin/users/:id/status
GET    /api/v1/admin/transactions
GET    /api/v1/admin/kyc
PATCH  /api/v1/admin/kyc/:userId/:documentType/review
GET    /api/v1/admin/accounts
GET    /api/v1/admin/settings
PUT    /api/v1/admin/settings
GET    /api/v1/admin/virtual-numbers
GET    /api/v1/admin/provider-transactions

GET    /health
```

## Security

| Control                | Mechanism                                          |
| ----------------------- | --------------------------------------------------- |
| Secure HTTP headers     | Helmet (CSP, HSTS, X-Frame-Options, …)              |
| Rate limiting           | `express-rate-limit` (global + per-route groups)    |
| Authentication          | JWT (HS256, 15-min access / 7-day refresh)          |
| Password hashing        | bcrypt (cost 12)                                    |
| Input validation        | Joi schemas on every route                          |
| PII encryption at rest  | AES-256-GCM on all sensitive columns                |
| Indexed encrypted lookups | HMAC-SHA256 tokens (email, phone, BVN, NIN)       |
| Race condition safety   | `SELECT … FOR UPDATE` on wallet balance updates      |
| Audit logging           | Winston structured JSON logs, daily rotation        |
| Secrets management      | Environment variables only (never committed)        |
| Webhook verification    | Paystack HMAC-SHA512 signature check on raw body    |

## Getting Started

### Prerequisites

- Node.js >= 18
- PostgreSQL >= 14 (or use the provided Docker Compose setup)
- API keys for [Paystack](https://paystack.com), [5SIM](https://5sim.net), and [SMS-Man](https://sms-man.com)

### Local setup

```bash
git clone <repo-url>
cd wallet-api
npm install
cp .env.example .env
```

Generate the required encryption secrets and populate `.env`:

```bash
node scripts/setup.js
```

Fill in the remaining values in `.env` (database URL, Paystack keys, provider API keys — see `.env.example` for the full list).

Start PostgreSQL and the API:

```bash
# Option A — Docker Compose (Postgres + API)
docker-compose up --build

# Option B — local Postgres already running
npm run dev
```

The database schema is created automatically on startup (`initSchema()` in `src/config/database.js`).

### Creating an admin user

```bash
node scripts/seed-admin.js
# or
node scripts/make-admin.js <email>
```

## Project Structure

```
src/
├── app.js                # Express app setup, security middleware, startup
├── config/
│   └── database.js       # PG pool + schema initialization
├── middleware/
│   ├── jwtAuth.js         # Access-token verification
│   ├── adminAuth.js       # Role-gated admin routes
│   ├── rateLimiter.js     # Global + per-route rate limits
│   └── errorHandler.js    # Centralized error responses
├── routes/                # auth, kyc, wallet, numbers, admin, webhooks
├── services/
│   ├── encryption.js      # AES-256-GCM + HMAC-SHA256 helpers
│   ├── walletService.js   # Balance, ledger, transfer logic
│   ├── kycService.js      # Document submission/review logic
│   ├── paystackService.js # Funding, transfers, account resolution
│   ├── phoneNumberService.js
│   └── providers/         # 5SIM and SMS-Man integrations
└── utils/
    └── logger.js          # Winston logger (console, file, BetterStack)

scripts/
├── setup.js               # Generates .env secrets
├── seed-admin.js          # Seeds a default admin account
└── make-admin.js          # Promotes an existing user to admin
```

## Environment Variables

See [.env.example](.env.example) for the full list, including database, encryption, JWT, Paystack, virtual number provider, and CORS configuration. Never commit a populated `.env` file.

## License

Private / proprietary — all rights reserved.
