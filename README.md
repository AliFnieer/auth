# Auth Service

A robust, secure, and feature-rich authentication service built with Express.js, Prisma ORM and PostgreSQL. This repository provides a reusable authentication backend with support for user registration, login, JWT access/refresh tokens, email verification, and password reset flows.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E=_18-brightgreen)
![Status](https://img.shields.io/badge/status-development-yellow)

Table of contents

- [Auth Service](#auth-service)
  - [Features](#features)
  - [Quick Start](#quick-start)
  - [Environment Variables](#environment-variables)
  - [Running PostgreSQL with Docker Compose](#running-postgresql-with-docker-compose)
  - [Database / Prisma](#database--prisma)
  - [Scripts](#scripts)
  - [Testing](#testing)
  - [API Endpoints (overview)](#api-endpoints-overview)
  - [Contributing](#contributing)
  - [Security](#security)
  - [License](#license)

## Features

- User registration and login (email/password)
- JWT access tokens and refresh tokens with secure storage
- Email verification and password reset via SMTP
- Middleware for authentication and basic authorization
- Prisma ORM with migrations
- Unit and integration tests

## Quick Start


1. Clone the repository:

```bash
git clone https://github.com/AliFnieer/auth.git
cd auth
```

1. Install dependencies:

```bash
npm install
```

1. Copy the example environment file and fill in real values:

```bash
cp .env.example .env
# Edit .env and set secrets, DB URL and SMTP credentials
```

1. Start a PostgreSQL instance (recommended) using Docker Compose (see below), or ensure a PostgreSQL server is available and `DATABASE_URL` points to it.

1. Run Prisma migrations to prepare the database:

```bash
npx prisma migrate deploy
```

1. Start the app:

```bash
npm start
```

The service listens on `PORT` (default `3000`).

## Environment Variables

All environment variables are listed in `.env.example`. Important variables:

- `DATABASE_URL` — Postgres connection string, e.g. `postgresql://user:pass@localhost:5432/auth_db?schema=public`
- `PORT` — HTTP port (default `3000`)
- `NODE_ENV` — `development` or `production`
- `JWT_SECRET` — Secret for signing JWTs (set to a strong random value)
- `JWT_ACCESS_EXPIRY` — Access token expiry (e.g. `15m`)
- `JWT_REFRESH_EXPIRY` — Refresh token expiry (e.g. `7d`)
- `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USER`, `EMAIL_PASS`, `SMTP_FROM` — SMTP settings used to send emails

Refer to `.env.example` for a complete template developers can copy.

## Running PostgreSQL with Docker Compose

A `docker-compose.yml` is included for local development. It creates a single PostgreSQL service.

Bring it up:

```bash
docker compose up -d
```

After the database is ready, update your `.env` `DATABASE_URL` if needed and run migrations.

To stop and remove the database container:

```bash
docker compose down -v
```

## Database / Prisma

- Schema is defined in `prisma/schema.prisma`.
- Generate or update the Prisma client after schema changes:

```bash
npx prisma generate
```

- Create a new migration during development:

```bash
npx prisma migrate dev --name add_something
```

## Scripts

- `npm start` — Run the server
- `npm run dev` — Run the server in development mode (if available)
- `npm test` — Run tests
- `npx prisma studio` — Open Prisma Studio to inspect the database

## Testing

Tests are located under the `tests/` directory. Run the test suite with:

```bash
npm test
```

## API Endpoints (overview)

This repo focuses on authentication-related endpoints. Example routes (adjust per implementation):

- `POST /auth/register` — Register a new user
- `POST /auth/login` — Authenticate and receive access + refresh tokens
- `POST /auth/refresh` — Exchange refresh token for a new access token
- `POST /auth/logout` — Revoke refresh token
- `POST /auth/forgot-password` — Start password reset flow
- `POST /auth/reset-password` — Finish password reset
- `GET /auth/verify-email?token=...` — Verify email address

For exact request/response formats, consult the controllers in `controllers/` and the tests in `tests/` for examples.

## Contributing

Contributions are welcome. Suggested workflow:

1. Fork the repo.
2. Create a feature branch: `git checkout -b feat/your-feature`.
3. Add tests for your changes.
4. Open a pull request describing the change and motivation.

Please keep changes focused and add tests for new behavior.

## Security

- Keep `JWT_SECRET` and SMTP credentials out of source control — use `.env` and secrets management.
- Revoke or rotate tokens if you suspect a leak.
- If you discover a security issue, please open a private issue describing the problem and mitigation steps.

## License

This project includes a `LICENSE` file. Ensure you review licensing before publishing.

---