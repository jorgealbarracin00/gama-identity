# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - Unreleased

### Added

- PostgreSQL repositories for Human Identity, Email Credential, and Session
- Versioned, repeatable, checksum-verified database migrations
- Pooled PostgreSQL connection management and graceful shutdown
- Atomic PostgreSQL registration transactions
- Configurable `memory` and `postgres` repository modes
- Railway `DATABASE_URL` integration and optional SSL configuration
- Database-aware health reporting
- PostgreSQL integration, migration, transaction, and configuration tests
- Local PostgreSQL, Railway deployment, and release documentation

### Changed

- Service version advanced to 1.1.0
- Health responses now include non-sensitive database connectivity status
- Production startup now fails before listening when PostgreSQL is unavailable
  or migrations cannot be applied

## [1.0.0]

### Added

- Human Identity domain
- Email and Password Credential domain
- Authentication engine
- Session management
- Registration orchestration
- Login and logout
- Session validation
- Fastify HTTP API
- Railway deployment support
- Argon2id password hashing
- Deterministic in-memory repositories
- Comprehensive automated test suite
