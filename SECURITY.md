# Security policy

## Reporting a vulnerability

Please do not open public issues for security vulnerabilities.

Report privately via GitHub's vulnerability reporting on this repository: **Security → Report a vulnerability** (<https://github.com/LuxAlgo/trade-journal/security/advisories/new>).

You can expect an acknowledgment within a few business days. Please include reproduction steps and the affected version or commit.

## Scope notes

Trade Journal is self-hosted software: it stores broker credentials (encrypted at rest) and trading history on the machine that runs it. Accounts are created at `/setup`, and each user's journal is a separately encrypted SQLite database that only that user's password or recovery key can unlock; sign-in is rate limited with persistent IP and account lockouts. Reports about credential handling, the encryption layer (`apps/web/src/server/crypto.ts`), authentication and session handling, and the statement importers (untrusted file parsing) are especially valuable.

## Supported versions

Security fixes target the latest release on `main`.
