# Multi-user login, rate limiting, and per-user encryption at rest

Date: 2026-09-21
Status: approved design, awaiting implementation plan

## Goals

1. Rate-limit and lock out login attempts, with admin control over IP blocks.
2. Replace the single shared password with username/password accounts, server-side sessions, and admin-managed users.
3. Encrypt each user's journal at rest with a key only that user's password (or recovery key) can unlock, so a copied data folder or backup is unreadable, including by the server administrator.

Each user has a fully separate journal: trades, accounts, notes, settings, attachments, prop-firm records. There is no shared data and no cross-user reporting.

## Non-goals

Two-factor authentication, email delivery, invite links or self-signup, impersonation, cross-user reports, changing the journal schema.

## Approach

One encrypted SQLite file per user, plus a small unencrypted authentication database. The existing journal schema and the 40 modules that import `db` stay unchanged. The `db` export becomes request-scoped and resolves to the calling user's file.

Chosen over a shared database with a user column on every table (weeks of query changes, and incompatible with per-user keys) and over carrying the key in the cookie (weaker for a small convenience).

## 1. Storage and keys

### Files

```
data/
  auth.db                       users, sessions, attempts, blocks (plain SQLite)
  users/<userId>/journal.db     existing schema, SQLCipher-encrypted
  journal.db.pre-encryption     original file kept after migration until deleted by hand
```

`userId` is a random 16-byte hex id, not the username, so renames are free and paths carry no personal data.

### Driver

`better-sqlite3-multiple-ciphers` replaces `better-sqlite3` in `apps/web/package.json`. It is API-compatible, ships prebuilt binaries for Node 22 on linux-x64 (verified to install in `node:22-slim` with no build tools), and adds `PRAGMA cipher` and `PRAGMA key`. Every user journal is opened with `cipher = 'sqlcipher'` and a raw 32-byte hex key (`key = "x'<hex>'"`), so no in-database key derivation runs. `auth.db` is opened without a key.

### Key hierarchy per user

- **DEK**: random 32 bytes generated at user creation. Encrypts `journal.db`. Never rotates.
- **Password KEK**: `scrypt(password, salt_p, N=2^15, r=8, p=1, 32 bytes)`, per-user random 16-byte `salt_p`.
- **Recovery KEK**: `scrypt(recoveryKey, salt_r, same parameters)`. The recovery key is 20 characters from a 32-symbol alphabet (Crockford base32, groups of 5 separated by dashes), generated server-side and shown exactly once.
- `auth.db` stores `dek_wrapped_password` and `dek_wrapped_recovery`, each an AES-256-GCM envelope `iv.ciphertext.tag` (same envelope format as `server/crypto.ts`).
- **Password verifier**: a separate `scrypt(password, salt_v, ...)` hash stored as `password_hash`, compared with `timingSafeEqual`. Login verifies the hash first, then unwraps the DEK. This keeps "wrong password" detection independent of the wrap.

Password change: verify old password, unwrap DEK with old KEK, re-wrap with new KEK, replace `password_hash`, `salt_p`, `salt_v`. The journal file is untouched.

Recovery: unwrap DEK with the recovery KEK, re-wrap with a new password KEK, generate and show a new recovery key, re-wrap `dek_wrapped_recovery`, delete all sessions for the user.

Admin reset: not possible after creation. Re-wrapping the DEK needs the old password or the recovery key, and the admin holds neither. A user who forgets their password uses the recovery form with their recovery key. A user who has lost both has lost the journal; the admin can only delete the account and create a new one. This is the consequence of the chosen threat model and is stated on the Create user dialog.

### JOURNAL_SECRET

Unchanged. It still encrypts broker and AI credentials inside each journal through `server/crypto.ts`. This is a second layer inside an already encrypted file and keeps the upstream module untouched. The `.secret` fallback file, when no env secret is set, is written to `data/` as today.

### Migration of an existing plaintext journal

On startup, if `data/journal.db` exists and `data/auth.db` does not, the app is in **setup mode**: every path redirects to `/setup`. After the admin account is created, the plaintext file is attached and copied into the admin's encrypted file using SQLCipher's `sqlcipher_export`, row counts per table are compared and logged, and the original is renamed to `journal.db.pre-encryption`. If `journal.db` does not exist either, setup creates an empty admin journal.

## 2. Sessions and the request path

### auth.db schema

```sql
users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  password_hash TEXT NOT NULL, salt_v TEXT NOT NULL,
  salt_p TEXT NOT NULL, dek_wrapped_password TEXT NOT NULL,
  salt_r TEXT NOT NULL, dek_wrapped_recovery TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,                -- ISO time, NULL when not locked
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL
)
sessions (
  token_hash TEXT PRIMARY KEY,      -- sha256(raw token)
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
  ip TEXT, user_agent TEXT
)
login_attempts (
  id INTEGER PRIMARY KEY,
  username TEXT, ip TEXT NOT NULL, at TEXT NOT NULL, success INTEGER NOT NULL
)
ip_blocks (
  cidr TEXT PRIMARY KEY,            -- single IP stored as /32 or /128
  source TEXT NOT NULL CHECK (source IN ('auto','manual')),
  reason TEXT, created_at TEXT NOT NULL, expires_at TEXT   -- NULL = permanent
)
```

### Session lifecycle

- Login inserts a session row and sets cookie `journal_session=<raw token>`: HttpOnly, SameSite=Lax, Path=/, Max-Age 30 days, Secure when `isSecureRequest()` is true.
- The unwrapped DEK is held only in a process-memory `Map<tokenHash, { userId, dek, role }>`. A restart empties it. A request whose session row is valid but whose DEK is absent gets `401 { error: "Locked", reason: "locked" }`; the client redirects to `/login?reason=restart`, and the stale row is deleted.
- `last_seen_at` is updated at most once per 5 minutes per session.
- Logout (`DELETE /api/auth`) deletes the row and the memory entry. "Sign out everywhere" deletes all rows for the user.
- Expired rows are deleted lazily on lookup and in a sweep on startup.

### Request-scoped database

- `apps/web/src/server/api.ts` `handler()`: reads the cookie, resolves the session, checks expiry and lock state, fetches the DEK from memory, enforces `must_change_password` (only password change and logout allowed, others 403 `{ reason: "password_change_required" }`), checks manual IP blocks (403), then runs the route inside `AsyncLocalStorage.run({ userId, role, dek }, fn)`.
- `apps/web/src/db/index.ts`: `db` becomes a `Proxy` whose every property access resolves `requestContext.getStore()`, obtains a connection from a cache keyed by `userId`, and forwards. Opening a connection runs `PRAGMA cipher`, `PRAGMA key`, `journal_mode = WAL`, `foreign_keys = ON`, then the existing `BOOTSTRAP_SQL` and additive migrations. Connections idle for 15 minutes are closed by a sweep timer. Access with no context throws `Error("No user context: db used outside handler()")`.
- New helper `currentUser()` returns `{ userId, role }` for routes that need it (Settings → Users, Account).
- `dataDir()` keeps its meaning (the root). New `userDataDir(userId)` returns `data/users/<id>`. `server/crypto.ts` keeps writing `.secret` to the root.

### Middleware

`apps/web/src/middleware.ts` allows `/login`, `/setup`, `/recover`, `/change-password`, `/api/auth`, `/api/auth/recover`, `/api/setup` and static assets without a cookie; redirects everything else to `/login` when the cookie is absent. Real validation stays in `handler()`. In setup mode (no `auth.db`), all paths redirect to `/setup`.

## 3. Login hardening and rate limiting

### Password rules

Minimum 12 characters, maximum 256, no composition rules. Enforced server-side at create, change, and recovery.

### Login endpoint

`POST /api/auth` with `{ username, password }`. Unknown user and wrong password return the same 401 `{ error: "Invalid username or password." }` after the same work (a dummy scrypt runs for unknown users). Success clears the username's failure counter, inserts the session, stores the DEK, sets the cookie, and returns `{ authenticated: true, mustChangePassword }`.

### Rate limits

Checked before any password work. Both counters and blocks persist in `auth.db`.

| Bucket | Threshold | Block |
|---|---|---|
| Client IP | 10 attempts in 5 minutes (success or failure) | 60 minutes, written to `ip_blocks` with `source = 'auto'` |
| Username | 5 failures in 5 minutes | 360 minutes, written to `users.locked_until` |

- Blocked requests return `429` with `Retry-After` (seconds) and `{ error: "Too many attempts. Try again in N minutes." }`.
- A successful login does not lift an IP block. Only the username failure window is cleared.
- Admin can lift a user lock and remove any IP block from Settings. Auto IP blocks also expire on their own.
- Manual IP blocks (single IP or CIDR, optional expiry, permanent when empty) are checked on every request in `handler()` and in the middleware for page loads, answering 403.
- Client IP: Next.js route handlers do not expose the socket address, so the app cannot verify which proxy sent a request. The rule is therefore: when `JOURNAL_TRUST_PROXY` is `true` (the default), the client IP is the first entry of `X-Forwarded-For`, or `X-Real-IP` when that header is absent; when neither header exists, or `JOURNAL_TRUST_PROXY=false`, the IP is recorded as `unknown` and only the username bucket applies. Because a client that reaches the port directly could forge the header, the port must be reachable only through the proxy. The installer, runbook and README state this, and the runbook already tells the operator not to forward the app port.
- Lockouts and manual blocks are logged with username and IP. Passwords are never logged.

### Recovery flow

`POST /api/auth/recover` with `{ username, recoveryKey, newPassword }`. Same IP and username buckets as login; a wrong recovery key counts as a failure. On success: DEK re-wrapped with the new password, new recovery key generated and returned once, all sessions deleted, `must_change_password` cleared.

## 4. Roles, screens, installer

### Roles

`admin` and `user`. First account created in setup is admin. Admin can promote or demote, but the last admin cannot be demoted or deleted. Admin cannot open another user's journal; there is no impersonation.

Admin actions: create user (sets username and a temporary password, shows the user's recovery key once, marks `must_change_password`), lock or unlock user, promote or demote, delete user (types the username to confirm; deletes `users/<id>` and all rows), manage IP blocks. There is no admin password reset; see section 1.

### Screens

- `/setup`: first run only. Username, password, confirm; shows the recovery key with a "I have saved it" checkbox; then runs migration and shows row counts.
- `/login`: username, password, link "Forgot password".
- `/recover`: username, recovery key, new password, confirm. Shows the new recovery key once.
- `/change-password`: current and new password. Forced when `must_change_password`; otherwise reachable from Settings.
- Settings → Account (all users): change password, list sessions with IP, user agent and last seen, "Sign out everywhere", regenerate recovery key (requires current password).
- Settings → Users (admin): tab **Users** with the list, status pills (active, locked until, must change password), Create user dialog, per-row actions. Tab **Access** listing IP blocks (cidr, source, reason, expiry) with Unblock, and an Add block form (IP or CIDR, reason, expiry or permanent).

### API surface (new)

```
POST   /api/setup                         create admin, migrate
POST   /api/auth                          login
DELETE /api/auth                          logout
POST   /api/auth/recover                  recovery
POST   /api/account/password              change own password
POST   /api/account/recovery-key          regenerate own recovery key
GET    /api/account/sessions              list own sessions
DELETE /api/account/sessions              sign out everywhere
GET    /api/admin/users                   list
POST   /api/admin/users                   create
PATCH  /api/admin/users/:id               role, lock or unlock
DELETE /api/admin/users/:id               delete
GET    /api/admin/blocks                  list IP blocks
POST   /api/admin/blocks                  add manual block
DELETE /api/admin/blocks/:cidr            remove block
```

Admin routes check `role === 'admin'` inside the handler and answer 403 otherwise.

### Installer and env

- `install_as_service.sh` stops generating `JOURNAL_PASSWORD`; keeps `JOURNAL_SECRET` and `JOURNAL_PORT`; final message says to open the URL and create the admin account.
- `JOURNAL_PASSWORD` in an existing `.env` is ignored with one startup log line.
- New optional `JOURNAL_TRUST_PROXY` (default `true`).
- `docker-compose.yml`, `.env.example`, README configuration table and the runbook are updated.

### Demo data and export

Unchanged. They run through the request-scoped `db` and therefore act on the caller's journal.

## 5. Errors, testing, rollout

### Errors

- Journal fails to open with the stored DEK (corrupt or tampered file): 500 `{ error: "Journal could not be opened" }`, user id logged, no retry with any other key.
- `auth.db` or `data/users` not writable at startup: process exits with a log line naming the path and the `chown` fix.
- Setup attempted when `auth.db` already exists: 409.
- Recovery key comparison happens through the AES-GCM tag check on unwrap, which is constant-time by construction; the verifier hash comparison uses `timingSafeEqual`.

### Tests (vitest, `apps/web/tests`)

- `auth-keys.test.ts`: wrap and unwrap round trip; wrong password fails; recovery key unwraps; password change keeps the DEK; scrypt parameters pinned.
- `auth-rate-limit.test.ts`: fake clock; IP block at 10 in 5 minutes for 60 minutes; user lock at 5 failures for 360 minutes; success does not lift IP block; persistence across a simulated restart; admin unblock; manual CIDR block matches.
- `auth-sessions.test.ts`: login sets cookie and memory; logout clears; expiry; restart leads to `locked`; must-change-password gate.
- `db-per-user.test.ts`: two users write a trade each and read back only their own; opening user A's file with user B's DEK fails with `SQLITE_NOTADB`; no-context access throws.
- `setup-migration.test.ts`: plaintext journal with sample rows migrates; per-table counts equal; original renamed.
- Existing suites: a test helper `withTestUser(fn)` creates a temp user and runs `fn` inside the request context so suites that used the singleton keep passing. All 450 existing tests must pass.
- Manual through Nginx Proxy Manager: cookie has `Secure`; IP bucket sees the client IP, not the proxy's.

### Rollout on this machine

1. Back up `data/` and `.env`.
2. Pull, rebuild, restart. First visit redirects to `/setup`.
3. Create the admin, save the recovery key, let migration run, check the row counts.
4. Verify trades and notes in the UI, then delete `data/journal.db.pre-encryption`.
5. Create the other users from Settings → Users and hand each their temporary password and recovery key.

### Backup note for the runbook

A backup now needs `data/` (all users' encrypted journals and `auth.db`) plus `.env`. Restoring a backup restores every user's journal; each user still needs their own password or recovery key to open theirs.
