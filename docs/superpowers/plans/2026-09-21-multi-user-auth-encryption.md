# Multi-user Login, Rate Limiting, and Per-user Encryption Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single shared password with admin-managed username/password accounts, persistent rate limiting with admin-controlled IP blocks, and one SQLCipher-encrypted journal per user whose key only that user's password or recovery key can unlock.

**Architecture:** A small plain `auth.db` holds users, wrapped keys, sessions, attempts and blocks. Each user's journal is the unchanged existing schema in `data/users/<id>/journal.db`, opened with a per-user 32-byte key. `handler()` resolves the session, fetches the unwrapped key from process memory, and runs the route inside an AsyncLocalStorage context; the `db` export becomes a Proxy that forwards to the calling user's connection, so the 40 modules importing `db` do not change.

**Tech Stack:** Next.js 15 (app router, route handlers), `better-sqlite3-multiple-ciphers` 13.0.3 (drop-in for better-sqlite3 with SQLCipher), drizzle-orm, Node 22 `node:crypto` (scrypt, AES-256-GCM), vitest, React with the repo's shadcn-style `components/ui`.

**Spec:** `docs/superpowers/specs/2026-09-21-multi-user-auth-encryption-design.md`

## Global Constraints

- Run all commands from the repo root `/home/rholand/lan-share/trade-journal`. pnpm is used through corepack: prefix every pnpm command with `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm`.
- Tests: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run <path>`. Full suite must stay green (450 tests today).
- Type check before each commit that touches `apps/web/src`: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json`. The project uses `noUncheckedIndexedAccess`: every array index read is `T | undefined`.
- Format before committing: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write <files>`.
- Commit messages end with the two attribution lines given in the session's system reminder (`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>` and `Claude-Session: https://claude.ai/code/session_01KbXiH6cfcWiX4ZRBitUAqt`).
- Password: 12 to 256 characters, no composition rules.
- scrypt parameters: `N = 2 ** 15, r = 8, p = 1, keylen = 32, maxmem = 64 MiB`.
- Recovery key: 20 symbols from Crockford base32 `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, displayed as `XXXXX-XXXXX-XXXXX-XXXXX`.
- Rate limits: IP bucket 10 attempts in 5 minutes, block 60 minutes. Username bucket 5 failures in 5 minutes, lock 360 minutes. Both persisted in `auth.db`.
- Cookie name `journal_session`; HttpOnly, SameSite=Lax, Path=/, Max-Age 30 days, Secure when `isSecureRequest()` is true.
- Session lifetime 30 days. Unwrapped keys live only in process memory.
- New env var `JOURNAL_TRUST_PROXY` (default `true`). `JOURNAL_PASSWORD` is ignored with one startup log line.
- Error JSON shape everywhere: `{ error: string, reason?: string }`.
- Copy: "Invalid username or password.", "Too many attempts. Try again in N minutes.", "Journal could not be opened".

## File Structure

New, under `apps/web/src`:

| File | Responsibility |
|---|---|
| `db/paths.ts` | `dataDir()`, `userDataDir(id)`, `authDbPath()`, `legacyJournalPath()`, `authDbExists()`. Pure path logic, no side effects. |
| `db/journal.ts` | `openJournal(file, dek?)`: opens one SQLite file (keyed when `dek` given), runs bootstrap and migrations, validates the key. Exports `JournalOpenError`. |
| `server/errors.ts` | `RequestError` and `requireValue`, moved out of `api.ts` so auth modules can throw them without importing the handler (avoids an import cycle). `api.ts` re-exports both. |
| `server/auth/keys.ts` | Pure crypto: DEK, salts, scrypt, wrap/unwrap, recovery key generation and normalisation, password hashing. No IO. |
| `server/auth/db.ts` | Opens `auth.db` (plain), creates its four tables, singleton across hot reloads. |
| `server/auth/users.ts` | User CRUD, login verification, password change, recovery, lock, role. |
| `server/auth/sessions.ts` | Session rows, in-memory DEK map, cookie helpers. |
| `server/auth/rate-limit.ts` | Attempts, IP and username buckets, blocks, CIDR matching, `clientIp()`. |
| `server/auth/context.ts` | AsyncLocalStorage store `{ userId, role, dek }`, `runWithUser`, `currentUser`. |
| `server/auth/setup.ts` | Setup-mode detection, admin creation, legacy journal migration. |
| `lib/auth-redirect.ts` | Client-side: turn 401/403/409 reasons into navigation. |
| `app/api/setup/route.ts`, `app/api/auth/route.ts`, `app/api/auth/recover/route.ts`, `app/api/account/password/route.ts`, `app/api/account/recovery-key/route.ts`, `app/api/account/sessions/route.ts`, `app/api/admin/users/route.ts`, `app/api/admin/users/[id]/route.ts`, `app/api/admin/blocks/route.ts`, `app/api/admin/blocks/[cidr]/route.ts` | HTTP surface from the spec. |
| `app/setup/page.tsx`, `app/recover/page.tsx`, `app/change-password/page.tsx` | New pages. |
| `components/account-settings.tsx`, `components/user-admin.tsx`, `components/recovery-key-card.tsx` | Settings UI. |

Modified: `db/index.ts` (Proxy), `server/api.ts` (handler), `server/auth.ts` (keeps only `AUTH_COOKIE` and `isSecureRequest`), `middleware.ts`, `lib/use-api.ts`, `lib/api-request.ts`, `components/shell.tsx`, `app/login/page.tsx`, `app/settings/page.tsx`, `apps/web/package.json`, `docker-compose.yml`, `.env.example`, `install_as_service.sh`, `README.md`.

Tests, under `apps/web/tests`: `auth-keys.test.ts`, `auth-users.test.ts`, `auth-sessions.test.ts`, `auth-rate-limit.test.ts`, `db-per-user.test.ts`, `setup-migration.test.ts`, `api-auth.test.ts` (rewritten), `auth-gate.unit.test.ts` (rewritten), `api-admin.test.ts`.

### Test helper used by many tasks

Every new test that touches the database starts with this preamble so it gets an isolated data directory. Copy it verbatim; do not share state between files.

```ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
```

Modules that read `JOURNAL_DATA_DIR` must be imported with `await import(...)` after these lines, exactly as `tests/execution-storage.test.ts` does today.

### Spec refinement decided while planning

The spec says database access with no user context throws. Existing tests import `db` at module level and call it outside `handler()`, and they run against a temp data dir that has no `auth.db`. Rule implemented in Task 4: no context and no `auth.db` means the legacy plaintext `data/journal.db` (today's behaviour, used by tests and by migration); no context with `auth.db` present throws. `handler()` (Task 7) passes requests through without a session only when `auth.db` is absent **and** `process.env.VITEST === "true"`; in production a missing `auth.db` answers `409 { reason: "setup_required" }`.

---

### Task 1: Swap the SQLite driver

**Files:**
- Modify: `apps/web/package.json` (dependencies)
- Modify: `apps/web/src/db/index.ts:1`
- Test: `apps/web/tests/driver-cipher.test.ts`

**Interfaces:**
- Produces: `import Database from "better-sqlite3-multiple-ciphers"` usable everywhere `better-sqlite3` was; `Database.Database` type alias identical.

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/driver-cipher.test.ts
import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3-multiple-ciphers";

describe("encrypted sqlite driver", () => {
  it("writes a file that is not plain SQLite and rejects a wrong key", () => {
    const dir = mkdtempSync(join(tmpdir(), "cipher-"));
    const file = join(dir, "t.db");
    const key = "a".repeat(64);
    const db = new Database(file);
    db.pragma("cipher='sqlcipher'");
    db.pragma(`key="x'${key}'"`);
    db.exec("CREATE TABLE t (x TEXT)");
    db.prepare("INSERT INTO t VALUES (?)").run("hello");
    db.close();
    expect(readFileSync(file).subarray(0, 15).toString()).not.toBe("SQLite format 3");
    const wrong = new Database(file);
    wrong.pragma("cipher='sqlcipher'");
    wrong.pragma(`key="x'${"b".repeat(64)}'"`);
    expect(() => wrong.prepare("SELECT x FROM t").get()).toThrow(/NOTADB|not a database/);
    wrong.close();
    const right = new Database(file);
    right.pragma("cipher='sqlcipher'");
    right.pragma(`key="x'${key}'"`);
    expect((right.prepare("SELECT x FROM t").get() as { x: string }).x).toBe("hello");
    right.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
```

- [ ] **Step 2: Run it to verify it fails**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/driver-cipher.test.ts`
Expected: FAIL, cannot find module `better-sqlite3-multiple-ciphers`.

- [ ] **Step 3: Replace the dependency**

Run:
```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web remove better-sqlite3
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web add better-sqlite3-multiple-ciphers@13.0.3
```
Keep `@types/better-sqlite3` in devDependencies; the new package ships its own types but drizzle's adapter types reference the old ones.

In `apps/web/src/db/index.ts` change line 1 to:
```ts
import Database from "better-sqlite3-multiple-ciphers";
```
If `tsc` complains that the `drizzle(sqlite, ...)` argument type does not match, change that call to:
```ts
return drizzle(sqlite as unknown as import("better-sqlite3").Database, { schema });
```

- [ ] **Step 4: Run the new test and the full suite**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run`
Expected: 47 files pass, 451 tests.

- [ ] **Step 5: Type check and commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
git add apps/web/package.json pnpm-lock.yaml apps/web/src/db/index.ts apps/web/tests/driver-cipher.test.ts
git commit -m "Switch SQLite driver to better-sqlite3-multiple-ciphers"
```

---

### Task 2: Key material and wrapping (`server/auth/keys.ts`)

**Files:**
- Create: `apps/web/src/server/auth/keys.ts`
- Test: `apps/web/tests/auth-keys.test.ts`

**Interfaces:**
- Produces:
  - `generateDek(): Buffer` (32 bytes)
  - `generateSalt(): string` (32 hex chars)
  - `generateRecoveryKey(): string` (`XXXXX-XXXXX-XXXXX-XXXXX`)
  - `normalizeRecoveryKey(input: string): string` (20 uppercase symbols, dashes and spaces removed, `O→0`, `I/L→1`)
  - `deriveKey(secret: string, saltHex: string): Buffer` (scrypt, 32 bytes)
  - `wrapDek(dek: Buffer, kek: Buffer): string` and `unwrapDek(envelope: string, kek: Buffer): Buffer | null`
  - `hashPassword(password: string, saltHex: string): string` and `verifyPassword(password: string, saltHex: string, hashHex: string): boolean`
  - `SCRYPT` constant.

- [ ] **Step 1: Write the failing tests**

```ts
// apps/web/tests/auth-keys.test.ts
import { describe, expect, it } from "vitest";
import {
  SCRYPT,
  deriveKey,
  generateDek,
  generateRecoveryKey,
  generateSalt,
  hashPassword,
  normalizeRecoveryKey,
  unwrapDek,
  verifyPassword,
  wrapDek,
} from "../src/server/auth/keys";

describe("key material", () => {
  it("pins scrypt parameters", () => {
    expect(SCRYPT).toEqual({ N: 32768, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 });
  });
  it("wraps and unwraps a DEK with the password key", () => {
    const dek = generateDek();
    const salt = generateSalt();
    const kek = deriveKey("correct horse battery", salt);
    const envelope = wrapDek(dek, kek);
    expect(unwrapDek(envelope, kek)?.equals(dek)).toBe(true);
  });
  it("returns null for a wrong password instead of throwing", () => {
    const dek = generateDek();
    const salt = generateSalt();
    const envelope = wrapDek(dek, deriveKey("right-password", salt));
    expect(unwrapDek(envelope, deriveKey("wrong-password", salt))).toBeNull();
    expect(unwrapDek("garbage", deriveKey("right-password", salt))).toBeNull();
  });
  it("recovery keys are 20 Crockford symbols in 4 groups and normalise ambiguous glyphs", () => {
    const key = generateRecoveryKey();
    expect(key).toMatch(/^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/);
    expect(normalizeRecoveryKey(key.toLowerCase())).toBe(key.replace(/-/g, ""));
    expect(normalizeRecoveryKey("oil0-1")).toBe("01101");
  });
  it("password hash verifies and rejects", () => {
    const salt = generateSalt();
    const hash = hashPassword("twelve-char-pw", salt);
    expect(verifyPassword("twelve-char-pw", salt, hash)).toBe(true);
    expect(verifyPassword("twelve-char-pX", salt, hash)).toBe(false);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-keys.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement**

```ts
// apps/web/src/server/auth/keys.ts
import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

/** Pinned so stored hashes and wraps keep verifying across releases. */
export const SCRYPT = { N: 2 ** 15, r: 8, p: 1, keylen: 32, maxmem: 64 * 1024 * 1024 } as const;

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export const generateDek = (): Buffer => randomBytes(32);
export const generateSalt = (): string => randomBytes(16).toString("hex");

export const generateRecoveryKey = (): string => {
  const bytes = randomBytes(20);
  const symbols: string[] = [];
  for (let i = 0; i < 20; i += 1) symbols.push(ALPHABET[(bytes[i] ?? 0) % 32] ?? "0");
  return [0, 5, 10, 15].map((start) => symbols.slice(start, start + 5).join("")).join("-");
};

export const normalizeRecoveryKey = (input: string): string =>
  input
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");

export const deriveKey = (secret: string, saltHex: string): Buffer =>
  scryptSync(secret, Buffer.from(saltHex, "hex"), SCRYPT.keylen, {
    N: SCRYPT.N,
    r: SCRYPT.r,
    p: SCRYPT.p,
    maxmem: SCRYPT.maxmem,
  });

export const wrapDek = (dek: Buffer, kek: Buffer): string => {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", kek, iv);
  const encrypted = Buffer.concat([cipher.update(dek), cipher.final()]);
  return [iv, encrypted, cipher.getAuthTag()].map((part) => part.toString("base64")).join(".");
};

export const unwrapDek = (envelope: string, kek: Buffer): Buffer | null => {
  const [iv, encrypted, tag] = envelope.split(".");
  if (!iv || !encrypted || !tag) return null;
  try {
    const decipher = createDecipheriv("aes-256-gcm", kek, Buffer.from(iv, "base64"));
    decipher.setAuthTag(Buffer.from(tag, "base64"));
    return Buffer.concat([decipher.update(Buffer.from(encrypted, "base64")), decipher.final()]);
  } catch {
    return null;
  }
};

export const hashPassword = (password: string, saltHex: string): string =>
  deriveKey(password, saltHex).toString("hex");

export const verifyPassword = (password: string, saltHex: string, hashHex: string): boolean => {
  const expected = Buffer.from(hashHex, "hex");
  const given = deriveKey(password, saltHex);
  return expected.length === given.length && timingSafeEqual(expected, given);
};
```

- [ ] **Step 4: Run tests**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-keys.test.ts`
Expected: 5 passed.

- [ ] **Step 5: Commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/server/auth/keys.ts apps/web/tests/auth-keys.test.ts
git add apps/web/src/server/auth/keys.ts apps/web/tests/auth-keys.test.ts
git commit -m "Add per-user key derivation and DEK wrapping"
```

---

### Task 3: Paths, auth database, and user management

**Files:**
- Create: `apps/web/src/db/paths.ts`
- Create: `apps/web/src/server/auth/db.ts`
- Create: `apps/web/src/server/auth/users.ts`
- Modify: `apps/web/src/db/index.ts` (import `dataDir` from `./paths` and re-export it)
- Test: `apps/web/tests/auth-users.test.ts`

**Interfaces:**
- Produces (`db/paths.ts`): `dataDir(): string`, `userDataDir(userId: string): string` (`<dataDir>/users/<id>`), `authDbPath(): string`, `legacyJournalPath(): string`, `authDbExists(): boolean`.
- Produces (`server/auth/db.ts`): `authDb(): Database.Database` singleton that creates the file and tables on first call. `type Role = "admin" | "user"`.
- Produces (`server/auth/users.ts`):
  - `interface UserRecord { id: string; username: string; role: Role; mustChangePassword: boolean; lockedUntil: string | null; createdAt: string }`
  - `validatePassword(password: string): void` (throws `RequestError`)
  - `createUser(input: { username: string; password: string; role: Role; mustChangePassword?: boolean }): { user: UserRecord; recoveryKey: string; dek: Buffer }`
  - `verifyLogin(username: string, password: string): { user: UserRecord; dek: Buffer } | null`
  - `changePassword(userId: string, currentPassword: string, newPassword: string): boolean`
  - `recoverWithKey(username: string, recoveryKey: string, newPassword: string): { user: UserRecord; dek: Buffer; recoveryKey: string } | null`
  - `regenerateRecoveryKey(userId: string, password: string): string | null`
  - `getUser(id: string): UserRecord | null`, `findUserByUsername(username: string): UserRecord | null`, `listUsers(): UserRecord[]`
  - `setUserLock(userId: string, lockedUntil: string | null): void`, `setUserRole(userId: string, role: Role): void`, `deleteUser(userId: string): void`, `countAdmins(): number`, `dummyPasswordWork(): void`.

- [ ] **Step 1: Write the failing tests**

```ts
// apps/web/tests/auth-users.test.ts
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { authDbExists, authDbPath } = await import("../src/db/paths");
const users = await import("../src/server/auth/users");

describe("user management", () => {
  it("creates the auth database on first user and returns a recovery key", () => {
    expect(authDbExists()).toBe(false);
    const created = users.createUser({ username: "Alice", password: "alice-password-1", role: "admin" });
    expect(existsSync(authDbPath())).toBe(true);
    expect(created.user.role).toBe("admin");
    expect(created.recoveryKey).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/);
    expect(created.dek.length).toBe(32);
  });
  it("rejects short passwords and duplicate usernames case-insensitively", () => {
    expect(() => users.validatePassword("short")).toThrow(/12 characters/);
    expect(() =>
      users.createUser({ username: "alice", password: "another-password", role: "user" }),
    ).toThrow(/already exists/);
  });
  it("verifies login and unwraps the same DEK", () => {
    const created = users.createUser({ username: "bob", password: "bob-password-123", role: "user" });
    const login = users.verifyLogin("BOB", "bob-password-123");
    expect(login?.dek.equals(created.dek)).toBe(true);
    expect(users.verifyLogin("bob", "bob-password-124")).toBeNull();
    expect(users.verifyLogin("nobody", "bob-password-123")).toBeNull();
  });
  it("password change keeps the DEK and invalidates the old password", () => {
    const created = users.createUser({ username: "carol", password: "carol-password-1", role: "user" });
    expect(users.changePassword(created.user.id, "wrong-password-1", "carol-password-2")).toBe(false);
    expect(users.changePassword(created.user.id, "carol-password-1", "carol-password-2")).toBe(true);
    expect(users.verifyLogin("carol", "carol-password-1")).toBeNull();
    expect(users.verifyLogin("carol", "carol-password-2")?.dek.equals(created.dek)).toBe(true);
    expect(users.getUser(created.user.id)?.mustChangePassword).toBe(false);
  });
  it("recovery key unwraps the DEK, sets a new password and rotates the key", () => {
    const created = users.createUser({ username: "dave", password: "dave-password-12", role: "user" });
    const recovered = users.recoverWithKey("dave", created.recoveryKey.toLowerCase(), "dave-password-13");
    expect(recovered?.dek.equals(created.dek)).toBe(true);
    expect(recovered?.recoveryKey).not.toBe(created.recoveryKey);
    expect(users.recoverWithKey("dave", created.recoveryKey, "dave-password-14")).toBeNull();
    expect(users.verifyLogin("dave", "dave-password-13")?.dek.equals(created.dek)).toBe(true);
  });
  it("lock, role and delete", () => {
    const created = users.createUser({ username: "erin", password: "erin-password-12", role: "user" });
    users.setUserLock(created.user.id, "2099-01-01T00:00:00.000Z");
    expect(users.getUser(created.user.id)?.lockedUntil).toBe("2099-01-01T00:00:00.000Z");
    users.setUserRole(created.user.id, "admin");
    expect(users.countAdmins()).toBe(2);
    users.deleteUser(created.user.id);
    expect(users.getUser(created.user.id)).toBeNull();
    expect(users.listUsers().map((u) => u.username)).toEqual(["Alice", "bob", "carol", "dave"]);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-users.test.ts`
Expected: FAIL, modules not found.

- [ ] **Step 3: Move `RequestError` to its own module and implement `db/paths.ts`**

Create `apps/web/src/server/errors.ts`:
```ts
// apps/web/src/server/errors.ts
export class RequestError extends Error {}
export function requireValue(condition: unknown, message: string): asserts condition {
  if (!condition) throw new RequestError(message);
}
```
In `apps/web/src/server/api.ts` delete lines 5 to 8 (the `RequestError` class and `requireValue` function) and add at the top:
```ts
import { RequestError } from "./errors";
export { RequestError, requireValue } from "./errors";
```
Every existing importer of `RequestError`/`requireValue` from `@/server/api` keeps working through the re-export.


```ts
// apps/web/src/db/paths.ts
import { existsSync } from "node:fs";
import { join } from "node:path";

export const dataDir = (): string => process.env.JOURNAL_DATA_DIR ?? join(process.cwd(), "data");
export const userDataDir = (userId: string): string => join(dataDir(), "users", userId);
export const authDbPath = (): string => join(dataDir(), "auth.db");
export const legacyJournalPath = (): string => join(dataDir(), "journal.db");
export const authDbExists = (): boolean => existsSync(authDbPath());
```

In `apps/web/src/db/index.ts` delete the line `export const dataDir = ...` and add near the top:
```ts
import { dataDir } from "./paths";
export { dataDir } from "./paths";
```

- [ ] **Step 4: Implement `server/auth/db.ts`**

```ts
// apps/web/src/server/auth/db.ts
import Database from "better-sqlite3-multiple-ciphers";
import { mkdirSync } from "node:fs";
import { dataDir, authDbPath } from "@/db/paths";

export type Role = "admin" | "user";

const AUTH_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL COLLATE NOCASE,
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  password_hash TEXT NOT NULL,
  salt_v TEXT NOT NULL,
  salt_p TEXT NOT NULL,
  dek_wrapped_password TEXT NOT NULL,
  salt_r TEXT NOT NULL,
  dek_wrapped_recovery TEXT NOT NULL,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS login_attempts (
  id INTEGER PRIMARY KEY,
  username TEXT,
  ip TEXT NOT NULL,
  at TEXT NOT NULL,
  success INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts(ip, at);
CREATE INDEX IF NOT EXISTS login_attempts_user ON login_attempts(username, at);
CREATE TABLE IF NOT EXISTS ip_blocks (
  cidr TEXT PRIMARY KEY,
  source TEXT NOT NULL CHECK (source IN ('auto','manual')),
  reason TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT
);
`;

const globalForAuth = globalThis as unknown as { __journalAuthDb?: Database.Database; __journalAuthDbPath?: string };

/** Creates data/auth.db on first call. Only setup and user creation may be the first caller. */
export const authDb = (): Database.Database => {
  const path = authDbPath();
  if (globalForAuth.__journalAuthDb && globalForAuth.__journalAuthDbPath === path) {
    return globalForAuth.__journalAuthDb;
  }
  mkdirSync(dataDir(), { recursive: true });
  const sqlite = new Database(path);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  sqlite.exec(AUTH_SQL);
  globalForAuth.__journalAuthDb = sqlite;
  globalForAuth.__journalAuthDbPath = path;
  return sqlite;
};

export const nowIso = (): string => new Date().toISOString();
```

- [ ] **Step 5: Implement `server/auth/users.ts`**

```ts
// apps/web/src/server/auth/users.ts
import { randomBytes } from "node:crypto";
import { rmSync } from "node:fs";
import { RequestError } from "@/server/errors";
import { userDataDir } from "@/db/paths";
import { authDb, nowIso, type Role } from "./db";
import {
  deriveKey,
  generateDek,
  generateRecoveryKey,
  generateSalt,
  hashPassword,
  normalizeRecoveryKey,
  unwrapDek,
  verifyPassword,
  wrapDek,
} from "./keys";

export interface UserRecord {
  id: string;
  username: string;
  role: Role;
  mustChangePassword: boolean;
  lockedUntil: string | null;
  createdAt: string;
}

interface UserRow {
  id: string;
  username: string;
  role: Role;
  password_hash: string;
  salt_v: string;
  salt_p: string;
  dek_wrapped_password: string;
  salt_r: string;
  dek_wrapped_recovery: string;
  must_change_password: number;
  locked_until: string | null;
  created_at: string;
}

const toRecord = (row: UserRow): UserRecord => ({
  id: row.id,
  username: row.username,
  role: row.role,
  mustChangePassword: row.must_change_password === 1,
  lockedUntil: row.locked_until,
  createdAt: row.created_at,
});

const rowById = (id: string): UserRow | undefined =>
  authDb().prepare("SELECT * FROM users WHERE id = ?").get(id) as UserRow | undefined;
const rowByUsername = (username: string): UserRow | undefined =>
  authDb().prepare("SELECT * FROM users WHERE username = ? COLLATE NOCASE").get(username) as
    | UserRow
    | undefined;

export const validatePassword = (password: string): void => {
  if (typeof password !== "string" || password.length < 12)
    throw new RequestError("Password must be at least 12 characters.");
  if (password.length > 256) throw new RequestError("Password must be at most 256 characters.");
};

const validateUsername = (username: string): void => {
  if (!/^[a-zA-Z0-9._-]{2,32}$/.test(username))
    throw new RequestError("Username: 2 to 32 letters, digits, dot, dash or underscore.");
};

/** Wrap a DEK for storage under a fresh password. Returns the columns to persist. */
const wrapForPassword = (dek: Buffer, password: string) => {
  const saltV = generateSalt();
  const saltP = generateSalt();
  return {
    password_hash: hashPassword(password, saltV),
    salt_v: saltV,
    salt_p: saltP,
    dek_wrapped_password: wrapDek(dek, deriveKey(password, saltP)),
  };
};

const wrapForRecovery = (dek: Buffer) => {
  const recoveryKey = generateRecoveryKey();
  const saltR = generateSalt();
  return {
    recoveryKey,
    salt_r: saltR,
    dek_wrapped_recovery: wrapDek(dek, deriveKey(normalizeRecoveryKey(recoveryKey), saltR)),
  };
};

export const createUser = (input: {
  username: string;
  password: string;
  role: Role;
  mustChangePassword?: boolean;
}): { user: UserRecord; recoveryKey: string; dek: Buffer } => {
  validateUsername(input.username);
  validatePassword(input.password);
  if (rowByUsername(input.username)) throw new RequestError("A user with that name already exists.");
  const dek = generateDek();
  const pw = wrapForPassword(dek, input.password);
  const rk = wrapForRecovery(dek);
  const id = randomBytes(16).toString("hex");
  const now = nowIso();
  authDb()
    .prepare(
      `INSERT INTO users (id, username, role, password_hash, salt_v, salt_p, dek_wrapped_password,
        salt_r, dek_wrapped_recovery, must_change_password, locked_until, created_at, updated_at)
       VALUES (@id, @username, @role, @password_hash, @salt_v, @salt_p, @dek_wrapped_password,
        @salt_r, @dek_wrapped_recovery, @must_change_password, NULL, @now, @now)`,
    )
    .run({
      id,
      username: input.username,
      role: input.role,
      ...pw,
      salt_r: rk.salt_r,
      dek_wrapped_recovery: rk.dek_wrapped_recovery,
      must_change_password: input.mustChangePassword ? 1 : 0,
      now,
    });
  const row = rowById(id);
  if (!row) throw new Error("User insert failed");
  return { user: toRecord(row), recoveryKey: rk.recoveryKey, dek };
};

/** Same cost as a real verification, used when the username does not exist. */
export const dummyPasswordWork = (): void => {
  deriveKey("dummy-password-work", "00000000000000000000000000000000");
};

export const verifyLogin = (
  username: string,
  password: string,
): { user: UserRecord; dek: Buffer } | null => {
  const row = rowByUsername(username);
  if (!row) {
    dummyPasswordWork();
    return null;
  }
  if (!verifyPassword(password, row.salt_v, row.password_hash)) return null;
  const dek = unwrapDek(row.dek_wrapped_password, deriveKey(password, row.salt_p));
  if (!dek) return null;
  return { user: toRecord(row), dek };
};

const storePassword = (id: string, dek: Buffer, newPassword: string): void => {
  const pw = wrapForPassword(dek, newPassword);
  authDb()
    .prepare(
      `UPDATE users SET password_hash = @password_hash, salt_v = @salt_v, salt_p = @salt_p,
        dek_wrapped_password = @dek_wrapped_password, must_change_password = 0, updated_at = @now
       WHERE id = @id`,
    )
    .run({ ...pw, id, now: nowIso() });
};

export const changePassword = (
  userId: string,
  currentPassword: string,
  newPassword: string,
): boolean => {
  validatePassword(newPassword);
  const row = rowById(userId);
  if (!row || !verifyPassword(currentPassword, row.salt_v, row.password_hash)) return false;
  const dek = unwrapDek(row.dek_wrapped_password, deriveKey(currentPassword, row.salt_p));
  if (!dek) return false;
  storePassword(userId, dek, newPassword);
  return true;
};

export const recoverWithKey = (
  username: string,
  recoveryKey: string,
  newPassword: string,
): { user: UserRecord; dek: Buffer; recoveryKey: string } | null => {
  validatePassword(newPassword);
  const row = rowByUsername(username);
  if (!row) {
    dummyPasswordWork();
    return null;
  }
  const dek = unwrapDek(
    row.dek_wrapped_recovery,
    deriveKey(normalizeRecoveryKey(recoveryKey), row.salt_r),
  );
  if (!dek) return null;
  storePassword(row.id, dek, newPassword);
  const rk = wrapForRecovery(dek);
  authDb()
    .prepare(
      "UPDATE users SET salt_r = ?, dek_wrapped_recovery = ?, updated_at = ? WHERE id = ?",
    )
    .run(rk.salt_r, rk.dek_wrapped_recovery, nowIso(), row.id);
  const fresh = rowById(row.id);
  if (!fresh) return null;
  return { user: toRecord(fresh), dek, recoveryKey: rk.recoveryKey };
};

export const regenerateRecoveryKey = (userId: string, password: string): string | null => {
  const row = rowById(userId);
  if (!row || !verifyPassword(password, row.salt_v, row.password_hash)) return null;
  const dek = unwrapDek(row.dek_wrapped_password, deriveKey(password, row.salt_p));
  if (!dek) return null;
  const rk = wrapForRecovery(dek);
  authDb()
    .prepare(
      "UPDATE users SET salt_r = ?, dek_wrapped_recovery = ?, updated_at = ? WHERE id = ?",
    )
    .run(rk.salt_r, rk.dek_wrapped_recovery, nowIso(), userId);
  return rk.recoveryKey;
};

export const getUser = (id: string): UserRecord | null => {
  const row = rowById(id);
  return row ? toRecord(row) : null;
};
export const findUserByUsername = (username: string): UserRecord | null => {
  const row = rowByUsername(username);
  return row ? toRecord(row) : null;
};
export const listUsers = (): UserRecord[] =>
  (authDb().prepare("SELECT * FROM users ORDER BY created_at, rowid").all() as UserRow[]).map(toRecord);

export const setUserLock = (userId: string, lockedUntil: string | null): void => {
  authDb()
    .prepare("UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?")
    .run(lockedUntil, nowIso(), userId);
};
export const setUserRole = (userId: string, role: Role): void => {
  authDb().prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").run(role, nowIso(), userId);
};
export const countAdmins = (): number =>
  (authDb().prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get() as { n: number }).n;

/** Removes the row (sessions cascade) and the user's journal folder. */
export const deleteUser = (userId: string): void => {
  authDb().prepare("DELETE FROM users WHERE id = ?").run(userId);
  rmSync(userDataDir(userId), { recursive: true, force: true });
};
```

- [ ] **Step 6: Run tests and the full suite**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-users.test.ts && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run`
Expected: 6 passed in the new file; whole suite green.

- [ ] **Step 7: Type check, format, commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/db/paths.ts apps/web/src/db/index.ts apps/web/src/server/auth apps/web/tests/auth-users.test.ts
git add apps/web/src/db/paths.ts apps/web/src/db/index.ts apps/web/src/server/errors.ts apps/web/src/server/api.ts apps/web/src/server/auth apps/web/tests/auth-users.test.ts
git commit -m "Add auth database and user management with wrapped per-user keys"
```

---

### Task 4: Request context and per-user journal connections

**Files:**
- Create: `apps/web/src/server/auth/context.ts`
- Create: `apps/web/src/db/journal.ts`
- Modify: `apps/web/src/db/index.ts` (replace the singleton with the Proxy)
- Test: `apps/web/tests/db-per-user.test.ts`

**Interfaces:**
- Produces (`context.ts`): `interface UserContext { userId: string; role: Role; dek: Buffer }`, `runWithUser<T>(ctx: UserContext, fn: () => T): T`, `currentUserContext(): UserContext | undefined`, `currentUser(): { userId: string; role: Role }` (throws when absent).
- Produces (`journal.ts`): `openJournal(file: string, dek?: Buffer): { sqlite: Database.Database; orm: Journal }`, `class JournalOpenError extends Error`, `type Journal` (the drizzle instance type).
- Produces (`db/index.ts`): `db` (Proxy, same surface as before), `journalFor(ctx: UserContext): Journal`, `closeJournal(userId: string): void`, `closeIdleJournals(maxIdleMs?: number): void`, `closeLegacyJournal(): void`, plus the unchanged `export * from "./schema"` and `export { dataDir }`.

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/db-per-user.test.ts
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { db, accounts, closeJournal } = await import("../src/db");
const { userDataDir } = await import("../src/db/paths");
const { openJournal, JournalOpenError } = await import("../src/db/journal");
const { runWithUser } = await import("../src/server/auth/context");
const { createUser } = await import("../src/server/auth/users");

const insertAccount = (id: string) =>
  db.insert(accounts).values({ id, name: id, kind: "manual", createdAt: "2026-01-01" }).run();
const accountIds = () => db.select({ id: accounts.id }).from(accounts).all().map((r) => r.id);

describe("per-user journals", () => {
  it("falls back to the legacy plaintext journal when no auth database exists", () => {
    insertAccount("legacy");
    expect(accountIds()).toEqual(["legacy"]);
    expect(existsSync(join(scratch, "journal.db"))).toBe(true);
  });
  it("routes each user's queries to their own encrypted file", () => {
    const a = createUser({ username: "alice", password: "alice-password-1", role: "admin" });
    const b = createUser({ username: "bob", password: "bob-password-123", role: "user" });
    const ctxA = { userId: a.user.id, role: a.user.role, dek: a.dek };
    const ctxB = { userId: b.user.id, role: b.user.role, dek: b.dek };
    runWithUser(ctxA, () => insertAccount("a1"));
    runWithUser(ctxB, () => insertAccount("b1"));
    expect(runWithUser(ctxA, accountIds)).toEqual(["a1"]);
    expect(runWithUser(ctxB, accountIds)).toEqual(["b1"]);
    const fileA = join(userDataDir(a.user.id), "journal.db");
    expect(readFileSync(fileA).subarray(0, 15).toString()).not.toBe("SQLite format 3");
    closeJournal(a.user.id);
    expect(() => openJournal(fileA, b.dek)).toThrow(JournalOpenError);
  });
  it("throws outside a user context once the auth database exists", () => {
    expect(() => accountIds()).toThrow(/No user context/);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/db-per-user.test.ts`
Expected: FAIL, modules not found.

- [ ] **Step 3: Implement `context.ts`**

```ts
// apps/web/src/server/auth/context.ts
import { AsyncLocalStorage } from "node:async_hooks";
import type { Role } from "./db";

export interface UserContext {
  userId: string;
  role: Role;
  dek: Buffer;
}

const globalForContext = globalThis as unknown as { __journalUserContext?: AsyncLocalStorage<UserContext> };
const storage = (globalForContext.__journalUserContext ??= new AsyncLocalStorage<UserContext>());

export const runWithUser = <T>(ctx: UserContext, fn: () => T): T => storage.run(ctx, fn);
export const currentUserContext = (): UserContext | undefined => storage.getStore();
export const currentUser = (): { userId: string; role: Role } => {
  const ctx = storage.getStore();
  if (!ctx) throw new Error("No user context: currentUser() called outside handler()");
  return { userId: ctx.userId, role: ctx.role };
};
```

- [ ] **Step 4: Implement `journal.ts`** (move the bootstrap and migration code out of `db/index.ts` into here, unchanged in behaviour)

```ts
// apps/web/src/db/journal.ts
import Database from "better-sqlite3-multiple-ciphers";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import * as schema from "./schema";
import { BOOTSTRAP_SQL } from "./bootstrap";

export class JournalOpenError extends Error {}

const applyMigrations = (sqlite: Database.Database): void => {
  sqlite.exec(BOOTSTRAP_SQL);
  // Additive upgrade: existing executions retain their fields and dedup hashes.
  const executionColumns = sqlite.pragma("table_info(executions)") as { name: string }[];
  if (!executionColumns.some((column) => column.name === "import_metadata_json")) {
    sqlite.exec("ALTER TABLE executions ADD COLUMN import_metadata_json TEXT");
  }
  // Materialize CSV bounds once so connection and range lookups never scan candle JSON.
  const csvColumns = sqlite.pragma("table_info(market_csv_datasets)") as { name: string }[];
  sqlite.transaction(() => {
    for (const name of ["bar_count", "first_time", "last_time"]) {
      if (!csvColumns.some((column) => column.name === name))
        sqlite.exec(
          `ALTER TABLE market_csv_datasets ADD COLUMN ${name} INTEGER NOT NULL DEFAULT 0`,
        );
    }
    sqlite.exec(`UPDATE market_csv_datasets SET
      bar_count = json_array_length(bars_json),
      first_time = json_extract(bars_json, '$[0].time'),
      last_time = json_extract(bars_json, '$[#-1].time') WHERE bar_count = 0`);
  })();
};

const makeOrm = (sqlite: Database.Database) =>
  drizzle(sqlite as unknown as import("better-sqlite3").Database, { schema });
export type Journal = ReturnType<typeof makeOrm>;

/** Open one journal file. With a DEK the file is SQLCipher-encrypted; a wrong DEK throws JournalOpenError. */
export const openJournal = (file: string, dek?: Buffer): { sqlite: Database.Database; orm: Journal } => {
  mkdirSync(dirname(file), { recursive: true });
  const sqlite = new Database(file);
  try {
    if (dek) {
      sqlite.pragma("cipher='sqlcipher'");
      sqlite.pragma(`key="x'${dek.toString("hex")}'"`);
    }
    sqlite.pragma("journal_mode = WAL");
    sqlite.pragma("foreign_keys = ON");
    // First real read: fails with SQLITE_NOTADB when the key is wrong.
    sqlite.prepare("SELECT count(*) AS n FROM sqlite_master").get();
    applyMigrations(sqlite);
  } catch (error) {
    sqlite.close();
    throw new JournalOpenError(error instanceof Error ? error.message : "Journal could not be opened");
  }
  return { sqlite, orm: makeOrm(sqlite) };
};
```

- [ ] **Step 5: Rewrite `db/index.ts`**

Replace the whole file with:

```ts
// apps/web/src/db/index.ts
import { join } from "node:path";
import { currentUserContext, type UserContext } from "@/server/auth/context";
import { authDbExists, dataDir, legacyJournalPath, userDataDir } from "./paths";
import { openJournal, type Journal } from "./journal";
import type Database from "better-sqlite3-multiple-ciphers";

export { dataDir } from "./paths";
export * from "./schema";

interface Open {
  sqlite: Database.Database;
  orm: Journal;
  lastUsed: number;
}

const LEGACY = "__legacy__";
const globalForDb = globalThis as unknown as { __journalOpen?: Map<string, Open> };
const open = (globalForDb.__journalOpen ??= new Map<string, Open>());

const acquire = (key: string, file: string, dek?: Buffer): Journal => {
  let entry = open.get(key);
  if (!entry) {
    const opened = openJournal(file, dek);
    entry = { ...opened, lastUsed: Date.now() };
    open.set(key, entry);
  }
  entry.lastUsed = Date.now();
  return entry.orm;
};

/** The calling user's journal. Opens and caches the encrypted connection. */
export const journalFor = (ctx: UserContext): Journal =>
  acquire(ctx.userId, join(userDataDir(ctx.userId), "journal.db"), ctx.dek);

const resolve = (): Journal => {
  const ctx = currentUserContext();
  if (ctx) return journalFor(ctx);
  if (!authDbExists()) return acquire(LEGACY, legacyJournalPath());
  throw new Error("No user context: db used outside handler()");
};

const close = (key: string): void => {
  const entry = open.get(key);
  if (!entry) return;
  entry.sqlite.close();
  open.delete(key);
};

export const closeJournal = (userId: string): void => close(userId);
export const closeLegacyJournal = (): void => close(LEGACY);
export const closeIdleJournals = (maxIdleMs = 15 * 60 * 1000): void => {
  const cutoff = Date.now() - maxIdleMs;
  for (const [key, entry] of open) if (entry.lastUsed < cutoff) close(key);
};

/**
 * Request-scoped database. Every property access resolves the current user's
 * connection, so the modules importing `db` need no changes.
 */
export const db: Journal = new Proxy({} as Journal, {
  get(_target, property) {
    const target = resolve();
    const value = Reflect.get(target, property, target) as unknown;
    return typeof value === "function" ? (value as (...a: unknown[]) => unknown).bind(target) : value;
  },
});
```

- [ ] **Step 6: Run the new test and the whole suite**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/db-per-user.test.ts && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run`
Expected: 3 passed; whole suite green. Existing suites still hit the legacy journal because their temp dirs have no `auth.db`.

If `drizzle(...).transaction` fails through the Proxy with "this is undefined", the bind in the `get` trap is missing; keep the `.bind(target)`.

- [ ] **Step 7: Type check, format, commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/db apps/web/src/server/auth/context.ts apps/web/tests/db-per-user.test.ts
git add apps/web/src/db apps/web/src/server/auth/context.ts apps/web/tests/db-per-user.test.ts
git commit -m "Route database access to the calling user's encrypted journal"
```

---

### Task 5: Sessions and in-memory keys

**Files:**
- Create: `apps/web/src/server/auth/sessions.ts`
- Modify: `apps/web/src/server/auth.ts` (keep only `AUTH_COOKIE` and `isSecureRequest`)
- Test: `apps/web/tests/auth-sessions.test.ts`

**Interfaces:**
- Produces:
  - `SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000`
  - `createSession(input: { userId: string; role: Role; dek: Buffer; ip?: string; userAgent?: string }): string` (raw token, 64 hex)
  - `type Resolved = { kind: "active"; tokenHash: string; userId: string; role: Role; dek: Buffer } | { kind: "locked"; tokenHash: string; userId: string } | { kind: "none" }`
  - `resolveSession(rawToken: string | undefined, now?: number): Resolved`
  - `touchSession(tokenHash: string, now?: number): void` (writes at most once per 5 minutes)
  - `deleteSession(rawToken: string): void`, `deleteUserSessions(userId: string): void`, `listUserSessions(userId: string): { tokenHash: string; createdAt: string; lastSeenAt: string; ip: string | null; userAgent: string | null }[]`, `sweepExpiredSessions(now?: number): number`
  - `sessionCookieOptions(request: Request): { httpOnly: true; sameSite: "lax"; secure: boolean; path: "/"; maxAge: number }`
  - `forgetMemory(): void` (test hook simulating a restart)

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/auth-sessions.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { createUser } = await import("../src/server/auth/users");
const s = await import("../src/server/auth/sessions");

const alice = createUser({ username: "alice", password: "alice-password-1", role: "admin" });
const base = { userId: alice.user.id, role: alice.user.role, dek: alice.dek };

describe("sessions", () => {
  it("creates, resolves and deletes a session", () => {
    const token = s.createSession({ ...base, ip: "10.0.0.5", userAgent: "vitest" });
    expect(token).toMatch(/^[0-9a-f]{64}$/);
    const resolved = s.resolveSession(token);
    expect(resolved.kind).toBe("active");
    if (resolved.kind === "active") expect(resolved.dek.equals(alice.dek)).toBe(true);
    expect(s.listUserSessions(alice.user.id)).toHaveLength(1);
    s.deleteSession(token);
    expect(s.resolveSession(token).kind).toBe("none");
  });
  it("rejects unknown and expired tokens", () => {
    expect(s.resolveSession(undefined).kind).toBe("none");
    expect(s.resolveSession("f".repeat(64)).kind).toBe("none");
    const token = s.createSession(base);
    const later = Date.now() + s.SESSION_TTL_MS + 1000;
    expect(s.resolveSession(token, later).kind).toBe("none");
  });
  it("reports locked when the key is gone from memory, then forgets the row", () => {
    const token = s.createSession(base);
    s.forgetMemory();
    expect(s.resolveSession(token).kind).toBe("locked");
    expect(s.resolveSession(token).kind).toBe("none");
  });
  it("sign out everywhere removes all of a user's sessions", () => {
    s.createSession(base);
    s.createSession(base);
    expect(s.listUserSessions(alice.user.id).length).toBeGreaterThanOrEqual(2);
    s.deleteUserSessions(alice.user.id);
    expect(s.listUserSessions(alice.user.id)).toHaveLength(0);
  });
  it("cookie is Secure only behind https", () => {
    const plain = new Request("http://localhost:3000/api/auth");
    const proxied = new Request("http://localhost:3000/api/auth", { headers: { "x-forwarded-proto": "https" } });
    expect(s.sessionCookieOptions(plain).secure).toBe(false);
    expect(s.sessionCookieOptions(proxied).secure).toBe(true);
    expect(s.sessionCookieOptions(plain).maxAge).toBe(30 * 24 * 60 * 60);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-sessions.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Trim `server/auth.ts`**

Replace the file with:

```ts
// apps/web/src/server/auth.ts
export const AUTH_COOKIE = "journal_session";

/**
 * Whether the browser reached us over HTTPS. Behind a TLS-terminating reverse
 * proxy the app only sees plain HTTP, so trust the first hop of
 * X-Forwarded-Proto before falling back to the request URL.
 */
export const isSecureRequest = (request: Request): boolean => {
  const forwarded = request.headers.get("x-forwarded-proto");
  if (forwarded) return forwarded.split(",")[0]?.trim().toLowerCase() === "https";
  return new URL(request.url).protocol === "https:";
};
```

`server/api.ts` and `app/api/auth/route.ts` still import the removed names; they are rewritten in Tasks 7 and 8. Until then `tsc` will report those two files; that is expected within this task. Do not run the full type check at the end of this task; run only the session test file.

- [ ] **Step 4: Implement `sessions.ts`**

```ts
// apps/web/src/server/auth/sessions.ts
import { createHash, randomBytes } from "node:crypto";
import { isSecureRequest } from "@/server/auth";
import { authDb, nowIso, type Role } from "./db";

export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;

interface MemoryEntry {
  userId: string;
  role: Role;
  dek: Buffer;
  touchedAt: number;
}
const globalForSessions = globalThis as unknown as { __journalSessionKeys?: Map<string, MemoryEntry> };
const memory = (globalForSessions.__journalSessionKeys ??= new Map<string, MemoryEntry>());

const hashToken = (raw: string): string => createHash("sha256").update(raw).digest("hex");

export type Resolved =
  | { kind: "active"; tokenHash: string; userId: string; role: Role; dek: Buffer }
  | { kind: "locked"; tokenHash: string; userId: string }
  | { kind: "none" };

export const createSession = (input: {
  userId: string;
  role: Role;
  dek: Buffer;
  ip?: string;
  userAgent?: string;
}): string => {
  const raw = randomBytes(32).toString("hex");
  const tokenHash = hashToken(raw);
  const now = Date.now();
  authDb()
    .prepare(
      `INSERT INTO sessions (token_hash, user_id, created_at, expires_at, last_seen_at, ip, user_agent)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      tokenHash,
      input.userId,
      new Date(now).toISOString(),
      new Date(now + SESSION_TTL_MS).toISOString(),
      new Date(now).toISOString(),
      input.ip ?? null,
      input.userAgent ?? null,
    );
  memory.set(tokenHash, { userId: input.userId, role: input.role, dek: input.dek, touchedAt: now });
  return raw;
};

export const resolveSession = (rawToken: string | undefined, now = Date.now()): Resolved => {
  if (!rawToken || !/^[0-9a-f]{64}$/.test(rawToken)) return { kind: "none" };
  const tokenHash = hashToken(rawToken);
  const row = authDb()
    .prepare("SELECT user_id, expires_at FROM sessions WHERE token_hash = ?")
    .get(tokenHash) as { user_id: string; expires_at: string } | undefined;
  if (!row) {
    memory.delete(tokenHash);
    return { kind: "none" };
  }
  if (new Date(row.expires_at).getTime() <= now) {
    authDb().prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    memory.delete(tokenHash);
    return { kind: "none" };
  }
  const entry = memory.get(tokenHash);
  if (!entry) {
    // Key was lost (process restart). Drop the row so the next call is a clean "none".
    authDb().prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
    return { kind: "locked", tokenHash, userId: row.user_id };
  }
  return { kind: "active", tokenHash, userId: entry.userId, role: entry.role, dek: entry.dek };
};

export const touchSession = (tokenHash: string, now = Date.now()): void => {
  const entry = memory.get(tokenHash);
  if (!entry || now - entry.touchedAt < TOUCH_INTERVAL_MS) return;
  entry.touchedAt = now;
  authDb()
    .prepare("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?")
    .run(new Date(now).toISOString(), tokenHash);
};

export const deleteSession = (rawToken: string): void => {
  const tokenHash = hashToken(rawToken);
  authDb().prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
  memory.delete(tokenHash);
};

export const deleteUserSessions = (userId: string): void => {
  authDb().prepare("DELETE FROM sessions WHERE user_id = ?").run(userId);
  for (const [hash, entry] of memory) if (entry.userId === userId) memory.delete(hash);
};

export const listUserSessions = (userId: string) =>
  (
    authDb()
      .prepare(
        "SELECT token_hash, created_at, last_seen_at, ip, user_agent FROM sessions WHERE user_id = ? ORDER BY last_seen_at DESC",
      )
      .all(userId) as {
      token_hash: string;
      created_at: string;
      last_seen_at: string;
      ip: string | null;
      user_agent: string | null;
    }[]
  ).map((r) => ({
    tokenHash: r.token_hash,
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at,
    ip: r.ip,
    userAgent: r.user_agent,
  }));

export const sweepExpiredSessions = (now = Date.now()): number => {
  const result = authDb()
    .prepare("DELETE FROM sessions WHERE expires_at <= ?")
    .run(new Date(now).toISOString());
  return result.changes;
};

export const sessionCookieOptions = (request: Request) => ({
  httpOnly: true as const,
  sameSite: "lax" as const,
  secure: isSecureRequest(request),
  path: "/" as const,
  maxAge: SESSION_TTL_MS / 1000,
});

/** Test hook: simulate a process restart. */
export const forgetMemory = (): void => memory.clear();

export { nowIso };
```

- [ ] **Step 5: Run the test**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-sessions.test.ts`
Expected: 5 passed.

- [ ] **Step 6: Format and commit** (type errors in `api.ts` and `api/auth/route.ts` are expected until Task 7 and 8)

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/server/auth.ts apps/web/src/server/auth/sessions.ts apps/web/tests/auth-sessions.test.ts
git add apps/web/src/server/auth.ts apps/web/src/server/auth/sessions.ts apps/web/tests/auth-sessions.test.ts
git commit -m "Add server-side sessions with in-memory journal keys"
```

---

### Task 6: Rate limiting and IP blocks

**Files:**
- Create: `apps/web/src/server/auth/rate-limit.ts`
- Test: `apps/web/tests/auth-rate-limit.test.ts`

**Interfaces:**
- Produces:
  - `LIMITS = { ip: { attempts: 10, windowMs: 300000, blockMs: 3600000 }, user: { failures: 5, windowMs: 300000, blockMs: 21600000 } }`
  - `clientIp(request: Request): string` (`"unknown"` when nothing usable)
  - `checkLogin(ip: string, username: string, now?: number): { allowed: true } | { allowed: false; retryAfterSec: number; message: string }`
  - `recordAttempt(ip: string, username: string, success: boolean, now?: number): void` (creates auto IP blocks and user locks when thresholds are crossed)
  - `isIpBlocked(ip: string, now?: number): boolean`
  - `listBlocks(now?: number): { cidr: string; source: "auto" | "manual"; reason: string | null; createdAt: string; expiresAt: string | null }[]`
  - `addBlock(input: { cidr: string; reason?: string; expiresAt?: string | null; source?: "auto" | "manual" }): void`
  - `removeBlock(cidr: string): void`
  - `ipInCidr(ip: string, cidr: string): boolean`

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/auth-rate-limit.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { createUser, getUser, setUserLock } = await import("../src/server/auth/users");
const rl = await import("../src/server/auth/rate-limit");

const alice = createUser({ username: "alice", password: "alice-password-1", role: "admin" });
const T0 = Date.parse("2026-09-21T12:00:00Z");
const min = (n: number) => n * 60 * 1000;

describe("rate limiting", () => {
  it("blocks an IP for 60 minutes after 10 attempts in 5 minutes, success included", () => {
    for (let i = 0; i < 9; i += 1) rl.recordAttempt("203.0.113.9", "ghost", i === 0, T0 + i * 1000);
    expect(rl.checkLogin("203.0.113.9", "ghost", T0 + 10000).allowed).toBe(true);
    rl.recordAttempt("203.0.113.9", "ghost", false, T0 + 10000);
    const denied = rl.checkLogin("203.0.113.9", "ghost", T0 + 11000);
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) {
      expect(denied.retryAfterSec).toBeGreaterThan(min(59) / 1000);
      expect(denied.message).toMatch(/Try again in 60 minutes/);
    }
    expect(rl.isIpBlocked("203.0.113.9", T0 + min(59))).toBe(true);
    expect(rl.isIpBlocked("203.0.113.9", T0 + min(61))).toBe(false);
    expect(rl.listBlocks(T0 + min(1))[0]?.source).toBe("auto");
  });
  it("locks a username for 360 minutes after 5 failures in 5 minutes and success does not lift it", () => {
    for (let i = 0; i < 5; i += 1) rl.recordAttempt(`198.51.100.${i}`, "alice", false, T0 + i * 1000);
    const denied = rl.checkLogin("198.51.100.99", "ALICE", T0 + 6000);
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) expect(denied.message).toMatch(/360 minutes/);
    expect(getUser(alice.user.id)?.lockedUntil).toBe(new Date(T0 + 4000 + min(360)).toISOString());
    rl.recordAttempt("198.51.100.99", "alice", true, T0 + 7000);
    expect(rl.checkLogin("198.51.100.99", "alice", T0 + 8000).allowed).toBe(false);
    setUserLock(alice.user.id, null);
    expect(rl.checkLogin("198.51.100.99", "alice", T0 + 9000).allowed).toBe(true);
  });
  it("manual CIDR blocks match and can be removed", () => {
    rl.addBlock({ cidr: "192.0.2.0/24", reason: "test" });
    expect(rl.isIpBlocked("192.0.2.77")).toBe(true);
    expect(rl.isIpBlocked("192.0.3.1")).toBe(false);
    rl.addBlock({ cidr: "2001:db8::/32" });
    expect(rl.isIpBlocked("2001:db8:1::5")).toBe(true);
    rl.removeBlock("192.0.2.0/24");
    expect(rl.isIpBlocked("192.0.2.77")).toBe(false);
    expect(rl.ipInCidr("::ffff:192.0.2.1", "192.0.2.0/24")).toBe(true);
  });
  it("derives the client IP from proxy headers when trusted", () => {
    const req = (headers: Record<string, string>) => new Request("http://localhost:3000/", { headers });
    expect(rl.clientIp(req({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" }))).toBe("203.0.113.7");
    expect(rl.clientIp(req({ "x-real-ip": "203.0.113.8" }))).toBe("203.0.113.8");
    expect(rl.clientIp(req({}))).toBe("unknown");
    process.env.JOURNAL_TRUST_PROXY = "false";
    expect(rl.clientIp(req({ "x-forwarded-for": "203.0.113.7" }))).toBe("unknown");
    delete process.env.JOURNAL_TRUST_PROXY;
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-rate-limit.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement `rate-limit.ts`**

```ts
// apps/web/src/server/auth/rate-limit.ts
import { isIP } from "node:net";
import { authDb } from "./db";
import { findUserByUsername, setUserLock } from "./users";

export const LIMITS = {
  ip: { attempts: 10, windowMs: 5 * 60 * 1000, blockMs: 60 * 60 * 1000 },
  user: { failures: 5, windowMs: 5 * 60 * 1000, blockMs: 360 * 60 * 1000 },
} as const;

const iso = (ms: number): string => new Date(ms).toISOString();

// ---------- IP parsing and CIDR matching ----------

const ipToBigInt = (ip: string): { value: bigint; bits: 128 } | null => {
  const mapped = ip.startsWith("::ffff:") ? ip.slice(7) : ip;
  if (isIP(mapped) === 4) {
    const parts = mapped.split(".").map(Number);
    const v4 = parts.reduce((acc, part) => (acc << 8n) + BigInt(part), 0n);
    return { value: (0xffffn << 32n) + v4, bits: 128 };
  }
  if (isIP(ip) !== 6) return null;
  const [head = "", tail = ""] = ip.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const missing = 8 - headParts.length - tailParts.length;
  const groups = [...headParts, ...Array<string>(Math.max(missing, 0)).fill("0"), ...tailParts];
  const value = groups.reduce((acc, group) => (acc << 16n) + BigInt(parseInt(group || "0", 16)), 0n);
  return { value, bits: 128 };
};

export const ipInCidr = (ip: string, cidr: string): boolean => {
  const [base, prefixText] = cidr.split("/");
  if (!base) return false;
  const baseParsed = ipToBigInt(base);
  const ipParsed = ipToBigInt(ip);
  if (!baseParsed || !ipParsed) return false;
  const baseIsV4 = isIP(base.startsWith("::ffff:") ? base.slice(7) : base) === 4;
  const rawPrefix = prefixText === undefined ? (baseIsV4 ? 32 : 128) : Number(prefixText);
  const prefix = baseIsV4 ? rawPrefix + 96 : rawPrefix;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 128) return false;
  const shift = BigInt(128 - prefix);
  return baseParsed.value >> shift === ipParsed.value >> shift;
};

const normalizeCidr = (cidr: string): string => {
  const [base, prefix] = cidr.trim().split("/");
  if (!base || isIP(base) === 0) throw new Error("Invalid IP or CIDR");
  const bits = isIP(base) === 4 ? 32 : 128;
  const p = prefix === undefined ? bits : Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > bits) throw new Error("Invalid CIDR prefix");
  return `${base}/${p}`;
};

// ---------- client IP ----------

export const clientIp = (request: Request): string => {
  const trust = (process.env.JOURNAL_TRUST_PROXY ?? "true").toLowerCase() !== "false";
  if (!trust) return "unknown";
  const forwarded = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  const candidate = forwarded || request.headers.get("x-real-ip")?.trim() || "";
  return isIP(candidate) ? candidate : "unknown";
};

// ---------- blocks ----------

export const listBlocks = (now = Date.now()) =>
  (
    authDb()
      .prepare(
        "SELECT cidr, source, reason, created_at, expires_at FROM ip_blocks WHERE expires_at IS NULL OR expires_at > ? ORDER BY created_at DESC",
      )
      .all(iso(now)) as {
      cidr: string;
      source: "auto" | "manual";
      reason: string | null;
      created_at: string;
      expires_at: string | null;
    }[]
  ).map((r) => ({
    cidr: r.cidr,
    source: r.source,
    reason: r.reason,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
  }));

export const addBlock = (input: {
  cidr: string;
  reason?: string;
  expiresAt?: string | null;
  source?: "auto" | "manual";
}): void => {
  authDb()
    .prepare(
      `INSERT INTO ip_blocks (cidr, source, reason, created_at, expires_at) VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(cidr) DO UPDATE SET source = excluded.source, reason = excluded.reason,
         created_at = excluded.created_at, expires_at = excluded.expires_at`,
    )
    .run(normalizeCidr(input.cidr), input.source ?? "manual", input.reason ?? null, iso(Date.now()), input.expiresAt ?? null);
};

export const removeBlock = (cidr: string): void => {
  authDb().prepare("DELETE FROM ip_blocks WHERE cidr = ?").run(normalizeCidr(cidr));
};

export const isIpBlocked = (ip: string, now = Date.now()): boolean => {
  if (ip === "unknown") return false;
  return listBlocks(now).some((block) => ipInCidr(ip, block.cidr));
};

const blockExpiry = (ip: string, now: number): number | null => {
  if (ip === "unknown") return null;
  const rows = listBlocks(now).filter((b) => ipInCidr(ip, b.cidr));
  if (rows.length === 0) return null;
  if (rows.some((b) => b.expiresAt === null)) return Number.POSITIVE_INFINITY;
  return Math.max(...rows.map((b) => new Date(b.expiresAt as string).getTime()));
};

// ---------- attempts ----------

const countAttempts = (column: "ip" | "username", value: string, since: number, failuresOnly: boolean): number =>
  (
    authDb()
      .prepare(
        `SELECT COUNT(*) AS n FROM login_attempts WHERE ${column} = ? COLLATE NOCASE AND at > ?${failuresOnly ? " AND success = 0" : ""}`,
      )
      .get(value, iso(since)) as { n: number }
  ).n;

const minutesLeft = (untilMs: number, now: number): number => Math.max(1, Math.ceil((untilMs - now) / 60000));

export const checkLogin = (
  ip: string,
  username: string,
  now = Date.now(),
): { allowed: true } | { allowed: false; retryAfterSec: number; message: string } => {
  const ipUntil = blockExpiry(ip, now);
  if (ipUntil !== null) {
    const retry = ipUntil === Number.POSITIVE_INFINITY ? 3600 : Math.ceil((ipUntil - now) / 1000);
    const minutes = ipUntil === Number.POSITIVE_INFINITY ? 60 : minutesLeft(ipUntil, now);
    return { allowed: false, retryAfterSec: retry, message: `Too many attempts. Try again in ${minutes} minutes.` };
  }
  const user = findUserByUsername(username);
  if (user?.lockedUntil && new Date(user.lockedUntil).getTime() > now) {
    const until = new Date(user.lockedUntil).getTime();
    return {
      allowed: false,
      retryAfterSec: Math.ceil((until - now) / 1000),
      message: `Too many attempts. Try again in ${minutesLeft(until, now)} minutes.`,
    };
  }
  return { allowed: true };
};

export const recordAttempt = (ip: string, username: string, success: boolean, now = Date.now()): void => {
  authDb()
    .prepare("INSERT INTO login_attempts (username, ip, at, success) VALUES (?, ?, ?, ?)")
    .run(username, ip, iso(now), success ? 1 : 0);
  if (ip !== "unknown" && countAttempts("ip", ip, now - LIMITS.ip.windowMs, false) >= LIMITS.ip.attempts) {
    addBlock({ cidr: ip, source: "auto", reason: "Too many login attempts", expiresAt: iso(now + LIMITS.ip.blockMs) });
    console.warn(`[auth] IP ${ip} blocked for ${LIMITS.ip.blockMs / 60000} minutes after ${LIMITS.ip.attempts} attempts`);
  }
  if (!success && countAttempts("username", username, now - LIMITS.user.windowMs, true) >= LIMITS.user.failures) {
    const user = findUserByUsername(username);
    if (user) {
      setUserLock(user.id, iso(now + LIMITS.user.blockMs));
      console.warn(`[auth] user ${user.username} locked for ${LIMITS.user.blockMs / 60000} minutes after ${LIMITS.user.failures} failures (ip ${ip})`);
    }
  }
  // Keep the table small: attempts older than the longest window are useless.
  authDb().prepare("DELETE FROM login_attempts WHERE at < ?").run(iso(now - LIMITS.user.windowMs * 2));
};
```

- [ ] **Step 4: Run the test**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-rate-limit.test.ts`
Expected: 4 passed. If the 60-minute assertion is off by one, check that `recordAttempt` inserts the row before counting.

- [ ] **Step 5: Format and commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/server/auth/rate-limit.ts apps/web/tests/auth-rate-limit.test.ts
git add apps/web/src/server/auth/rate-limit.ts apps/web/tests/auth-rate-limit.test.ts
git commit -m "Add persistent login rate limiting and IP blocks"
```

---

### Task 7: Route wrapper and middleware

**Files:**
- Modify: `apps/web/src/server/api.ts` (the `handler` function)
- Modify: `apps/web/src/middleware.ts`
- Rewrite: `apps/web/tests/api-auth.test.ts`
- Delete: `apps/web/tests/auth-gate.unit.test.ts` (its cases move into `api-auth.test.ts`)

**Interfaces:**
- Consumes: `resolveSession`, `touchSession` (Task 5); `getUser` (Task 3); `runWithUser` (Task 4); `isIpBlocked`, `clientIp` (Task 6); `authDbExists` (Task 3); `JournalOpenError` (Task 4).
- Produces: `handler(fn, options?: { public?: boolean; admin?: boolean; allowPasswordChange?: boolean })`. Unchanged exports `ok`, `bad`, `RequestError`, `requireValue`. New export `forbidden(reason: string, message?: string)`.

- [ ] **Step 1: Write the failing tests**

Replace `apps/web/tests/api-auth.test.ts` with:

```ts
// apps/web/tests/api-auth.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const jar = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (jar.token ? { value: jar.token } : undefined),
    set: () => undefined,
    delete: () => undefined,
  }),
}));

const { handler, ok } = await import("../src/server/api");
const { createUser } = await import("../src/server/auth/users");
const { createSession, forgetMemory } = await import("../src/server/auth/sessions");
const { addBlock, removeBlock } = await import("../src/server/auth/rate-limit");
const { db, accounts } = await import("../src/db");

afterEach(() => {
  jar.token = undefined;
});

const req = (headers: Record<string, string> = {}) =>
  new Request("http://localhost:3000/api/x", { headers });
const route = handler(async () => ok({ count: db.select().from(accounts).all().length }));

describe("handler auth gate", () => {
  it("passes through before setup only under vitest", async () => {
    expect((await route(req())).status).toBe(200);
  });
  it("rejects missing and forged cookies once users exist", async () => {
    createUser({ username: "alice", password: "alice-password-1", role: "admin" });
    for (const token of [undefined, "forged", "0".repeat(64)]) {
      jar.token = token;
      expect((await route(req())).status).toBe(401);
    }
  });
  it("accepts a real session and runs inside the user's journal", async () => {
    const bob = createUser({ username: "bob", password: "bob-password-123", role: "user" });
    jar.token = createSession({ userId: bob.user.id, role: "user", dek: bob.dek });
    const response = await route(req());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ count: 0 });
  });
  it("answers locked after a restart", async () => {
    const carol = createUser({ username: "carol", password: "carol-password-1", role: "user" });
    jar.token = createSession({ userId: carol.user.id, role: "user", dek: carol.dek });
    forgetMemory();
    const response = await route(req());
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "Locked", reason: "locked" });
  });
  it("forces a password change and gates admin routes", async () => {
    const dave = createUser({ username: "dave", password: "dave-password-12", role: "user", mustChangePassword: true });
    jar.token = createSession({ userId: dave.user.id, role: "user", dek: dave.dek });
    const gated = await route(req());
    expect(gated.status).toBe(403);
    expect((await gated.json()).reason).toBe("password_change_required");
    const allowed = handler(async () => ok({ fine: true }), { allowPasswordChange: true });
    expect((await allowed(req())).status).toBe(200);
    const adminOnly = handler(async () => ok({ admin: true }), { admin: true });
    expect((await adminOnly(req())).status).toBe(403);
  });
  it("blocks manually blocked IPs on every route", async () => {
    addBlock({ cidr: "203.0.113.0/24", reason: "test" });
    const publicRoute = handler(async () => ok({ open: true }), { public: true });
    expect((await publicRoute(req({ "x-forwarded-for": "203.0.113.5" }))).status).toBe(403);
    expect((await publicRoute(req({ "x-forwarded-for": "198.51.100.5" }))).status).toBe(200);
    removeBlock("203.0.113.0/24");
  });
});
```

Delete `apps/web/tests/auth-gate.unit.test.ts`.

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/api-auth.test.ts`
Expected: FAIL (old `handler` imports removed names from `server/auth`).

- [ ] **Step 3: Rewrite `handler` in `server/api.ts`**

Replace the imports and the `handler` export; keep `ok` and `bad` as they are and keep the `./errors` re-export added in Task 3.

```ts
// apps/web/src/server/api.ts  (top of file)
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { RequestError } from "./errors";
export { RequestError, requireValue } from "./errors";
import { AUTH_COOKIE } from "./auth";
import { authDbExists } from "@/db/paths";
import { JournalOpenError } from "@/db/journal";
import { runWithUser } from "./auth/context";
import { getUser } from "./auth/users";
import { resolveSession, touchSession } from "./auth/sessions";
import { clientIp, isIpBlocked } from "./auth/rate-limit";
```

```ts
export const forbidden = (reason: string, message = "Forbidden") =>
  NextResponse.json({ error: message, reason }, { status: 403 });

export interface HandlerOptions {
  /** No session needed (login, setup, recovery). IP blocks still apply. */
  public?: boolean;
  /** Only admins. */
  admin?: boolean;
  /** Reachable while must_change_password is set (password change, logout, whoami). */
  allowPasswordChange?: boolean;
}

/** Route-handler wrapper: auth gate, per-user journal context, uniform error JSON. */
export const handler =
  <A extends unknown[]>(
    fn: (...args: A) => Promise<Response> | Response,
    options: HandlerOptions = {},
  ) =>
  async (...args: A): Promise<Response> => {
    try {
      const request = args[0] instanceof Request ? args[0] : undefined;
      const setupDone = authDbExists();
      if (request && setupDone && isIpBlocked(clientIp(request))) return forbidden("ip_blocked");
      if (options.public) return await fn(...args);
      if (!setupDone) {
        if (process.env.VITEST === "true") return await fn(...args);
        return NextResponse.json({ error: "Setup required", reason: "setup_required" }, { status: 409 });
      }
      const raw = (await cookies()).get(AUTH_COOKIE)?.value;
      const session = resolveSession(raw);
      if (session.kind === "none") return bad("Unauthorized", 401);
      if (session.kind === "locked")
        return NextResponse.json({ error: "Locked", reason: "locked" }, { status: 401 });
      const user = getUser(session.userId);
      if (!user) return bad("Unauthorized", 401);
      if (user.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now())
        return forbidden("user_locked", "Account locked");
      if (user.mustChangePassword && !options.allowPasswordChange)
        return forbidden("password_change_required", "Password change required");
      if (options.admin && user.role !== "admin") return forbidden("admin_only");
      touchSession(session.tokenHash);
      return await runWithUser(
        { userId: user.id, role: user.role, dek: session.dek },
        () => fn(...args),
      );
    } catch (error) {
      if (error instanceof JournalOpenError) {
        console.error("[journal] open failed:", error.message);
        return NextResponse.json({ error: "Journal could not be opened" }, { status: 500 });
      }
      const message = error instanceof Error ? error.message : "Internal error";
      return NextResponse.json(
        { error: message },
        { status: error instanceof RequestError ? 400 : 500 },
      );
    }
  };
```

`runWithUser` returns whatever `fn` returns; because `fn` is async the result is a promise and the `await` above is correct.

- [ ] **Step 4: Rewrite `middleware.ts`**

```ts
// apps/web/src/middleware.ts
import { NextResponse, type NextRequest } from "next/server";

const PUBLIC_PAGES = new Set(["/login", "/setup", "/recover"]);
const PUBLIC_API = new Set(["/api/auth", "/api/auth/recover", "/api/setup"]);

/**
 * Presence gate only: the edge runtime has no filesystem or Node crypto, so the
 * cookie is validated in handler(). Pages without a cookie go to /login; the
 * login page itself redirects to /setup when the server reports setup mode.
 */
export const middleware = (request: NextRequest) => {
  const { pathname } = request.nextUrl;
  if (PUBLIC_PAGES.has(pathname) || PUBLIC_API.has(pathname)) return NextResponse.next();
  const cookie = request.cookies.get("journal_session")?.value;
  if (!cookie) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
};

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

- [ ] **Step 5: Run the auth test, then the whole suite**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/api-auth.test.ts && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run`
Expected: 6 passed; whole suite green. Existing suites that stub `JOURNAL_PASSWORD` keep passing because the stub is now ignored.

- [ ] **Step 6: Type check (only `app/api/auth/route.ts` may still fail; Task 8 rewrites it), format, commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/server/api.ts apps/web/src/middleware.ts apps/web/tests/api-auth.test.ts
git add -A apps/web/src/server/api.ts apps/web/src/middleware.ts apps/web/tests/api-auth.test.ts apps/web/tests/auth-gate.unit.test.ts
git commit -m "Gate routes on server sessions and run them in the user's journal"
```

---

### Task 8: Setup, migration, and the auth routes

**Files:**
- Create: `apps/web/src/server/auth/setup.ts`
- Create: `apps/web/src/app/api/setup/route.ts`
- Rewrite: `apps/web/src/app/api/auth/route.ts`
- Create: `apps/web/src/app/api/auth/recover/route.ts`
- Test: `apps/web/tests/setup-migration.test.ts`
- Test: `apps/web/tests/api-login.test.ts`

**Interfaces:**
- Consumes: Tasks 3 to 7.
- Produces (`setup.ts`): `setupRequired(): boolean`, `runSetup(input: { username: string; password: string }): { user: UserRecord; recoveryKey: string; migrated: Record<string, number> | null }`, `migrateLegacyJournal(userId: string, dek: Buffer): Record<string, number> | null`.
- Produces (HTTP):
  - `GET /api/auth` → `{ setupRequired: boolean; authenticated: boolean; user?: { id, username, role, mustChangePassword } }`
  - `POST /api/auth` `{ username, password }` → `200 { authenticated: true, mustChangePassword }` | `401` | `429` | `409 setup_required`
  - `DELETE /api/auth` → `200 { authenticated: false }` and clears the cookie
  - `POST /api/setup` `{ username, password }` → `200 { user, recoveryKey, migrated }` | `409`
  - `POST /api/auth/recover` `{ username, recoveryKey, newPassword }` → `200 { recoveryKey }` | `401` | `429`

- [ ] **Step 1: Write the failing migration test**

```ts
// apps/web/tests/setup-migration.test.ts
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { db, accounts, notes, folders } = await import("../src/db");
const { runWithUser } = await import("../src/server/auth/context");
const { setupRequired, runSetup } = await import("../src/server/auth/setup");
const { verifyLogin } = await import("../src/server/auth/users");

describe("first-run setup and migration", () => {
  it("moves a plaintext journal into the admin's encrypted journal", () => {
    // Seed the legacy journal (no auth.db yet, so db resolves to data/journal.db).
    db.insert(accounts).values({ id: "acc", name: "Legacy", kind: "manual", createdAt: "2026-01-01" }).run();
    db.insert(folders).values({ id: "f1", name: "Ideas", createdAt: "2026-01-01" }).run();
    db.insert(notes).values({ id: "n1", folderId: "f1", title: "Hello", content: "world", createdAt: "2026-01-01", updatedAt: "2026-01-01" }).run();
    expect(setupRequired()).toBe(true);

    const result = runSetup({ username: "admin", password: "admin-password-1" });
    expect(setupRequired()).toBe(false);
    expect(result.user.role).toBe("admin");
    expect(result.migrated).toMatchObject({ accounts: 1, folders: 1, notes: 1 });
    expect(existsSync(join(scratch, "journal.db.pre-encryption"))).toBe(true);
    expect(existsSync(join(scratch, "journal.db"))).toBe(false);

    const login = verifyLogin("admin", "admin-password-1");
    expect(login).not.toBeNull();
    if (!login) return;
    const ctx = { userId: login.user.id, role: login.user.role, dek: login.dek };
    expect(runWithUser(ctx, () => db.select().from(notes).all()).map((n) => n.title)).toEqual(["Hello"]);
    expect(() => runSetup({ username: "again", password: "again-password-1" })).toThrow(/already/);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/setup-migration.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement `setup.ts`**

```ts
// apps/web/src/server/auth/setup.ts
import Database from "better-sqlite3-multiple-ciphers";
import { existsSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { RequestError } from "@/server/errors";
import { closeLegacyJournal } from "@/db";
import { openJournal } from "@/db/journal";
import { authDbExists, legacyJournalPath, userDataDir } from "@/db/paths";
import { createUser, type UserRecord } from "./users";

export const setupRequired = (): boolean => !authDbExists();

/**
 * Copy every table of the plaintext data/journal.db into the user's encrypted
 * journal, row by row, then rename the original. Returns per-table row counts,
 * or null when there was nothing to migrate.
 */
export const migrateLegacyJournal = (userId: string, dek: Buffer): Record<string, number> | null => {
  const legacyPath = legacyJournalPath();
  if (!existsSync(legacyPath)) return null;
  closeLegacyJournal();
  const legacy = new Database(legacyPath, { readonly: false });
  legacy.pragma("wal_checkpoint(TRUNCATE)");
  const target = openJournal(join(userDataDir(userId), "journal.db"), dek);
  const counts: Record<string, number> = {};
  try {
    const tables = (
      legacy
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .all() as { name: string }[]
    ).map((row) => row.name);
    const targetTables = new Set(
      (target.sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as { name: string }[]).map((r) => r.name),
    );
    target.sqlite.pragma("foreign_keys = OFF");
    const copyAll = target.sqlite.transaction(() => {
      for (const table of tables) {
        if (!targetTables.has(table)) continue;
        const legacyCols = (legacy.pragma(`table_info(${table})`) as { name: string }[]).map((c) => c.name);
        const targetCols = new Set((target.sqlite.pragma(`table_info(${table})`) as { name: string }[]).map((c) => c.name));
        const cols = legacyCols.filter((c) => targetCols.has(c));
        if (cols.length === 0) continue;
        const list = cols.map((c) => `"${c}"`).join(", ");
        const insert = target.sqlite.prepare(
          `INSERT OR REPLACE INTO "${table}" (${list}) VALUES (${cols.map(() => "?").join(", ")})`,
        );
        let n = 0;
        for (const row of legacy.prepare(`SELECT ${list} FROM "${table}"`).iterate() as Iterable<Record<string, unknown>>) {
          insert.run(...cols.map((c) => row[c]));
          n += 1;
        }
        counts[table] = n;
      }
    });
    copyAll();
    target.sqlite.pragma("foreign_keys = ON");
  } finally {
    legacy.close();
    target.sqlite.close();
  }
  renameSync(legacyPath, `${legacyPath}.pre-encryption`);
  for (const suffix of ["-wal", "-shm"]) rmSync(`${legacyPath}${suffix}`, { force: true });
  console.info("[setup] migrated legacy journal:", JSON.stringify(counts));
  return counts;
};

export const runSetup = (input: {
  username: string;
  password: string;
}): { user: UserRecord; recoveryKey: string; migrated: Record<string, number> | null } => {
  if (!setupRequired()) throw new RequestError("Setup has already been completed.");
  const created = createUser({ username: input.username, password: input.password, role: "admin" });
  const migrated = migrateLegacyJournal(created.user.id, created.dek);
  return { user: created.user, recoveryKey: created.recoveryKey, migrated };
};
```

- [ ] **Step 4: Run the migration test**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/setup-migration.test.ts`
Expected: 1 passed. If `INSERT OR REPLACE` complains about a NOT NULL column that the legacy table lacks, the legacy file predates that column; the bootstrap's default covers it, so filter `cols` as written (only common columns) and rely on the target default.

- [ ] **Step 5: Write the failing login route test**

```ts
// apps/web/tests/api-login.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const jar = vi.hoisted(() => ({ token: undefined as string | undefined, set: [] as unknown[] }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (jar.token ? { value: jar.token } : undefined),
    set: (name: string, value: string, options: unknown) => {
      jar.set.push({ name, value, options });
      jar.token = value;
    },
    delete: () => {
      jar.token = undefined;
    },
  }),
}));

const setup = await import("../src/app/api/setup/route");
const auth = await import("../src/app/api/auth/route");
const recover = await import("../src/app/api/auth/recover/route");

const post = (url: string, body: unknown, headers: Record<string, string> = {}) =>
  new Request(`http://localhost:3000${url}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body),
  });
const get = (url: string) => new Request(`http://localhost:3000${url}`);

describe("setup and login routes", () => {
  let recoveryKey = "";
  it("reports setup mode, then completes setup once", async () => {
    expect(await (await auth.GET(get("/api/auth"))).json()).toMatchObject({ setupRequired: true, authenticated: false });
    const res = await setup.POST(post("/api/setup", { username: "admin", password: "admin-password-1" }));
    expect(res.status).toBe(200);
    recoveryKey = (await res.json()).recoveryKey;
    expect(recoveryKey).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/);
    expect((await setup.POST(post("/api/setup", { username: "x", password: "xxxxxxxxxxxx" }))).status).toBe(400);
  });
  it("logs in, reports the user, and logs out", async () => {
    const wrong = await auth.POST(post("/api/auth", { username: "admin", password: "nope-nope-nope" }));
    expect(wrong.status).toBe(401);
    expect(await wrong.json()).toEqual({ error: "Invalid username or password." });
    const res = await auth.POST(post("/api/auth", { username: "admin", password: "admin-password-1" }));
    expect(res.status).toBe(200);
    expect(jar.token).toMatch(/^[0-9a-f]{64}$/);
    expect(await (await auth.GET(get("/api/auth"))).json()).toMatchObject({ authenticated: true, user: { username: "admin", role: "admin" } });
    expect((await auth.DELETE(get("/api/auth"))).status).toBe(200);
    expect(await (await auth.GET(get("/api/auth"))).json()).toMatchObject({ authenticated: false });
  });
  it("rate limits by username and answers 429 with Retry-After", async () => {
    let last: Response | undefined;
    for (let i = 0; i < 6; i += 1)
      last = await auth.POST(post("/api/auth", { username: "admin", password: "bad-password-99" }, { "x-forwarded-for": `198.51.100.${i}` }));
    expect(last?.status).toBe(429);
    expect(last?.headers.get("retry-after")).toMatch(/^\d+$/);
    expect((await last?.json()).error).toMatch(/Try again in 360 minutes/);
  });
  it("recovers with the recovery key and rotates it", async () => {
    const { setUserLock, findUserByUsername } = await import("../src/server/auth/users");
    const admin = findUserByUsername("admin");
    if (admin) setUserLock(admin.id, null);
    const res = await recover.POST(post("/api/auth/recover", { username: "admin", recoveryKey, newPassword: "admin-password-2" }, { "x-forwarded-for": "203.0.113.50" }));
    expect(res.status).toBe(200);
    const fresh = (await res.json()).recoveryKey;
    expect(fresh).not.toBe(recoveryKey);
    expect((await auth.POST(post("/api/auth", { username: "admin", password: "admin-password-2" }, { "x-forwarded-for": "203.0.113.51" }))).status).toBe(200);
  });
});
```

- [ ] **Step 6: Implement the three routes**

```ts
// apps/web/src/app/api/setup/route.ts
import { bad, handler, ok } from "@/server/api";
import { runSetup } from "@/server/auth/setup";

export const POST = handler(
  async (request: Request) => {
    const { username, password } = (await request.json()) as { username?: string; password?: string };
    if (typeof username !== "string" || typeof password !== "string") return bad("Username and password required");
    return ok(runSetup({ username, password }));
  },
  { public: true },
);
```

```ts
// apps/web/src/app/api/auth/route.ts
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { AUTH_COOKIE } from "@/server/auth";
import { bad, handler, ok } from "@/server/api";
import { setupRequired } from "@/server/auth/setup";
import { getUser, verifyLogin } from "@/server/auth/users";
import { createSession, deleteSession, resolveSession, sessionCookieOptions } from "@/server/auth/sessions";
import { checkLogin, clientIp, recordAttempt } from "@/server/auth/rate-limit";

export const GET = handler(
  async () => {
    if (setupRequired()) return ok({ setupRequired: true, authenticated: false });
    const raw = (await cookies()).get(AUTH_COOKIE)?.value;
    const session = resolveSession(raw);
    if (session.kind !== "active") return ok({ setupRequired: false, authenticated: false, locked: session.kind === "locked" });
    const user = getUser(session.userId);
    if (!user) return ok({ setupRequired: false, authenticated: false });
    return ok({
      setupRequired: false,
      authenticated: true,
      user: { id: user.id, username: user.username, role: user.role, mustChangePassword: user.mustChangePassword },
    });
  },
  { public: true },
);

export const POST = handler(
  async (request: Request) => {
    if (setupRequired()) return NextResponse.json({ error: "Setup required", reason: "setup_required" }, { status: 409 });
    const { username, password } = (await request.json()) as { username?: string; password?: string };
    if (typeof username !== "string" || typeof password !== "string" || !username || !password)
      return bad("Invalid username or password.", 401);
    const ip = clientIp(request);
    const limit = checkLogin(ip, username);
    if (!limit.allowed)
      return NextResponse.json({ error: limit.message }, { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } });
    const login = verifyLogin(username, password);
    recordAttempt(ip, username, Boolean(login));
    if (!login) return bad("Invalid username or password.", 401);
    const token = createSession({
      userId: login.user.id,
      role: login.user.role,
      dek: login.dek,
      ip,
      userAgent: request.headers.get("user-agent") ?? undefined,
    });
    (await cookies()).set(AUTH_COOKIE, token, sessionCookieOptions(request));
    return ok({ authenticated: true, mustChangePassword: login.user.mustChangePassword });
  },
  { public: true },
);

export const DELETE = handler(
  async () => {
    const jar = await cookies();
    const raw = jar.get(AUTH_COOKIE)?.value;
    if (raw) deleteSession(raw);
    jar.delete(AUTH_COOKIE);
    return ok({ authenticated: false });
  },
  { public: true },
);
```

```ts
// apps/web/src/app/api/auth/recover/route.ts
import { NextResponse } from "next/server";
import { bad, handler, ok } from "@/server/api";
import { recoverWithKey } from "@/server/auth/users";
import { deleteUserSessions } from "@/server/auth/sessions";
import { checkLogin, clientIp, recordAttempt } from "@/server/auth/rate-limit";

export const POST = handler(
  async (request: Request) => {
    const body = (await request.json()) as { username?: string; recoveryKey?: string; newPassword?: string };
    const { username, recoveryKey, newPassword } = body;
    if (typeof username !== "string" || typeof recoveryKey !== "string" || typeof newPassword !== "string")
      return bad("Username, recovery key and new password required");
    const ip = clientIp(request);
    const limit = checkLogin(ip, username);
    if (!limit.allowed)
      return NextResponse.json({ error: limit.message }, { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } });
    const result = recoverWithKey(username, recoveryKey, newPassword);
    recordAttempt(ip, username, Boolean(result));
    if (!result) return bad("Invalid username or recovery key.", 401);
    deleteUserSessions(result.user.id);
    return ok({ recoveryKey: result.recoveryKey });
  },
  { public: true },
);
```

- [ ] **Step 7: Run both new tests and the suite; type check**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/api-login.test.ts apps/web/tests/setup-migration.test.ts && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json`
Expected: all green, no type errors. From here on `tsc` must be clean at every commit.

- [ ] **Step 8: Format and commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/server/auth/setup.ts apps/web/src/app/api/setup apps/web/src/app/api/auth apps/web/tests/setup-migration.test.ts apps/web/tests/api-login.test.ts
git add apps/web/src/server/auth/setup.ts apps/web/src/app/api/setup apps/web/src/app/api/auth apps/web/tests/setup-migration.test.ts apps/web/tests/api-login.test.ts
git commit -m "Add first-run setup with journal migration, login, logout and recovery routes"
```

---

### Task 9: Account and admin routes

**Files:**
- Create: `apps/web/src/app/api/account/password/route.ts`
- Create: `apps/web/src/app/api/account/recovery-key/route.ts`
- Create: `apps/web/src/app/api/account/sessions/route.ts`
- Create: `apps/web/src/app/api/admin/users/route.ts`
- Create: `apps/web/src/app/api/admin/users/[id]/route.ts`
- Create: `apps/web/src/app/api/admin/blocks/route.ts`
- Create: `apps/web/src/app/api/admin/blocks/[cidr]/route.ts`
- Test: `apps/web/tests/api-admin.test.ts`

**Interfaces:**
- Consumes: `currentUser()` (Task 4), users functions (Task 3), sessions (Task 5), rate-limit (Task 6), `handler` options (Task 7).
- Produces (HTTP):
  - `POST /api/account/password` `{ currentPassword, newPassword }` → `200 { changed: true }` | `400`
  - `POST /api/account/recovery-key` `{ password }` → `200 { recoveryKey }` | `400`
  - `GET /api/account/sessions` → `{ sessions: [...] }`; `DELETE /api/account/sessions` → signs out everywhere (including the caller) and clears the cookie
  - `GET /api/admin/users` → `{ users: UserRecord[] }`; `POST /api/admin/users` `{ username, password }` → `{ user, recoveryKey, temporaryPassword }`
  - `PATCH /api/admin/users/:id` `{ role?: Role; locked?: boolean }`; `DELETE /api/admin/users/:id` `{ confirmUsername }`
  - `GET /api/admin/blocks` → `{ blocks }`; `POST /api/admin/blocks` `{ cidr, reason?, expiresAt? }`; `DELETE /api/admin/blocks/:cidr` (cidr URL-encoded)

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/api-admin.test.ts
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const jar = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (jar.token ? { value: jar.token } : undefined),
    set: (_n: string, v: string) => {
      jar.token = v;
    },
    delete: () => {
      jar.token = undefined;
    },
  }),
}));

const { createUser } = await import("../src/server/auth/users");
const { createSession } = await import("../src/server/auth/sessions");
const { userDataDir } = await import("../src/db/paths");
const { db, accounts } = await import("../src/db");
const { runWithUser } = await import("../src/server/auth/context");
const password = await import("../src/app/api/account/password/route");
const recoveryKey = await import("../src/app/api/account/recovery-key/route");
const sessions = await import("../src/app/api/account/sessions/route");
const users = await import("../src/app/api/admin/users/route");
const userById = await import("../src/app/api/admin/users/[id]/route");
const blocks = await import("../src/app/api/admin/blocks/route");
const blockByCidr = await import("../src/app/api/admin/blocks/[cidr]/route");

const json = (url: string, method: string, body?: unknown) =>
  new Request(`http://localhost:3000${url}`, {
    method,
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
const params = (p: Record<string, string>) => ({ params: Promise.resolve(p) });

const admin = createUser({ username: "admin", password: "admin-password-1", role: "admin" });
const asAdmin = () => {
  jar.token = createSession({ userId: admin.user.id, role: "admin", dek: admin.dek });
};

describe("account routes", () => {
  it("changes the password and regenerates the recovery key", async () => {
    asAdmin();
    expect((await password.POST(json("/api/account/password", "POST", { currentPassword: "wrong-password-1", newPassword: "admin-password-2" }))).status).toBe(400);
    expect((await password.POST(json("/api/account/password", "POST", { currentPassword: "admin-password-1", newPassword: "admin-password-2" }))).status).toBe(200);
    const rk = await recoveryKey.POST(json("/api/account/recovery-key", "POST", { password: "admin-password-2" }));
    expect(rk.status).toBe(200);
    expect((await rk.json()).recoveryKey).not.toBe(admin.recoveryKey);
  });
  it("lists sessions and signs out everywhere", async () => {
    asAdmin();
    createSession({ userId: admin.user.id, role: "admin", dek: admin.dek });
    const list = await sessions.GET(json("/api/account/sessions", "GET"));
    expect((await list.json()).sessions.length).toBeGreaterThanOrEqual(2);
    expect((await sessions.DELETE(json("/api/account/sessions", "DELETE"))).status).toBe(200);
    expect(jar.token).toBeUndefined();
  });
});

describe("admin routes", () => {
  let bobId = "";
  it("creates a user with a temporary password and recovery key", async () => {
    asAdmin();
    const res = await users.POST(json("/api/admin/users", "POST", { username: "bob", password: "temporary-pw-12" }));
    expect(res.status).toBe(200);
    const body = await res.json();
    bobId = body.user.id;
    expect(body.user.mustChangePassword).toBe(true);
    expect(body.recoveryKey).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/);
    expect((await (await users.GET(json("/api/admin/users", "GET"))).json()).users.map((u: { username: string }) => u.username)).toEqual(["admin", "bob"]);
  });
  it("refuses non-admins", async () => {
    const bob = createUser({ username: "bob2", password: "bob2-password-12", role: "user" });
    jar.token = createSession({ userId: bob.user.id, role: "user", dek: bob.dek });
    expect((await users.GET(json("/api/admin/users", "GET"))).status).toBe(403);
  });
  it("locks, unlocks, promotes, and protects the last admin", async () => {
    asAdmin();
    expect((await userById.PATCH(json(`/api/admin/users/${bobId}`, "PATCH", { locked: true }), params({ id: bobId }))).status).toBe(200);
    expect((await userById.PATCH(json(`/api/admin/users/${bobId}`, "PATCH", { locked: false, role: "admin" }), params({ id: bobId }))).status).toBe(200);
    expect((await userById.PATCH(json(`/api/admin/users/${bobId}`, "PATCH", { role: "user" }), params({ id: bobId }))).status).toBe(200);
    const self = await userById.PATCH(json(`/api/admin/users/${admin.user.id}`, "PATCH", { role: "user" }), params({ id: admin.user.id }));
    expect(self.status).toBe(400);
  });
  it("deletes a user only with the confirmed username and removes their folder", async () => {
    asAdmin();
    const bob = { userId: bobId, role: "user" as const, dek: Buffer.alloc(32, 7) };
    // materialise bob's journal folder
    const bobUser = createUser({ username: "bob3", password: "bob3-password-12", role: "user" });
    runWithUser({ userId: bobUser.user.id, role: "user", dek: bobUser.dek }, () => db.select().from(accounts).all());
    expect(existsSync(userDataDir(bobUser.user.id))).toBe(true);
    expect((await userById.DELETE(json(`/api/admin/users/${bobUser.user.id}`, "DELETE", { confirmUsername: "wrong" }), params({ id: bobUser.user.id }))).status).toBe(400);
    expect((await userById.DELETE(json(`/api/admin/users/${bobUser.user.id}`, "DELETE", { confirmUsername: "bob3" }), params({ id: bobUser.user.id }))).status).toBe(200);
    expect(existsSync(userDataDir(bobUser.user.id))).toBe(false);
    void bob;
  });
  it("manages IP blocks", async () => {
    asAdmin();
    expect((await blocks.POST(json("/api/admin/blocks", "POST", { cidr: "203.0.113.0/24", reason: "abuse" }))).status).toBe(200);
    expect((await blocks.POST(json("/api/admin/blocks", "POST", { cidr: "not-an-ip" }))).status).toBe(400);
    const list = await (await blocks.GET(json("/api/admin/blocks", "GET"))).json();
    expect(list.blocks[0]).toMatchObject({ cidr: "203.0.113.0/24", source: "manual", reason: "abuse" });
    expect((await blockByCidr.DELETE(json("/api/admin/blocks/x", "DELETE"), params({ cidr: encodeURIComponent("203.0.113.0/24") }))).status).toBe(200);
    expect((await (await blocks.GET(json("/api/admin/blocks", "GET"))).json()).blocks).toEqual([]);
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/api-admin.test.ts`
Expected: FAIL, modules not found.

- [ ] **Step 3: Implement the account routes**

```ts
// apps/web/src/app/api/account/password/route.ts
import { bad, handler, ok } from "@/server/api";
import { currentUser } from "@/server/auth/context";
import { changePassword } from "@/server/auth/users";

export const POST = handler(
  async (request: Request) => {
    const { currentPassword, newPassword } = (await request.json()) as { currentPassword?: string; newPassword?: string };
    if (typeof currentPassword !== "string" || typeof newPassword !== "string") return bad("Both passwords are required");
    const { userId } = currentUser();
    if (!changePassword(userId, currentPassword, newPassword)) return bad("Current password is wrong");
    return ok({ changed: true });
  },
  { allowPasswordChange: true },
);
```

```ts
// apps/web/src/app/api/account/recovery-key/route.ts
import { bad, handler, ok } from "@/server/api";
import { currentUser } from "@/server/auth/context";
import { regenerateRecoveryKey } from "@/server/auth/users";

export const POST = handler(async (request: Request) => {
  const { password } = (await request.json()) as { password?: string };
  if (typeof password !== "string") return bad("Password required");
  const recoveryKey = regenerateRecoveryKey(currentUser().userId, password);
  if (!recoveryKey) return bad("Password is wrong");
  return ok({ recoveryKey });
});
```

```ts
// apps/web/src/app/api/account/sessions/route.ts
import { cookies } from "next/headers";
import { AUTH_COOKIE } from "@/server/auth";
import { handler, ok } from "@/server/api";
import { currentUser } from "@/server/auth/context";
import { deleteUserSessions, listUserSessions } from "@/server/auth/sessions";

export const GET = handler(async () => ok({ sessions: listUserSessions(currentUser().userId) }), {
  allowPasswordChange: true,
});

export const DELETE = handler(
  async () => {
    deleteUserSessions(currentUser().userId);
    (await cookies()).delete(AUTH_COOKIE);
    return ok({ signedOut: true });
  },
  { allowPasswordChange: true },
);
```

- [ ] **Step 4: Implement the admin routes**

```ts
// apps/web/src/app/api/admin/users/route.ts
import { bad, handler, ok } from "@/server/api";
import { createUser, listUsers } from "@/server/auth/users";

export const GET = handler(async () => ok({ users: listUsers() }), { admin: true });

export const POST = handler(
  async (request: Request) => {
    const { username, password } = (await request.json()) as { username?: string; password?: string };
    if (typeof username !== "string" || typeof password !== "string") return bad("Username and temporary password required");
    const created = createUser({ username, password, role: "user", mustChangePassword: true });
    return ok({ user: created.user, recoveryKey: created.recoveryKey, temporaryPassword: password });
  },
  { admin: true },
);
```

```ts
// apps/web/src/app/api/admin/users/[id]/route.ts
import { bad, handler, ok } from "@/server/api";
import { closeJournal } from "@/db";
import { currentUser } from "@/server/auth/context";
import { deleteUserSessions } from "@/server/auth/sessions";
import { countAdmins, deleteUser, getUser, setUserLock, setUserRole } from "@/server/auth/users";

type Ctx = { params: Promise<{ id: string }> };

export const PATCH = handler(
  async (request: Request, { params }: Ctx) => {
    const { id } = await params;
    const target = getUser(id);
    if (!target) return bad("User not found", 404);
    const body = (await request.json()) as { role?: "admin" | "user"; locked?: boolean };
    if (body.role !== undefined) {
      if (body.role !== "admin" && body.role !== "user") return bad("Invalid role");
      if (target.role === "admin" && body.role === "user" && countAdmins() <= 1) return bad("Cannot demote the last admin");
      if (target.id === currentUser().userId && body.role === "user") return bad("You cannot demote yourself");
      setUserRole(id, body.role);
    }
    if (body.locked !== undefined) {
      setUserLock(id, body.locked ? "9999-12-31T00:00:00.000Z" : null);
      if (body.locked) deleteUserSessions(id);
    }
    return ok({ user: getUser(id) });
  },
  { admin: true },
);

export const DELETE = handler(
  async (request: Request, { params }: Ctx) => {
    const { id } = await params;
    const target = getUser(id);
    if (!target) return bad("User not found", 404);
    const { confirmUsername } = (await request.json()) as { confirmUsername?: string };
    if (confirmUsername !== target.username) return bad("Type the username exactly to confirm");
    if (target.role === "admin" && countAdmins() <= 1) return bad("Cannot delete the last admin");
    if (target.id === currentUser().userId) return bad("You cannot delete yourself");
    deleteUserSessions(id);
    closeJournal(id);
    deleteUser(id);
    return ok({ deleted: true });
  },
  { admin: true },
);
```

```ts
// apps/web/src/app/api/admin/blocks/route.ts
import { bad, handler, ok } from "@/server/api";
import { addBlock, listBlocks } from "@/server/auth/rate-limit";

export const GET = handler(async () => ok({ blocks: listBlocks() }), { admin: true });

export const POST = handler(
  async (request: Request) => {
    const { cidr, reason, expiresAt } = (await request.json()) as { cidr?: string; reason?: string; expiresAt?: string | null };
    if (typeof cidr !== "string") return bad("IP or CIDR required");
    if (expiresAt && Number.isNaN(Date.parse(expiresAt))) return bad("Invalid expiry");
    try {
      addBlock({ cidr, reason: reason || undefined, expiresAt: expiresAt || null, source: "manual" });
    } catch (error) {
      return bad(error instanceof Error ? error.message : "Invalid IP or CIDR");
    }
    return ok({ blocks: listBlocks() });
  },
  { admin: true },
);
```

```ts
// apps/web/src/app/api/admin/blocks/[cidr]/route.ts
import { bad, handler, ok } from "@/server/api";
import { listBlocks, removeBlock } from "@/server/auth/rate-limit";

export const DELETE = handler(
  async (_request: Request, { params }: { params: Promise<{ cidr: string }> }) => {
    const { cidr } = await params;
    try {
      removeBlock(decodeURIComponent(cidr));
    } catch (error) {
      return bad(error instanceof Error ? error.message : "Invalid IP or CIDR");
    }
    return ok({ blocks: listBlocks() });
  },
  { admin: true },
);
```

- [ ] **Step 5: Run the test, the suite, and the type check**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/api-admin.test.ts && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json`
Expected: 7 passed; suite green; no type errors.

- [ ] **Step 6: Format and commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/app/api/account apps/web/src/app/api/admin apps/web/tests/api-admin.test.ts
git add apps/web/src/app/api/account apps/web/src/app/api/admin apps/web/tests/api-admin.test.ts
git commit -m "Add account and admin API routes"
```

---

### Task 10: Client plumbing and shell

**Files:**
- Create: `apps/web/src/lib/auth-redirect.ts`
- Modify: `apps/web/src/lib/api-request.ts:14-19`
- Modify: `apps/web/src/lib/use-api.ts:69-82` (`postJson`)
- Modify: `apps/web/src/components/shell.tsx:148` (bare pages) and the footer area (sign-out and username)
- Test: `apps/web/tests/auth-redirect.test.ts`

**Interfaces:**
- Produces: `authRedirectFor(status: number, body: { reason?: string } | null, pathname: string): string | null` (pure), `applyAuthRedirect(status, body)` (calls `window.location.assign` when a target exists and differs from the current path).

- [ ] **Step 1: Write the failing test**

```ts
// apps/web/tests/auth-redirect.test.ts
import { describe, expect, it } from "vitest";
import { authRedirectFor } from "../src/lib/auth-redirect";

describe("auth redirects", () => {
  it("maps API auth failures to pages", () => {
    expect(authRedirectFor(401, { reason: "locked" }, "/")).toBe("/login?reason=restart");
    expect(authRedirectFor(401, {}, "/journal")).toBe("/login");
    expect(authRedirectFor(403, { reason: "password_change_required" }, "/")).toBe("/change-password");
    expect(authRedirectFor(409, { reason: "setup_required" }, "/login")).toBe("/setup");
    expect(authRedirectFor(403, { reason: "admin_only" }, "/settings")).toBeNull();
    expect(authRedirectFor(500, null, "/")).toBeNull();
  });
  it("does not bounce the login page to itself", () => {
    expect(authRedirectFor(401, {}, "/login")).toBeNull();
    expect(authRedirectFor(401, { reason: "locked" }, "/login")).toBeNull();
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-redirect.test.ts`
Expected: FAIL, module not found.

- [ ] **Step 3: Implement**

```ts
// apps/web/src/lib/auth-redirect.ts
export const authRedirectFor = (
  status: number,
  body: { reason?: string } | null,
  pathname: string,
): string | null => {
  const reason = body?.reason;
  if (status === 409 && reason === "setup_required") return pathname === "/setup" ? null : "/setup";
  if (status === 403 && reason === "password_change_required")
    return pathname === "/change-password" ? null : "/change-password";
  if (status === 401) {
    if (pathname === "/login" || pathname === "/setup" || pathname === "/recover") return null;
    return reason === "locked" ? "/login?reason=restart" : "/login";
  }
  return null;
};

export const applyAuthRedirect = (status: number, body: { reason?: string } | null): void => {
  if (typeof window === "undefined") return;
  const target = authRedirectFor(status, body, window.location.pathname);
  if (target) window.location.assign(target);
};
```

In `apps/web/src/lib/api-request.ts`, add `import { applyAuthRedirect } from "./auth-redirect";` at the top and change the `.then` body to:

```ts
      .then(async (response) => {
        const body = await response.json();
        if (!response.ok) {
          applyAuthRedirect(response.status, body);
          throw new Error(body.error ?? `Request failed (${response.status})`);
        }
        return body;
      })
```

In `apps/web/src/lib/use-api.ts`, add the same import and change `postJson`'s failure branch to:

```ts
  const data = (await response.json()) as T & { error?: string; reason?: string };
  if (!response.ok) {
    applyAuthRedirect(response.status, data);
    throw new Error(data.error ?? `Request failed (${response.status})`);
  }
  return data;
```

- [ ] **Step 4: Shell changes**

In `apps/web/src/components/shell.tsx` line 148 replace
```tsx
  if (pathname === "/login") return <>{children}</>;
```
with
```tsx
  if (["/login", "/setup", "/recover", "/change-password"].includes(pathname)) return <>{children}</>;
```

Add a `useApi` call near the top of the `Shell` component body (after the existing hooks):
```tsx
  const { data: me } = useApi<{ authenticated: boolean; user?: { username: string; role: "admin" | "user" } }>("/api/auth");
```
and replace `const footer = null;` with:
```tsx
  const footer = me?.user ? (
    <div className="journal-sidebar-footer flex items-center justify-between gap-2 border-t p-3 text-xs text-muted-foreground">
      <span className="truncate" title={me.user.username}>
        {sidebarCollapsed ? me.user.username.slice(0, 2).toUpperCase() : me.user.username}
      </span>
      <button
        type="button"
        className="underline underline-offset-2 hover:text-foreground"
        onClick={async () => {
          await postJson("/api/auth", undefined, "DELETE");
          window.location.assign("/login");
        }}
      >
        {sidebarCollapsed ? "Out" : "Sign out"}
      </button>
    </div>
  ) : null;
```
Add `import { postJson, useApi } from "@/lib/use-api";` next to the existing `import { cn } from "@/lib/utils";` (line 27). `sidebarCollapsed` is the state declared at line 92 of `shell.tsx`.

- [ ] **Step 5: Run test, suite, type check; commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run apps/web/tests/auth-redirect.test.ts && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/lib apps/web/src/components/shell.tsx apps/web/tests/auth-redirect.test.ts
git add apps/web/src/lib apps/web/src/components/shell.tsx apps/web/tests/auth-redirect.test.ts
git commit -m "Redirect on auth failures and show sign-out in the sidebar"
```

---

### Task 11: Setup, login, recover, and change-password pages

**Files:**
- Create: `apps/web/src/components/recovery-key-card.tsx`
- Create: `apps/web/src/app/setup/page.tsx`
- Rewrite: `apps/web/src/app/login/page.tsx`
- Create: `apps/web/src/app/recover/page.tsx`
- Create: `apps/web/src/app/change-password/page.tsx`

**Interfaces:**
- Consumes: routes from Tasks 8 and 9, `postJson`, `useApi`, `components/ui` (`Button`, `Card`, `CardContent`, `CardHeader`, `CardTitle`, `Input`, `Label`, `Checkbox`).
- Produces: `RecoveryKeyCard({ recoveryKey, onAcknowledge })` component reused by Settings in Task 12.

No unit tests for pages (the repo has none for existing pages). Verification is manual in Task 14.

- [ ] **Step 1: Recovery key card**

```tsx
// apps/web/src/components/recovery-key-card.tsx
"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";

export function RecoveryKeyCard({
  recoveryKey,
  onAcknowledge,
  title = "Save your recovery key",
}: {
  recoveryKey: string;
  onAcknowledge: () => void;
  title?: string;
}) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  return (
    <div className="space-y-3">
      <h2 className="text-sm font-semibold">{title}</h2>
      <p className="text-xs text-muted-foreground">
        This key is the only way to open your journal if you forget your password. It is shown once. Nobody, including the administrator, can recover a journal without the password or this key.
      </p>
      <code className="block select-all rounded border bg-muted px-3 py-2 text-center font-mono text-base tracking-wider">
        {recoveryKey}
      </code>
      <Button
        type="button"
        variant="outline"
        className="w-full"
        onClick={async () => {
          await navigator.clipboard.writeText(recoveryKey);
          setCopied(true);
        }}
      >
        {copied ? "Copied" : "Copy to clipboard"}
      </Button>
      <div className="flex items-center gap-2">
        <Checkbox id="recovery-saved" checked={saved} onCheckedChange={(v) => setSaved(v === true)} />
        <Label htmlFor="recovery-saved" className="text-xs">
          I have saved this key somewhere safe
        </Label>
      </div>
      <Button type="button" className="w-full" disabled={!saved} onClick={onAcknowledge}>
        Continue
      </Button>
    </div>
  );
}
```

- [ ] **Step 2: Setup page**

```tsx
// apps/web/src/app/setup/page.tsx
"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { RecoveryKeyCard } from "@/components/recovery-key-card";
import { postJson, useApi } from "@/lib/use-api";

interface SetupResult {
  recoveryKey: string;
  migrated: Record<string, number> | null;
}

export default function SetupPage() {
  const router = useRouter();
  const { data: state } = useApi<{ setupRequired: boolean }>("/api/auth");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SetupResult | null>(null);

  useEffect(() => {
    if (state && !state.setupRequired) router.replace("/login");
  }, [state, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (password !== confirm) return setError("Passwords do not match");
    setBusy(true);
    setError(null);
    try {
      setResult(await postJson<SetupResult>("/api/setup", { username, password }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Setup failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardContent className="pt-6">
          {result ? (
            <div className="space-y-4">
              {result.migrated && (
                <p className="text-xs text-muted-foreground">
                  Your existing journal was moved into your encrypted journal:{" "}
                  {Object.entries(result.migrated)
                    .filter(([, n]) => n > 0)
                    .map(([table, n]) => `${table} ${n}`)
                    .join(", ")}
                  . The original is kept as journal.db.pre-encryption until you delete it.
                </p>
              )}
              <RecoveryKeyCard recoveryKey={result.recoveryKey} onAcknowledge={() => router.replace("/login")} />
            </div>
          ) : (
            <form onSubmit={submit} className="space-y-3">
              <div className="text-center">
                <h1 className="text-sm font-semibold">Create the administrator account</h1>
                <p className="text-xs text-muted-foreground">This is the first and only setup step.</p>
              </div>
              <Input id="setup-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" autoFocus autoComplete="username" />
              <Input id="setup-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password (12+ characters)" autoComplete="new-password" />
              <Input id="setup-confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Confirm password" autoComplete="new-password" />
              {error && <p className="text-center text-xs text-loss">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Creating…" : "Create account"}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 3: Login page**

Replace `apps/web/src/app/login/page.tsx` with:

```tsx
"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { postJson, useApi } from "@/lib/use-api";

export default function LoginPage() {
  return (
    <Suspense>
      <Login />
    </Suspense>
  );
}

function Login() {
  const router = useRouter();
  const search = useSearchParams();
  const { data: state } = useApi<{ setupRequired: boolean; authenticated: boolean }>("/api/auth");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (state?.setupRequired) router.replace("/setup");
    else if (state?.authenticated) router.replace("/");
  }, [state, router]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await postJson<{ mustChangePassword: boolean }>("/api/auth", { username, password });
      router.push(result.mustChangePassword ? "/change-password" : "/");
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Sign in failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-xs">
        <CardContent className="pt-6">
          <form onSubmit={submit} className="space-y-3">
            <div className="text-center">
              <h1 className="text-sm font-semibold">Trade Journal</h1>
              {search.get("reason") === "restart" && (
                <p className="text-xs text-muted-foreground">The server restarted. Please sign in again.</p>
              )}
            </div>
            <Input id="login-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" autoFocus autoComplete="username" />
            <Input id="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" autoComplete="current-password" />
            {error && <p className="text-center text-xs text-loss">{error}</p>}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Signing in…" : "Sign in"}
            </Button>
            <p className="text-center text-xs">
              <Link href="/recover" className="underline underline-offset-2">
                Forgot password
              </Link>
            </p>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 4: Recover page**

```tsx
// apps/web/src/app/recover/page.tsx
"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { RecoveryKeyCard } from "@/components/recovery-key-card";
import { postJson } from "@/lib/use-api";

export default function RecoverPage() {
  const router = useRouter();
  const [username, setUsername] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [freshKey, setFreshKey] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (newPassword !== confirm) return setError("Passwords do not match");
    setBusy(true);
    setError(null);
    try {
      const result = await postJson<{ recoveryKey: string }>("/api/auth/recover", { username, recoveryKey, newPassword });
      setFreshKey(result.recoveryKey);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Recovery failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-sm">
        <CardContent className="pt-6">
          {freshKey ? (
            <RecoveryKeyCard title="Password changed. Save your new recovery key" recoveryKey={freshKey} onAcknowledge={() => router.replace("/login")} />
          ) : (
            <form onSubmit={submit} className="space-y-3">
              <div className="text-center">
                <h1 className="text-sm font-semibold">Recover your journal</h1>
                <p className="text-xs text-muted-foreground">Enter the recovery key you saved when the account was created.</p>
              </div>
              <Input id="recover-username" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Username" autoFocus autoComplete="username" />
              <Input id="recover-key" value={recoveryKey} onChange={(e) => setRecoveryKey(e.target.value)} placeholder="XXXXX-XXXXX-XXXXX-XXXXX" className="font-mono" autoComplete="off" />
              <Input id="recover-password" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (12+ characters)" autoComplete="new-password" />
              <Input id="recover-confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Confirm new password" autoComplete="new-password" />
              {error && <p className="text-center text-xs text-loss">{error}</p>}
              <Button type="submit" className="w-full" disabled={busy}>
                {busy ? "Recovering…" : "Set new password"}
              </Button>
              <p className="text-center text-xs">
                <Link href="/login" className="underline underline-offset-2">
                  Back to sign in
                </Link>
              </p>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 5: Change-password page**

```tsx
// apps/web/src/app/change-password/page.tsx
"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { postJson } from "@/lib/use-api";

export default function ChangePasswordPage() {
  const router = useRouter();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (newPassword !== confirm) return setError("Passwords do not match");
    setBusy(true);
    setError(null);
    try {
      await postJson("/api/account/password", { currentPassword, newPassword });
      router.replace("/");
      router.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Change failed");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-xs">
        <CardContent className="pt-6">
          <form onSubmit={submit} className="space-y-3">
            <div className="text-center">
              <h1 className="text-sm font-semibold">Choose a new password</h1>
              <p className="text-xs text-muted-foreground">Your temporary password must be replaced before you continue.</p>
            </div>
            <Input id="cp-current" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" autoFocus autoComplete="current-password" />
            <Input id="cp-new" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (12+ characters)" autoComplete="new-password" />
            <Input id="cp-confirm" type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} placeholder="Confirm new password" autoComplete="new-password" />
            {error && <p className="text-center text-xs text-loss">{error}</p>}
            <Button type="submit" className="w-full" disabled={busy}>
              {busy ? "Saving…" : "Save password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
```

- [ ] **Step 6: Type check, format, commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/app/setup apps/web/src/app/login apps/web/src/app/recover apps/web/src/app/change-password apps/web/src/components/recovery-key-card.tsx
git add apps/web/src/app/setup apps/web/src/app/login apps/web/src/app/recover apps/web/src/app/change-password apps/web/src/components/recovery-key-card.tsx
git commit -m "Add setup, login, recovery and change-password pages"
```

---

### Task 12: Settings UI for account and user administration

**Files:**
- Create: `apps/web/src/components/account-settings.tsx`
- Create: `apps/web/src/components/user-admin.tsx`
- Modify: `apps/web/src/app/settings/page.tsx` (render both; admin one only for admins)

**Interfaces:**
- Consumes: routes from Task 9, `RecoveryKeyCard` (Task 11), `useApi`/`postJson`, `components/ui` (`Card*`, `Button`, `Input`, `Label`, `Badge`, `Tabs*`, `Table*`, `Dialog*`).

- [ ] **Step 1: Account settings**

```tsx
// apps/web/src/components/account-settings.tsx
"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { RecoveryKeyCard } from "@/components/recovery-key-card";
import { postJson, useApi } from "@/lib/use-api";

interface SessionRow {
  tokenHash: string;
  createdAt: string;
  lastSeenAt: string;
  ip: string | null;
  userAgent: string | null;
}

export function AccountSettings() {
  const { data, refresh } = useApi<{ sessions: SessionRow[] }>("/api/account/sessions");
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [rkPassword, setRkPassword] = useState("");
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [freshKey, setFreshKey] = useState<string | null>(null);

  const run = async (fn: () => Promise<void>, success: string) => {
    setError(null);
    setMessage(null);
    try {
      await fn();
      setMessage(success);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account</CardTitle>
      </CardHeader>
      <CardContent className="space-y-6">
        <form
          className="space-y-2"
          onSubmit={(e) => {
            e.preventDefault();
            void run(async () => {
              await postJson("/api/account/password", { currentPassword, newPassword });
              setCurrentPassword("");
              setNewPassword("");
            }, "Password changed");
          }}
        >
          <Label htmlFor="acct-current">Change password</Label>
          <Input id="acct-current" type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} placeholder="Current password" autoComplete="current-password" />
          <Input id="acct-new" type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="New password (12+ characters)" autoComplete="new-password" />
          <Button type="submit" size="sm">Change password</Button>
        </form>

        <div className="space-y-2">
          <Label htmlFor="acct-rk-password">Recovery key</Label>
          {freshKey ? (
            <RecoveryKeyCard title="New recovery key" recoveryKey={freshKey} onAcknowledge={() => setFreshKey(null)} />
          ) : (
            <form
              className="flex gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void run(async () => {
                  const r = await postJson<{ recoveryKey: string }>("/api/account/recovery-key", { password: rkPassword });
                  setRkPassword("");
                  setFreshKey(r.recoveryKey);
                }, "Recovery key regenerated. The old one no longer works.");
              }}
            >
              <Input id="acct-rk-password" type="password" value={rkPassword} onChange={(e) => setRkPassword(e.target.value)} placeholder="Password to confirm" autoComplete="current-password" />
              <Button type="submit" size="sm" variant="outline">Regenerate</Button>
            </form>
          )}
        </div>

        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <Label>Signed-in devices</Label>
            <Button
              size="sm"
              variant="outline"
              onClick={() =>
                void run(async () => {
                  await postJson("/api/account/sessions", undefined, "DELETE");
                  window.location.assign("/login");
                }, "Signed out everywhere")
              }
            >
              Sign out everywhere
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Last seen</TableHead>
                <TableHead>IP</TableHead>
                <TableHead>Browser</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(data?.sessions ?? []).map((s) => (
                <TableRow key={s.tokenHash}>
                  <TableCell>{new Date(s.lastSeenAt).toLocaleString()}</TableCell>
                  <TableCell>{s.ip ?? "unknown"}</TableCell>
                  <TableCell className="max-w-64 truncate">{s.userAgent ?? "unknown"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
          <Button size="sm" variant="ghost" onClick={refresh}>Refresh</Button>
        </div>

        {message && <p className="text-xs text-muted-foreground">{message}</p>}
        {error && <p className="text-xs text-loss">{error}</p>}
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 2: User administration**

```tsx
// apps/web/src/components/user-admin.tsx
"use client";

import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { postJson, useApi } from "@/lib/use-api";

interface User {
  id: string;
  username: string;
  role: "admin" | "user";
  mustChangePassword: boolean;
  lockedUntil: string | null;
  createdAt: string;
}
interface Block {
  cidr: string;
  source: "auto" | "manual";
  reason: string | null;
  createdAt: string;
  expiresAt: string | null;
}
interface Created {
  user: User;
  recoveryKey: string;
  temporaryPassword: string;
}

const isLocked = (u: User) => Boolean(u.lockedUntil && new Date(u.lockedUntil).getTime() > Date.now());

export function UserAdmin({ currentUserId }: { currentUserId: string }) {
  const users = useApi<{ users: User[] }>("/api/admin/users");
  const blocks = useApi<{ blocks: Block[] }>("/api/admin/blocks");
  const [error, setError] = useState<string | null>(null);
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [created, setCreated] = useState<Created | null>(null);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [confirmName, setConfirmName] = useState("");
  const [cidr, setCidr] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const act = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      users.refresh();
      blocks.refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Request failed");
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>Users and access</CardTitle>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="users">
          <TabsList>
            <TabsTrigger value="users">Users</TabsTrigger>
            <TabsTrigger value="access">Access</TabsTrigger>
          </TabsList>

          <TabsContent value="users" className="space-y-4">
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  const r = await postJson<Created>("/api/admin/users", { username: newUsername, password: newPassword });
                  setCreated(r);
                  setNewUsername("");
                  setNewPassword("");
                });
              }}
            >
              <div>
                <Label htmlFor="new-username">Username</Label>
                <Input id="new-username" value={newUsername} onChange={(e) => setNewUsername(e.target.value)} />
              </div>
              <div>
                <Label htmlFor="new-temp-password">Temporary password</Label>
                <Input id="new-temp-password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} placeholder="12+ characters" />
              </div>
              <Button type="submit" size="sm">Create user</Button>
            </form>
            <p className="text-xs text-muted-foreground">
              New users must change the temporary password at first sign-in. Their recovery key is shown once to you; hand it over with the password. There is no admin password reset: without the password or the recovery key a journal cannot be opened.
            </p>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>User</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(users.data?.users ?? []).map((u) => (
                  <TableRow key={u.id}>
                    <TableCell>{u.username}</TableCell>
                    <TableCell>{u.role}</TableCell>
                    <TableCell className="space-x-1">
                      {isLocked(u) && <Badge variant="default">locked</Badge>}
                      {u.mustChangePassword && <Badge variant="secondary">must change password</Badge>}
                      {!isLocked(u) && !u.mustChangePassword && <Badge variant="outline">active</Badge>}
                    </TableCell>
                    <TableCell className="space-x-1 text-right">
                      <Button size="sm" variant="outline" disabled={u.id === currentUserId} onClick={() => void act(() => postJson(`/api/admin/users/${u.id}`, { locked: !isLocked(u) }, "PATCH"))}>
                        {isLocked(u) ? "Unlock" : "Lock"}
                      </Button>
                      <Button size="sm" variant="outline" disabled={u.id === currentUserId} onClick={() => void act(() => postJson(`/api/admin/users/${u.id}`, { role: u.role === "admin" ? "user" : "admin" }, "PATCH"))}>
                        {u.role === "admin" ? "Make user" : "Make admin"}
                      </Button>
                      <Button size="sm" variant="destructive" disabled={u.id === currentUserId} onClick={() => { setDeleting(u); setConfirmName(""); }}>
                        Delete
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TabsContent>

          <TabsContent value="access" className="space-y-4">
            <form
              className="flex flex-wrap items-end gap-2"
              onSubmit={(e) => {
                e.preventDefault();
                void act(async () => {
                  await postJson("/api/admin/blocks", { cidr, reason, expiresAt: expiresAt ? new Date(expiresAt).toISOString() : null });
                  setCidr("");
                  setReason("");
                  setExpiresAt("");
                });
              }}
            >
              <div>
                <Label htmlFor="block-cidr">IP or CIDR</Label>
                <Input id="block-cidr" value={cidr} onChange={(e) => setCidr(e.target.value)} placeholder="203.0.113.5 or 203.0.113.0/24" className="font-mono" />
              </div>
              <div>
                <Label htmlFor="block-reason">Reason</Label>
                <Input id="block-reason" value={reason} onChange={(e) => setReason(e.target.value)} />
              </div>
              <div>
                <Label htmlFor="block-expires">Expires (empty = permanent)</Label>
                <Input id="block-expires" type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} />
              </div>
              <Button type="submit" size="sm">Block</Button>
            </form>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {(blocks.data?.blocks ?? []).map((b) => (
                  <TableRow key={b.cidr}>
                    <TableCell className="font-mono">{b.cidr}</TableCell>
                    <TableCell>{b.source}</TableCell>
                    <TableCell>{b.reason ?? ""}</TableCell>
                    <TableCell>{b.expiresAt ? new Date(b.expiresAt).toLocaleString() : "never"}</TableCell>
                    <TableCell className="text-right">
                      <Button size="sm" variant="outline" onClick={() => void act(() => postJson(`/api/admin/blocks/${encodeURIComponent(b.cidr)}`, undefined, "DELETE"))}>
                        Unblock
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TabsContent>
        </Tabs>
        {error && <p className="mt-3 text-xs text-loss">{error}</p>}

        <Dialog open={created !== null} onOpenChange={(open) => !open && setCreated(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>User {created?.user.username} created</DialogTitle>
              <DialogDescription>Give the user both values. They are not shown again.</DialogDescription>
            </DialogHeader>
            <div className="space-y-2 text-sm">
              <p>Temporary password</p>
              <code className="block select-all rounded border bg-muted px-3 py-2 font-mono">{created?.temporaryPassword}</code>
              <p>Recovery key</p>
              <code className="block select-all rounded border bg-muted px-3 py-2 text-center font-mono tracking-wider">{created?.recoveryKey}</code>
            </div>
            <Button onClick={() => setCreated(null)}>Done</Button>
          </DialogContent>
        </Dialog>

        <Dialog open={deleting !== null} onOpenChange={(open) => !open && setDeleting(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Delete {deleting?.username}?</DialogTitle>
              <DialogDescription>This deletes their encrypted journal permanently. Type the username to confirm.</DialogDescription>
            </DialogHeader>
            <Input id="delete-confirm" value={confirmName} onChange={(e) => setConfirmName(e.target.value)} placeholder={deleting?.username} />
            <Button
              variant="destructive"
              disabled={confirmName !== deleting?.username}
              onClick={() =>
                void act(async () => {
                  if (!deleting) return;
                  await postJson(`/api/admin/users/${deleting.id}`, { confirmUsername: confirmName }, "DELETE");
                  setDeleting(null);
                })
              }
            >
              Delete user and journal
            </Button>
          </DialogContent>
        </Dialog>
      </CardContent>
    </Card>
  );
}
```

- [ ] **Step 3: Wire into the settings page**

In `apps/web/src/app/settings/page.tsx`:
- add imports `import { AccountSettings } from "@/components/account-settings";` and `import { UserAdmin } from "@/components/user-admin";`
- inside `Settings()` add `const { data: me } = useApi<{ user?: { id: string; role: "admin" | "user" } }>("/api/auth");`
- after `<AiSettings />` (line 150) insert:
```tsx
        <AccountSettings />
        {me?.user?.role === "admin" && <UserAdmin currentUserId={me.user.id} />}
```

- [ ] **Step 4: Type check, format, commit**

```bash
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/components/account-settings.tsx apps/web/src/components/user-admin.tsx apps/web/src/app/settings/page.tsx
git add apps/web/src/components/account-settings.tsx apps/web/src/components/user-admin.tsx apps/web/src/app/settings/page.tsx
git commit -m "Add account and user administration settings"
```

---

### Task 13: Startup housekeeping, installer, compose, docs

**Files:**
- Modify: `apps/web/src/db/index.ts` (idle sweep and startup log)
- Modify: `apps/web/src/server/auth/sessions.ts` (startup sweep)
- Modify: `install_as_service.sh`
- Modify: `docker-compose.yml`, `.env.example`, `README.md` (configuration table)
- Modify: `docs/superpowers/specs/2026-09-21-multi-user-auth-encryption-design.md` (append the planning refinement)

- [ ] **Step 1: Startup log line and sweeps**

Append to `apps/web/src/db/index.ts`:
```ts
const globalForHousekeeping = globalThis as unknown as { __journalHousekeeping?: boolean };
if (!globalForHousekeeping.__journalHousekeeping) {
  globalForHousekeeping.__journalHousekeeping = true;
  if (process.env.JOURNAL_PASSWORD)
    console.warn("[auth] JOURNAL_PASSWORD is ignored: accounts are managed in Settings → Users. Remove it from .env.");
  if (process.env.VITEST !== "true") {
    try {
      mkdirSync(join(dataDir(), "users"), { recursive: true });
      accessSync(dataDir(), constants.W_OK);
    } catch {
      console.error(
        `[journal] data directory ${dataDir()} is not writable by uid ${process.getuid?.() ?? "?"}. ` +
          "Fix: docker compose exec -u root journal chown -R node:node /data && docker compose restart",
      );
      process.exit(1);
    }
    const timer = setInterval(() => closeIdleJournals(), 5 * 60 * 1000);
    timer.unref();
  }
}
```
Add `import { accessSync, constants, mkdirSync } from "node:fs";` to the imports of `db/index.ts`.

Append to `apps/web/src/server/auth/sessions.ts`:
```ts
const globalForSweep = globalThis as unknown as { __journalSessionSweep?: boolean };
if (!globalForSweep.__journalSessionSweep && process.env.VITEST !== "true") {
  globalForSweep.__journalSessionSweep = true;
  queueMicrotask(() => {
    try {
      if (authDbExists()) sweepExpiredSessions();
    } catch {
      /* auth.db not writable yet; handler() reports it on first request */
    }
  });
}
```
Add `import { authDbExists } from "@/db/paths";` at the top of `sessions.ts`.

- [ ] **Step 2: Installer**

In `install_as_service.sh`:
- Delete the `GENERATED_PASSWORD` variable, the `if [[ -z "${JOURNAL_PASSWORD:-}" ]]` block, and the `JOURNAL_PASSWORD=${JOURNAL_PASSWORD}` line of the heredoc.
- Change the heredoc comment to: `# Trade Journal secrets. Keep this file: losing JOURNAL_SECRET makes saved broker and AI keys unreadable.`
- Add `JOURNAL_TRUST_PROXY=true` to the heredoc.
- In the usage comment at the top, remove `JOURNAL_PASSWORD` from the overrides list and add `JOURNAL_TRUST_PROXY  read client IP from X-Forwarded-For (default: true)`.
- Replace the final password block with:
```bash
cat <<EOF

 Open the URL above to create the administrator account. Save the
 recovery key it shows; it is the only way back in if the password is lost.
EOF
```
- Add `mkdir -p "$INSTALL_DIR/data/users" && chown -R "$CONTAINER_UID:$CONTAINER_UID" "$INSTALL_DIR/data"` in section 4 (replace the existing `mkdir`/`chown` pair).

- [ ] **Step 3: Compose and env example**

`docker-compose.yml` environment block becomes:
```yaml
    environment:
      # Encryption secret for broker and AI credentials inside each journal
      JOURNAL_SECRET: ${JOURNAL_SECRET}
      # Read the client IP from X-Forwarded-For (keep true behind a reverse proxy;
      # never expose the container port directly when true)
      JOURNAL_TRUST_PROXY: ${JOURNAL_TRUST_PROXY:-true}
      JOURNAL_DATA_DIR: /data
```

`.env.example`: remove the `JOURNAL_PASSWORD` lines; add
```
# Read the client IP from X-Forwarded-For / X-Real-IP set by your reverse proxy.
# Default true. Set false only when the app port is reached directly.
# JOURNAL_TRUST_PROXY=true
```

`README.md` configuration table: replace the `JOURNAL_PASSWORD` row with
```
| `JOURNAL_TRUST_PROXY` | Trust `X-Forwarded-For` for rate limiting and session records (default `true`). Keep the app port reachable only through the proxy. |
```
and add one sentence under the table: "Accounts are created on first run at `/setup`; further users are added by the administrator in **Settings → Users**. Each user's journal is a separate SQLCipher-encrypted database that only their password or recovery key can open."

- [ ] **Step 4: Spec addendum**

Append to the spec file:
```markdown
## Addendum (planning)

- Database access with no user context resolves to the legacy plaintext `data/journal.db` only while `auth.db` does not exist (tests, first-run migration). Once `auth.db` exists it throws.
- `handler()` passes requests through without a session only when `auth.db` is absent and `process.env.VITEST === "true"`; in production it answers 409 `setup_required`.
- The client IP trust switch is `JOURNAL_TRUST_PROXY` (boolean).
- Locking a user from Settings also ends their sessions.
- Manual IP blocks are enforced in `handler()` for every API call. The edge middleware cannot read `auth.db`, so a blocked client can still load the HTML shell; every data request it makes answers 403.
```

- [ ] **Step 5: Verify the installer still parses; commit**

```bash
bash -n install_as_service.sh
docker compose config >/dev/null
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm vitest run && COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm --filter web exec tsc --noEmit -p tsconfig.json
COREPACK_ENABLE_DOWNLOAD_PROMPT=0 corepack pnpm prettier --write apps/web/src/db/index.ts apps/web/src/server/auth/sessions.ts README.md
git add apps/web/src/db/index.ts apps/web/src/server/auth/sessions.ts install_as_service.sh docker-compose.yml .env.example README.md docs/superpowers/specs/2026-09-21-multi-user-auth-encryption-design.md
git commit -m "Drop JOURNAL_PASSWORD, add JOURNAL_TRUST_PROXY, update installer and docs"
```

---

### Task 14: Build, rollout on this machine, manual checks

**Files:** none new. Runbook artifact at https://claude.ai/artifact/NKBjwfHaByjAxxwZ1gWqp5 is updated by the session lead after this task.

- [ ] **Step 1: Back up**

```bash
cd /home/rholand/lan-share/trade-journal
docker compose stop
tar czf ~/trade-journal-backup-$(date +%F)-pre-multiuser.tgz data .env
docker compose start
```

- [ ] **Step 2: Build the image and confirm the build really succeeded**

```bash
docker compose build 2>&1 | tail -3; echo "exit: ${PIPESTATUS[0]}"
docker image inspect trade-journal-journal:latest --format '{{.Created}}'
```
Expected: exit 0 and a timestamp from the last minute. A non-zero exit means a type error: read the full output, fix, rebuild.

- [ ] **Step 3: Remove the old password from .env and restart**

```bash
sed -i '/^JOURNAL_PASSWORD=/d' .env
grep -q '^JOURNAL_TRUST_PROXY=' .env || echo 'JOURNAL_TRUST_PROXY=true' >> .env
docker compose up -d --force-recreate
sleep 4
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' http://localhost:3333/
curl -s http://localhost:3333/api/auth
```
Expected: `307 -> http://localhost:3333/login` and `{"setupRequired":true,"authenticated":false}`.

- [ ] **Step 4: Setup through the browser**

Open http://localhost:3333. It should land on `/setup`. Create the admin account, copy the recovery key, tick the box, continue. Sign in. Confirm the dashboard shows the pre-existing trades and journal days.

Then check on disk:
```bash
ls -la data data/users/*/
docker compose logs --since 5m | grep -i 'migrated legacy'
head -c 15 data/users/*/journal.db | od -c | head -1
```
Expected: `auth.db`, `journal.db.pre-encryption`, one user folder with `journal.db`; the migrated log line with per-table counts; the first bytes of the user journal are not `SQLite format 3`.

- [ ] **Step 5: Rate limit and lockout through the proxy**

From another machine or with curl through the public URL, send six wrong passwords for the admin. The sixth must return 429 with the 360-minute message. In Settings → Users → Users the admin shows "locked"; unlock it there. Check Settings → Users → Access for an auto IP block if ten attempts were made; unblock it.

- [ ] **Step 6: Cookie flag through Nginx Proxy Manager**

In the browser devtools Network tab, the `Set-Cookie` on the login response through the public https URL must include `Secure`. Through http://localhost:3333 it must not.

- [ ] **Step 7: Second user end to end**

Create a user in Settings → Users, note both values. In a private window sign in as that user with the temporary password; it must force `/change-password`. After changing, the dashboard is empty (separate journal). Add one manual trade. Sign back in as admin and confirm the admin's journal does not show it.

- [ ] **Step 8: Restart behaviour**

`docker compose restart`. Reloading the app must land on `/login?reason=restart` with the restart message.

- [ ] **Step 9: Delete the plaintext copy and push**

```bash
rm data/journal.db.pre-encryption
git push origin main
```

- [ ] **Step 10: Report**

Report to the session lead: test counts, image timestamp, migration counts, and which manual checks passed. Do not claim a check that was not run.
