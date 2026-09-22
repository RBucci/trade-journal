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
    UserRow | undefined;

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
  if (rowByUsername(input.username))
    throw new RequestError("A user with that name already exists.");
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
    .prepare("UPDATE users SET salt_r = ?, dek_wrapped_recovery = ?, updated_at = ? WHERE id = ?")
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
    .prepare("UPDATE users SET salt_r = ?, dek_wrapped_recovery = ?, updated_at = ? WHERE id = ?")
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
  (authDb().prepare("SELECT * FROM users ORDER BY created_at, rowid").all() as UserRow[]).map(
    toRecord,
  );

export const setUserLock = (userId: string, lockedUntil: string | null): void => {
  authDb()
    .prepare("UPDATE users SET locked_until = ?, updated_at = ? WHERE id = ?")
    .run(lockedUntil, nowIso(), userId);
};
export const setUserRole = (userId: string, role: Role): void => {
  authDb()
    .prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?")
    .run(role, nowIso(), userId);
};
export const countAdmins = (): number =>
  (authDb().prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get() as { n: number })
    .n;

/** Removes the row (sessions cascade) and the user's journal folder. */
export const deleteUser = (userId: string): void => {
  authDb().prepare("DELETE FROM users WHERE id = ?").run(userId);
  rmSync(userDataDir(userId), { recursive: true, force: true });
};
