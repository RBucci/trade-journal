import Database from "better-sqlite3-multiple-ciphers";
import { existsSync, mkdirSync } from "node:fs";
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

const globalForAuth = globalThis as unknown as {
  __journalAuthDb?: Database.Database;
  __journalAuthDbPath?: string;
};

/**
 * Opens data/auth.db. Creating the file is opt-in and reserved for createUser,
 * which is the only path setup takes: setupRequired() is just "auth.db is
 * absent", so any other caller that created the file would end setup mode with
 * no account in it and leave the install unreachable. Every other caller must
 * therefore be safe before setup (see authDbExists in @/db/paths) and gets an
 * error here rather than an empty database.
 */
export const authDb = (options?: { create?: boolean }): Database.Database => {
  const path = authDbPath();
  if (globalForAuth.__journalAuthDb && globalForAuth.__journalAuthDbPath === path) {
    return globalForAuth.__journalAuthDb;
  }
  if (options?.create !== true && !existsSync(path))
    throw new Error("auth.db does not exist; setup has not run");
  mkdirSync(dataDir(), { recursive: true });
  const sqlite = new Database(path);
  sqlite.pragma("journal_mode = WAL");
  sqlite.pragma("foreign_keys = ON");
  sqlite.exec(AUTH_SQL);
  globalForAuth.__journalAuthDb = sqlite;
  globalForAuth.__journalAuthDbPath = path;
  return sqlite;
};

/** Closes the cached connection (if any) and clears the cache, so the next authDb() call reopens the file. */
export const closeAuthDb = (): void => {
  globalForAuth.__journalAuthDb?.close();
  globalForAuth.__journalAuthDb = undefined;
  globalForAuth.__journalAuthDbPath = undefined;
};

export const nowIso = (): string => new Date().toISOString();
