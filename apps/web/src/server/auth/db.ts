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

const globalForAuth = globalThis as unknown as {
  __journalAuthDb?: Database.Database;
  __journalAuthDbPath?: string;
};

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
