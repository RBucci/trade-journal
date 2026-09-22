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
    return typeof value === "function"
      ? (value as (...a: unknown[]) => unknown).bind(target)
      : value;
  },
});
