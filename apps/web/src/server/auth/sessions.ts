// apps/web/src/server/auth/sessions.ts
import { createHash, randomBytes } from "node:crypto";
import { isSecureRequest } from "@/server/auth";
import { authDbExists } from "@/db/paths";
import { authDb, nowIso, type Role } from "./db";

export const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const TOUCH_INTERVAL_MS = 5 * 60 * 1000;

interface MemoryEntry {
  userId: string;
  role: Role;
  dek: Buffer;
  touchedAt: number;
}
const globalForSessions = globalThis as unknown as {
  __journalSessionKeys?: Map<string, MemoryEntry>;
};
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
  const cutoff = new Date(now).toISOString();
  const expired = authDb()
    .prepare("SELECT token_hash FROM sessions WHERE expires_at <= ?")
    .all(cutoff) as { token_hash: string }[];
  for (const { token_hash: tokenHash } of expired) memory.delete(tokenHash);
  const result = authDb().prepare("DELETE FROM sessions WHERE expires_at <= ?").run(cutoff);
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
