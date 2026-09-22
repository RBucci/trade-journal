// apps/web/tests/auth-db-guard.test.ts
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { authDb } = await import("../src/server/auth/db");
const { authDbPath } = await import("../src/db/paths");
const sessions = await import("../src/server/auth/sessions");
const rl = await import("../src/server/auth/rate-limit");

describe("auth.db creation is opt-in", () => {
  it("refuses to open a missing auth.db unless the caller asks to create it", () => {
    expect(existsSync(authDbPath())).toBe(false);
    expect(() => authDb()).toThrow(/does not exist/);
    expect(() => authDb({})).toThrow(/does not exist/);
    expect(() => authDb({ create: false })).toThrow(/does not exist/);
    expect(existsSync(authDbPath())).toBe(false);
  });

  it("leaves the file absent when session and rate-limit helpers run before setup", () => {
    expect(sessions.resolveSession("a".repeat(64)).kind).toBe("none");
    expect(() => sessions.deleteSession("a".repeat(64))).not.toThrow();
    expect(() => sessions.deleteUserSessions("nobody")).not.toThrow();
    expect(sessions.listUserSessions("nobody")).toEqual([]);
    expect(() => sessions.touchSession("a".repeat(64))).not.toThrow();
    expect(sessions.sweepExpiredSessions()).toBe(0);
    expect(rl.checkLogin("203.0.113.1", "ghost").allowed).toBe(true);
    expect(() => rl.recordAttempt("203.0.113.1", "ghost", false)).not.toThrow();
    expect(rl.isIpBlocked("203.0.113.1")).toBe(false);
    expect(rl.listBlocks()).toEqual([]);
    expect(existsSync(authDbPath())).toBe(false);
  });

  it("creates the file only for an explicit create, then reopens it without one", async () => {
    const { createUser } = await import("../src/server/auth/users");
    createUser({ username: "admin", password: "admin-password-1", role: "admin" });
    expect(existsSync(authDbPath())).toBe(true);
    expect(() => authDb()).not.toThrow();
  });
});
