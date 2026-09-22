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
    const proxied = new Request("http://localhost:3000/api/auth", {
      headers: { "x-forwarded-proto": "https" },
    });
    expect(s.sessionCookieOptions(plain).secure).toBe(false);
    expect(s.sessionCookieOptions(proxied).secure).toBe(true);
    expect(s.sessionCookieOptions(plain).maxAge).toBe(30 * 24 * 60 * 60);
  });
});
