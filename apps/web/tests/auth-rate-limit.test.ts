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
    // A distinct username per attempt, so only the IP bucket can fire here.
    for (let i = 0; i < 9; i += 1)
      rl.recordAttempt("203.0.113.9", `ghost-${i}`, i === 0, T0 + i * 1000);
    expect(rl.checkLogin("203.0.113.9", "ghost", T0 + 10000).allowed).toBe(true);
    rl.recordAttempt("203.0.113.9", "ghost-9", false, T0 + 10000);
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
    for (let i = 0; i < 5; i += 1)
      rl.recordAttempt(`198.51.100.${i}`, "alice", false, T0 + i * 1000);
    const denied = rl.checkLogin("198.51.100.99", "ALICE", T0 + 6000);
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) expect(denied.message).toMatch(/360 minutes/);
    expect(getUser(alice.user.id)?.lockedUntil).toBe(new Date(T0 + 4000 + min(360)).toISOString());
    rl.recordAttempt("198.51.100.99", "alice", true, T0 + 7000);
    expect(rl.checkLogin("198.51.100.99", "alice", T0 + 8000).allowed).toBe(false);
    setUserLock(alice.user.id, null);
    expect(rl.checkLogin("198.51.100.99", "alice", T0 + 9000).allowed).toBe(true);
  });
  it("locks an unknown username too, so the message does not reveal real accounts", () => {
    const t = T0 + min(60);
    for (let i = 0; i < 5; i += 1)
      rl.recordAttempt(`198.51.100.${i}`, "ghost", false, t + i * 1000);
    const denied = rl.checkLogin("198.51.100.99", "ghost", t + 6000);
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) expect(denied.message).toMatch(/Try again in 360 minutes/);
    // Same answer for a real account with the same number of failures.
    expect(rl.checkLogin("198.51.100.99", "GHOST", t + 6000)).toEqual(denied);
    rl.clearUsernameFailures("ghost");
    expect(rl.checkLogin("198.51.100.99", "ghost", t + 7000).allowed).toBe(true);
  });
  it("reports an admin-disabled account as disabled, not as a retry in millions of minutes", () => {
    setUserLock(alice.user.id, "9999-12-31T00:00:00.000Z");
    const denied = rl.checkLogin("198.51.100.99", "alice", T0 + min(120));
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) {
      expect(denied.message).toBe("This account has been disabled.");
      expect(denied.retryAfterSec).toBe(3600);
    }
    setUserLock(alice.user.id, null);
  });
  it("a successful sign-in clears the username's failure counter", () => {
    const t = T0 + min(180);
    rl.clearUsernameFailures("alice");
    for (let i = 0; i < 4; i += 1) rl.recordAttempt("203.0.113.40", "alice", false, t + i * 1000);
    rl.recordAttempt("203.0.113.40", "alice", true, t + 5000);
    rl.recordAttempt("203.0.113.40", "alice", false, t + 6000);
    expect(rl.checkLogin("203.0.113.40", "alice", t + 7000).allowed).toBe(true);
    expect(getUser(alice.user.id)?.lockedUntil).toBe(null);
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
  it("reports a permanent manual block with a fixed message, not a fake retry time", () => {
    rl.addBlock({ cidr: "198.18.0.5" });
    const denied = rl.checkLogin("198.18.0.5", "ghost");
    expect(denied.allowed).toBe(false);
    if (!denied.allowed) {
      expect(denied.message).toBe("Access from this address is blocked.");
      expect(denied.retryAfterSec).toBe(3600);
    }
    rl.removeBlock("198.18.0.5");
  });
  it("derives the client IP from proxy headers when trusted", () => {
    const req = (headers: Record<string, string>) =>
      new Request("http://localhost:3000/", { headers });
    expect(rl.clientIp(req({ "x-forwarded-for": "203.0.113.7, 10.0.0.1" }))).toBe("203.0.113.7");
    expect(rl.clientIp(req({ "x-real-ip": "203.0.113.8" }))).toBe("203.0.113.8");
    expect(rl.clientIp(req({}))).toBe("unknown");
    process.env.JOURNAL_TRUST_PROXY = "false";
    expect(rl.clientIp(req({ "x-forwarded-for": "203.0.113.7" }))).toBe("unknown");
    delete process.env.JOURNAL_TRUST_PROXY;
  });
});
