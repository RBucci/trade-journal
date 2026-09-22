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
