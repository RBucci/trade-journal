// apps/web/tests/auth-login-timing.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeEach, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

// Every scrypt call is the unit of work an attacker can time. Counting them is
// deterministic where a stopwatch would be flaky.
const cost = vi.hoisted(() => ({ derivations: 0 }));
vi.mock("../src/server/auth/keys", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/server/auth/keys")>();
  return {
    ...actual,
    deriveKey: (secret: string, salt: string) => {
      cost.derivations += 1;
      return actual.deriveKey(secret, salt);
    },
    verifyPassword: (password: string, salt: string, hash: string) => {
      cost.derivations += 1;
      return actual.verifyPassword(password, salt, hash);
    },
  };
});

const { createUser, verifyLogin } = await import("../src/server/auth/users");

createUser({ username: "alice", password: "alice-password-1", role: "admin" });

describe("login cost does not reveal whether an account exists", () => {
  beforeEach(() => {
    cost.derivations = 0;
  });

  it("spends two derivations on an unknown username", () => {
    expect(verifyLogin("nobody", "alice-password-1")).toBe(null);
    expect(cost.derivations).toBe(2);
  });

  it("spends two derivations on a known username with a wrong password", () => {
    expect(verifyLogin("alice", "wrong-password-99")).toBe(null);
    expect(cost.derivations).toBe(2);
  });

  it("spends two derivations on a successful login", () => {
    expect(verifyLogin("alice", "alice-password-1")).not.toBe(null);
    expect(cost.derivations).toBe(2);
  });
});
