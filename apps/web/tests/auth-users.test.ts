import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { authDbExists, authDbPath } = await import("../src/db/paths");
const users = await import("../src/server/auth/users");

describe("user management", () => {
  it("creates the auth database on first user and returns a recovery key", () => {
    expect(authDbExists()).toBe(false);
    const created = users.createUser({
      username: "Alice",
      password: "alice-password-1",
      role: "admin",
    });
    expect(existsSync(authDbPath())).toBe(true);
    expect(created.user.role).toBe("admin");
    expect(created.recoveryKey).toMatch(/^[0-9A-Z]{5}(-[0-9A-Z]{5}){3}$/);
    expect(created.dek.length).toBe(32);
  });
  it("rejects short passwords and duplicate usernames case-insensitively", () => {
    expect(() => users.validatePassword("short")).toThrow(/12 characters/);
    expect(() =>
      users.createUser({ username: "alice", password: "another-password", role: "user" }),
    ).toThrow(/already exists/);
  });
  it("verifies login and unwraps the same DEK", () => {
    const created = users.createUser({
      username: "bob",
      password: "bob-password-123",
      role: "user",
    });
    const login = users.verifyLogin("BOB", "bob-password-123");
    expect(login?.dek.equals(created.dek)).toBe(true);
    expect(users.verifyLogin("bob", "bob-password-124")).toBeNull();
    expect(users.verifyLogin("nobody", "bob-password-123")).toBeNull();
  });
  it("password change keeps the DEK and invalidates the old password", () => {
    const created = users.createUser({
      username: "carol",
      password: "carol-password-1",
      role: "user",
    });
    expect(users.changePassword(created.user.id, "wrong-password-1", "carol-password-2")).toBe(
      false,
    );
    expect(users.changePassword(created.user.id, "carol-password-1", "carol-password-2")).toBe(
      true,
    );
    expect(users.verifyLogin("carol", "carol-password-1")).toBeNull();
    expect(users.verifyLogin("carol", "carol-password-2")?.dek.equals(created.dek)).toBe(true);
    expect(users.getUser(created.user.id)?.mustChangePassword).toBe(false);
  });
  it("recovery key unwraps the DEK, sets a new password and rotates the key", () => {
    const created = users.createUser({
      username: "dave",
      password: "dave-password-12",
      role: "user",
    });
    const recovered = users.recoverWithKey(
      "dave",
      created.recoveryKey.toLowerCase(),
      "dave-password-13",
    );
    expect(recovered?.dek.equals(created.dek)).toBe(true);
    expect(recovered?.recoveryKey).not.toBe(created.recoveryKey);
    expect(users.recoverWithKey("dave", created.recoveryKey, "dave-password-14")).toBeNull();
    expect(users.verifyLogin("dave", "dave-password-13")?.dek.equals(created.dek)).toBe(true);
    // The old recovery key no longer works (checked above); the rotated key does.
    const secondRecovery = users.recoverWithKey(
      "dave",
      recovered?.recoveryKey ?? "",
      "dave-password-15",
    );
    expect(secondRecovery?.dek.equals(created.dek)).toBe(true);
    expect(users.verifyLogin("dave", "dave-password-15")?.dek.equals(created.dek)).toBe(true);
  });
  it("lock, role and delete", () => {
    const created = users.createUser({
      username: "erin",
      password: "erin-password-12",
      role: "user",
    });
    users.setUserLock(created.user.id, "2099-01-01T00:00:00.000Z");
    expect(users.getUser(created.user.id)?.lockedUntil).toBe("2099-01-01T00:00:00.000Z");
    users.setUserRole(created.user.id, "admin");
    expect(users.countAdmins()).toBe(2);
    users.deleteUser(created.user.id);
    expect(users.getUser(created.user.id)).toBeNull();
    expect(users.listUsers().map((u) => u.username)).toEqual(["Alice", "bob", "carol", "dave"]);
  });
});
