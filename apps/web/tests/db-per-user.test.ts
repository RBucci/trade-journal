import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { db, accounts, closeJournal } = await import("../src/db");
const { userDataDir } = await import("../src/db/paths");
const { openJournal, JournalOpenError } = await import("../src/db/journal");
const { runWithUser } = await import("../src/server/auth/context");
const { createUser } = await import("../src/server/auth/users");

const insertAccount = (id: string) =>
  db.insert(accounts).values({ id, name: id, kind: "manual", createdAt: "2026-01-01" }).run();
const accountIds = () =>
  db
    .select({ id: accounts.id })
    .from(accounts)
    .all()
    .map((r) => r.id);

describe("per-user journals", () => {
  it("falls back to the legacy plaintext journal when no auth database exists", () => {
    insertAccount("legacy");
    expect(accountIds()).toEqual(["legacy"]);
    expect(existsSync(join(scratch, "journal.db"))).toBe(true);
  });
  it("routes each user's queries to their own encrypted file", () => {
    const a = createUser({ username: "alice", password: "alice-password-1", role: "admin" });
    const b = createUser({ username: "bob", password: "bob-password-123", role: "user" });
    const ctxA = { userId: a.user.id, role: a.user.role, dek: a.dek };
    const ctxB = { userId: b.user.id, role: b.user.role, dek: b.dek };
    runWithUser(ctxA, () => insertAccount("a1"));
    runWithUser(ctxB, () => insertAccount("b1"));
    expect(runWithUser(ctxA, accountIds)).toEqual(["a1"]);
    expect(runWithUser(ctxB, accountIds)).toEqual(["b1"]);
    const fileA = join(userDataDir(a.user.id), "journal.db");
    expect(readFileSync(fileA).subarray(0, 15).toString()).not.toBe("SQLite format 3");
    closeJournal(a.user.id);
    expect(() => openJournal(fileA, b.dek)).toThrow(JournalOpenError);
  });
  it("throws outside a user context once the auth database exists", () => {
    expect(() => accountIds()).toThrow(/No user context/);
  });
});
