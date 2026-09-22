// apps/web/tests/setup-migration.test.ts
import { mkdtempSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const { db, accounts, notes, folders } = await import("../src/db");
const { runWithUser } = await import("../src/server/auth/context");
const { setupRequired, runSetup } = await import("../src/server/auth/setup");
const { verifyLogin } = await import("../src/server/auth/users");

describe("first-run setup and migration", () => {
  it("rolls back cleanly when migration fails, leaving setup retryable", () => {
    const legacyPath = join(scratch, "journal.db");
    writeFileSync(legacyPath, Buffer.alloc(64, 1));
    expect(() => runSetup({ username: "admin", password: "admin-password-1" })).toThrow();
    expect(setupRequired()).toBe(true);
    expect(existsSync(join(scratch, "users"))).toBe(false);
    rmSync(legacyPath, { force: true });
  });

  it("moves a plaintext journal into the admin's encrypted journal", () => {
    // Seed the legacy journal (no auth.db yet, so db resolves to data/journal.db).
    db.insert(accounts)
      .values({ id: "acc", name: "Legacy", kind: "manual", createdAt: "2026-01-01" })
      .run();
    db.insert(folders).values({ id: "f1", name: "Ideas", createdAt: "2026-01-01" }).run();
    db.insert(notes)
      .values({
        id: "n1",
        folderId: "f1",
        title: "Hello",
        content: "world",
        createdAt: "2026-01-01",
        updatedAt: "2026-01-01",
      })
      .run();
    expect(setupRequired()).toBe(true);

    const result = runSetup({ username: "admin", password: "admin-password-1" });
    expect(setupRequired()).toBe(false);
    expect(result.user.role).toBe("admin");
    expect(result.migrated).toMatchObject({ accounts: 1, folders: 1, notes: 1 });
    expect(existsSync(join(scratch, "journal.db.pre-encryption"))).toBe(true);
    expect(existsSync(join(scratch, "journal.db"))).toBe(false);

    const login = verifyLogin("admin", "admin-password-1");
    expect(login).not.toBeNull();
    if (!login) return;
    const ctx = { userId: login.user.id, role: login.user.role, dek: login.dek };
    expect(runWithUser(ctx, () => db.select().from(notes).all()).map((n) => n.title)).toEqual([
      "Hello",
    ]);
    expect(() => runSetup({ username: "again", password: "again-password-1" })).toThrow(/already/);
  });
});
