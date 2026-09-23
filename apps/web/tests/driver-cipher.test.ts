import { describe, expect, it } from "vitest";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3-multiple-ciphers";

describe("encrypted sqlite driver", () => {
  it("writes a file that is not plain SQLite and rejects a wrong key", () => {
    const dir = mkdtempSync(join(tmpdir(), "cipher-"));
    const file = join(dir, "t.db");
    const key = "a".repeat(64);
    const db = new Database(file);
    db.pragma("cipher='sqlcipher'");
    db.pragma(`key="x'${key}'"`);
    db.exec("CREATE TABLE t (x TEXT)");
    db.prepare("INSERT INTO t VALUES (?)").run("hello");
    db.close();
    expect(readFileSync(file).subarray(0, 15).toString()).not.toBe("SQLite format 3");
    const wrong = new Database(file);
    wrong.pragma("cipher='sqlcipher'");
    wrong.pragma(`key="x'${"b".repeat(64)}'"`);
    expect(() => wrong.prepare("SELECT x FROM t").get()).toThrow(/NOTADB|not a database/);
    wrong.close();
    const right = new Database(file);
    right.pragma("cipher='sqlcipher'");
    right.pragma(`key="x'${key}'"`);
    expect((right.prepare("SELECT x FROM t").get() as { x: string }).x).toBe("hello");
    right.close();
    rmSync(dir, { recursive: true, force: true });
  });
});
