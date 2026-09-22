// apps/web/src/server/auth/setup.ts
import Database from "better-sqlite3-multiple-ciphers";
import { existsSync, renameSync, rmSync } from "node:fs";
import { join } from "node:path";
import { RequestError } from "@/server/errors";
import { closeLegacyJournal } from "@/db";
import { openJournal } from "@/db/journal";
import { authDbExists, legacyJournalPath, userDataDir } from "@/db/paths";
import { createUser, type UserRecord } from "./users";

export const setupRequired = (): boolean => !authDbExists();

/**
 * Copy every table of the plaintext data/journal.db into the user's encrypted
 * journal, row by row, then rename the original. Returns per-table row counts,
 * or null when there was nothing to migrate.
 */
export const migrateLegacyJournal = (
  userId: string,
  dek: Buffer,
): Record<string, number> | null => {
  const legacyPath = legacyJournalPath();
  if (!existsSync(legacyPath)) return null;
  closeLegacyJournal();
  const legacy = new Database(legacyPath, { readonly: false });
  legacy.pragma("wal_checkpoint(TRUNCATE)");
  const target = openJournal(join(userDataDir(userId), "journal.db"), dek);
  const counts: Record<string, number> = {};
  try {
    const tables = (
      legacy
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .all() as { name: string }[]
    ).map((row) => row.name);
    const targetTables = new Set(
      (
        target.sqlite.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as {
          name: string;
        }[]
      ).map((r) => r.name),
    );
    target.sqlite.pragma("foreign_keys = OFF");
    const copyAll = target.sqlite.transaction(() => {
      for (const table of tables) {
        if (!targetTables.has(table)) continue;
        const legacyColInfo = legacy.pragma(`table_info(${table})`) as {
          name: string;
          pk: number;
        }[];
        const legacyCols = legacyColInfo.map((c) => c.name);
        const targetCols = new Set(
          (target.sqlite.pragma(`table_info(${table})`) as { name: string }[]).map((c) => c.name),
        );
        const cols = legacyCols.filter((c) => targetCols.has(c));
        if (cols.length === 0) continue;
        const list = cols.map((c) => `"${c}"`).join(", ");
        const insert = target.sqlite.prepare(
          `INSERT OR REPLACE INTO "${table}" (${list}) VALUES (${cols.map(() => "?").join(", ")})`,
        );
        // Bootstrap seeds a handful of default rows (e.g. system folders) into
        // every fresh journal, including the target we just created, so a raw
        // copied-row count would over-report. Count only rows whose primary
        // key was not already present in the target before this copy.
        const pkCols = legacyColInfo.filter((c) => c.pk > 0).map((c) => c.name);
        const pkCol = pkCols.length === 1 ? pkCols[0] : undefined;
        const existingIds =
          pkCol && targetCols.has(pkCol)
            ? new Set(
                (
                  target.sqlite.prepare(`SELECT "${pkCol}" AS id FROM "${table}"`).all() as {
                    id: unknown;
                  }[]
                ).map((r) => r.id),
              )
            : null;
        let n = 0;
        for (const row of legacy.prepare(`SELECT ${list} FROM "${table}"`).iterate() as Iterable<
          Record<string, unknown>
        >) {
          insert.run(...cols.map((c) => row[c]));
          if (!existingIds || !existingIds.has(row[pkCol as string])) n += 1;
        }
        counts[table] = n;
      }
    });
    copyAll();
    target.sqlite.pragma("foreign_keys = ON");
  } finally {
    legacy.close();
    target.sqlite.close();
  }
  renameSync(legacyPath, `${legacyPath}.pre-encryption`);
  for (const suffix of ["-wal", "-shm"]) rmSync(`${legacyPath}${suffix}`, { force: true });
  console.info("[setup] migrated legacy journal:", JSON.stringify(counts));
  return counts;
};

export const runSetup = (input: {
  username: string;
  password: string;
}): { user: UserRecord; recoveryKey: string; migrated: Record<string, number> | null } => {
  if (!setupRequired()) throw new RequestError("Setup has already been completed.");
  const created = createUser({ username: input.username, password: input.password, role: "admin" });
  const migrated = migrateLegacyJournal(created.user.id, created.dek);
  return { user: created.user, recoveryKey: created.recoveryKey, migrated };
};
