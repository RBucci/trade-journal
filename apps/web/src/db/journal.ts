import Database from "better-sqlite3-multiple-ciphers";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import * as schema from "./schema";
import { BOOTSTRAP_SQL } from "./bootstrap";

export class JournalOpenError extends Error {}

const applyMigrations = (sqlite: Database.Database): void => {
  sqlite.exec(BOOTSTRAP_SQL);
  // Additive upgrade: existing executions retain their fields and dedup hashes.
  const executionColumns = sqlite.pragma("table_info(executions)") as { name: string }[];
  if (!executionColumns.some((column) => column.name === "import_metadata_json")) {
    sqlite.exec("ALTER TABLE executions ADD COLUMN import_metadata_json TEXT");
  }
  // Materialize CSV bounds once so connection and range lookups never scan candle JSON.
  const csvColumns = sqlite.pragma("table_info(market_csv_datasets)") as { name: string }[];
  sqlite.transaction(() => {
    for (const name of ["bar_count", "first_time", "last_time"]) {
      if (!csvColumns.some((column) => column.name === name))
        sqlite.exec(
          `ALTER TABLE market_csv_datasets ADD COLUMN ${name} INTEGER NOT NULL DEFAULT 0`,
        );
    }
    sqlite.exec(`UPDATE market_csv_datasets SET
      bar_count = json_array_length(bars_json),
      first_time = json_extract(bars_json, '$[0].time'),
      last_time = json_extract(bars_json, '$[#-1].time') WHERE bar_count = 0`);
  })();
};

const makeOrm = (sqlite: Database.Database) => drizzle(sqlite, { schema });
export type Journal = ReturnType<typeof makeOrm>;

/** Open one journal file. With a DEK the file is SQLCipher-encrypted; a wrong DEK throws JournalOpenError. */
export const openJournal = (
  file: string,
  dek?: Buffer,
): { sqlite: Database.Database; orm: Journal } => {
  mkdirSync(dirname(file), { recursive: true });
  const sqlite = new Database(file);
  try {
    if (dek) {
      sqlite.pragma("cipher='sqlcipher'");
      sqlite.pragma(`key="x'${dek.toString("hex")}'"`);
    }
    sqlite.pragma("journal_mode = WAL");
    sqlite.pragma("foreign_keys = ON");
    // First real read: fails with SQLITE_NOTADB when the key is wrong.
    sqlite.prepare("SELECT count(*) AS n FROM sqlite_master").get();
    applyMigrations(sqlite);
  } catch (error) {
    sqlite.close();
    throw new JournalOpenError(
      error instanceof Error ? error.message : "Journal could not be opened",
    );
  }
  return { sqlite, orm: makeOrm(sqlite) };
};
