import { existsSync } from "node:fs";
import { join } from "node:path";

export const dataDir = (): string => process.env.JOURNAL_DATA_DIR ?? join(process.cwd(), "data");
export const userDataDir = (userId: string): string => join(dataDir(), "users", userId);
export const authDbPath = (): string => join(dataDir(), "auth.db");
export const legacyJournalPath = (): string => join(dataDir(), "journal.db");
export const authDbExists = (): boolean => existsSync(authDbPath());
