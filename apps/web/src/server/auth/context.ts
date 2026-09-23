import { AsyncLocalStorage } from "node:async_hooks";
import type { Role } from "./db";

export interface UserContext {
  userId: string;
  role: Role;
  dek: Buffer;
}

const globalForContext = globalThis as unknown as {
  __journalUserContext?: AsyncLocalStorage<UserContext>;
};
const storage = (globalForContext.__journalUserContext ??= new AsyncLocalStorage<UserContext>());

export const runWithUser = <T>(ctx: UserContext, fn: () => T): T => storage.run(ctx, fn);
export const currentUserContext = (): UserContext | undefined => storage.getStore();
export const currentUser = (): { userId: string; role: Role } => {
  const ctx = storage.getStore();
  if (!ctx) throw new Error("No user context: currentUser() called outside handler()");
  return { userId: ctx.userId, role: ctx.role };
};
