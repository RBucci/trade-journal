import { bad, handler, ok } from "@/server/api";
import { currentUser } from "@/server/auth/context";
import { regenerateRecoveryKey } from "@/server/auth/users";

export const POST = handler(async (request: Request) => {
  const { password } = (await request.json()) as { password?: string };
  if (typeof password !== "string") return bad("Password required");
  const recoveryKey = regenerateRecoveryKey(currentUser().userId, password);
  if (!recoveryKey) return bad("Password is wrong");
  return ok({ recoveryKey });
});
