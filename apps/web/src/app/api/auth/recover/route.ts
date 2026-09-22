import { NextResponse } from "next/server";
import { bad, handler, ok } from "@/server/api";
import { setupRequired } from "@/server/auth/setup";
import { recoverWithKey } from "@/server/auth/users";
import { deleteUserSessions } from "@/server/auth/sessions";
import { checkLogin, clientIp, recordAttempt } from "@/server/auth/rate-limit";

export const POST = handler(
  async (request: Request) => {
    if (setupRequired())
      return NextResponse.json(
        { error: "Setup required", reason: "setup_required" },
        { status: 409 },
      );
    const body = (await request.json()) as {
      username?: string;
      recoveryKey?: string;
      newPassword?: string;
    };
    const { username, recoveryKey, newPassword } = body;
    if (
      typeof username !== "string" ||
      typeof recoveryKey !== "string" ||
      typeof newPassword !== "string"
    )
      return bad("Username, recovery key and new password required");
    const ip = clientIp(request);
    const limit = checkLogin(ip, username);
    if (!limit.allowed)
      return NextResponse.json(
        { error: limit.message },
        { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } },
      );
    const result = recoverWithKey(username, recoveryKey, newPassword);
    recordAttempt(ip, username, Boolean(result));
    if (!result) return bad("Invalid username or recovery key.", 401);
    deleteUserSessions(result.user.id);
    return ok({ recoveryKey: result.recoveryKey });
  },
  { public: true },
);
