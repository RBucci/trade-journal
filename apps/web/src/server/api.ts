import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { RequestError } from "./errors";
export { RequestError, requireValue } from "./errors";
import { AUTH_COOKIE } from "./auth";
import { authDbExists } from "@/db/paths";
import { JournalOpenError } from "@/db/journal";
import { runWithUser } from "./auth/context";
import { getUser } from "./auth/users";
import { resolveSession, touchSession } from "./auth/sessions";
import { clientIp, isIpBlocked } from "./auth/rate-limit";

export const ok = (data: unknown, init?: ResponseInit) => {
  const headers = new Headers(init?.headers);
  if (!headers.has("Cache-Control")) headers.set("Cache-Control", "private, no-store");
  return NextResponse.json(data, { ...init, headers });
};

export const bad = (message: string, status = 400) =>
  NextResponse.json({ error: message }, { status });

export const forbidden = (reason: string, message = "Forbidden") =>
  NextResponse.json({ error: message, reason }, { status: 403 });

export interface HandlerOptions {
  /** No session needed (login, setup, recovery). IP blocks still apply. */
  public?: boolean;
  /** Only admins. */
  admin?: boolean;
  /** Reachable while must_change_password is set (password change, logout, whoami). */
  allowPasswordChange?: boolean;
}

/** Route-handler wrapper: auth gate, per-user journal context, uniform error JSON. */
export const handler =
  <C extends unknown[]>(
    fn: (request: Request, ...rest: C) => Promise<Response> | Response,
    options: HandlerOptions = {},
  ) =>
  async (request: Request, ...rest: C): Promise<Response> => {
    try {
      const setupDone = authDbExists();
      if (setupDone && isIpBlocked(clientIp(request))) return forbidden("ip_blocked");
      if (options.public) return await fn(request, ...rest);
      if (!setupDone) {
        if (process.env.VITEST === "true") return await fn(request, ...rest);
        return NextResponse.json(
          { error: "Setup required", reason: "setup_required" },
          { status: 409 },
        );
      }
      const raw = (await cookies()).get(AUTH_COOKIE)?.value;
      const session = resolveSession(raw);
      if (session.kind === "none") return bad("Unauthorized", 401);
      if (session.kind === "locked")
        return NextResponse.json({ error: "Locked", reason: "locked" }, { status: 401 });
      const user = getUser(session.userId);
      if (!user) return bad("Unauthorized", 401);
      if (user.lockedUntil && new Date(user.lockedUntil).getTime() > Date.now())
        return forbidden("user_locked", "Account locked");
      if (user.mustChangePassword && !options.allowPasswordChange)
        return forbidden("password_change_required", "Password change required");
      if (options.admin && user.role !== "admin") return forbidden("admin_only");
      touchSession(session.tokenHash);
      return await runWithUser({ userId: user.id, role: user.role, dek: session.dek }, () =>
        fn(request, ...rest),
      );
    } catch (error) {
      if (error instanceof JournalOpenError) {
        console.error("[journal] open failed:", error.message);
        return NextResponse.json({ error: "Journal could not be opened" }, { status: 500 });
      }
      const message = error instanceof Error ? error.message : "Internal error";
      return NextResponse.json(
        { error: message },
        { status: error instanceof RequestError ? 400 : 500 },
      );
    }
  };
