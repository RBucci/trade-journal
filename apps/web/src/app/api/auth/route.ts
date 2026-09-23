import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { AUTH_COOKIE } from "@/server/auth";
import { bad, handler, ok } from "@/server/api";
import { setupRequired } from "@/server/auth/setup";
import { getUser, verifyLogin } from "@/server/auth/users";
import {
  createSession,
  deleteSession,
  resolveSession,
  sessionCookieOptions,
} from "@/server/auth/sessions";
import { checkLogin, clientIp, recordAttempt } from "@/server/auth/rate-limit";

export const GET = handler(
  async () => {
    if (setupRequired()) return ok({ setupRequired: true, authenticated: false });
    const raw = (await cookies()).get(AUTH_COOKIE)?.value;
    const session = resolveSession(raw);
    if (session.kind !== "active")
      return ok({ setupRequired: false, authenticated: false, locked: session.kind === "locked" });
    const user = getUser(session.userId);
    if (!user) return ok({ setupRequired: false, authenticated: false });
    return ok({
      setupRequired: false,
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        mustChangePassword: user.mustChangePassword,
      },
    });
  },
  { public: true },
);

export const POST = handler(
  async (request: Request) => {
    if (setupRequired())
      return NextResponse.json(
        { error: "Setup required", reason: "setup_required" },
        { status: 409 },
      );
    const { username, password } = (await request.json()) as {
      username?: string;
      password?: string;
    };
    if (typeof username !== "string" || typeof password !== "string" || !username || !password)
      return bad("Invalid username or password.", 401);
    const ip = clientIp(request);
    const limit = checkLogin(ip, username);
    if (!limit.allowed)
      return NextResponse.json(
        { error: limit.message },
        { status: 429, headers: { "Retry-After": String(limit.retryAfterSec) } },
      );
    const login = verifyLogin(username, password);
    recordAttempt(ip, username, Boolean(login));
    if (!login) return bad("Invalid username or password.", 401);
    const token = createSession({
      userId: login.user.id,
      role: login.user.role,
      dek: login.dek,
      ip,
      userAgent: request.headers.get("user-agent") ?? undefined,
    });
    (await cookies()).set(AUTH_COOKIE, token, sessionCookieOptions(request));
    return ok({ authenticated: true, mustChangePassword: login.user.mustChangePassword });
  },
  { public: true },
);

export const DELETE = handler(
  async () => {
    // Before setup there is no session to delete, and reaching auth.db here
    // would create it — which would end setup mode with no account in it.
    if (setupRequired()) return ok({ authenticated: false });
    const jar = await cookies();
    const raw = jar.get(AUTH_COOKIE)?.value;
    if (raw) deleteSession(raw);
    jar.delete(AUTH_COOKIE);
    return ok({ authenticated: false });
  },
  { public: true },
);
