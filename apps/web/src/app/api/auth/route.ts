import { cookies } from "next/headers";
import {
  AUTH_COOKIE,
  isSecureRequest,
  passwordConfigured,
  sessionToken,
  verifyPassword,
} from "@/server/auth";
import { bad, handler, ok } from "@/server/api";

export const POST = handler(
  async (request: Request) => {
    if (!passwordConfigured()) return ok({ authenticated: true });
    const { password } = (await request.json()) as { password?: string };
    if (typeof password !== "string" || !password || !verifyPassword(password))
      return bad("Wrong password", 401);
    const jar = await cookies();
    jar.set(AUTH_COOKIE, sessionToken(), {
      httpOnly: true,
      sameSite: "lax",
      secure: isSecureRequest(request),
      path: "/",
      maxAge: 60 * 60 * 24 * 30,
    });
    return ok({ authenticated: true });
  },
  { public: true },
);
