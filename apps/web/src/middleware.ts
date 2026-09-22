import { NextResponse, type NextRequest } from "next/server";

const PUBLIC_PAGES = new Set(["/login", "/setup", "/recover"]);
const PUBLIC_API = new Set(["/api/auth", "/api/auth/recover", "/api/setup"]);

/**
 * Presence gate only: the edge runtime has no filesystem or Node crypto, so the
 * cookie is validated in handler(). Pages without a cookie go to /login; the
 * login page itself redirects to /setup when the server reports setup mode.
 */
export const middleware = (request: NextRequest) => {
  const { pathname } = request.nextUrl;
  if (PUBLIC_PAGES.has(pathname) || PUBLIC_API.has(pathname)) return NextResponse.next();
  const cookie = request.cookies.get("journal_session")?.value;
  if (!cookie) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/login", request.url));
  }
  return NextResponse.next();
};

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
