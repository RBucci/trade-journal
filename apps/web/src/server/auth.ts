// apps/web/src/server/auth.ts
import { createHmac, timingSafeEqual } from "node:crypto";

export const AUTH_COOKIE = "journal_session";

// Legacy single-password auth. Removed in Task 7 once handler() uses sessions.
export const passwordConfigured = (): boolean => Boolean(process.env.JOURNAL_PASSWORD);

export const sessionToken = (): string =>
  createHmac("sha256", process.env.JOURNAL_PASSWORD ?? "")
    .update("session-v1")
    .digest("hex");

export const verifyPassword = (candidate: string): boolean => {
  const expected = Buffer.from(process.env.JOURNAL_PASSWORD ?? "", "utf8");
  const given = Buffer.from(candidate, "utf8");
  return expected.length === given.length && timingSafeEqual(expected, given);
};

export const verifySession = (token: string | undefined): boolean => {
  if (!passwordConfigured()) return true;
  if (!token) return false;
  const expected = Buffer.from(sessionToken(), "utf8");
  const given = Buffer.from(token, "utf8");
  return expected.length === given.length && timingSafeEqual(expected, given);
};

/**
 * Whether the browser reached us over HTTPS. Behind a TLS-terminating reverse
 * proxy the app only sees plain HTTP, so trust the first hop of
 * X-Forwarded-Proto before falling back to the request URL.
 */
export const isSecureRequest = (request: Request): boolean => {
  const forwarded = request.headers.get("x-forwarded-proto");
  if (forwarded) return forwarded.split(",")[0]?.trim().toLowerCase() === "https";
  return new URL(request.url).protocol === "https:";
};
