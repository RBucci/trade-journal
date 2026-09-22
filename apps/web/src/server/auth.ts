// apps/web/src/server/auth.ts
export const AUTH_COOKIE = "journal_session";

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
