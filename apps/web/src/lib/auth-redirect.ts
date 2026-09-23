export const authRedirectFor = (
  status: number,
  body: { reason?: string } | null,
  pathname: string,
): string | null => {
  const reason = body?.reason;
  if (status === 409 && reason === "setup_required") return pathname === "/setup" ? null : "/setup";
  if (status === 403 && reason === "password_change_required")
    return pathname === "/change-password" ? null : "/change-password";
  if (status === 401) {
    if (pathname === "/login" || pathname === "/setup" || pathname === "/recover") return null;
    return reason === "locked" ? "/login?reason=restart" : "/login";
  }
  return null;
};

export const applyAuthRedirect = (status: number, body: { reason?: string } | null): void => {
  if (typeof window === "undefined") return;
  const target = authRedirectFor(status, body, window.location.pathname);
  if (target) window.location.assign(target);
};
