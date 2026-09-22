import { describe, expect, it } from "vitest";
import { authRedirectFor } from "../src/lib/auth-redirect";

describe("auth redirects", () => {
  it("maps API auth failures to pages", () => {
    expect(authRedirectFor(401, { reason: "locked" }, "/")).toBe("/login?reason=restart");
    expect(authRedirectFor(401, {}, "/journal")).toBe("/login");
    expect(authRedirectFor(403, { reason: "password_change_required" }, "/")).toBe(
      "/change-password",
    );
    expect(authRedirectFor(409, { reason: "setup_required" }, "/login")).toBe("/setup");
    expect(authRedirectFor(403, { reason: "admin_only" }, "/settings")).toBeNull();
    expect(authRedirectFor(500, null, "/")).toBeNull();
  });
  it("does not bounce the login page to itself", () => {
    expect(authRedirectFor(401, {}, "/login")).toBeNull();
    expect(authRedirectFor(401, { reason: "locked" }, "/login")).toBeNull();
  });
});
