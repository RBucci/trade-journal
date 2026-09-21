import { afterEach, describe, expect, it, vi } from "vitest";
import { handler, ok } from "../src/server/api";
import { isSecureRequest, sessionToken, verifyPassword } from "../src/server/auth";

const session = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("next/headers", () => ({
  cookies: async () => ({ get: () => (session.token ? { value: session.token } : undefined) }),
}));
afterEach(() => {
  vi.unstubAllEnvs();
  session.token = undefined;
});

describe("optional journal password protection", () => {
  it("permits local access when no password is configured", async () => {
    vi.stubEnv("JOURNAL_PASSWORD", "");
    expect((await handler(() => ok({ data: true }))()).status).toBe(200);
  });
  it("rejects both missing and forged cookies before executing any handler", async () => {
    vi.stubEnv("JOURNAL_PASSWORD", "test-password");
    const action = vi.fn(() => ok({ secret: true }));
    for (const token of [undefined, "forged", "0".repeat(64)]) {
      session.token = token;
      expect((await handler(action)()).status).toBe(401);
    }
    expect(action).not.toHaveBeenCalled();
  });
  it("accepts signed sessions and invalidates them when the password changes", async () => {
    vi.stubEnv("JOURNAL_PASSWORD", "test-password");
    session.token = sessionToken();
    expect((await handler(() => ok({ data: true }))()).status).toBe(200);
    vi.stubEnv("JOURNAL_PASSWORD", "new-password");
    expect((await handler(() => ok({ data: true }))()).status).toBe(401);
  });
  it("allows the login endpoint to verify a password without a session", async () => {
    vi.stubEnv("JOURNAL_PASSWORD", "test-password");
    expect(verifyPassword("test-password")).toBe(true);
    expect(verifyPassword("wrong-password")).toBe(false);
    expect((await handler(() => ok({ login: true }), { public: true })()).status).toBe(200);
  });
});

describe("secure cookie detection behind a reverse proxy", () => {
  const req = (url: string, headers: Record<string, string> = {}) => new Request(url, { headers });
  it("is secure for a direct https request", () => {
    expect(isSecureRequest(req("https://journal.example/api/auth"))).toBe(true);
  });
  it("is not secure for plain http with no proxy headers", () => {
    expect(isSecureRequest(req("http://localhost:3000/api/auth"))).toBe(false);
  });
  it("trusts X-Forwarded-Proto https from a TLS-terminating proxy", () => {
    expect(
      isSecureRequest(req("http://localhost:3000/api/auth", { "x-forwarded-proto": "https" })),
    ).toBe(true);
  });
  it("uses the first hop when X-Forwarded-Proto lists several", () => {
    expect(
      isSecureRequest(
        req("http://localhost:3000/api/auth", { "x-forwarded-proto": "https, http" }),
      ),
    ).toBe(true);
    expect(
      isSecureRequest(
        req("http://localhost:3000/api/auth", { "x-forwarded-proto": "http, https" }),
      ),
    ).toBe(false);
  });
});
