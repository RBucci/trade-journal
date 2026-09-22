// apps/web/tests/api-auth.test.ts
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, describe, expect, it, vi } from "vitest";

const scratch = mkdtempSync(join(tmpdir(), "journal-auth-test-"));
process.env.JOURNAL_DATA_DIR = scratch;
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

const jar = vi.hoisted(() => ({ token: undefined as string | undefined }));
vi.mock("next/headers", () => ({
  cookies: async () => ({
    get: () => (jar.token ? { value: jar.token } : undefined),
    set: () => undefined,
    delete: () => undefined,
  }),
}));

const { handler, ok } = await import("../src/server/api");
const { isSecureRequest } = await import("../src/server/auth");
const { createUser } = await import("../src/server/auth/users");
const { createSession, forgetMemory } = await import("../src/server/auth/sessions");
const { addBlock, removeBlock } = await import("../src/server/auth/rate-limit");
const { db, accounts } = await import("../src/db");

afterEach(() => {
  jar.token = undefined;
});

const req = (headers: Record<string, string> = {}) =>
  new Request("http://localhost:3000/api/x", { headers });
const route = handler(async () => ok({ count: db.select().from(accounts).all().length }));

describe("handler auth gate", () => {
  it("reports setup_required before any user exists, outside the vitest pass-through", async () => {
    vi.stubEnv("VITEST", "false");
    const response = await route(req());
    expect(response.status).toBe(409);
    expect(await response.json()).toEqual({ error: "Setup required", reason: "setup_required" });
    vi.unstubAllEnvs();
  });
  it("passes through before setup only under vitest", async () => {
    expect((await route(req())).status).toBe(200);
  });
  it("rejects missing and forged cookies once users exist", async () => {
    createUser({ username: "alice", password: "alice-password-1", role: "admin" });
    const action = vi.fn(async () => ok({ secret: true }));
    const guarded = handler(action);
    for (const token of [undefined, "forged", "0".repeat(64)]) {
      jar.token = token;
      expect((await guarded(req())).status).toBe(401);
    }
    expect(action).not.toHaveBeenCalled();
  });
  it("accepts a real session and runs inside the user's journal", async () => {
    const bob = createUser({ username: "bob", password: "bob-password-123", role: "user" });
    jar.token = createSession({ userId: bob.user.id, role: "user", dek: bob.dek });
    const response = await route(req());
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ count: 0 });
  });
  it("answers locked after a restart", async () => {
    const carol = createUser({ username: "carol", password: "carol-password-1", role: "user" });
    jar.token = createSession({ userId: carol.user.id, role: "user", dek: carol.dek });
    forgetMemory();
    const response = await route(req());
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: "Locked", reason: "locked" });
  });
  it("forces a password change and gates admin routes", async () => {
    const dave = createUser({
      username: "dave",
      password: "dave-password-12",
      role: "user",
      mustChangePassword: true,
    });
    jar.token = createSession({ userId: dave.user.id, role: "user", dek: dave.dek });
    const gated = await route(req());
    expect(gated.status).toBe(403);
    expect((await gated.json()).reason).toBe("password_change_required");
    const allowed = handler(async () => ok({ fine: true }), { allowPasswordChange: true });
    expect((await allowed(req())).status).toBe(200);
    const adminOnly = handler(async () => ok({ admin: true }), { admin: true });
    expect((await adminOnly(req())).status).toBe(403);
  });
  it("blocks manually blocked IPs on every route", async () => {
    addBlock({ cidr: "203.0.113.0/24", reason: "test" });
    const publicRoute = handler(async () => ok({ open: true }), { public: true });
    expect((await publicRoute(req({ "x-forwarded-for": "203.0.113.5" }))).status).toBe(403);
    expect((await publicRoute(req({ "x-forwarded-for": "198.51.100.5" }))).status).toBe(200);
    removeBlock("203.0.113.0/24");
  });
});

describe("secure cookie detection behind a reverse proxy", () => {
  const secureReq = (url: string, headers: Record<string, string> = {}) =>
    new Request(url, { headers });
  it("is secure for a direct https request", () => {
    expect(isSecureRequest(secureReq("https://journal.example/api/auth"))).toBe(true);
  });
  it("is not secure for plain http with no proxy headers", () => {
    expect(isSecureRequest(secureReq("http://localhost:3000/api/auth"))).toBe(false);
  });
  it("trusts X-Forwarded-Proto https from a TLS-terminating proxy", () => {
    expect(
      isSecureRequest(
        secureReq("http://localhost:3000/api/auth", { "x-forwarded-proto": "https" }),
      ),
    ).toBe(true);
  });
  it("uses the first hop when X-Forwarded-Proto lists several", () => {
    expect(
      isSecureRequest(
        secureReq("http://localhost:3000/api/auth", { "x-forwarded-proto": "https, http" }),
      ),
    ).toBe(true);
    expect(
      isSecureRequest(
        secureReq("http://localhost:3000/api/auth", { "x-forwarded-proto": "http, https" }),
      ),
    ).toBe(false);
  });
});
